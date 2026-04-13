# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "tree-sitter>=0.23.0",
#     "tree-sitter-java>=0.23.0",
#     "tree-sitter-python>=0.23.0",
#     "tree-sitter-javascript>=0.23.0",
#     "tree-sitter-go>=0.23.0",
#     "pyyaml>=6.0",
# ]
# ///
"""
extract.py — Stage 1 of the knowledge graph pipeline

What this script does:
  1. Discovers service folders in a monorepo (or a directory of cloned repos)
  2. Runs cdxgen per service to get the full dependency tree (direct + transitive)
  3. Uses tree-sitter to parse source code and find:
       - HTTP endpoints (routes exposed by the service)
       - Inter-service calls (FeignClient, HTTP client usage, env-var URLs)
       - Internal import connections (shared libraries, building blocks)
       - Annotations and framework markers (Spring Boot, etc.)
  4. Reads manifest files (manifest.yml, CF app config) for runtime metadata
  5. Writes everything to intermediate.json

Usage:
  # Option A — run directly with uv (no setup needed, deps auto-installed)
  uv run extract.py --repo-root ./microservices-demo --output intermediate.json

  # Option B — install as a project with uv
  uv sync
  uv run extract.py --repo-root ./microservices-demo --output intermediate.json

  # Option C — install deps and run with plain python
  uv pip install -r pyproject.toml
  python extract.py --repo-root ./microservices-demo --output intermediate.json

  # cdxgen must be installed separately (Node.js tool):
  npm install -g @cyclonedx/cdxgen
  cdxgen --version   # verify

  # Skip cdxgen if not yet installed:
  uv run extract.py --repo-root ./microservices-demo --skip-cdxgen

  # Debug a single service:
  uv run extract.py --repo-root ./microservices-demo --service cartservice --verbose
"""

import os
import re
import json
import subprocess
import hashlib
import argparse
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

import yaml

# tree-sitter core + per-language grammar packages
from tree_sitter import Language, Parser, Query, QueryCursor
import tree_sitter_java
import tree_sitter_python
import tree_sitter_javascript
import tree_sitter_go

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Language setup
# We build one Parser per language once at startup and reuse it.
# ---------------------------------------------------------------------------

def _build_parser(language_module) -> Parser:
    lang = Language(language_module.language())
    parser = Parser(lang)
    return parser


PARSERS: dict[str, Parser] = {}
LANGUAGES: dict[str, Language] = {}

def init_parsers():
    """Initialise tree-sitter parsers for all supported languages."""
    specs = {
        "java":       tree_sitter_java,
        "python":     tree_sitter_python,
        "javascript": tree_sitter_javascript,
        "typescript": tree_sitter_javascript,   # TS grammar is a superset
        "go":         tree_sitter_go,
    }
    for name, module in specs.items():
        lang = Language(module.language())
        parser = Parser(lang)
        PARSERS[name] = parser
        LANGUAGES[name] = lang
    log.info("Initialised tree-sitter parsers for: %s", ", ".join(specs.keys()))


# Map file extensions → language key
EXT_TO_LANG: dict[str, str] = {
    ".java": "java",
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "typescript",
    ".go":   "go",
}

# Files/dirs to always skip when walking
SKIP_DIRS  = {".git", "node_modules", "__pycache__", ".mvn", "vendor", "dist", "build", "target"}
SKIP_FILES = {"setup.py", "conftest.py"}

# Method names to filter out (boilerplate, framework internals)
METHOD_NOISE = frozenset({
    "Check", "Watch", "blockUntilShutdown", "stop", "start",
    "__init__", "__repr__", "__str__", "constructor",
    "main", "loadProto", "loadAllProtos", "listen",
    "ConfigureServices", "Configure", "init",
})


# ---------------------------------------------------------------------------
# Service discovery
# ---------------------------------------------------------------------------

def detect_language(service_dir: Path) -> str:
    """
    Determine the primary language of a service folder by checking
    which dependency/build file is present.
    """
    markers = [
        ("java",       ["pom.xml", "build.gradle", "build.gradle.kts"]),
        ("python",     ["requirements.txt", "pyproject.toml", "setup.py"]),
        ("javascript", ["package.json"]),
        ("go",         ["go.mod"]),
        ("csharp",     [".csproj", "*.csproj"]),
    ]
    for lang, files in markers:
        for fname in files:
            if fname.startswith("*"):
                # glob pattern
                if list(service_dir.glob(fname)):
                    return lang
            elif (service_dir / fname).exists():
                return lang
    return "unknown"


def discover_services(repo_root: Path) -> list[Path]:
    """
    Find service directories inside repo_root.

    Strategy:
      - If repo_root itself has a dependency file → single-service repo
      - Otherwise look one or two levels deep for sub-dirs that have
        a recognised dependency file (monorepo layout)
    """
    if detect_language(repo_root) != "unknown":
        return [repo_root]

    services = []
    for candidate in sorted(repo_root.iterdir()):
        if not candidate.is_dir() or candidate.name in SKIP_DIRS:
            continue
        if detect_language(candidate) != "unknown":
            services.append(candidate)
        else:
            # one level deeper (e.g. src/<service>/)
            for sub in sorted(candidate.iterdir()):
                if sub.is_dir() and sub.name not in SKIP_DIRS:
                    if detect_language(sub) != "unknown":
                        services.append(sub)

    log.info("Discovered %d service(s) under %s", len(services), repo_root)
    return services


# ---------------------------------------------------------------------------
# SBOM / dependency extraction via cdxgen
# ---------------------------------------------------------------------------

def run_cdxgen(service_dir: Path) -> dict:
    """
    Run cdxgen on a service directory and return parsed SBOM JSON.
    cdxgen must be installed globally: npm install -g @cyclonedx/cdxgen

    Returns a dict with keys:
      dependencies   — list of {name, version, scope, depth, purl}
      calls          — list of service names this service calls
                       (cdxgen emits these for some ecosystems)
    """
    sbom_path = service_dir / "bom.json"

    # On Windows, npm global binaries are .cmd files not resolvable without shell=True
    is_windows = os.name == "nt"
    cdxgen_cmd = "cdxgen.cmd" if is_windows else "cdxgen"

    cmd = [
        cdxgen_cmd,
        "--output", str(sbom_path),
        "--spec-version", "1.5",
        "--project-name", service_dir.name,
        ".",
    ]

    log.info("  Running cdxgen in %s", service_dir.name)
    try:
        result = subprocess.run(
            cmd,
            cwd=service_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        log.warning("  cdxgen not found — install it with: npm install -g @cyclonedx/cdxgen")
        return {"dependencies": [], "calls": []}

    if result.returncode != 0:
        log.warning("  cdxgen failed for %s: %s", service_dir.name, result.stderr[:200])
        return {"dependencies": [], "calls": []}

    if not sbom_path.exists():
        log.warning("  cdxgen produced no output for %s", service_dir.name)
        return {"dependencies": [], "calls": []}

    with open(sbom_path) as f:
        sbom = json.load(f)

    # Clean up the generated file so the repo stays tidy
    sbom_path.unlink(missing_ok=True)

    return parse_sbom(sbom)


def parse_sbom(sbom: dict) -> dict:
    """
    Extract dependency list and service-call graph from a CycloneDX SBOM.

    CycloneDX 1.5 structure we care about:
      components[]          — every library/component
        .name               — library name
        .version
        .purl               — package URL (unique identifier)
        .scope              — "required" | "optional" | "excluded"

      dependencies[]        — the dependency graph
        .ref                — component being described
        .dependsOn[]        — what it directly depends on

      services[]            — external services called (cdxgen adds these
                              for some ecosystems, e.g. from OpenAPI clients)
        .name
        .endpoints[]
    """
    components_by_ref: dict[str, dict] = {}
    for comp in sbom.get("components", []):
        ref = comp.get("bom-ref") or comp.get("purl", comp.get("name", ""))
        components_by_ref[ref] = comp

    # Build a depth map: BFS from root component
    root_ref = sbom.get("metadata", {}).get("component", {}).get("bom-ref", "")
    dep_graph: dict[str, list[str]] = {}
    for dep_entry in sbom.get("dependencies", []):
        dep_graph[dep_entry["ref"]] = dep_entry.get("dependsOn", [])

    depth_map = _bfs_depth(root_ref, dep_graph)

    dependencies = []
    for ref, comp in components_by_ref.items():
        dependencies.append({
            "name":    comp.get("name", ""),
            "version": comp.get("version", "unknown"),
            "purl":    comp.get("purl", ""),
            "scope":   comp.get("scope", "required"),
            "depth":   depth_map.get(ref, 99),   # 99 = depth unknown
        })

    # External service calls declared in the SBOM
    calls = []
    for svc in sbom.get("services", []):
        calls.append({
            "name":      svc.get("name", ""),
            "endpoints": [e.get("value", "") for e in svc.get("endpoints", [])],
        })

    return {"dependencies": dependencies, "calls": calls}


def _bfs_depth(root: str, graph: dict[str, list[str]]) -> dict[str, int]:
    """BFS from root through the dependency graph, recording depth of each node."""
    if not root:
        return {}
    visited: dict[str, int] = {root: 0}
    queue = [root]
    while queue:
        current = queue.pop(0)
        for child in graph.get(current, []):
            if child not in visited:
                visited[child] = visited[current] + 1
                queue.append(child)
    return visited


# ---------------------------------------------------------------------------
# Source code analysis via tree-sitter
# ---------------------------------------------------------------------------

def collect_source_files(service_dir: Path, language: str) -> list[Path]:
    """
    Walk service_dir and return source files for the given language,
    skipping generated code, test directories, and vendor folders.
    """
    ext = {
        "java":       ".java",
        "python":     ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "go":         ".go",
        "csharp":     ".cs",
    }.get(language)

    if ext is None:
        return []

    # Generated proto files add noise without useful signal
    SKIP_SUFFIXES = {"_pb2.py", "_pb2_grpc.py", ".pb.go", "_grpc.pb.go"}

    files = []
    for root, dirs, filenames in os.walk(service_dir):
        # Prune skip dirs in-place so os.walk won't descend into them
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS
            and "test" not in d.lower()
            and "spec"  not in d.lower()
        ]
        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            if any(filename.endswith(s) for s in SKIP_SUFFIXES):
                continue
            if filename.endswith(ext):
                files.append(Path(root) / filename)

    return files


def parse_proto_files(service_dir: Path) -> dict:
    """
    Walk service_dir for .proto files and extract gRPC service names and RPC methods.
    Uses regex — no tree-sitter needed for the simple proto syntax.
    """
    grpc_services: list[str] = []
    grpc_methods:  list[str] = []

    for proto_file in service_dir.rglob("*.proto"):
        if any(part in SKIP_DIRS for part in proto_file.parts):
            continue
        try:
            content = proto_file.read_text(errors="replace")
        except OSError:
            continue
        for m in re.finditer(r'\bservice\s+(\w+)\s*\{', content):
            grpc_services.append(m.group(1))
        for m in re.finditer(r'\brpc\s+(\w+)\s*\(', content):
            grpc_methods.append(m.group(1))

    return {
        "grpc_services": _dedupe(grpc_services),
        "grpc_methods":  _dedupe(grpc_methods),
    }


def parse_source_file(filepath: Path, language: str) -> bytes:
    """Read and return source bytes; tree-sitter works on bytes, not strings."""
    try:
        return filepath.read_bytes()
    except (OSError, PermissionError) as e:
        log.debug("  Could not read %s: %s", filepath, e)
        return b""


# --- tree-sitter query helpers ---

def _run_query(language_key: str, query_src: str, tree, source: bytes) -> list[dict]:
    """
    Run a tree-sitter query and return captures as a list of
    {name: capture_name, text: matched_text, line: line_number}.
    Uses the tree-sitter >= 0.24 QueryCursor API.
    """
    lang = LANGUAGES.get(language_key)
    if lang is None:
        return []
    try:
        query  = Query(lang, query_src)
        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)
    except Exception as e:
        log.debug("  Query error (%s): %s", language_key, e)
        return []

    results = []
    for _, captures in matches:
        for capture_name, nodes in captures.items():
            for node in nodes:
                text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()
                results.append({
                    "name": capture_name,
                    "text": text,
                    "line": node.start_point[0] + 1,
                })
    return results


# --- Java analysis ---

JAVA_QUERIES = {
    # Spring MVC route annotations
    "routes": """
        (annotation
          name: (identifier) @ann_name
          (#match? @ann_name "^(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)$")
          arguments: (annotation_argument_list
            (string_literal) @route_path)
        )
    """,

    # FeignClient — declares a typed HTTP client to another service
    "feign_clients": """
        (annotation
          name: (identifier) @ann_name
          (#eq? @ann_name "FeignClient")
          arguments: (annotation_argument_list) @args
        )
    """,

    # RestTemplate / WebClient — programmatic HTTP calls
    "http_clients": """
        (method_invocation
          object: (identifier) @obj
          (#match? @obj "^(restTemplate|webClient|httpClient|restClient)$")
          name: (identifier) @method
        )
    """,

    # Import statements — catch ALL imports including transitive wrapper libs
    "imports": """
        (import_declaration
          (scoped_identifier) @import_path
        )
    """,

    # Class-level Spring annotations for service classification
    "class_annotations": """
        (class_declaration
          (modifiers
            (annotation
              name: (identifier) @class_ann
              (#match? @class_ann "^(RestController|Service|Repository|Component|SpringBootApplication|EnableFeignClients)$")
            )
          )
        )
    """,

    # Environment variable reads — often hide service URLs
    "env_reads": """
        (method_invocation
          object: [(identifier)(field_access)] @obj
          name: (identifier) @method
          (#match? @method "^(getenv|getProperty|getRequiredProperty)$")
          arguments: (argument_list (string_literal) @env_key)
        )
    """,

    # gRPC service implementation: extends XxxGrpc.XxxImplBase
    "grpc_servers": """
        (class_declaration
          superclass: (type_identifier) @grpc_base
          (#match? @grpc_base "ImplBase$")
        )
    """,

    # gRPC addService call: ServerBuilder.forPort(...).addService(new XxxImpl())
    "grpc_clients": """
        (method_invocation
          name: (identifier) @method
          (#eq? @method "addService")
          arguments: (argument_list
            (object_creation_expression
              type: (type_identifier) @grpc_service_impl
            )
          )
        )
    """,
}


def analyse_java(files: list[Path]) -> dict:
    parser = PARSERS["java"]
    routes, feign_clients, imports, class_anns, env_reads, http_calls = [], [], [], [], [], []
    grpc_servers, grpc_clients = [], []

    for filepath in files:
        source = parse_source_file(filepath, "java")
        if not source:
            continue
        tree = parser.parse(source)

        routes       += [c["text"] for c in _run_query("java", JAVA_QUERIES["routes"],            tree, source) if c["name"] == "route_path"]
        feign_clients+= [c["text"] for c in _run_query("java", JAVA_QUERIES["feign_clients"],     tree, source) if c["name"] == "args"]
        imports      += [c["text"] for c in _run_query("java", JAVA_QUERIES["imports"],           tree, source) if c["name"] == "import_path"]
        class_anns   += [c["text"] for c in _run_query("java", JAVA_QUERIES["class_annotations"], tree, source) if c["name"] == "class_ann"]
        env_reads    += [c["text"] for c in _run_query("java", JAVA_QUERIES["env_reads"],         tree, source) if c["name"] == "env_key"]
        http_calls   += [c["text"] for c in _run_query("java", JAVA_QUERIES["http_clients"],      tree, source) if c["name"] == "method"]
        grpc_servers += [c["text"] for c in _run_query("java", JAVA_QUERIES["grpc_servers"],      tree, source) if c["name"] == "grpc_base"]
        grpc_clients += [c["text"] for c in _run_query("java", JAVA_QUERIES["grpc_clients"],      tree, source) if c["name"] == "grpc_service_impl"]

    return {
        "routes":            _dedupe(routes),
        "feign_clients":     _dedupe(feign_clients),
        "imports":           _dedupe(imports),
        "class_annotations": _dedupe(class_anns),
        "env_reads":         _dedupe(env_reads),
        "http_calls":        _dedupe(http_calls),
        "grpc_servers":      _dedupe(grpc_servers),
        "grpc_clients":      _dedupe(grpc_clients),
    }


# --- Python analysis ---

PYTHON_QUERIES = {
    # Flask / FastAPI route decorators
    "routes": """
        (decorated_definition
          (decorator
            (call
              function: (attribute
                object: (identifier) @obj
                attribute: (identifier) @method
                (#match? @method "^(route|get|post|put|delete|patch)$")
              )
              arguments: (argument_list (string) @route_path)
            )
          )
        )
    """,

    # import statements
    "imports": """
        (import_from_statement
          module_name: (dotted_name) @module
        )
        (import_statement
          name: (dotted_name) @module
        )
    """,

    # requests / httpx calls to external services
    "http_clients": """
        (call
          function: (attribute
            object: (identifier) @lib
            (#match? @lib "^(requests|httpx|urllib|aiohttp|session)$")
            attribute: (identifier) @method
            (#match? @method "^(get|post|put|delete|patch|request)$")
          )
          arguments: (argument_list (string) @url)
        )
    """,

    # os.environ reads
    "env_reads": """
        (subscript
          value: (attribute
            object: (identifier) @os
            (#eq? @os "os")
            attribute: (identifier) @attr
            (#eq? @attr "environ")
          )
          subscript: (string) @env_key
        )
        (call
          function: (attribute
            object: (attribute) @obj
            attribute: (identifier) @method
            (#match? @method "^(get|getenv)$")
          )
          arguments: (argument_list (string) @env_key)
        )
    """,

    # gRPC servicer registration: demo_pb2_grpc.add_XxxServicer_to_server(svc, server)
    "grpc_servers": """
        (call
          function: (attribute
            attribute: (identifier) @grpc_server_name
            (#match? @grpc_server_name "^add_.+Servicer_to_server$")
          )
        )
    """,

    # gRPC stub creation: demo_pb2_grpc.XxxServiceStub(channel)
    "grpc_clients": """
        (call
          function: (attribute
            attribute: (identifier) @grpc_client_name
            (#match? @grpc_client_name "^.+Stub$")
          )
        )
    """,
}


def analyse_python(files: list[Path]) -> dict:
    parser = PARSERS["python"]
    routes, imports, http_clients, env_reads = [], [], [], []
    grpc_servers, grpc_clients = [], []

    for filepath in files:
        source = parse_source_file(filepath, "python")
        if not source:
            continue
        tree = parser.parse(source)

        routes       += [c["text"] for c in _run_query("python", PYTHON_QUERIES["routes"],       tree, source) if c["name"] == "route_path"]
        imports      += [c["text"] for c in _run_query("python", PYTHON_QUERIES["imports"],      tree, source) if c["name"] == "module"]
        http_clients += [c["text"] for c in _run_query("python", PYTHON_QUERIES["http_clients"], tree, source) if c["name"] == "url"]
        env_reads    += [c["text"] for c in _run_query("python", PYTHON_QUERIES["env_reads"],    tree, source) if c["name"] == "env_key"]
        grpc_servers += [c["text"] for c in _run_query("python", PYTHON_QUERIES["grpc_servers"], tree, source) if c["name"] == "grpc_server_name"]
        grpc_clients += [c["text"] for c in _run_query("python", PYTHON_QUERIES["grpc_clients"], tree, source) if c["name"] == "grpc_client_name"]

    return {
        "routes":       _dedupe(routes),
        "imports":      _dedupe(imports),
        "http_clients": _dedupe(http_clients),
        "env_reads":    _dedupe(env_reads),
        "grpc_servers": _dedupe(grpc_servers),
        "grpc_clients": _dedupe(grpc_clients),
    }


# --- Go analysis ---

GO_QUERIES = {
    # HTTP handler registrations (net/http and gorilla/mux style) — plain string literal
    "routes": """
        (call_expression
          function: (selector_expression
            field: (field_identifier) @method
            (#match? @method "^(Handle|HandleFunc|GET|POST|PUT|DELETE|PATCH)$")
          )
          arguments: (argument_list (interpreted_string_literal) @route_path)
        )
    """,

    # gorilla/mux with baseUrl prefix: r.HandleFunc(baseUrl+"/path", ...)
    "routes_concat": """
        (call_expression
          function: (selector_expression
            field: (field_identifier) @method
            (#match? @method "^(HandleFunc|Handle)$")
          )
          arguments: (argument_list
            (binary_expression
              right: (interpreted_string_literal) @route_path
            )
          )
        )
    """,

    # gRPC server registration: pb.RegisterXxxServer(srv, impl)
    "grpc_servers": """
        (call_expression
          function: (selector_expression
            field: (field_identifier) @grpc_server_name
            (#match? @grpc_server_name "^Register.+Server$")
          )
        )
    """,

    # gRPC client creation: pb.NewXxxClient(conn)
    "grpc_clients": """
        (call_expression
          function: (selector_expression
            field: (field_identifier) @grpc_client_name
            (#match? @grpc_client_name "^New.+Client$")
          )
        )
    """,

    # Import paths
    "imports": """
        (import_spec
          path: (interpreted_string_literal) @import_path
        )
    """,

    # http.Get / http.Post calls
    "http_clients": """
        (call_expression
          function: (selector_expression
            operand: (identifier) @pkg
            (#eq? @pkg "http")
            field: (field_identifier) @method
            (#match? @method "^(Get|Post|Do|NewRequest)$")
          )
          arguments: (argument_list (interpreted_string_literal) @url)
        )
    """,

    # os.Getenv calls
    "env_reads": """
        (call_expression
          function: (selector_expression
            operand: (identifier) @pkg
            (#eq? @pkg "os")
            field: (field_identifier) @fn
            (#eq? @fn "Getenv")
          )
          arguments: (argument_list (interpreted_string_literal) @env_key)
        )
    """,
}


def analyse_go(files: list[Path]) -> dict:
    parser = PARSERS["go"]
    routes, imports, http_clients, env_reads = [], [], [], []
    grpc_servers, grpc_clients = [], []

    for filepath in files:
        source = parse_source_file(filepath, "go")
        if not source:
            continue
        tree = parser.parse(source)

        routes       += [c["text"] for c in _run_query("go", GO_QUERIES["routes"],        tree, source) if c["name"] == "route_path"]
        routes       += [c["text"] for c in _run_query("go", GO_QUERIES["routes_concat"], tree, source) if c["name"] == "route_path"]
        imports      += [c["text"] for c in _run_query("go", GO_QUERIES["imports"],       tree, source) if c["name"] == "import_path"]
        http_clients += [c["text"] for c in _run_query("go", GO_QUERIES["http_clients"],  tree, source) if c["name"] == "url"]
        env_reads    += [c["text"] for c in _run_query("go", GO_QUERIES["env_reads"],     tree, source) if c["name"] == "env_key"]
        grpc_servers += [c["text"] for c in _run_query("go", GO_QUERIES["grpc_servers"],  tree, source) if c["name"] == "grpc_server_name"]
        grpc_clients += [c["text"] for c in _run_query("go", GO_QUERIES["grpc_clients"],  tree, source) if c["name"] == "grpc_client_name"]

    return {
        "routes":       _dedupe(routes),
        "imports":      _dedupe(imports),
        "http_clients": _dedupe(http_clients),
        "env_reads":    _dedupe(env_reads),
        "grpc_servers": _dedupe(grpc_servers),
        "grpc_clients": _dedupe(grpc_clients),
    }


# --- JavaScript / TypeScript analysis ---

JS_QUERIES = {
    # Express-style route registrations
    "routes": """
        (call_expression
          function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @method
            (#match? @method "^(get|post|put|delete|patch|use)$")
          )
          arguments: (arguments (string) @route_path)
        )
    """,

    # import / require
    "imports": """
        (import_declaration
          source: (string) @import_path
        )
        (call_expression
          function: (identifier) @fn
          (#eq? @fn "require")
          arguments: (arguments (string) @import_path)
        )
    """,

    # fetch / axios calls
    "http_clients": """
        (call_expression
          function: [(identifier)(member_expression)] @fn
          (#match? @fn "^(fetch|axios)")
          arguments: (arguments (string) @url)
        )
    """,

    # process.env reads
    "env_reads": """
        (member_expression
          object: (member_expression
            object: (identifier) @process
            (#eq? @process "process")
            property: (property_identifier) @env
            (#eq? @env "env")
          )
          property: (property_identifier) @env_key
        )
    """,

    # gRPC service registration: server.addService(proto.XxxService.service, {...})
    "grpc_servers": """
        (call_expression
          function: (member_expression
            property: (property_identifier) @method
            (#eq? @method "addService")
          )
          arguments: (arguments
            (member_expression
              object: (member_expression
                property: (property_identifier) @grpc_service_name
              )
              property: (property_identifier) @svc_prop
              (#eq? @svc_prop "service")
            )
          )
        )
    """,
}


def analyse_javascript(files: list[Path]) -> dict:
    parser = PARSERS["javascript"]
    routes, imports, http_clients, env_reads = [], [], [], []
    grpc_servers = []

    for filepath in files:
        source = parse_source_file(filepath, "javascript")
        if not source:
            continue
        tree = parser.parse(source)

        routes       += [c["text"] for c in _run_query("javascript", JS_QUERIES["routes"],       tree, source) if c["name"] == "route_path"]
        imports      += [c["text"] for c in _run_query("javascript", JS_QUERIES["imports"],      tree, source) if c["name"] == "import_path"]
        http_clients += [c["text"] for c in _run_query("javascript", JS_QUERIES["http_clients"], tree, source) if c["name"] == "url"]
        env_reads    += [c["text"] for c in _run_query("javascript", JS_QUERIES["env_reads"],    tree, source) if c["name"] == "env_key"]
        grpc_servers += [c["text"] for c in _run_query("javascript", JS_QUERIES["grpc_servers"], tree, source) if c["name"] == "grpc_service_name"]

    return {
        "routes":       _dedupe(routes),
        "imports":      _dedupe(imports),
        "http_clients": _dedupe(http_clients),
        "env_reads":    _dedupe(env_reads),
        "grpc_servers": _dedupe(grpc_servers),
    }


# --- C# analysis (regex-based — no tree-sitter grammar required) ---

def analyse_csharp(files: list[Path]) -> dict:
    """
    Regex-based C# analyser covering ASP.NET Core gRPC services.
    Detects: gRPC service implementations, gRPC client creation, env var reads.
    """
    grpc_servers: list[str] = []
    grpc_clients: list[str] = []
    env_reads:    list[str] = []
    imports:      list[str] = []

    for filepath in files:
        try:
            content = filepath.read_text(errors="replace")
        except OSError:
            continue

        # using statements
        for m in re.finditer(r'^using\s+([\w.]+)\s*;', content, re.MULTILINE):
            imports.append(m.group(1))

        # gRPC service base class: "class XxxService : ...XxxServiceBase"
        for m in re.finditer(r'\bclass\s+\w+\s*:.*?(\w+ServiceBase)\b', content):
            grpc_servers.append(m.group(1).removesuffix("Base"))

        # MapGrpcService<XxxService>() — explicit service mapping
        for m in re.finditer(r'MapGrpcService<(\w+)>\s*\(\)', content):
            grpc_servers.append(m.group(1))

        # gRPC client: new XxxServiceClient(channel)
        for m in re.finditer(r'new\s+(\w+Client)\s*\(', content):
            grpc_clients.append(m.group(1))

        # Configuration["KEY"] or GetEnvironmentVariable("KEY")
        for m in re.finditer(r'Configuration\["(\w+)"\]', content):
            env_reads.append(m.group(1))
        for m in re.finditer(r'GetEnvironmentVariable\("(\w+)"\)', content):
            env_reads.append(m.group(1))

    return {
        "routes":       [],
        "imports":      _dedupe(imports),
        "env_reads":    _dedupe(env_reads),
        "grpc_servers": _dedupe(grpc_servers),
        "grpc_clients": _dedupe(grpc_clients),
        "http_clients": [],
    }


# --- Class / struct extraction by language ---

GO_CLASS_QUERIES = {
    "structs": """
        (type_declaration
          (type_spec
            name: (type_identifier) @struct_name
            type: (struct_type)
          )
        )
    """,
    "methods": """
        (method_declaration
          receiver: (parameter_list
            (parameter_declaration
              type: [(type_identifier)(pointer_type)] @recv_type
            )
          )
          name: (field_identifier) @method_name
        )
    """,
}

JAVA_CLASS_QUERIES = {
    "classes": """
        (class_declaration
          name: (identifier) @class_name
          superclass: (type_identifier) @base_class
        )
    """,
    "methods": """
        (class_declaration
          (class_body
            (method_declaration
              name: (identifier) @method_name
            )
          )
        )
    """,
}

PYTHON_CLASS_QUERIES = {
    "classes": """
        (class_definition
          name: (identifier) @class_name
          superclasses: (argument_list
            (identifier) @base_class
          )
        )
    """,
    "methods": """
        (class_definition
          (block
            (function_definition
              name: (identifier) @method_name
            )
          )
        )
    """,
}

JS_CLASS_QUERIES = {
    "classes": """
        (class_declaration
          name: (identifier) @class_name
        )
    """,
    "methods": """
        (class_declaration
          (class_body
            (method_definition
              name: (property_identifier) @method_name
            )
          )
        )
    """,
}


def _walk_classes_go(tree, source: bytes, filepath: Path) -> list[dict]:
    """
    Extract Go structs and their methods.
    Groups method_declaration nodes by receiver type.
    """
    structs_result = _run_query("go", GO_CLASS_QUERIES["structs"], tree, source)
    methods_result = _run_query("go", GO_CLASS_QUERIES["methods"], tree, source)

    struct_names = {r["text"] for r in structs_result if r["name"] == "struct_name"}
    method_by_recv: dict[str, list[str]] = {}

    for r in methods_result:
        if r["name"] == "recv_type":
            recv = r["text"].lstrip("*")
            if recv in struct_names:
                method_by_recv.setdefault(recv, [])
        elif r["name"] == "method_name" and method_by_recv:
            last_recv = list(method_by_recv.keys())[-1] if method_by_recv else None
            if last_recv and r["text"] not in METHOD_NOISE:
                method_by_recv[last_recv].append(r["text"])

    classes = []
    for struct_name in struct_names:
        classes.append({
            "name": struct_name,
            "kind": "struct",
            "base": None,
            "file": filepath.name,
            "methods": method_by_recv.get(struct_name, []),
        })

    return classes


def _walk_classes_java(tree, source: bytes, filepath: Path) -> list[dict]:
    """
    Extract Java classes that extend *ImplBase (gRPC) and their methods.
    """
    classes_result = _run_query("java", JAVA_CLASS_QUERIES["classes"], tree, source)
    methods_result = _run_query("java", JAVA_CLASS_QUERIES["methods"], tree, source)

    class_info: dict[str, dict] = {}
    for r in classes_result:
        if r["name"] == "class_name":
            class_info[r["text"]] = {"name": r["text"], "kind": "class", "base": None, "file": filepath.name, "methods": []}
        elif r["name"] == "base_class":
            if class_info:
                last_class = list(class_info.keys())[-1]
                if "ImplBase" in r["text"]:
                    class_info[last_class]["base"] = r["text"]

    method_names = {r["text"] for r in methods_result if r["name"] == "method_name" and r["text"] not in METHOD_NOISE}
    for cls in class_info.values():
        cls["methods"] = sorted(method_names)

    return list(class_info.values())


def _walk_classes_python(tree, source: bytes, filepath: Path) -> list[dict]:
    """
    Extract Python classes and their methods.
    Identifies *Servicer base classes.
    """
    classes_result = _run_query("python", PYTHON_CLASS_QUERIES["classes"], tree, source)
    methods_result = _run_query("python", PYTHON_CLASS_QUERIES["methods"], tree, source)

    class_info: dict[str, dict] = {}
    for r in classes_result:
        if r["name"] == "class_name":
            class_info[r["text"]] = {"name": r["text"], "kind": "class", "base": None, "file": filepath.name, "methods": []}
        elif r["name"] == "base_class":
            if class_info:
                last_class = list(class_info.keys())[-1]
                if "Servicer" in r["text"]:
                    class_info[last_class]["base"] = r["text"]

    method_names = {r["text"] for r in methods_result if r["name"] == "method_name" and r["text"] not in METHOD_NOISE}
    for cls in class_info.values():
        cls["methods"] = sorted(method_names)

    return list(class_info.values())


def _walk_classes_js(tree, source: bytes, filepath: Path) -> list[dict]:
    """
    Extract JS/TS class declarations and their methods.
    """
    classes_result = _run_query("javascript", JS_CLASS_QUERIES["classes"], tree, source)
    methods_result = _run_query("javascript", JS_CLASS_QUERIES["methods"], tree, source)

    class_names = {r["text"] for r in classes_result if r["name"] == "class_name"}
    method_names = {r["text"] for r in methods_result if r["name"] == "method_name" and r["text"] not in METHOD_NOISE}

    classes = []
    for name in class_names:
        classes.append({
            "name": name,
            "kind": "class",
            "base": None,
            "file": filepath.name,
            "methods": sorted(method_names),
        })

    return classes


def _walk_classes_csharp(files: list[Path]) -> list[dict]:
    """
    Regex-based C# class extractor.
    Matches: class Xxx : ...XxxServiceBase
    Extracts override methods via regex.
    """
    classes = []

    for filepath in files:
        try:
            content = filepath.read_text(errors="replace")
        except OSError:
            continue

        # Find class declarations with base classes
        for m in re.finditer(r'\bclass\s+(\w+)\s*:\s*([^{]+?)\{', content):
            class_name = m.group(1)
            base_str = m.group(2).strip()
            base = base_str.split(',')[0].strip() if base_str else None

            # Extract methods from class body
            methods = []
            for method_m in re.finditer(r'\bpublic\s+(?:async\s+)?(?:override\s+)?(\w+)\s+(\w+)\s*\(', content):
                method_name = method_m.group(2)
                if method_name not in METHOD_NOISE:
                    methods.append(method_name)

            classes.append({
                "name": class_name,
                "kind": "class",
                "base": base if base and "ServiceBase" in base else None,
                "file": filepath.name,
                "methods": sorted(set(methods)),
            })

    return classes


def extract_classes(service_dir: Path, language: str, source_files: list[Path]) -> list[dict]:
    """
    Dispatcher: call the right walker per language.
    Returns list of class dicts with {name, kind, base, file, methods}.
    """
    if not source_files:
        return []

    parser = PARSERS.get(language)
    if not parser:
        return []

    if language == "go":
        classes = []
        for filepath in source_files:
            source = parse_source_file(filepath, language)
            if not source:
                continue
            tree = parser.parse(source)
            classes.extend(_walk_classes_go(tree, source, filepath))
        return classes

    elif language == "java":
        classes = []
        for filepath in source_files:
            source = parse_source_file(filepath, language)
            if not source:
                continue
            tree = parser.parse(source)
            classes.extend(_walk_classes_java(tree, source, filepath))
        return classes

    elif language == "python":
        classes = []
        for filepath in source_files:
            source = parse_source_file(filepath, language)
            if not source:
                continue
            tree = parser.parse(source)
            classes.extend(_walk_classes_python(tree, source, filepath))
        return classes

    elif language in ("javascript", "typescript"):
        classes = []
        for filepath in source_files:
            source = parse_source_file(filepath, language)
            if not source:
                continue
            tree = parser.parse(source)
            classes.extend(_walk_classes_js(tree, source, filepath))
        return classes

    elif language == "csharp":
        return _walk_classes_csharp(source_files)

    return []


ANALYSERS = {
    "java":       analyse_java,
    "python":     analyse_python,
    "go":         analyse_go,
    "javascript": analyse_javascript,
    "typescript": analyse_javascript,   # same grammar / queries
    "csharp":     analyse_csharp,
}


# ---------------------------------------------------------------------------
# Manifest / Cloud Foundry metadata
# ---------------------------------------------------------------------------

def read_manifest(service_dir: Path) -> dict:
    """
    Read Cloud Foundry manifest.yml (or manifest.yaml) for runtime metadata:
    memory, instances, buildpack, env vars declared at deploy time, custom labels.
    """
    for name in ("manifest.yml", "manifest.yaml"):
        manifest_path = service_dir / name
        if manifest_path.exists():
            try:
                with open(manifest_path) as f:
                    data = yaml.safe_load(f)
                apps = data.get("applications", [data]) if isinstance(data, dict) else []
                app = apps[0] if apps else {}
                env = app.get("env", {})
                return {
                    "memory":     app.get("memory"),
                    "instances":  app.get("instances"),
                    "buildpack":  app.get("buildpack") or app.get("buildpacks"),
                    "env_declared": list(env.keys()),
                    "journey":    env.get("JOURNEY"),          # custom label you plant
                    "domain":     env.get("DOMAIN"),           # optional domain label
                    "stack":      app.get("stack"),
                }
            except Exception as e:
                log.warning("  Could not parse manifest for %s: %s", service_dir.name, e)
    return {}


# ---------------------------------------------------------------------------
# Git metadata
# ---------------------------------------------------------------------------

def read_git_metadata(service_dir: Path) -> dict:
    """
    Read last-commit date and top contributors from git log.
    Walks up to find the .git directory (handles monorepos).
    """
    try:
        result = subprocess.run(
            ["git", "log", "--follow", "-1", "--format=%aI", "--", "."],
            cwd=service_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        last_modified = result.stdout.strip() or None

        age_days = None
        if last_modified:
            from datetime import datetime, timezone
            try:
                dt = datetime.fromisoformat(last_modified)
                age_days = (datetime.now(timezone.utc) - dt).days
            except ValueError:
                pass

        # Hash of all source files for staleness detection
        source_hash = _hash_source_files(service_dir)

        return {
            "last_modified": last_modified,
            "age_days":      age_days,
            "source_hash":   source_hash,
        }
    except Exception as e:
        log.debug("  Git metadata unavailable for %s: %s", service_dir.name, e)
        return {}


def _hash_source_files(service_dir: Path) -> str:
    """MD5 of all source file contents — used to detect staleness in later runs."""
    h = hashlib.md5()
    for root, dirs, files in os.walk(service_dir):
        dirs[:] = [d for d in sorted(dirs) if d not in SKIP_DIRS]
        for fname in sorted(files):
            ext = Path(fname).suffix
            if ext in EXT_TO_LANG:
                try:
                    h.update(Path(root, fname).read_bytes())
                except OSError:
                    pass
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Infer inter-service calls from source analysis
# ---------------------------------------------------------------------------

def infer_service_calls(source_analysis: dict, known_services: list[str]) -> list[str]:
    """
    Look at env var reads, HTTP client URLs, and FeignClient args
    and try to match them to known service names.

    Heuristic: if an env var key or URL string contains a service name
    (case-insensitive), we record a CALLS relationship.

    Example: env var "ORDER_SERVICE_URL" → calls "orderservice"
    """
    called = set()
    candidates = (
        source_analysis.get("env_reads", [])
        + source_analysis.get("http_clients", [])
        + source_analysis.get("feign_clients", [])
        + source_analysis.get("grpc_clients", [])
    )
    for candidate in candidates:
        normalised = candidate.lower().replace("-", "").replace("_", "").replace(" ", "")
        for svc in known_services:
            svc_norm = svc.lower().replace("-", "").replace("_", "")
            if svc_norm in normalised and svc_norm != "":
                called.add(svc)
    return sorted(called)


# ---------------------------------------------------------------------------
# Framework detection
# ---------------------------------------------------------------------------

def infer_framework(language: str, source_analysis: dict, proto_data: dict) -> str:
    """
    Infer the primary framework from language + source signals.
    Returns a short label like "gRPC (grpcio)", "Spring Boot", "Express", etc.
    """
    anns        = source_analysis.get("class_annotations", [])
    imports     = source_analysis.get("imports", [])
    routes      = source_analysis.get("routes", [])
    grpc_srvs   = source_analysis.get("grpc_servers", []) + proto_data.get("grpc_services", [])
    imports_str = " ".join(imports).lower()

    # Java
    if language == "java":
        if "SpringBootApplication" in anns:
            return "Spring Boot"
        if any(a in anns for a in ("RestController", "Service", "Component")):
            return "Spring"
        if grpc_srvs or "grpc" in imports_str:
            return "gRPC (grpc-java)"
        return "Java"

    # Python
    if language == "python":
        if "fastapi" in imports_str or "FastAPI" in imports_str:
            return "FastAPI"
        if "flask" in imports_str:
            return "Flask"
        if grpc_srvs or "grpc" in imports_str:
            return "gRPC (grpcio)"
        return "Python"

    # Go
    if language == "go":
        if routes:
            if "gorilla/mux" in imports_str:
                return "gorilla/mux + gRPC" if grpc_srvs else "gorilla/mux"
            return "net/http + gRPC" if grpc_srvs else "net/http"
        if grpc_srvs or "google.golang.org/grpc" in imports_str:
            return "gRPC (grpc-go)"
        return "Go"

    # JavaScript / TypeScript
    if language in ("javascript", "typescript"):
        if "express" in imports_str:
            return "Express"
        if grpc_srvs or "@grpc/grpc-js" in imports_str or "grpc" in imports_str:
            return "gRPC (grpc-js)"
        return "Node.js"

    # C#
    if language == "csharp":
        if grpc_srvs or "Grpc" in imports_str:
            return "ASP.NET Core gRPC"
        return "ASP.NET Core"

    return language


# ---------------------------------------------------------------------------
# Main per-service processing
# ---------------------------------------------------------------------------

def process_service(service_dir: Path, known_services: list[str], skip_cdxgen: bool = False) -> dict:
    """
    Run the full extraction pipeline for one service and return a service record.
    """
    log.info("Processing: %s", service_dir.name)

    language = detect_language(service_dir)
    source_files = collect_source_files(service_dir, language)
    log.info("  Language: %s  |  Source files: %d", language, len(source_files))

    # 1. Proto file parsing (language-agnostic)
    proto_data = parse_proto_files(service_dir)
    if proto_data["grpc_services"]:
        log.info("  gRPC services (from .proto): %s", proto_data["grpc_services"])

    # 2. SBOM via cdxgen
    if skip_cdxgen:
        sbom_data = {"dependencies": [], "calls": []}
    else:
        sbom_data = run_cdxgen(service_dir)
    log.info("  Dependencies (total incl. transitive): %d", len(sbom_data["dependencies"]))

    # 3. Source analysis via tree-sitter
    analyser = ANALYSERS.get(language)
    if analyser and source_files:
        source_analysis = analyser(source_files)
    else:
        source_analysis = {}
        if language not in ANALYSERS:
            log.info("  No tree-sitter analyser for language: %s — skipping source analysis", language)

    log.info(
        "  Routes: %d  |  Imports: %d  |  Env reads: %d",
        len(source_analysis.get("routes", [])),
        len(source_analysis.get("imports", [])),
        len(source_analysis.get("env_reads", [])),
    )

    # 4. Manifest metadata
    manifest = read_manifest(service_dir)

    # 5. Git metadata
    git_meta = read_git_metadata(service_dir)

    # 6. Infer inter-service CALLS from source signals
    inferred_calls = infer_service_calls(source_analysis, known_services)
    # Merge with any calls cdxgen found in the SBOM services section
    sbom_calls = [c["name"] for c in sbom_data.get("calls", [])]
    all_calls = sorted(set(inferred_calls + sbom_calls) - {service_dir.name})
    if all_calls:
        log.info("  Inferred CALLS to: %s", ", ".join(all_calls))

    # 7. Intra-service architecture (classes/structs and methods)
    classes = extract_classes(service_dir, language, source_files)
    if classes:
        log.info("  Classes/structs: %d", len(classes))

    # 8. Build the source context block used later by the enrichment stage
    #    We store the curated file list so enrich.py doesn't have to re-discover
    context_files = _select_context_files(service_dir, language, source_files)

    return {
        # Identity
        "name":          service_dir.name,
        "path":          str(service_dir.resolve()),
        "language":      language,
        "framework":     infer_framework(language, source_analysis, proto_data),

        # Dependencies (from cdxgen SBOM)
        "dependencies":  sbom_data["dependencies"],

        # Endpoints exposed by this service
        # HTTP routes get protocol=http; gRPC methods from .proto get protocol=grpc
        "endpoints":     (
            [{"path": r,  "method": "unknown", "protocol": "http"}
             for r in source_analysis.get("routes", [])]
            + [{"path": m, "method": "grpc",    "protocol": "grpc"}
               for m in proto_data["grpc_methods"]]
        ),

        # Inter-service relationships
        "calls":         all_calls,

        # Internal imports (for building block detection)
        "imports":       source_analysis.get("imports", []),

        # Framework / role markers
        "class_annotations": source_analysis.get("class_annotations", []),

        # Environment variables — hints at runtime configuration
        "env_reads":     source_analysis.get("env_reads", []),

        # HTTP client calls with literal URLs extracted
        "http_clients":  source_analysis.get("http_clients", []),

        # gRPC: services this exposes and services it calls
        "grpc_services": (proto_data["grpc_services"]
                          + source_analysis.get("grpc_servers", [])),
        "grpc_clients":  source_analysis.get("grpc_clients", []),

        # Intra-service architecture (classes, structs, and their methods)
        "classes":       classes,

        # Cloud Foundry manifest metadata
        "manifest":      manifest,

        # Git metadata (last modified, age, hash for staleness)
        "git":           git_meta,

        # File paths for the enrichment stage to read
        "context_files": [str(p) for p in context_files],

        # Extraction timestamp
        "extracted_at":  datetime.now(timezone.utc).isoformat(),
    }


def _select_context_files(service_dir: Path, language: str, all_files: list[Path]) -> list[Path]:
    """
    Pick the most informative files to pass to the LLM in the enrichment stage.
    Priority order:
      1. Entry point files (main, app, Application, index, server)
      2. Controller / route handler files
      3. Largest remaining files (up to a cap)

    Returns at most 8 files (typically 200-600 lines total).
    """
    entry_names  = {"main", "app", "application", "server", "index", "cmd"}
    controller_keywords = {"controller", "handler", "router", "route", "api", "endpoint", "resource"}

    entry, controllers, others = [], [], []

    for f in all_files:
        stem = f.stem.lower()
        if stem in entry_names:
            entry.append(f)
        elif any(kw in stem for kw in controller_keywords):
            controllers.append(f)
        else:
            others.append(f)

    # Sort others by file size descending — bigger files tend to have more logic
    others.sort(key=lambda p: p.stat().st_size, reverse=True)

    selected = entry + controllers + others
    return selected[:8]


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _dedupe(items: list) -> list:
    """Remove duplicates while preserving order."""
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract service metadata from a microservice repo into intermediate.json"
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path("."),
        help="Root directory of the repo or monorepo (default: current directory)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("intermediate.json"),
        help="Output file path (default: intermediate.json)",
    )
    parser.add_argument(
        "--skip-cdxgen",
        action="store_true",
        help="Skip cdxgen SBOM generation (useful if cdxgen is not installed)",
    )
    parser.add_argument(
        "--service",
        type=str,
        default=None,
        help="Process only this service name (useful for debugging a single service)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Initialise tree-sitter parsers
    init_parsers()

    repo_root = args.repo_root.resolve()
    if not repo_root.exists():
        log.error("Repo root does not exist: %s", repo_root)
        return

    # Discover all services
    service_dirs = discover_services(repo_root)

    # Optionally filter to a single service for debugging
    if args.service:
        service_dirs = [s for s in service_dirs if s.name == args.service]
        if not service_dirs:
            log.error("Service '%s' not found under %s", args.service, repo_root)
            return

    known_service_names = [s.name for s in service_dirs]
    log.info("Services to process: %s", known_service_names)

    # Process each service
    results = []
    for service_dir in service_dirs:
        try:
            record = process_service(
                service_dir,
                known_services=known_service_names,
                skip_cdxgen=args.skip_cdxgen,
            )
            results.append(record)
        except Exception as e:
            log.error("Failed to process %s: %s", service_dir.name, e, exc_info=True)

    # Write output
    output = {
        "meta": {
            "repo_root":      str(repo_root),
            "extracted_at":   datetime.now(timezone.utc).isoformat(),
            "service_count":  len(results),
            "cdxgen_skipped": args.skip_cdxgen,
        },
        "services": results,
    }

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    log.info("Written %d service records to %s", len(results), args.output)

    # Print a brief summary
    total_deps  = sum(len(s["dependencies"]) for s in results)
    total_routes = sum(len(s["endpoints"]) for s in results)
    total_calls  = sum(len(s["calls"]) for s in results)
    log.info(
        "Summary — dependencies: %d  |  endpoints: %d  |  service calls: %d",
        total_deps, total_routes, total_calls,
    )


if __name__ == "__main__":
    main()
