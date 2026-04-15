"""
agent.py — Stage 3 of the knowledge graph pipeline

A Claude-powered agent that answers architectural questions about a microservices
codebase by querying the Neo4j knowledge graph and reading source files.

Usage:
    from agent import GraphAgent

    agent = GraphAgent(
        neo4j_uri="bolt://localhost:7687",
        neo4j_user="neo4j",
        neo4j_password="password",
        repo_root="./repos/microservices-demo",
    )
    answer = agent.run("Show me the checkout flow — which services are called in what order?")
    print(answer)

Requires:
    ANTHROPIC_API_KEY environment variable to be set.
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Any

import anthropic
from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS: list[dict] = [
    {
        "name": "query_graph",
        "description": (
            "Run a Cypher query against the Neo4j knowledge graph and return the results. "
            "Use this to explore service topology, inter-service calls, gRPC contracts, "
            "dependencies, classes, and methods. "
            "Node labels: Service, Endpoint, Library, GrpcService, Class, Function. "
            "Relationships: CALLS, EXPOSES, DEPENDS_ON, IMPLEMENTS, USES_GRPC, "
            "HAS_CLASS, HAS_METHOD, EXTENDS."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cypher": {
                    "type": "string",
                    "description": "The Cypher query to execute against Neo4j.",
                }
            },
            "required": ["cypher"],
        },
    },
    {
        "name": "read_source_file",
        "description": (
            "Read the contents of a source file from the repository. "
            "Use the 'path' property on Service nodes to find the service directory, "
            "then append the filename (e.g. 'main.go', 'server.js'). "
            "Returns up to 200 lines with line numbers."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file.",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "search_code",
        "description": (
            "Search for a regex pattern in source files across one or all services. "
            "Returns up to 30 matches as {file, line, content}. "
            "Use to find cross-cutting patterns like error handling, logging, or "
            "specific function calls."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for in source files.",
                },
                "service_name": {
                    "type": "string",
                    "description": (
                        "Optional service name to limit search to one service. "
                        "If omitted, searches all services."
                    ),
                },
            },
            "required": ["pattern"],
        },
    },
]

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert software architect analyzing a microservices codebase.
You have access to a Neo4j knowledge graph built from the repository and can read source files.

## Graph Schema

**Node Labels:**
- Service {name, language, framework, path, last_modified, age_days}
- Endpoint {id, path, method, protocol, service_name}
- Library {purl, name, version}
- GrpcService {name}
- Class {id, name, kind, base, file, service_name}
- Function {id, name, service_name}

**Relationships:**
- (Service)-[:CALLS]->(Service)            — inter-service HTTP/gRPC calls
- (Service)-[:EXPOSES]->(Endpoint)         — routes and gRPC methods
- (Service)-[:DEPENDS_ON {depth, scope, is_transitive}]->(Library)
- (Service)-[:IMPLEMENTS]->(GrpcService)   — gRPC contracts this service serves
- (Service)-[:USES_GRPC]->(GrpcService)    — gRPC contracts this service calls
- (Service)-[:HAS_CLASS]->(Class)
- (Class)-[:HAS_METHOD]->(Function)
- (Class)-[:EXTENDS]->(GrpcService)

## Useful Cypher Patterns

```cypher
// Who calls a service?
MATCH (caller:Service)-[:CALLS]->(s:Service {name: 'paymentservice'})
RETURN caller.name

// Full call chain from a service
MATCH path = (s:Service {name: 'frontend'})-[:CALLS*1..4]->(t:Service)
RETURN [n IN nodes(path) | n.name] AS chain

// Services depending on a library
MATCH (s:Service)-[:DEPENDS_ON]->(l:Library)
WHERE l.name =~ '(?i).*log4j.*'
RETURN s.name, l.name, l.version

// Most-coupled services
MATCH (s:Service)-[:USES_GRPC]->(g:GrpcService)
RETURN s.name, count(g) AS grpc_deps ORDER BY grpc_deps DESC

// Classes with most methods
MATCH (c:Class)-[:HAS_METHOD]->(f:Function)
RETURN c.service_name, c.name, count(f) AS methods ORDER BY methods DESC
```

## Tool Usage Guidelines

- Start with `query_graph` to understand topology before reading code
- Use `read_source_file` to examine implementation details for specific findings
- Use `search_code` for cross-cutting patterns (error handling, logging, retries)
- Service `path` property gives the absolute directory; append filenames from Class.file or common entry points (main.go, server.js, app.py)
- Always synthesize graph data + code evidence into a concrete answer

Be specific, cite service names, file paths, and line numbers where relevant.
"""

# ---------------------------------------------------------------------------
# GraphAgent
# ---------------------------------------------------------------------------

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".mvn", "vendor", "dist", "build", "target"}
SOURCE_EXTS = {".java", ".py", ".js", ".ts", ".go", ".cs"}


class GraphAgent:
    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "password",
        repo_root: str = "./repos/microservices-demo",
        model: str = "claude-opus-4-5",
    ):
        self.repo_root = Path(repo_root).resolve()
        self.model = model
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    def close(self):
        self.driver.close()

    # --- tool implementations ---

    def _query_graph(self, cypher: str) -> list[dict]:
        """Execute a Cypher query and return results as a list of dicts."""
        try:
            with self.driver.session() as session:
                result = session.run(cypher)
                rows = []
                for record in result:
                    row = {}
                    for key in record.keys():
                        val = record[key]
                        # Convert neo4j Node/Relationship to plain dict
                        if hasattr(val, "_properties"):
                            row[key] = dict(val._properties)
                        else:
                            row[key] = val
                    rows.append(row)
                    if len(rows) >= 100:
                        break
                return rows
        except Neo4jError as e:
            return [{"error": str(e)}]

    def _read_source_file(self, path: str) -> str:
        """Read a source file, returning up to 200 lines with line numbers."""
        p = Path(path)
        if not p.is_absolute():
            p = self.repo_root / path
        try:
            lines = p.read_text(errors="replace").splitlines()
            truncated = len(lines) > 200
            output = "\n".join(f"{i+1:4d}  {line}" for i, line in enumerate(lines[:200]))
            if truncated:
                output += f"\n... ({len(lines) - 200} more lines truncated)"
            return output
        except (OSError, PermissionError) as e:
            return f"Error reading file: {e}"

    def _search_code(self, pattern: str, service_name: str | None = None) -> list[dict]:
        """Search source files for a regex pattern. Returns up to 30 matches."""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return [{"error": f"Invalid regex: {e}"}]

        search_root = self.repo_root
        if service_name:
            # Find the service directory
            candidates = list(search_root.rglob(service_name))
            for c in candidates:
                if c.is_dir():
                    search_root = c
                    break

        matches = []
        for root, dirs, files in os.walk(search_root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if Path(fname).suffix not in SOURCE_EXTS:
                    continue
                fpath = Path(root) / fname
                try:
                    for i, line in enumerate(fpath.read_text(errors="replace").splitlines(), 1):
                        if compiled.search(line):
                            matches.append({
                                "file": str(fpath.relative_to(self.repo_root)),
                                "line": i,
                                "content": line.strip(),
                            })
                            if len(matches) >= 30:
                                return matches
                except OSError:
                    continue
        return matches

    def _dispatch_tool(self, name: str, inputs: dict) -> Any:
        """Route a tool call to the correct implementation."""
        if name == "query_graph":
            return self._query_graph(inputs["cypher"])
        elif name == "read_source_file":
            return self._read_source_file(inputs["path"])
        elif name == "search_code":
            return self._search_code(inputs["pattern"], inputs.get("service_name"))
        return {"error": f"Unknown tool: {name}"}

    # --- agent loop ---

    def run(self, question: str) -> str:
        """
        Run the agent on a question. Returns the final answer as a string.
        Loops until Claude produces a final text response (stop_reason == 'end_turn').
        """
        messages = [{"role": "user", "content": question}]
        turn = 0

        while True:
            turn += 1
            log.debug("Agent turn %d, messages: %d", turn, len(messages))

            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                messages=messages,
            )

            # Append assistant turn to history
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                # Extract the final text block
                for block in response.content:
                    if hasattr(block, "text"):
                        return block.text
                return "(no text response)"

            # Execute all tool calls in this turn
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    log.info("  Tool: %s(%s)", block.name,
                             json.dumps(block.input, ensure_ascii=False)[:120])
                    result = self._dispatch_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, default=str, ensure_ascii=False),
                    })

            messages.append({"role": "user", "content": tool_results})
