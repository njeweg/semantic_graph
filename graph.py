# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "neo4j>=5.0",
# ]
# ///
"""
graph.py — Stage 2/3 of the knowledge graph pipeline

What this script does:
  1. Loads intermediate.json (output from extract.py)
  2. Connects to Neo4j and ensures schema constraints
  3. Creates nodes for Services, Endpoints, Libraries, and GrpcServices
  4. Creates relationships: CALLS, EXPOSES, DEPENDS_ON, IMPLEMENTS, USES_GRPC
  5. Uses MERGE for idempotency — re-run safely without duplicating data

Usage:
  # Run with default Docker Neo4j (neo4j/password @ bolt://localhost:7687)
  uv run graph.py --input intermediate.json

  # Custom Neo4j instance
  uv run graph.py --input intermediate.json \\
    --neo4j-uri bolt://myserver:7687 \\
    --neo4j-user admin \\
    --neo4j-password mypassword

  # Clear graph and rebuild (wipe all data first)
  uv run graph.py --input intermediate.json --clear

  # Install Neo4j locally with Docker (one-time setup):
  docker run --name neo4j -p 7474:7474 -p 7687:7687 \\
    -e NEO4J_AUTH=neo4j/password -d neo4j:latest
  # Then open http://localhost:7474
"""

import os
import json
import argparse
import logging
from pathlib import Path
from typing import Optional

from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError

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
# Normalisation helpers
# ---------------------------------------------------------------------------

def clean_endpoint_path(raw: str) -> str:
    """
    Strip surrounding quotes from Go string literals.
    Input: '"\"/cart\""' or '"/cart"' or 'GetCart'
    Output: '/cart' or 'GetCart'
    """
    if not raw:
        return raw
    # Strip outer double quotes first
    s = raw.strip('"').strip("'")
    # If it now has surrounding quotes, strip again (nested quotes)
    s = s.strip('"').strip("'")
    return s


def normalize_grpc_service_name(raw: str) -> Optional[str]:
    """
    Normalize gRPC service names from various formats to canonical proto name.

    Go patterns:
      RegisterCheckoutServiceServer → CheckoutService
      NewShippingServiceClient → ShippingService

    Python patterns:
      add_RecommendationServiceServicer_to_server → RecommendationService
      CartServiceStub → CartService

    Proto names:
      CartService → CartService (pass-through)

    Returns None for generic names (Health, HealthCheck, etc.)
    """
    if not raw or not isinstance(raw, str):
        return None

    name = raw.strip()

    # Go: RegisterXxxServer → Xxx
    if name.startswith("Register") and name.endswith("Server"):
        name = name[len("Register"):-len("Server")]

    # Go: NewXxxClient → Xxx
    elif name.startswith("New") and name.endswith("Client"):
        name = name[len("New"):-len("Client")]

    # Python: add_XxxServicer_to_server → XxxService
    elif name.startswith("add_") and name.endswith("_to_server"):
        name = name[len("add_"):-len("_to_server")]
        if name.endswith("Servicer"):
            name = name[:-len("Servicer")]

    # Python: XxxStub → Xxx
    elif name.endswith("Stub"):
        name = name[:-len("Stub")]

    # Filter out generics
    if name in ("Health", "HealthCheck", "Healthcheck", "health", ""):
        return None

    return name if name else None


def make_endpoint_id(service_name: str, path: str, method: str) -> str:
    """Create a unique identifier for an endpoint."""
    return f"{service_name}::{path}::{method}"


# ---------------------------------------------------------------------------
# Neo4j connection
# ---------------------------------------------------------------------------

def verify_connectivity(driver) -> bool:
    """Verify Neo4j connectivity; return True if OK, False otherwise."""
    try:
        with driver.session() as session:
            result = session.run("RETURN 1")
            result.single()
        log.info("Connected to Neo4j")
        return True
    except Neo4jError as e:
        log.error("Neo4j connection failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# Schema setup
# ---------------------------------------------------------------------------

def ensure_constraints(session) -> None:
    """Create uniqueness constraints for merge-safe idempotency."""
    constraints = [
        'CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE',
        'CREATE CONSTRAINT library_purl IF NOT EXISTS FOR (l:Library) REQUIRE l.purl IS UNIQUE',
        'CREATE CONSTRAINT endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.id IS UNIQUE',
        'CREATE CONSTRAINT grpcservice_name IF NOT EXISTS FOR (g:GrpcService) REQUIRE g.name IS UNIQUE',
        'CREATE CONSTRAINT class_id IF NOT EXISTS FOR (c:Class) REQUIRE c.id IS UNIQUE',
        'CREATE CONSTRAINT function_id IF NOT EXISTS FOR (f:Function) REQUIRE f.id IS UNIQUE',
    ]
    for cypher in constraints:
        try:
            session.run(cypher)
        except Neo4jError as e:
            # Constraint may already exist
            log.debug("Constraint setup: %s", e)


# ---------------------------------------------------------------------------
# Graph loaders
# ---------------------------------------------------------------------------

def load_service(session, svc: dict) -> None:
    """Load a Service node."""
    cypher = """
    MERGE (s:Service {name: $name})
    SET s.language = $language,
        s.framework = $framework,
        s.path = $path,
        s.last_modified = $last_modified,
        s.age_days = $age_days,
        s.source_hash = $source_hash,
        s.extracted_at = $extracted_at
    """

    git = svc.get("git", {})
    params = {
        "name": svc["name"],
        "language": svc["language"],
        "framework": svc.get("framework", "unknown"),
        "path": svc["path"],
        "last_modified": git.get("last_modified"),
        "age_days": git.get("age_days"),
        "source_hash": git.get("source_hash"),
        "extracted_at": svc.get("extracted_at"),
    }
    session.run(cypher, params)


def load_endpoints(session, svc: dict) -> None:
    """Load Endpoint nodes for a service (batched)."""
    endpoints = svc.get("endpoints", [])
    if not endpoints:
        return

    # Build batch
    batch = []
    for ep in endpoints:
        endpoint_id = make_endpoint_id(
            svc["name"],
            clean_endpoint_path(ep.get("path", "")),
            ep.get("method", "unknown")
        )
        batch.append({
            "id": endpoint_id,
            "path": clean_endpoint_path(ep.get("path", "")),
            "method": ep.get("method", "unknown"),
            "protocol": ep.get("protocol", "unknown"),
            "service_name": svc["name"],
        })

    cypher = """
    UNWIND $batch AS row
    MERGE (e:Endpoint {id: row.id})
    SET e.path = row.path,
        e.method = row.method,
        e.protocol = row.protocol,
        e.service_name = row.service_name
    WITH e, row
    MATCH (s:Service {name: row.service_name})
    MERGE (s)-[:EXPOSES]->(e)
    """
    session.run(cypher, {"batch": batch})


def load_libraries(session, svc: dict) -> None:
    """Load Library nodes for a service (batched, 100 per transaction)."""
    deps = svc.get("dependencies", [])
    if not deps:
        return

    # Batch size 100
    batch_size = 100
    for i in range(0, len(deps), batch_size):
        batch = deps[i:i+batch_size]

        # Transform to load format
        rows = []
        for dep in batch:
            depth = dep.get("depth")
            is_transitive = depth is None or depth == 99 or (isinstance(depth, int) and depth > 1)
            rows.append({
                "purl": dep.get("purl", ""),
                "name": dep.get("name", ""),
                "version": dep.get("version", "unknown"),
                "depth": depth if depth is not None else 99,
                "scope": dep.get("scope", "required"),
                "is_transitive": is_transitive,
                "service_name": svc["name"],
            })

        cypher = """
        UNWIND $batch AS row
        MERGE (l:Library {purl: row.purl})
        SET l.name = row.name,
            l.version = row.version
        WITH l, row
        MATCH (s:Service {name: row.service_name})
        MERGE (s)-[r:DEPENDS_ON]->(l)
        SET r.depth = row.depth,
            r.scope = row.scope,
            r.is_transitive = row.is_transitive
        """
        session.run(cypher, {"batch": rows})


def load_calls(session, svc: dict, all_service_names: set) -> None:
    """Load CALLS relationships from this service to others."""
    calls = svc.get("calls", [])
    if not calls:
        return

    for callee in calls:
        # Verify callee exists
        if callee not in all_service_names:
            log.warning("  Service %s calls unknown service: %s", svc["name"], callee)
            continue

        cypher = """
        MATCH (a:Service {name: $caller})
        MATCH (b:Service {name: $callee})
        MERGE (a)-[:CALLS]->(b)
        """
        session.run(cypher, {"caller": svc["name"], "callee": callee})


def load_grpc_implements(session, svc: dict) -> None:
    """Load IMPLEMENTS relationships for gRPC services this service exposes."""
    grpc_services = svc.get("grpc_services", [])
    if not grpc_services:
        return

    for raw_name in grpc_services:
        normalized = normalize_grpc_service_name(raw_name)
        if not normalized:
            continue

        cypher = """
        MERGE (g:GrpcService {name: $grpc_service_name})
        WITH g
        MATCH (s:Service {name: $service_name})
        MERGE (s)-[:IMPLEMENTS]->(g)
        """
        session.run(cypher, {
            "grpc_service_name": normalized,
            "service_name": svc["name"],
        })


def load_grpc_uses(session, svc: dict) -> None:
    """Load USES_GRPC relationships for gRPC services this service calls."""
    grpc_clients = svc.get("grpc_clients", [])
    if not grpc_clients:
        return

    for raw_name in grpc_clients:
        normalized = normalize_grpc_service_name(raw_name)
        if not normalized:
            continue

        cypher = """
        MERGE (g:GrpcService {name: $grpc_service_name})
        WITH g
        MATCH (s:Service {name: $service_name})
        MERGE (s)-[:USES_GRPC]->(g)
        """
        session.run(cypher, {
            "grpc_service_name": normalized,
            "service_name": svc["name"],
        })


def _resolve_grpc_service_from_base(base: str) -> Optional[str]:
    """
    Map a class base name to a GrpcService name.
    Go: UnimplementedXxxServer → Xxx  (strip Unimplemented + Server)
    Java: XxxGrpc.XxxImplBase → Xxx   (take last segment, strip ImplBase)
    Python: XxxServicer → XxxService  (strip r)
    C#: XxxServiceBase → XxxService   (strip Base)
    Returns None if no recognizable pattern.
    """
    if not base or not isinstance(base, str):
        return None

    name = base.strip()

    # Go: UnimplementedXxxServer → Xxx
    if name.startswith("Unimplemented") and name.endswith("Server"):
        name = name[len("Unimplemented"):-len("Server")]
        return name if name else None

    # Java: XxxGrpc.XxxImplBase → Xxx (take the last segment)
    if name.endswith("ImplBase"):
        if "." in name:
            name = name.split(".")[-1]
        name = name[:-len("ImplBase")]
        return name if name else None

    # Python: XxxServicer → XxxService (strip trailing r)
    if name.endswith("Servicer"):
        name = name[:-len("Servicer")] + "Service"
        return name if name and name != "Service" else None

    # C#: XxxServiceBase → XxxService (strip Base)
    if name.endswith("ServiceBase"):
        name = name[:-len("Base")]
        return name if name else None

    return None


def load_classes(session, svc: dict) -> None:
    """Load Class + Function nodes and HAS_CLASS / HAS_METHOD / EXTENDS relationships."""
    classes = svc.get("classes", [])
    if not classes:
        return

    # Filter for noise methods (same list as extract.py)
    method_noise = frozenset({
        "Check", "Watch", "blockUntilShutdown", "stop", "start",
        "__init__", "__repr__", "__str__", "constructor",
        "main", "loadProto", "loadAllProtos", "listen",
        "ConfigureServices", "Configure", "init",
    })

    for cls in classes:
        class_id = f"{svc['name']}::{cls['name']}"

        # MERGE Class node and HAS_CLASS relationship
        cypher_class = """
        MERGE (c:Class {id: $id})
        SET c.name = $name,
            c.kind = $kind,
            c.base = $base,
            c.file = $file,
            c.service_name = $service_name
        WITH c
        MATCH (s:Service {name: $service_name})
        MERGE (s)-[:HAS_CLASS]->(c)
        """
        session.run(cypher_class, {
            "id": class_id,
            "name": cls["name"],
            "kind": cls.get("kind", "class"),
            "base": cls.get("base"),
            "file": cls.get("file"),
            "service_name": svc["name"],
        })

        # EXTENDS → GrpcService (if base resolves)
        base = cls.get("base")
        if base:
            grpc_name = _resolve_grpc_service_from_base(base)
            if grpc_name:
                session.run("""
                MERGE (g:GrpcService {name: $grpc_name})
                WITH g
                MATCH (c:Class {id: $class_id})
                MERGE (c)-[:EXTENDS]->(g)
                """, {"grpc_name": grpc_name, "class_id": class_id})

        # HAS_METHOD → Function nodes (batched, filtered by noise)
        methods = [m for m in cls.get("methods", []) if m not in method_noise]
        if methods:
            batch = [
                {
                    "id": f"{class_id}::{m}",
                    "name": m,
                    "class_id": class_id,
                    "service_name": svc["name"],
                }
                for m in methods
            ]
            session.run(
                """
                UNWIND $batch AS row
                MERGE (f:Function {id: row.id})
                SET f.name = row.name, f.service_name = row.service_name
                WITH f, row
                MATCH (c:Class {id: row.class_id})
                MERGE (c)-[:HAS_METHOD]->(f)
                """,
                {"batch": batch},
            )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(session) -> None:
    """Print node and relationship counts."""
    print("\n" + "=" * 60)
    print("GRAPH SUMMARY")
    print("=" * 60)

    # Node counts
    print("Nodes:")
    for label in ["Service", "Endpoint", "Library", "GrpcService", "Class", "Function"]:
        result = session.run(f"MATCH (n:{label}) RETURN count(n) AS c")
        count = result.single()["c"]
        print(f"  {label:20s}: {count}")

    # Relationship counts
    print("\nRelationships:")
    for rel_type in ["CALLS", "EXPOSES", "DEPENDS_ON", "IMPLEMENTS", "USES_GRPC", "HAS_CLASS", "HAS_METHOD", "EXTENDS"]:
        result = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN count(r) AS c")
        count = result.single()["c"]
        print(f"  {rel_type:20s}: {count}")

    # Service call graph
    print("\nService Call Graph:")
    result = session.run(
        "MATCH (a:Service)-[:CALLS]->(b:Service) RETURN a.name AS caller, b.name AS callee ORDER BY caller"
    )
    for row in result:
        print(f"  {row['caller']} -> {row['callee']}")

    # Most-depended-on libraries
    print("\nTop 10 Most-used Libraries:")
    result = session.run("""
        MATCH (s:Service)-[:DEPENDS_ON]->(l:Library)
        RETURN l.name AS lib, l.version AS version, count(s) AS services
        ORDER BY services DESC LIMIT 10
    """)
    for row in result:
        print(f"  {row['services']} services  {row['lib']} @ {row['version']}")

    print("=" * 60)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Load extracted service data into Neo4j graph"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("intermediate.json"),
        help="Input JSON file from extract.py (default: intermediate.json)",
    )
    parser.add_argument(
        "--neo4j-uri",
        type=str,
        default="bolt://localhost:7687",
        help="Neo4j bolt URI (default: bolt://localhost:7687)",
    )
    parser.add_argument(
        "--neo4j-user",
        type=str,
        default="neo4j",
        help="Neo4j username (default: neo4j)",
    )
    parser.add_argument(
        "--neo4j-password",
        type=str,
        default=os.environ.get("NEO4J_PASSWORD", "password"),
        help="Neo4j password (default: 'password' or NEO4J_PASSWORD env var)",
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear all existing data before loading (wipe and rebuild)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load input
    if not args.input.exists():
        log.error("Input file not found: %s", args.input)
        return

    with open(args.input) as f:
        data = json.load(f)

    services = data.get("services", [])
    log.info("Loaded %d services from %s", len(services), args.input)

    # Connect to Neo4j
    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))

    if not verify_connectivity(driver):
        log.error("Could not connect to Neo4j at %s", args.neo4j_uri)
        driver.close()
        return

    try:
        with driver.session() as session:
            # Setup schema
            ensure_constraints(session)

            # Optionally clear
            if args.clear:
                log.info("Clearing all existing data...")
                session.run("MATCH (n) DETACH DELETE n")

            # Build set of all service names for referential integrity checks
            all_service_names = {svc["name"] for svc in services}

            # Load all services
            log.info("Loading %d services...", len(services))
            for i, svc in enumerate(services, 1):
                log.info("  [%d/%d] %s", i, len(services), svc["name"])
                load_service(session, svc)
                load_endpoints(session, svc)
                load_libraries(session, svc)
                load_calls(session, svc, all_service_names)
                load_grpc_implements(session, svc)
                load_grpc_uses(session, svc)
                load_classes(session, svc)

            # Print summary
            print_summary(session)

    finally:
        driver.close()


if __name__ == "__main__":
    main()
