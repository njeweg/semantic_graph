# Semantic Knowledge Graph Pipeline

A three-stage pipeline to extract microservice metadata, build a Neo4j knowledge graph, and query service topology, dependencies, and intra-service architecture.

## Overview

This pipeline analyzes a microservices monorepo and produces a queryable knowledge graph with service topology, dependencies, gRPC contracts, and intra-service architecture (classes and methods).

## Quick Start

### Prerequisites
- Python 3.10+
- uv package manager
- npm (for cdxgen): npm install -g @cyclonedx/cdxgen
- Neo4j (Docker)

### Setup

1. Install dependencies:
   uv sync

2. Start Neo4j:
   docker run --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password -d neo4j:latest

3. Place your monorepo at repos/microservices-demo/

## Usage

### Stage 1: Extract Metadata
uv run python extract.py --repo-root repos/microservices-demo --output intermediate.json

### Stage 2: Load into Neo4j
uv run python graph.py --input intermediate.json --clear

### Stage 3: Query in Neo4j Browser
Open http://localhost:7474 and run Cypher queries.

## Languages Supported
- Java (Spring Boot, gRPC)
- Python (Flask, FastAPI, gRPC)
- Go (net/http, gorilla/mux, gRPC)
- JavaScript/TypeScript (Express, gRPC)
- C# (ASP.NET Core, gRPC)

## Graph Output

Nodes: Service, Endpoint, Library, GrpcService, Class, Function

Relationships: CALLS, EXPOSES, DEPENDS_ON, IMPLEMENTS, USES_GRPC, HAS_CLASS, HAS_METHOD, EXTENDS

Results (11 services):
- 60 endpoints
- 31 classes
- 42 methods
- 10 gRPC services

## Files
- extract.py — Stage 1 metadata extraction
- graph.py — Stage 2 Neo4j loader
- extract.ipynb — Interactive notebook
- README.md — This file

## References
- tree-sitter: https://tree-sitter.github.io/tree-sitter/
- Neo4j: https://neo4j.com/
- cdxgen: https://github.com/CycloneDX/cdxgen
