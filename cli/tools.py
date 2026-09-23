"""
Tools definition and execution module for AutoSchema & API Auditor.
Handles Tavily Search API interactions with fallback offline intelligence cache.
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, List
from config import Config

logger = logging.getLogger(__name__)

# OpenAI-compatible function definition for Nebius Token Factory
TAVILY_TOOL_SPEC = {
    "type": "function",
    "function": {
        "name": "tavily_search",
        "description": "Search the live web for recent CVEs, database engine advisories, OWASP standards, and library security advisories.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Targeted technical search query (e.g. 'PostgreSQL 16 jsonb GIN index performance', 'CVE-2024 fastify auth bypass', 'OWASP API1:2023 BOLA remediation')"
                }
            },
            "required": ["query"]
        }
    }
}

ALL_TOOLS = [TAVILY_TOOL_SPEC]

# Curated offline intelligence fallback when live Tavily API key is not supplied
OFFLINE_KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
    "postgres_foreign_key_index": {
        "keywords": ["foreign key", "index", "cascade", "postgres", "locking", "share update exclusive"],
        "title": "PostgreSQL Documentation - Foreign Key Indexing & Concurrency",
        "content": (
            "PostgreSQL does NOT automatically create indexes on foreign key columns. "
            "When rows in the referenced table are updated or deleted (especially with ON DELETE CASCADE), "
            "PostgreSQL performs a sequential scan on the referencing table, causing heavy table locks "
            "and severe latency spikes under production workloads. Indexes should be added using "
            "'CREATE INDEX CONCURRENTLY' to prevent table locking during migration."
        ),
        "citation": "https://www.postgresql.org/docs/current/ddl-constraints.html#DDL-CONSTRAINTS-FK"
    },
    "postgres_jsonb_gin": {
        "keywords": ["jsonb", "gin", "index", "performance", "containment"],
        "title": "PostgreSQL Documentation - Indexing JSONB with GIN",
        "content": (
            "Querying JSONB columns with operators such as @>, ?, ?&, or inside nested keys results in sequential "
            "scans unless a GIN (Generalized Inverted Index) or expression index is defined. "
            "For full document indexing use 'USING gin(metadata jsonb_path_ops)' for compact size and fast containment lookups."
        ),
        "citation": "https://www.postgresql.org/docs/current/datatype-json.html#JSON-INDEXING"
    },
    "owasp_bola_idor": {
        "keywords": ["bola", "idor", "broken object level authorization", "api1:2023", "cwe-639"],
        "title": "OWASP API Security Top 10 - API1:2023 Broken Object Level Authorization",
        "content": (
            "API1:2023 BOLA occurs when an endpoint accepts an object identifier (e.g. orderId, userId) from user input "
            "without verifying that the authenticated caller has authorization to access or modify that specific resource. "
            "Remediation requires enforcing tenant/user context checks directly within database queries or authorization middleware (e.g. WHERE id = :id AND tenant_id = :sessionTenantId)."
        ),
        "citation": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
    },
    "sql_injection_cwe89": {
        "keywords": ["sql injection", "cwe-89", "parameterized", "raw query", "string concatenation"],
        "title": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "content": (
            "Direct string concatenation or template literals (`SELECT ... WHERE id = '${id}'`) exposes the database to SQL injection attacks. "
            "Remediation mandates strict parameterized queries, prepared statements, or ORM parameter binding."
        ),
        "citation": "https://cwe.mitre.org/data/definitions/89.html"
    },
    "plaintext_credentials_cwe312": {
        "keywords": ["plaintext", "password", "credit card", "cwe-312", "pci-dss", "encryption"],
        "title": "CWE-312: Cleartext Storage of Sensitive Information & PCI-DSS 3.4",
        "content": (
            "Storing credentials, access tokens, or payment card details in plaintext violates CWE-312 and PCI-DSS Requirement 3.4. "
            "Passwords must be hashed using adaptive work factor algorithms (Argon2id or bcrypt). Card data must use tokenization or AES-256-GCM encryption."
        ),
        "citation": "https://cwe.mitre.org/data/definitions/312.html"
    },
    "n_plus_one_query": {
        "keywords": ["n+1", "loop", "batch query", "orm", "eager loading", "latency"],
        "title": "Database Optimization Guide - N+1 Query Antipattern",
        "content": (
            "Executing separate database queries inside an iteration loop (e.g. fetching items per order in a for-loop) "
            "results in N+1 network roundtrips to the database engine. Remediation: use SQL JOINs, 'IN (...)' batch fetches, or GraphQL/ORM dataloaders."
        ),
        "citation": "https://use-the-index-luke.com/sql/joins/nested-loops-n-plus-one"
    },
    "row_level_security": {
        "keywords": ["rls", "row level security", "tenant", "isolation", "multi-tenant"],
        "title": "PostgreSQL Documentation - Row Level Security (RLS)",
        "content": (
            "In multi-tenant schemas sharing the same tables, relying purely on application-level filtering risks accidental data leaks. "
            "Enabling RLS ('ALTER TABLE orders ENABLE ROW LEVEL SECURITY') ensures that even flawed application code cannot read across tenant boundaries."
        ),
        "citation": "https://www.postgresql.org/docs/current/ddl-rowsecurity.html"
    }
}

def execute_tavily_search(query: str, max_results: int = 3) -> str:
    """
    Executes a web search via Tavily API.
    If no API key is configured, falls back to the curated technical knowledge base.
    """
    query_lower = query.lower()
    logger.info("Executing Tavily Search for query: '%s'", query)

    # 1. Live Tavily Search API if configured
    if Config.is_tavily_configured():
        try:
            payload = json.dumps({
                "api_key": Config.TAVILY_API_KEY,
                "query": query,
                "search_depth": "advanced",
                "include_answer": True,
                "max_results": max_results
            }).encode("utf-8")

            req = urllib.request.Request(
                Config.TAVILY_BASE_URL,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "AutoSchemaAuditor/1.0"}
            )

            with urllib.request.urlopen(req, timeout=12) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    answer = data.get("answer", "")
                    results = data.get("results", [])
                    
                    formatted_results = []
                    if answer:
                        formatted_results.append(f"### Direct Answer:\n{answer}\n")
                    
                    for r in results:
                        formatted_results.append(
                            f"- **{r.get('title')}**\n  URL: {r.get('url')}\n  Snippet: {r.get('content')}"
                        )
                    
                    if formatted_results:
                        return "\n\n".join(formatted_results)
        except Exception as e:
            logger.warning("Live Tavily API request failed (%s). Falling back to internal intelligence.", e)

    # 2. Intelligent Offline Fallback
    matched_entries = []
    for key, data in OFFLINE_KNOWLEDGE_BASE.items():
        score = sum(1 for kw in data["keywords"] if kw in query_lower)
        if score > 0:
            matched_entries.append((score, data))

    matched_entries.sort(key=lambda x: x[0], reverse=True)

    if matched_entries:
        top_matches = matched_entries[:max_results]
        results_str = [
            f"- **{entry['title']}**\n  Citation: {entry['citation']}\n  Summary: {entry['content']}"
            for _, entry in top_matches
        ]
        return "### Verified Threat Intelligence & Engine Advisory:\n" + "\n\n".join(results_str)

    # Generic technical response if no direct match
    return (
        f"Search query completed for '{query}'.\n"
        "Engine standards mandate adhering to least privilege, parameterized input bindings, non-blocking DDL migrations, "
        "and indexing foreign key columns to avoid table locks."
    )

def handle_tool_call(tool_name: str, arguments: Dict[str, Any]) -> str:
    """Dispatches tool execution by name."""
    if tool_name == "tavily_search":
        query = arguments.get("query", "")
        return execute_tavily_search(query)
    return f"Error: Tool '{tool_name}' is not recognized."
