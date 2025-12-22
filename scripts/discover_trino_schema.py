#!/usr/bin/env python3
"""
Discover Trino schema structure and available tables.

Usage:
    python scripts/discover_trino_schema.py
"""

import base64
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]

TRINO_HOST = "trino.internal.dep1.euc1.stg.huskeys.io"
TRINO_PORT = 443
TRINO_USER = "admin"
TRINO_PASSWORD = "admin"
TRINO_SCHEME = "https"
TRINO_BASE_URL = f"{TRINO_SCHEME}://{TRINO_HOST}:{TRINO_PORT}"


def execute_query(client: httpx.Client, sql: str) -> dict:
    """Execute a query and return results."""
    headers = {
        "Content-Type": "application/json",
        "X-Trino-User": TRINO_USER,
        "X-Trino-Password": TRINO_PASSWORD,
        "X-Trino-Catalog": "waf_logs_db",
        "X-Trino-Schema": "default",
    }
    
    url = f"{TRINO_BASE_URL}/v1/statement"
    
    try:
        response = client.post(url, headers=headers, json={"query": sql}, timeout=60.0)
        response.raise_for_status()
        result_data = response.json()
        
        rows = []
        columns = result_data.get("columns", [])
        next_uri = result_data.get("nextUri")
        
        while next_uri:
            poll_headers = {
                "X-Trino-User": TRINO_USER,
                "X-Trino-Password": TRINO_PASSWORD,
            }
            poll_response = client.get(next_uri, headers=poll_headers, timeout=60.0)
            poll_response.raise_for_status()
            poll_data = poll_response.json()
            
            if "data" in poll_data:
                rows.extend(poll_data["data"])
            
            next_uri = poll_data.get("nextUri")
            
            if poll_data.get("stats", {}).get("state") == "FINISHED":
                break
        
        return {
            "success": True,
            "rows": rows,
            "columns": [col.get("name", "?") for col in columns],
            "row_count": len(rows),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "rows": [],
            "columns": [],
            "row_count": 0,
        }


def main() -> int:
    """Discover schema."""
    print("🔍 Discovering Trino Schema Structure")
    print("=" * 80)
    
    discovery_queries = [
        {
            "name": "Show Catalogs",
            "sql": "SHOW CATALOGS"
        },
        {
            "name": "Show Schemas in waf_logs_db",
            "sql": "SHOW SCHEMAS FROM waf_logs_db"
        },
        {
            "name": "Show Tables in waf_logs_db.default",
            "sql": "SHOW TABLES FROM waf_logs_db.default"
        },
        {
            "name": "Show Columns in quillbot_waf_logs_huskeys_copy",
            "sql": "SHOW COLUMNS FROM waf_logs_db.quillbot_waf_logs_huskeys_copy"
        },
        {
            "name": "Describe Table",
            "sql": "DESCRIBE waf_logs_db.quillbot_waf_logs_huskeys_copy"
        },
        {
            "name": "Check Table Exists",
            "sql": """
            SELECT table_schema, table_name 
            FROM information_schema.tables 
            WHERE table_catalog = 'waf_logs_db' 
            AND table_name LIKE '%waf%'
            """
        },
        {
            "name": "Sample Query (no WHERE)",
            "sql": "SELECT * FROM waf_logs_db.quillbot_waf_logs_huskeys_copy LIMIT 1"
        },
    ]
    
    results = {}
    
    with httpx.Client(verify=False, timeout=120.0) as client:
        for query_info in discovery_queries:
            print(f"\n📊 {query_info['name']}...")
            result = execute_query(client, query_info["sql"])
            results[query_info["name"]] = result
            
            if result["success"]:
                print(f"   ✅ {result['row_count']} rows")
                if result["columns"]:
                    print(f"   Columns: {', '.join(result['columns'])}")
                if result["rows"]:
                    for i, row in enumerate(result["rows"][:5], 1):
                        print(f"   Row {i}: {row}")
            else:
                print(f"   ❌ Error: {result['error'][:300]}")
    
    # Save results
    results_file = ROOT / "docs/research-log-analysis/schema-discovery.json"
    results_file.write_text(json.dumps(results, indent=2, default=str))
    print(f"\n💾 Results saved to: {results_file}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

