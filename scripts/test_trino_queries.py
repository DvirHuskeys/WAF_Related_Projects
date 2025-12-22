#!/usr/bin/env python3
"""
Test all WAF log research queries against Trino via REST API.

Usage:
    python scripts/test_trino_queries.py
"""

import base64
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import httpx

ROOT = Path(__file__).resolve().parents[1]
QUERIES_FILE = ROOT / "docs/research-log-analysis/queries.md"

# Trino connection config from mcp.json
TRINO_HOST = "trino.internal.dep1.euc1.stg.huskeys.io"
TRINO_PORT = 443
TRINO_USER = "admin"
TRINO_PASSWORD = "admin"
TRINO_SCHEME = "https"

TRINO_BASE_URL = f"{TRINO_SCHEME}://{TRINO_HOST}:{TRINO_PORT}"


def extract_queries_from_markdown(content: str) -> List[Dict[str, str]]:
    """Extract SQL queries from markdown file."""
    queries = []
    
    # Pattern to match query blocks: ### Q{number}: {title} ... ```sql ... ```
    pattern = r'### (Q\d+):\s*(.+?)\n\n\*\*Purpose:\*\*(.+?)\n\n\*\*Impact:\*\*(.+?)\n\n\*\*Query:\*\*\n```sql\n(.*?)```'
    
    matches = re.finditer(pattern, content, re.DOTALL)
    
    for match in matches:
        query_num = match.group(1)
        title = match.group(2).strip()
        purpose = match.group(3).strip()
        impact = match.group(4).strip()
        sql = match.group(5).strip()
        
        queries.append({
            "id": query_num,
            "title": title,
            "purpose": purpose,
            "impact": impact,
            "sql": sql
        })
    
    return queries


def execute_trino_query(client: httpx.Client, sql: str) -> Dict[str, any]:
    """Execute a query against Trino REST API."""
    # Trino password authentication headers
    headers = {
        "Content-Type": "application/json",
        "X-Trino-User": TRINO_USER,
        "X-Trino-Password": TRINO_PASSWORD,
        "X-Trino-Catalog": "waf_logs_db",
        "X-Trino-Schema": "default",
    }
    
    # Trino REST API endpoint
    url = f"{TRINO_BASE_URL}/v1/statement"
    
    try:
        # Initial query submission
        response = client.post(url, headers=headers, json={"query": sql}, timeout=30.0)
        response.raise_for_status()
        
        result_data = response.json()
        
        # If query is still running, poll for results
        next_uri = result_data.get("nextUri")
        rows = []
        
        while next_uri:
            poll_headers = {
                "X-Trino-User": TRINO_USER,
                "X-Trino-Password": TRINO_PASSWORD,
            }
            poll_response = client.get(next_uri, headers=poll_headers, timeout=30.0)
            poll_response.raise_for_status()
            poll_data = poll_response.json()
            
            if "data" in poll_data:
                rows.extend(poll_data["data"])
            
            next_uri = poll_data.get("nextUri")
            
            # If query is complete
            if poll_data.get("stats", {}).get("state") == "FINISHED":
                break
        
        return {
            "success": True,
            "rows": rows[:10],  # Limit to first 10 rows
            "row_count": len(rows),
            "columns": result_data.get("columns", []),
        }
        
    except httpx.HTTPStatusError as e:
        return {
            "success": False,
            "error": f"HTTP {e.response.status_code}: {e.response.text[:200]}",
            "rows": [],
            "row_count": 0,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "rows": [],
            "row_count": 0,
        }


def test_query(client: httpx.Client, query_info: Dict[str, str]) -> Dict[str, any]:
    """Test a single query against Trino."""
    query_id = query_info["id"]
    sql = query_info["sql"]
    
    result = {
        "id": query_id,
        "title": query_info["title"],
        "status": "pending",
        "error": None,
        "row_count": 0,
        "execution_time": None,
        "sample_rows": [],
        "columns": []
    }
    
    try:
        start_time = time.time()
        query_result = execute_trino_query(client, sql)
        result["execution_time"] = time.time() - start_time
        
        if query_result["success"]:
            result["status"] = "success"
            result["row_count"] = query_result["row_count"]
            result["sample_rows"] = query_result["rows"][:3]
            result["columns"] = query_result.get("columns", [])
        else:
            result["status"] = "error"
            result["error"] = query_result["error"]
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        if "execution_time" not in result:
            result["execution_time"] = 0
    
    return result


def main() -> int:
    """Main test execution."""
    if not QUERIES_FILE.exists():
        print(f"❌ Queries file not found: {QUERIES_FILE}")
        return 1
    
    print("📖 Reading queries from markdown...")
    content = QUERIES_FILE.read_text()
    queries = extract_queries_from_markdown(content)
    
    if not queries:
        print("⚠️  No queries found in markdown file.")
        return 1
    
    print(f"✅ Found {len(queries)} queries to test\n")
    
    # Test queries with httpx client
    print("🔌 Connecting to Trino via REST API...")
    print(f"   Host: {TRINO_HOST}:{TRINO_PORT}\n")
    
    results = []
    success_count = 0
    error_count = 0
    
    print("🧪 Testing queries...\n")
    print("=" * 80)
    
    with httpx.Client(verify=False, timeout=60.0) as client:
        for i, query_info in enumerate(queries, 1):
            query_id = query_info["id"]
            title = query_info["title"]
            
            print(f"\n[{i}/{len(queries)}] {query_id}: {title}")
            print("-" * 80)
            
            result = test_query(client, query_info)
            results.append(result)
            
            if result["status"] == "success":
                success_count += 1
                exec_time = result.get("execution_time", 0)
                row_count = result.get("row_count", 0)
                print(f"✅ SUCCESS - {row_count} rows, {exec_time:.2f}s")
                if result.get("columns"):
                    print(f"   Columns: {', '.join([c.get('name', '?') for c in result['columns'][:5]])}")
                if result.get("sample_rows"):
                    print(f"   Sample row: {result['sample_rows'][0]}")
            else:
                error_count += 1
                error_msg = result.get("error", "Unknown error")
                print(f"❌ ERROR: {error_msg[:150]}")
    
    # Summary
    print("\n" + "=" * 80)
    print("\n📊 TEST SUMMARY")
    print("=" * 80)
    print(f"Total Queries: {len(queries)}")
    print(f"✅ Successful: {success_count}")
    print(f"❌ Failed: {error_count}")
    
    # Show failed queries
    if error_count > 0:
        print("\n❌ Failed Queries:")
        for r in results:
            if r["status"] == "error":
                print(f"   {r['id']}: {r['title']}")
                print(f"      Error: {r['error'][:100]}")
    
    # Save results
    results_file = ROOT / "docs/research-log-analysis/test-results.json"
    results_file.write_text(json.dumps({
        "summary": {
            "total": len(queries),
            "success": success_count,
            "failed": error_count
        },
        "results": results
    }, indent=2))
    print(f"\n💾 Results saved to: {results_file}")
    
    return 0 if error_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
