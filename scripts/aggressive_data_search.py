#!/usr/bin/env python3
"""
Aggressively search for data in Trino by testing multiple approaches.

Usage:
    python scripts/aggressive_data_search.py
"""

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


def execute_query(client: httpx.Client, sql: str, timeout: int = 120) -> dict:
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
        response = client.post(url, headers=headers, json={"query": sql}, timeout=timeout)
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
            poll_response = client.get(next_uri, headers=poll_headers, timeout=timeout)
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
    """Aggressively search for data."""
    print("🔍 Aggressive Data Search for Quillbot WAF Logs")
    print("=" * 80)
    
    search_queries = [
        {
            "name": "Check if table exists (any data)",
            "sql": "SELECT COUNT(*) FROM waf_logs_db.quillbot_waf_logs_huskeys_copy"
        },
        {
            "name": "Check table structure",
            "sql": "DESCRIBE waf_logs_db.quillbot_waf_logs_huskeys_copy"
        },
        {
            "name": "Find any year with data",
            "sql": """
            SELECT year, COUNT(*) as total
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy
            GROUP BY year
            ORDER BY year DESC
            LIMIT 10
            """
        },
        {
            "name": "Find any month with data (2024)",
            "sql": """
            SELECT year, month, COUNT(*) as total
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy
            WHERE year = 2024
            GROUP BY year, month
            ORDER BY year DESC, month DESC
            LIMIT 12
            """
        },
        {
            "name": "Find any month with data (2023)",
            "sql": """
            SELECT year, month, COUNT(*) as total
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy
            WHERE year = 2023
            GROUP BY year, month
            ORDER BY year DESC, month DESC
            LIMIT 12
            """
        },
        {
            "name": "Sample without WHERE clause",
            "sql": "SELECT * FROM waf_logs_db.quillbot_waf_logs_huskeys_copy LIMIT 5"
        },
        {
            "name": "Check partitions",
            "sql": """
            SELECT DISTINCT year, month, day
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy
            ORDER BY year DESC, month DESC, day DESC
            LIMIT 20
            """
        },
        {
            "name": "Find latest data point",
            "sql": """
            SELECT year, month, day, hour, COUNT(*) as requests
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy
            GROUP BY year, month, day, hour
            ORDER BY year DESC, month DESC, day DESC, hour DESC
            LIMIT 10
            """
        },
    ]
    
    results = {}
    
    with httpx.Client(verify=False, timeout=180.0) as client:
        for query_info in search_queries:
            print(f"\n📊 {query_info['name']}...")
            result = execute_query(client, query_info["sql"])
            results[query_info["name"]] = result
            
            if result["success"]:
                print(f"   ✅ {result['row_count']} rows")
                if result["columns"]:
                    print(f"   Columns: {', '.join(result['columns'][:5])}")
                if result["rows"]:
                    print(f"   Sample data:")
                    for i, row in enumerate(result["rows"][:3], 1):
                        print(f"      {i}: {row}")
                    
                    # If we found data, extract time window
                    if "year" in result["columns"] and result["rows"]:
                        best_window = result["rows"][0]
                        print(f"\n   🎯 Best time window found: {best_window}")
            else:
                error_msg = result["error"][:200]
                print(f"   ❌ Error: {error_msg}")
    
    # Save results
    results_file = ROOT / "docs/research-log-analysis/aggressive-search-results.json"
    results_file.write_text(json.dumps(results, indent=2, default=str))
    print(f"\n💾 Results saved to: {results_file}")
    
    # If we found data, extract best window
    best_window = None
    for query_name, result in results.items():
        if result["success"] and result["rows"]:
            if "year" in result.get("columns", []):
                best_window = result["rows"][0]
                break
    
    if best_window:
        print(f"\n🎯 Best time window identified: {best_window}")
        print(f"\n🚀 Next step: Run analysis with this time window")
        print(f"   python scripts/generate_findings_report.py --year {best_window[0]} --month {best_window[1]} --day {best_window[2]} --hour {best_window[3] if len(best_window) > 3 else 0}")
    else:
        print("\n⚠️  No data windows found. Table may be empty or structure different.")
        print("   Check table structure and verify data exists.")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

