#!/usr/bin/env python3
"""
Find actual data windows in Trino by testing multiple time periods.

Usage:
    python scripts/find_data_windows.py
"""

import json
import sys
from pathlib import Path
from typing import Dict, List

import httpx

ROOT = Path(__file__).resolve().parents[1]

TRINO_HOST = "trino.internal.dep1.euc1.stg.huskeys.io"
TRINO_PORT = 443
TRINO_USER = "admin"
TRINO_PASSWORD = "admin"
TRINO_SCHEME = "https"
TRINO_BASE_URL = f"{TRINO_SCHEME}://{TRINO_HOST}:{TRINO_PORT}"


def execute_query(client: httpx.Client, sql: str, timeout: int = 120) -> Dict:
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
    """Find data windows."""
    print("🔍 Finding Data Windows for Quillbot WAF Logs")
    print("=" * 80)
    
    # Try multiple time windows - go back in time
    test_windows = []
    
    # Try recent dates (Dec 2025)
    for day in range(21, 0, -1):
        for hour in range(23, -1, -1):
            test_windows.append((2025, 12, day, hour))
    
    # Try November 2025
    for day in range(30, 0, -1):
        for hour in [23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12]:
            test_windows.append((2025, 11, day, hour))
    
    # Try October 2025
    for day in range(31, 0, -1):
        for hour in [23, 22, 21, 20]:
            test_windows.append((2025, 10, day, hour))
    
    print(f"Testing {len(test_windows)} time windows...\n")
    
    found_windows = []
    
    with httpx.Client(verify=False, timeout=60.0) as client:
        for i, (year, month, day, hour) in enumerate(test_windows[:100], 1):  # Limit to first 100
            if i % 20 == 0:
                print(f"Progress: {i}/{min(100, len(test_windows))}...")
            
            sql = f"""
            SELECT COUNT(*) as request_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year}
              AND month = {month}
              AND day = {day}
              AND hour = {hour}
            """
            
            result = execute_query(client, sql)
            
            if result["success"] and result["rows"]:
                count = result["rows"][0][0] if result["rows"] else 0
                if count > 0:
                    found_windows.append({
                        "year": year,
                        "month": month,
                        "day": day,
                        "hour": hour,
                        "request_count": count
                    })
                    print(f"✅ Found data: {year}-{month:02d}-{day:02d} hour {hour:02d} - {count} requests")
                    
                    if len(found_windows) >= 10:  # Stop after finding 10 windows
                        break
    
    # Sort by request count
    found_windows.sort(key=lambda x: x["request_count"], reverse=True)
    
    print(f"\n📊 Found {len(found_windows)} time windows with data")
    
    if found_windows:
        print("\nTop time windows:")
        for window in found_windows[:5]:
            print(f"  {window['year']}-{window['month']:02d}-{window['day']:02d} hour {window['hour']:02d}: {window['request_count']:,} requests")
    
    # Save results
    results_file = ROOT / "docs/research-log-analysis/data-windows.json"
    results_file.write_text(json.dumps({
        "total_tested": len(test_windows[:100]),
        "found_windows": found_windows
    }, indent=2))
    print(f"\n💾 Results saved to: {results_file}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

