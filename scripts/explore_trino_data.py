#!/usr/bin/env python3
"""
Explore Trino data to find available time windows and test queries with real data.

Usage:
    python scripts/explore_trino_data.py
"""

import base64
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

import httpx

ROOT = Path(__file__).resolve().parents[1]

# Trino connection config
TRINO_HOST = "trino.internal.dep1.euc1.stg.huskeys.io"
TRINO_PORT = 443
TRINO_USER = "admin"
TRINO_PASSWORD = "admin"
TRINO_SCHEME = "https"
TRINO_BASE_URL = f"{TRINO_SCHEME}://{TRINO_HOST}:{TRINO_PORT}"


def execute_query(client: httpx.Client, sql: str, description: str = "") -> Dict:
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


def find_available_time_windows(client: httpx.Client) -> List[Dict]:
    """Find what time windows have data."""
    print("🔍 Exploring available time windows...")
    
    queries = [
        {
            "name": "Available Years",
            "sql": "SELECT DISTINCT year FROM waf_logs_db.quillbot_waf_logs_huskeys_copy ORDER BY year DESC LIMIT 10"
        },
        {
            "name": "Available Months (2025)",
            "sql": "SELECT DISTINCT year, month FROM waf_logs_db.quillbot_waf_logs_huskeys_copy WHERE year = 2025 ORDER BY month DESC LIMIT 12"
        },
        {
            "name": "Available Days (Dec 2025)",
            "sql": "SELECT DISTINCT year, month, day FROM waf_logs_db.quillbot_waf_logs_huskeys_copy WHERE year = 2025 AND month = 12 ORDER BY day DESC LIMIT 31"
        },
        {
            "name": "Available Hours (Latest Day)",
            "sql": """
            SELECT DISTINCT year, month, day, hour, COUNT(*) as request_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = 2025 AND month = 12 AND day = 21
            GROUP BY year, month, day, hour
            ORDER BY hour DESC
            LIMIT 24
            """
        },
        {
            "name": "Total Request Count",
            "sql": "SELECT COUNT(*) as total_requests FROM waf_logs_db.quillbot_waf_logs_huskeys_copy"
        },
        {
            "name": "Sample Data (Latest 10 rows)",
            "sql": "SELECT * FROM waf_logs_db.quillbot_waf_logs_huskeys_copy ORDER BY year DESC, month DESC, day DESC, hour DESC LIMIT 10"
        },
        {
            "name": "Column Names",
            "sql": "SHOW COLUMNS FROM waf_logs_db.quillbot_waf_logs_huskeys_copy"
        },
    ]
    
    results = []
    for query_info in queries:
        print(f"\n📊 {query_info['name']}...")
        result = execute_query(client, query_info["sql"], query_info["name"])
        results.append({
            "query": query_info["name"],
            "result": result
        })
        
        if result["success"]:
            print(f"   ✅ Found {result['row_count']} rows")
            if result["rows"]:
                print(f"   Columns: {', '.join(result['columns'][:5])}")
                if result["row_count"] <= 5:
                    for row in result["rows"]:
                        print(f"   {row}")
                else:
                    print(f"   Sample: {result['rows'][0]}")
        else:
            print(f"   ❌ Error: {result['error'][:200]}")
    
    return results


def test_key_queries_with_data(client: httpx.Client, year: int, month: int, day: int, hour: int):
    """Test key queries with actual data."""
    print(f"\n🧪 Testing key queries with data from {year}-{month:02d}-{day:02d} hour {hour}...")
    
    # Key queries to test
    key_queries = [
        {
            "id": "Q1",
            "name": "High-Volume IPs",
            "sql": f"""
            SELECT 
                clientip,
                COUNT(*) as request_count,
                COUNT(DISTINCT clientrequesturi) as unique_endpoints,
                COUNT(DISTINCT clientrequestuseragent) as unique_user_agents
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year}
              AND month = {month}
              AND day = {day}
              AND hour = {hour}
            GROUP BY clientip
            ORDER BY request_count DESC
            LIMIT 20
            """
        },
        {
            "id": "Q6",
            "name": "WAF Action Distribution",
            "sql": f"""
            SELECT 
                wafaction,
                COUNT(*) as action_count,
                COUNT(DISTINCT clientip) as unique_ips
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year}
              AND month = {month}
              AND day = {day}
              AND hour = {hour}
              AND wafaction IS NOT NULL
            GROUP BY wafaction
            ORDER BY action_count DESC
            """
        },
        {
            "id": "Q24",
            "name": "HTTP Method Distribution",
            "sql": f"""
            SELECT 
                clientrequestmethod,
                COUNT(*) as method_count,
                COUNT(DISTINCT clientip) as unique_ips
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year}
              AND month = {month}
              AND day = {day}
              AND hour = {hour}
            GROUP BY clientrequestmethod
            ORDER BY method_count DESC
            """
        },
        {
            "id": "Q10",
            "name": "Status Code Distribution",
            "sql": f"""
            SELECT 
                edgeresponsestatus,
                COUNT(*) as status_count,
                COUNT(DISTINCT clientip) as unique_ips
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year}
              AND month = {month}
              AND day = {day}
              AND hour = {hour}
            GROUP BY edgeresponsestatus
            ORDER BY status_count DESC
            LIMIT 20
            """
        },
        {
            "id": "Q17",
            "name": "SQL Injection Attempts",
            "sql": f"""
            SELECT 
                clientip,
                clientrequesturi,
                COUNT(*) as attempt_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year}
              AND month = {month}
              AND day = {day}
              AND hour = {hour}
              AND (
                LOWER(clientrequesturi) LIKE '%union%select%'
                OR LOWER(clientrequesturi) LIKE '%or%1=1%'
                OR LOWER(clientrequesturi) LIKE '%drop%table%'
                OR LOWER(clientrequesturi) LIKE '%exec%(%'
                OR LOWER(clientrequesturi) LIKE '%;--%'
              )
            GROUP BY clientip, clientrequesturi
            ORDER BY attempt_count DESC
            LIMIT 20
            """
        },
    ]
    
    results = []
    for query_info in key_queries:
        print(f"\n🔍 {query_info['id']}: {query_info['name']}...")
        result = execute_query(client, query_info["sql"], query_info["name"])
        results.append({
            "query": query_info,
            "result": result
        })
        
        if result["success"]:
            print(f"   ✅ {result['row_count']} rows")
            if result["rows"]:
                print(f"   Columns: {', '.join(result['columns'])}")
                for i, row in enumerate(result["rows"][:3], 1):
                    print(f"   Row {i}: {row}")
        else:
            print(f"   ❌ Error: {result['error'][:200]}")
    
    return results


def main() -> int:
    """Main exploration."""
    print("🚀 Starting Trino Data Exploration")
    print("=" * 80)
    
    with httpx.Client(verify=False, timeout=120.0) as client:
        # Step 1: Find available data
        print("\n" + "=" * 80)
        print("STEP 1: Finding Available Data")
        print("=" * 80)
        time_windows = find_available_time_windows(client)
        
        # Step 2: Find a time window with data
        print("\n" + "=" * 80)
        print("STEP 2: Analyzing Available Time Windows")
        print("=" * 80)
        
        # Try to find a good time window
        year, month, day, hour = 2025, 12, 21, 5
        
        # Check if we have data for different hours
        check_hours_sql = """
        SELECT DISTINCT year, month, day, hour, COUNT(*) as request_count
        FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
        WHERE year = 2025 AND month = 12 AND day = 21
        GROUP BY year, month, day, hour
        HAVING COUNT(*) > 0
        ORDER BY request_count DESC
        LIMIT 5
        """
        
        print("\n🔍 Finding hours with data...")
        hours_result = execute_query(client, check_hours_sql, "Hours with data")
        
        if hours_result["success"] and hours_result["rows"]:
            # Use the hour with most data
            best_hour = hours_result["rows"][0]
            year = best_hour[0]
            month = best_hour[1]
            day = best_hour[2]
            hour = best_hour[3]
            request_count = best_hour[4]
            print(f"✅ Found data: {year}-{month:02d}-{day:02d} hour {hour} ({request_count} requests)")
        else:
            print("⚠️  No specific hour data found, using default time window")
        
        # Step 3: Test key queries with actual data
        print("\n" + "=" * 80)
        print("STEP 3: Testing Key Queries with Real Data")
        print("=" * 80)
        query_results = test_key_queries_with_data(client, year, month, day, hour)
        
        # Step 4: Summary
        print("\n" + "=" * 80)
        print("📊 EXPLORATION SUMMARY")
        print("=" * 80)
        
        total_requests = 0
        for result in time_windows:
            if result["query"] == "Total Request Count" and result["result"]["success"]:
                if result["result"]["rows"]:
                    total_requests = result["result"]["rows"][0][0]
        
        print(f"\n📈 Total Requests in Database: {total_requests:,}")
        print(f"🎯 Test Time Window: {year}-{month:02d}-{day:02d} hour {hour}")
        print(f"✅ Key Queries Tested: {len(query_results)}")
        
        # Save results
        results_file = ROOT / "docs/research-log-analysis/exploration-results.json"
        results_file.write_text(json.dumps({
            "time_windows": time_windows,
            "query_results": query_results,
            "test_window": {"year": year, "month": month, "day": day, "hour": hour}
        }, indent=2, default=str))
        print(f"\n💾 Results saved to: {results_file}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

