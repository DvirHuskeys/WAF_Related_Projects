#!/usr/bin/env python3
"""
Run comprehensive analysis suite on WAF logs.

Usage:
    python scripts/run_analysis_suite.py --year 2025 --month 12 --day 21 --hour 5
"""

import argparse
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


def run_analysis_suite(client: httpx.Client, year: int, month: int, day: int, hour: int) -> Dict:
    """Run comprehensive analysis suite."""
    
    print(f"\n🔍 Running Analysis Suite for {year}-{month:02d}-{day:02d} hour {hour}")
    print("=" * 80)
    
    # Key analysis queries
    analyses = [
        {
            "name": "Traffic Overview",
            "query": f"""
            SELECT 
                COUNT(*) as total_requests,
                COUNT(DISTINCT clientip) as unique_ips,
                COUNT(DISTINCT clientrequesturi) as unique_endpoints,
                COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
                COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count,
                COUNT(CASE WHEN wafaction = 'log' THEN 1 END) as logged_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            """
        },
        {
            "name": "Top Attacking IPs",
            "query": f"""
            SELECT 
                clientip,
                COUNT(*) as request_count,
                COUNT(DISTINCT clientrequesturi) as unique_endpoints,
                COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            GROUP BY clientip
            ORDER BY request_count DESC
            LIMIT 20
            """
        },
        {
            "name": "Most Targeted Endpoints",
            "query": f"""
            SELECT 
                clientrequesturi,
                COUNT(*) as request_count,
                COUNT(DISTINCT clientip) as unique_ips,
                COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            GROUP BY clientrequesturi
            ORDER BY request_count DESC
            LIMIT 20
            """
        },
        {
            "name": "Attack Type Breakdown",
            "query": f"""
            SELECT 
                CASE 
                    WHEN LOWER(clientrequesturi) LIKE '%union%select%' OR LOWER(clientrequesturi) LIKE '%or%1=1%' THEN 'SQL Injection'
                    WHEN LOWER(clientrequesturi) LIKE '%<script%' THEN 'XSS'
                    WHEN clientrequesturi LIKE '%../%' THEN 'Path Traversal'
                    WHEN LOWER(clientrequesturi) LIKE '%|%whoami%' THEN 'Command Injection'
                    ELSE 'Other'
                END as attack_type,
                COUNT(*) as count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            AND (
                LOWER(clientrequesturi) LIKE '%union%select%'
                OR LOWER(clientrequesturi) LIKE '%or%1=1%'
                OR LOWER(clientrequesturi) LIKE '%<script%'
                OR clientrequesturi LIKE '%../%'
                OR LOWER(clientrequesturi) LIKE '%|%whoami%'
            )
            GROUP BY attack_type
            ORDER BY count DESC
            """
        },
        {
            "name": "Geographic Distribution",
            "query": f"""
            SELECT 
                clientcountry,
                COUNT(*) as request_count,
                COUNT(DISTINCT clientip) as unique_ips,
                COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            AND clientcountry IS NOT NULL
            GROUP BY clientcountry
            ORDER BY request_count DESC
            LIMIT 20
            """
        },
    ]
    
    results = {}
    
    for analysis in analyses:
        print(f"\n📊 {analysis['name']}...")
        result = execute_query(client, analysis["query"])
        results[analysis["name"]] = result
        
        if result["success"]:
            print(f"   ✅ {result['row_count']} rows returned")
            if result["rows"]:
                print(f"   Columns: {', '.join(result['columns'])}")
                for i, row in enumerate(result["rows"][:3], 1):
                    print(f"   {i}: {row}")
        else:
            print(f"   ❌ Error: {result['error'][:200]}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Run WAF log analysis suite")
    parser.add_argument("--year", type=int, default=2025, help="Year")
    parser.add_argument("--month", type=int, default=12, help="Month")
    parser.add_argument("--day", type=int, default=21, help="Day")
    parser.add_argument("--hour", type=int, default=5, help="Hour")
    
    args = parser.parse_args()
    
    print("🚀 WAF Log Analysis Suite")
    print("=" * 80)
    
    with httpx.Client(verify=False, timeout=180.0) as client:
        results = run_analysis_suite(
            client, 
            args.year, 
            args.month, 
            args.day, 
            args.hour
        )
        
        # Save results
        output_file = ROOT / f"docs/research-log-analysis/analysis-{args.year}-{args.month:02d}-{args.day:02d}-{args.hour:02d}.json"
        output_file.write_text(json.dumps(results, indent=2, default=str))
        print(f"\n💾 Results saved to: {output_file}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

