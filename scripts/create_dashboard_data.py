#!/usr/bin/env python3
"""
Generate dashboard data for visualization.

Usage:
    python scripts/create_dashboard_data.py --year 2025 --month 12 --day 21
"""

import argparse
import json
import sys
from datetime import datetime
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


def generate_dashboard_data(client: httpx.Client, year: int, month: int, day: int) -> Dict:
    """Generate dashboard data for visualization."""
    
    dashboard_data = {
        "timestamp": datetime.now().isoformat(),
        "time_window": f"{year}-{month:02d}-{day:02d}",
        "metrics": {},
        "charts": {}
    }
    
    # Hourly traffic distribution
    hourly_sql = f"""
    SELECT 
        hour,
        COUNT(*) as request_count,
        COUNT(DISTINCT clientip) as unique_ips,
        COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count
    FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
    WHERE year = {year} AND month = {month} AND day = {day}
    GROUP BY hour
    ORDER BY hour
    """
    
    result = execute_query(client, hourly_sql)
    if result["success"]:
        dashboard_data["charts"]["hourly_traffic"] = {
            "labels": [row[0] for row in result["rows"]],
            "datasets": [
                {
                    "label": "Total Requests",
                    "data": [row[1] for row in result["rows"]]
                },
                {
                    "label": "Unique IPs",
                    "data": [row[2] for row in result["rows"]]
                },
                {
                    "label": "Blocked",
                    "data": [row[3] for row in result["rows"]]
                }
            ]
        }
    
    # Top countries
    countries_sql = f"""
    SELECT 
        clientcountry,
        COUNT(*) as request_count,
        COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count
    FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
    WHERE year = {year} AND month = {month} AND day = {day}
    AND clientcountry IS NOT NULL
    GROUP BY clientcountry
    ORDER BY request_count DESC
    LIMIT 10
    """
    
    result = execute_query(client, countries_sql)
    if result["success"]:
        dashboard_data["charts"]["top_countries"] = {
            "labels": [row[0] for row in result["rows"]],
            "datasets": [
                {
                    "label": "Requests",
                    "data": [row[1] for row in result["rows"]]
                },
                {
                    "label": "Blocked",
                    "data": [row[2] for row in result["rows"]]
                }
            ]
        }
    
    # Attack types distribution
    attack_types_sql = f"""
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
    WHERE year = {year} AND month = {month} AND day = {day}
    AND (
        LOWER(clientrequesturi) LIKE '%union%select%'
        OR LOWER(clientrequesturi) LIKE '%or%1=1%'
        OR LOWER(clientrequesturi) LIKE '%<script%'
        OR clientrequesturi LIKE '%../%'
        OR LOWER(clientrequesturi) LIKE '%|%whoami%'
    )
    GROUP BY attack_type
    """
    
    result = execute_query(client, attack_types_sql)
    if result["success"]:
        dashboard_data["charts"]["attack_types"] = {
            "labels": [row[0] for row in result["rows"]],
            "data": [row[1] for row in result["rows"]]
        }
    
    # WAF action distribution
    waf_actions_sql = f"""
    SELECT 
        COALESCE(wafaction, 'none') as action,
        COUNT(*) as count
    FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
    WHERE year = {year} AND month = {month} AND day = {day}
    GROUP BY wafaction
    """
    
    result = execute_query(client, waf_actions_sql)
    if result["success"]:
        dashboard_data["charts"]["waf_actions"] = {
            "labels": [row[0] for row in result["rows"]],
            "data": [row[1] for row in result["rows"]]
        }
    
    # Summary metrics
    summary_sql = f"""
    SELECT 
        COUNT(*) as total_requests,
        COUNT(DISTINCT clientip) as unique_ips,
        COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
        COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count
    FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
    WHERE year = {year} AND month = {month} AND day = {day}
    """
    
    result = execute_query(client, summary_sql)
    if result["success"] and result["rows"]:
        row = result["rows"][0]
        dashboard_data["metrics"] = {
            "total_requests": row[0],
            "unique_ips": row[1],
            "blocked_count": row[2],
            "challenged_count": row[3],
            "block_rate": round(row[2] * 100.0 / row[0], 2) if row[0] > 0 else 0
        }
    
    return dashboard_data


def main():
    parser = argparse.ArgumentParser(description="Generate dashboard data")
    parser.add_argument("--year", type=int, default=2025, help="Year")
    parser.add_argument("--month", type=int, default=12, help="Month")
    parser.add_argument("--day", type=int, default=21, help="Day")
    parser.add_argument("--format", choices=["json", "csv"], default="json", help="Output format")
    
    args = parser.parse_args()
    
    print("📊 Generating Dashboard Data")
    print("=" * 80)
    print(f"Time Window: {args.year}-{args.month:02d}-{args.day:02d}")
    
    with httpx.Client(verify=False, timeout=180.0) as client:
        dashboard_data = generate_dashboard_data(client, args.year, args.month, args.day)
        
        # Save JSON
        output_file = ROOT / f"docs/research-log-analysis/dashboard-{args.year}-{args.month:02d}-{args.day:02d}.json"
        output_file.write_text(json.dumps(dashboard_data, indent=2))
        print(f"✅ Dashboard data saved to: {output_file}")
        
        # Print summary
        if dashboard_data.get("metrics"):
            print("\n📈 Summary Metrics:")
            for key, value in dashboard_data["metrics"].items():
                print(f"   {key}: {value}")
        
        if dashboard_data.get("charts"):
            print(f"\n📊 Charts Generated: {len(dashboard_data['charts'])}")
            for chart_name in dashboard_data["charts"].keys():
                print(f"   - {chart_name}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

