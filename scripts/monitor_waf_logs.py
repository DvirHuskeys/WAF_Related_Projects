#!/usr/bin/env python3
"""
Continuous monitoring script for WAF logs with alerting.

Usage:
    python scripts/monitor_waf_logs.py --interval 3600 --alert-threshold 1000
"""

import argparse
import json
import sys
import time
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


def check_threats(client: httpx.Client, year: int, month: int, day: int, hour: int, threshold: int = 1000) -> Dict:
    """Check for threats in current time window."""
    
    alerts = []
    
    # Check for high-volume IPs
    high_volume_sql = f"""
    SELECT 
        clientip,
        COUNT(*) as request_count
    FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
    WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
    GROUP BY clientip
    HAVING COUNT(*) > {threshold}
    ORDER BY request_count DESC
    LIMIT 10
    """
    
    result = execute_query(client, high_volume_sql)
    if result["success"] and result["rows"]:
        for row in result["rows"]:
            alerts.append({
                "type": "high_volume_ip",
                "severity": "high",
                "ip": row[0],
                "request_count": row[1],
                "message": f"IP {row[0]} generated {row[1]} requests (threshold: {threshold})"
            })
    
    # Check for attack patterns
    attack_sql = f"""
    SELECT 
        clientip,
        COUNT(*) as attack_count
    FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
    WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
    AND (
        LOWER(clientrequesturi) LIKE '%union%select%'
        OR LOWER(clientrequesturi) LIKE '%or%1=1%'
        OR LOWER(clientrequesturi) LIKE '%<script%'
        OR clientrequesturi LIKE '%../%'
    )
    GROUP BY clientip
    HAVING COUNT(*) > 5
    ORDER BY attack_count DESC
    LIMIT 10
    """
    
    result = execute_query(client, attack_sql)
    if result["success"] and result["rows"]:
        for row in result["rows"]:
            alerts.append({
                "type": "attack_pattern",
                "severity": "critical",
                "ip": row[0],
                "attack_count": row[1],
                "message": f"IP {row[0]} attempted {row[1]} attacks"
            })
    
    # Check for WAF bypass attempts
    bypass_sql = f"""
    SELECT 
        clientip,
        COUNT(*) as bypass_count
    FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
    WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
    AND wafaction IN ('challenge', 'log')
    AND edgeresponsestatus = 200
    GROUP BY clientip
    HAVING COUNT(*) > 10
    ORDER BY bypass_count DESC
    LIMIT 10
    """
    
    result = execute_query(client, bypass_sql)
    if result["success"] and result["rows"]:
        for row in result["rows"]:
            alerts.append({
                "type": "waf_bypass",
                "severity": "critical",
                "ip": row[0],
                "bypass_count": row[1],
                "message": f"IP {row[0]} successfully bypassed WAF {row[1]} times"
            })
    
    return {
        "timestamp": datetime.now().isoformat(),
        "time_window": f"{year}-{month:02d}-{day:02d}-{hour:02d}",
        "alerts": alerts,
        "alert_count": len(alerts)
    }


def send_alert(alert: Dict, alert_config: Dict):
    """Send alert via configured method."""
    # Placeholder for alerting integration
    # Can integrate with:
    # - Email (SMTP)
    # - Slack webhook
    # - PagerDuty API
    # - Custom webhook
    # - Log file
    
    alert_file = ROOT / "docs/research-log-analysis/alerts.log"
    with alert_file.open("a") as f:
        f.write(f"{alert['timestamp']} [{alert['severity'].upper()}] {alert['message']}\n")
    
    print(f"🚨 ALERT [{alert['severity'].upper()}]: {alert['message']}")


def main():
    parser = argparse.ArgumentParser(description="Monitor WAF logs continuously")
    parser.add_argument("--interval", type=int, default=3600, help="Check interval in seconds (default: 3600 = 1 hour)")
    parser.add_argument("--alert-threshold", type=int, default=1000, help="Request count threshold for alerts")
    parser.add_argument("--year", type=int, help="Year (default: current)")
    parser.add_argument("--month", type=int, help="Month (default: current)")
    parser.add_argument("--day", type=int, help="Day (default: current)")
    parser.add_argument("--hour", type=int, help="Hour (default: current)")
    parser.add_argument("--once", action="store_true", help="Run once instead of continuous")
    
    args = parser.parse_args()
    
    # Use current time if not specified
    now = datetime.now()
    year = args.year or now.year
    month = args.month or now.month
    day = args.day or now.day
    hour = args.hour or now.hour
    
    print("🔍 WAF Log Monitoring Started")
    print("=" * 80)
    print(f"Time Window: {year}-{month:02d}-{day:02d} hour {hour:02d}")
    print(f"Alert Threshold: {args.alert_threshold} requests")
    print(f"Interval: {args.interval} seconds")
    print("=" * 80)
    
    alert_config = {}  # Configure alerting methods here
    
    with httpx.Client(verify=False, timeout=180.0) as client:
        while True:
            try:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Checking threats...")
                
                results = check_threats(client, year, month, day, hour, args.alert_threshold)
                
                if results["alert_count"] > 0:
                    print(f"⚠️  Found {results['alert_count']} alerts!")
                    for alert in results["alerts"]:
                        send_alert(alert, alert_config)
                else:
                    print("✅ No threats detected")
                
                # Save monitoring results
                monitor_file = ROOT / "docs/research-log-analysis/monitoring-results.json"
                with monitor_file.open("a") as f:
                    f.write(json.dumps(results) + "\n")
                
                if args.once:
                    break
                
                print(f"Sleeping for {args.interval} seconds...")
                time.sleep(args.interval)
                
                # Update time window for next check
                hour += 1
                if hour > 23:
                    hour = 0
                    day += 1
                    if day > 31:
                        day = 1
                        month += 1
                        if month > 12:
                            month = 1
                            year += 1
                
            except KeyboardInterrupt:
                print("\n\nMonitoring stopped by user")
                break
            except Exception as e:
                print(f"\n❌ Error: {e}")
                if args.once:
                    break
                time.sleep(args.interval)
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

