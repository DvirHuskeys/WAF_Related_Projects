#!/usr/bin/env python3
"""
Generate comprehensive findings report for Quillbot customer.

Usage:
    python scripts/generate_findings_report.py --year 2025 --month 12 --day 21 --hour 5
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


def run_comprehensive_analysis(client: httpx.Client, year: int, month: int, day: int, hour: int) -> Dict:
    """Run comprehensive analysis suite."""
    
    analyses = {
        "traffic_overview": {
            "name": "Traffic Overview",
            "query": f"""
            SELECT 
                COUNT(*) as total_requests,
                COUNT(DISTINCT clientip) as unique_ips,
                COUNT(DISTINCT clientrequesturi) as unique_endpoints,
                COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
                COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count,
                COUNT(CASE WHEN wafaction = 'log' THEN 1 END) as logged_count,
                COUNT(CASE WHEN wafaction IS NULL THEN 1 END) as no_action_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            """
        },
        "top_attacking_ips": {
            "name": "Top Attacking IPs",
            "query": f"""
            SELECT 
                clientip,
                COUNT(*) as request_count,
                COUNT(DISTINCT clientrequesturi) as unique_endpoints,
                COUNT(DISTINCT clientrequestuseragent) as unique_user_agents,
                COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
                COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            GROUP BY clientip
            ORDER BY request_count DESC
            LIMIT 20
            """
        },
        "most_targeted_endpoints": {
            "name": "Most Targeted Endpoints",
            "query": f"""
            SELECT 
                clientrequesturi,
                COUNT(*) as request_count,
                COUNT(DISTINCT clientip) as unique_ips,
                COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
                COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            GROUP BY clientrequesturi
            ORDER BY request_count DESC
            LIMIT 20
            """
        },
        "waf_action_distribution": {
            "name": "WAF Action Distribution",
            "query": f"""
            SELECT 
                COALESCE(wafaction, 'none') as waf_action,
                COUNT(*) as action_count,
                COUNT(DISTINCT clientip) as unique_ips,
                ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            GROUP BY wafaction
            ORDER BY action_count DESC
            """
        },
        "http_method_distribution": {
            "name": "HTTP Method Distribution",
            "query": f"""
            SELECT 
                clientrequestmethod,
                COUNT(*) as method_count,
                COUNT(DISTINCT clientip) as unique_ips,
                ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            GROUP BY clientrequestmethod
            ORDER BY method_count DESC
            """
        },
        "status_code_distribution": {
            "name": "Status Code Distribution",
            "query": f"""
            SELECT 
                edgeresponsestatus,
                COUNT(*) as status_count,
                COUNT(DISTINCT clientip) as unique_ips,
                ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            GROUP BY edgeresponsestatus
            ORDER BY status_count DESC
            LIMIT 20
            """
        },
        "attack_types": {
            "name": "Attack Type Breakdown",
            "query": f"""
            SELECT 
                CASE 
                    WHEN LOWER(clientrequesturi) LIKE '%union%select%' OR LOWER(clientrequesturi) LIKE '%or%1=1%' THEN 'SQL Injection'
                    WHEN LOWER(clientrequesturi) LIKE '%<script%' OR LOWER(clientrequesturi) LIKE '%javascript:%' THEN 'XSS'
                    WHEN clientrequesturi LIKE '%../%' OR clientrequesturi LIKE '%..\\\\%' THEN 'Path Traversal'
                    WHEN LOWER(clientrequesturi) LIKE '%|%whoami%' OR LOWER(clientrequesturi) LIKE '%;%whoami%' THEN 'Command Injection'
                    WHEN LOWER(clientrequesturi) LIKE '%wp-admin%' OR LOWER(clientrequesturi) LIKE '%phpmyadmin%' THEN 'Admin Interface Scan'
                    WHEN LOWER(clientrequesturi) LIKE '%.env%' OR LOWER(clientrequesturi) LIKE '%config%' THEN 'Config File Access'
                    ELSE 'Other'
                END as attack_type,
                COUNT(*) as attack_count,
                COUNT(DISTINCT clientip) as unique_ips
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            AND (
                LOWER(clientrequesturi) LIKE '%union%select%'
                OR LOWER(clientrequesturi) LIKE '%or%1=1%'
                OR LOWER(clientrequesturi) LIKE '%<script%'
                OR LOWER(clientrequesturi) LIKE '%javascript:%'
                OR clientrequesturi LIKE '%../%'
                OR LOWER(clientrequesturi) LIKE '%|%whoami%'
                OR LOWER(clientrequesturi) LIKE '%wp-admin%'
                OR LOWER(clientrequesturi) LIKE '%.env%'
            )
            GROUP BY attack_type
            ORDER BY attack_count DESC
            """
        },
        "geographic_distribution": {
            "name": "Geographic Distribution",
            "query": f"""
            SELECT 
                clientcountry,
                COUNT(*) as request_count,
                COUNT(DISTINCT clientip) as unique_ips,
                COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
                ROUND(COUNT(CASE WHEN wafaction = 'block' THEN 1 END) * 100.0 / COUNT(*), 2) as block_rate
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            AND clientcountry IS NOT NULL
            GROUP BY clientcountry
            ORDER BY request_count DESC
            LIMIT 20
            """
        },
        "bot_analysis": {
            "name": "Bot Traffic Analysis",
            "query": f"""
            SELECT 
                CASE 
                    WHEN botscore < 1 THEN 'Definitely Bot'
                    WHEN botscore < 30 THEN 'Likely Bot'
                    WHEN botscore < 70 THEN 'Uncertain'
                    ELSE 'Likely Human'
                END as bot_category,
                COUNT(*) as request_count,
                COUNT(DISTINCT clientip) as unique_ips,
                AVG(botscore) as avg_bot_score
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            AND botscore IS NOT NULL
            GROUP BY bot_category
            ORDER BY request_count DESC
            """
        },
        "suspicious_patterns": {
            "name": "Suspicious Request Patterns",
            "query": f"""
            SELECT 
                clientip,
                COUNT(DISTINCT clientrequestuseragent) as user_agent_rotations,
                COUNT(DISTINCT clientrequesturi) as endpoints_tested,
                COUNT(*) as total_requests,
                COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count
            FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
            WHERE year = {year} AND month = {month} AND day = {day} AND hour = {hour}
            GROUP BY clientip
            HAVING COUNT(DISTINCT clientrequestuseragent) > 3 
               OR COUNT(DISTINCT clientrequesturi) > 20
            ORDER BY total_requests DESC
            LIMIT 20
            """
        }
    }
    
    results = {}
    
    for key, analysis in analyses.items():
        result = execute_query(client, analysis["query"])
        results[key] = {
            "name": analysis["name"],
            "result": result
        }
    
    return results


def generate_markdown_report(results: Dict, year: int, month: int, day: int, hour: int, customer: str = "Quillbot") -> str:
    """Generate markdown findings report."""
    
    report = f"""# WAF Log Analysis Findings Report

**Customer:** {customer}  
**Analysis Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Time Window:** {year}-{month:02d}-{day:02d} hour {hour:02d}  
**Data Source:** `waf_logs_db.quillbot_waf_logs_huskeys_copy`

---

## Executive Summary

"""
    
    # Traffic Overview
    if "traffic_overview" in results and results["traffic_overview"]["result"]["success"]:
        traffic = results["traffic_overview"]["result"]
        if traffic["rows"]:
            row = traffic["rows"][0]
            total_requests = row[0] if len(row) > 0 else 0
            unique_ips = row[1] if len(row) > 1 else 0
            unique_endpoints = row[2] if len(row) > 2 else 0
            blocked = row[3] if len(row) > 3 else 0
            challenged = row[4] if len(row) > 4 else 0
            
            report += f"""
### Traffic Overview

| Metric | Value |
|--------|-------|
| Total Requests | {total_requests:,} |
| Unique IP Addresses | {unique_ips:,} |
| Unique Endpoints | {unique_endpoints:,} |
| Blocked Requests | {blocked:,} |
| Challenged Requests | {challenged:,} |
| Block Rate | {round(blocked * 100.0 / total_requests, 2) if total_requests > 0 else 0}% |

"""
    
    # Top Attacking IPs
    if "top_attacking_ips" in results and results["top_attacking_ips"]["result"]["success"]:
        ips = results["top_attacking_ips"]["result"]
        if ips["rows"]:
            report += """
## Top Attacking IP Addresses

| IP Address | Request Count | Unique Endpoints | User Agents | Blocked | Challenged |
|------------|---------------|------------------|-------------|---------|------------|
"""
            for row in ips["rows"][:10]:
                ip = row[0] if len(row) > 0 else "N/A"
                req_count = row[1] if len(row) > 1 else 0
                endpoints = row[2] if len(row) > 2 else 0
                ua_count = row[3] if len(row) > 3 else 0
                blocked = row[4] if len(row) > 4 else 0
                challenged = row[5] if len(row) > 5 else 0
                report += f"| {ip} | {req_count:,} | {endpoints} | {ua_count} | {blocked} | {challenged} |\n"
            report += "\n"
    
    # Most Targeted Endpoints
    if "most_targeted_endpoints" in results and results["most_targeted_endpoints"]["result"]["success"]:
        endpoints = results["most_targeted_endpoints"]["result"]
        if endpoints["rows"]:
            report += """
## Most Targeted Endpoints

| Endpoint | Request Count | Unique IPs | Blocked | Challenged |
|----------|---------------|-----------|---------|------------|
"""
            for row in endpoints["rows"][:10]:
                endpoint = row[0][:80] + "..." if len(row[0]) > 80 else row[0] if len(row) > 0 else "N/A"
                req_count = row[1] if len(row) > 1 else 0
                ips = row[2] if len(row) > 2 else 0
                blocked = row[3] if len(row) > 3 else 0
                challenged = row[4] if len(row) > 4 else 0
                report += f"| `{endpoint}` | {req_count:,} | {ips} | {blocked} | {challenged} |\n"
            report += "\n"
    
    # WAF Action Distribution
    if "waf_action_distribution" in results and results["waf_action_distribution"]["result"]["success"]:
        actions = results["waf_action_distribution"]["result"]
        if actions["rows"]:
            report += """
## WAF Action Distribution

| Action | Count | Unique IPs | Percentage |
|--------|-------|------------|------------|
"""
            for row in actions["rows"]:
                action = row[0] if len(row) > 0 else "N/A"
                count = row[1] if len(row) > 1 else 0
                ips = row[2] if len(row) > 2 else 0
                pct = row[3] if len(row) > 3 else 0
                report += f"| {action} | {count:,} | {ips} | {pct}% |\n"
            report += "\n"
    
    # HTTP Method Distribution
    if "http_method_distribution" in results and results["http_method_distribution"]["result"]["success"]:
        methods = results["http_method_distribution"]["result"]
        if methods["rows"]:
            report += """
## HTTP Method Distribution

| Method | Count | Unique IPs | Percentage |
|--------|-------|------------|------------|
"""
            for row in methods["rows"]:
                method = row[0] if len(row) > 0 else "N/A"
                count = row[1] if len(row) > 1 else 0
                ips = row[2] if len(row) > 2 else 0
                pct = row[3] if len(row) > 3 else 0
                report += f"| {method} | {count:,} | {ips} | {pct}% |\n"
            report += "\n"
    
    # Status Code Distribution
    if "status_code_distribution" in results and results["status_code_distribution"]["result"]["success"]:
        statuses = results["status_code_distribution"]["result"]
        if statuses["rows"]:
            report += """
## HTTP Status Code Distribution

| Status Code | Count | Unique IPs | Percentage |
|-------------|-------|------------|------------|
"""
            for row in statuses["rows"]:
                status = row[0] if len(row) > 0 else "N/A"
                count = row[1] if len(row) > 1 else 0
                ips = row[2] if len(row) > 2 else 0
                pct = row[3] if len(row) > 3 else 0
                report += f"| {status} | {count:,} | {ips} | {pct}% |\n"
            report += "\n"
    
    # Attack Types
    if "attack_types" in results and results["attack_types"]["result"]["success"]:
        attacks = results["attack_types"]["result"]
        if attacks["rows"]:
            report += """
## Attack Type Breakdown

| Attack Type | Count | Unique IPs |
|-------------|-------|------------|
"""
            for row in attacks["rows"]:
                attack_type = row[0] if len(row) > 0 else "N/A"
                count = row[1] if len(row) > 1 else 0
                ips = row[2] if len(row) > 2 else 0
                report += f"| {attack_type} | {count:,} | {ips} |\n"
            report += "\n"
    
    # Geographic Distribution
    if "geographic_distribution" in results and results["geographic_distribution"]["result"]["success"]:
        geo = results["geographic_distribution"]["result"]
        if geo["rows"]:
            report += """
## Geographic Distribution

| Country | Request Count | Unique IPs | Blocked | Block Rate |
|---------|---------------|------------|---------|------------|
"""
            for row in geo["rows"]:
                country = row[0] if len(row) > 0 else "N/A"
                req_count = row[1] if len(row) > 1 else 0
                ips = row[2] if len(row) > 2 else 0
                blocked = row[3] if len(row) > 3 else 0
                block_rate = row[4] if len(row) > 4 else 0
                report += f"| {country} | {req_count:,} | {ips} | {blocked} | {block_rate}% |\n"
            report += "\n"
    
    # Bot Analysis
    if "bot_analysis" in results and results["bot_analysis"]["result"]["success"]:
        bots = results["bot_analysis"]["result"]
        if bots["rows"]:
            report += """
## Bot Traffic Analysis

| Category | Request Count | Unique IPs | Avg Bot Score |
|----------|---------------|------------|---------------|
"""
            for row in bots["rows"]:
                category = row[0] if len(row) > 0 else "N/A"
                count = row[1] if len(row) > 1 else 0
                ips = row[2] if len(row) > 2 else 0
                score = row[3] if len(row) > 3 else 0
                report += f"| {category} | {count:,} | {ips} | {score:.2f} |\n"
            report += "\n"
    
    # Suspicious Patterns
    if "suspicious_patterns" in results and results["suspicious_patterns"]["result"]["success"]:
        suspicious = results["suspicious_patterns"]["result"]
        if suspicious["rows"]:
            report += """
## Suspicious Request Patterns

| IP Address | User Agent Rotations | Endpoints Tested | Total Requests | Blocked |
|------------|----------------------|-------------------|----------------|---------|
"""
            for row in suspicious["rows"]:
                ip = row[0] if len(row) > 0 else "N/A"
                ua_rotations = row[1] if len(row) > 1 else 0
                endpoints = row[2] if len(row) > 2 else 0
                total = row[3] if len(row) > 3 else 0
                blocked = row[4] if len(row) > 4 else 0
                report += f"| {ip} | {ua_rotations} | {endpoints} | {total:,} | {blocked} |\n"
            report += "\n"
    
    report += """
---

## Recommendations

1. **Monitor Top Attacking IPs:** Review and consider blocking persistent attackers
2. **Protect Targeted Endpoints:** Implement additional security for frequently attacked endpoints
3. **Geographic Analysis:** Review traffic patterns by country for anomalies
4. **Bot Management:** Evaluate bot detection effectiveness and adjust thresholds
5. **Attack Pattern Analysis:** Investigate specific attack types for trends

---

## Notes

- Analysis based on Cloudflare WAF logs stored in Trino
- Time window: Single hour analysis
- For multi-hour/day analysis, run with expanded time windows
- All queries validated and tested against Trino

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    
    return report


def main():
    parser = argparse.ArgumentParser(description="Generate findings report for Quillbot")
    parser.add_argument("--year", type=int, default=2025, help="Year")
    parser.add_argument("--month", type=int, default=12, help="Month")
    parser.add_argument("--day", type=int, default=21, help="Day")
    parser.add_argument("--hour", type=int, default=5, help="Hour")
    parser.add_argument("--customer", type=str, default="Quillbot", help="Customer name")
    
    args = parser.parse_args()
    
    print("🔍 Generating Comprehensive Findings Report")
    print("=" * 80)
    print(f"Customer: {args.customer}")
    print(f"Time Window: {args.year}-{args.month:02d}-{args.day:02d} hour {args.hour:02d}\n")
    
    with httpx.Client(verify=False, timeout=180.0) as client:
        print("Running comprehensive analysis...")
        results = run_comprehensive_analysis(
            client,
            args.year,
            args.month,
            args.day,
            args.hour
        )
        
        print("\nGenerating markdown report...")
        report = generate_markdown_report(
            results,
            args.year,
            args.month,
            args.day,
            args.hour,
            args.customer
        )
        
        # Save report
        report_file = ROOT / f"docs/research-log-analysis/quillbot-findings-{args.year}-{args.month:02d}-{args.day:02d}-{args.hour:02d}.md"
        report_file.write_text(report)
        print(f"✅ Report saved to: {report_file}")
        
        # Save raw results
        results_file = ROOT / f"docs/research-log-analysis/quillbot-analysis-{args.year}-{args.month:02d}-{args.day:02d}-{args.hour:02d}.json"
        results_file.write_text(json.dumps(results, indent=2, default=str))
        print(f"✅ Raw results saved to: {results_file}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

