# WAF Security Analysis Prompt Template

**Purpose:** Reusable prompt for performing deep-dive WAF security analysis for any customer using PostgreSQL (configurations) and Trino (logs).

---

## How to Use This Template

1. Replace `{CUSTOMER_NAME}` with the actual customer name
2. Replace `{ORGANIZATION_ID}` with the customer's organization ID from PostgreSQL
3. Follow the structured analysis workflow below
4. Copy the analysis sections to Claude/AI assistant as needed

---

## Phase 1: Customer Identification & Data Availability Check

### Prompt 1.1: Identify Customer Organization
```
Query the PostgreSQL database to find the organization ID for customer "{CUSTOMER_NAME}".

Search the cloudflare_raw_zones_history table for zones containing the customer name:

SELECT DISTINCT organization_id, name 
FROM cloudflare_raw_zones_history 
WHERE lower(name) LIKE '%{customer_name_lowercase}%'
AND is_deleted = false
LIMIT 10;

Store the organization_id for subsequent queries.
```

### Prompt 1.2: Verify Trino Log Availability
```
Check if WAF logs exist for this customer in Trino:

1. List available customer log tables:
   SELECT table_name
   FROM huskeys_customers_logs.information_schema.tables
   WHERE table_schema = 'waf_logs_db'
   ORDER BY table_name;

2. If a customer-specific table exists (e.g., {customer}_waf_logs), query recent data:
   SELECT year, month, day, COUNT(*) as events
   FROM huskeys_customers_logs.waf_logs_db.{customer}_waf_logs
   GROUP BY year, month, day
   ORDER BY year DESC, month DESC, day DESC
   LIMIT 10;

3. Check raw Cloudflare logs partition:
   SELECT COUNT(*) as events
   FROM huskeys_customers_logs.cloudflare_waf_logs.raw 
   WHERE organization = '{CUSTOMER_NAME}'
   AND zone = '{known_zone_name}'
   AND year = 2025 
   AND month = 12
   AND day = {recent_day}
   AND hour = 12;

Document whether logs are available. If not, note this as a CRITICAL finding.
```

---

## Phase 2: Log-Based Security Analysis (PostgreSQL Metrics)

### Prompt 2.0: Security Action Summary (CRITICAL FIRST STEP)
```
Query the cloudflare_raw_zone_metrics_history table to understand traffic security posture:

SELECT
    m.security_action,
    SUM(m.metric_value) as total_events
FROM cloudflare_raw_zone_metrics_history m
JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND m.metric_timestamp >= NOW() - INTERVAL '7 days'
AND m.is_deleted = false
GROUP BY m.security_action
ORDER BY total_events DESC;

Calculate:
- BLOCK rate (actual protection)
- LOG rate (detection-only, NOT blocking)
- SKIP rate (WAF bypass)
- UNKNOWN rate (no WAF evaluation)

CRITICAL: If SKIP + UNKNOWN > 50%, this is a major security gap!
Target: BLOCK rate should be >90% of detected threats.
```

### Prompt 2.0.1: SKIP Events by Zone (WAF Bypass Analysis)
```
Identify zones with highest WAF bypass traffic:

SELECT
    z.name as zone_name,
    m.security_source,
    SUM(m.metric_value) as skip_events
FROM cloudflare_raw_zone_metrics_history m
JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND m.security_action = 'skip'
AND m.metric_timestamp >= NOW() - INTERVAL '7 days'
GROUP BY z.name, m.security_source
ORDER BY skip_events DESC
LIMIT 50;

For zones with high SKIP but NO SKIP rules - they have NO WAF protection!
For zones with high SKIP AND SKIP rules - investigate the bypass rules.
```

### Prompt 2.0.2: LOG Events by Zone (Detection-Only Analysis)
```
Identify zones detecting attacks but NOT blocking them:

SELECT
    z.name as zone_name,
    m.security_source,
    SUM(m.metric_value) as log_events
FROM cloudflare_raw_zone_metrics_history m
JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND m.security_action = 'log'
AND m.metric_timestamp >= NOW() - INTERVAL '7 days'
GROUP BY z.name, m.security_source
ORDER BY log_events DESC
LIMIT 50;

These are active attacks being detected but NOT stopped!
Prioritize switching these rules from LOG to BLOCK mode.
```

---

## Phase 3: Configuration-Based Security Analysis (PostgreSQL)

### Prompt 3.1: Zone Protection Coverage Analysis
```
Cross-reference SKIP traffic with zone protection status:

WITH skip_metrics AS (
    SELECT
        z.name as zone_name,
        z.id as zone_id,
        SUM(m.metric_value) as skip_events
    FROM cloudflare_raw_zone_metrics_history m
    JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
    WHERE z.organization_id = '{ORGANIZATION_ID}'
    AND m.security_action = 'skip'
    AND m.metric_timestamp >= NOW() - INTERVAL '7 days'
    GROUP BY z.name, z.id
),
zone_protection AS (
    SELECT
        z.id as zone_id,
        COUNT(DISTINCT ri.ruleset_id) as ruleset_count
    FROM cloudflare_raw_zones_history z
    LEFT JOIN cloudflare_raw_rulesets_instance_history ri 
        ON z.id = ri.zone_id AND ri.is_deleted = false
    WHERE z.organization_id = '{ORGANIZATION_ID}' 
    AND z.is_deleted = false
    GROUP BY z.id
)
SELECT 
    s.zone_name,
    s.skip_events,
    COALESCE(p.ruleset_count, 0) as ruleset_count,
    CASE WHEN p.ruleset_count > 0 THEN 'Protected' ELSE 'UNPROTECTED' END as status
FROM skip_metrics s
LEFT JOIN zone_protection p ON s.zone_id = p.zone_id
ORDER BY s.skip_events DESC;

Using PostgreSQL with organization_id = '{ORGANIZATION_ID}':

CRITICAL FINDING: Identify production zones WITHOUT ANY WAF protection:

SELECT z.name
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    WHERE ri.zone_id = z.id AND ri.is_deleted = false
)
AND z.name NOT LIKE '%dev%'
AND z.name NOT LIKE '%test%'
AND z.name NOT LIKE '%staging%'
AND z.name NOT LIKE '%vnv%'
AND z.name NOT LIKE '%int%'
AND z.name NOT LIKE '%load%'
ORDER BY z.name;

Calculate protection rate:
- Total production zones
- Protected production zones
- Protection percentage

Flag any authentication, API, login, or user-data zones that are unprotected.
```

### Prompt 2.2: WAF Rules in LOG Mode (Detection Only)
```
HIGH FINDING: Identify WAF rules that detect but don't block attacks:

SELECT 
    z.name as zone,
    r.description as rule,
    rs.name as ruleset,
    rs.phase
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'LOG' AND r.enabled = true
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false
AND z.name NOT LIKE '%dev%'
AND z.name NOT LIKE '%test%'
AND z.name NOT LIKE '%vnv%'
ORDER BY z.name, r.description;

Group findings by:
- Zone
- Rule type (CVE-related, credential detection, attack type)
- Count occurrences

Prioritize CVE-related rules and credential detection rules as highest risk.
```

### Prompt 2.3: SKIP/Bypass Rules Analysis
```
HIGH FINDING: Identify WAF bypass rules that create security gaps:

SELECT 
    z.name as zone,
    r.description as rule_desc,
    r.expression,
    rs.phase,
    r.action_parameters::text as action_params
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'SKIP' AND r.enabled = true
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false
ORDER BY z.name, r.description;

Flag risky patterns:
- Rules without IP restrictions
- User-agent based bypasses (easily spoofed)
- Path-based bypasses without additional conditions
- Overly broad CIDR ranges in whitelists
- Zones with excessive SKIP rules (>5)
```

### Prompt 2.4: DNS Record Exposure Analysis
```
HIGH FINDING: Identify unproxied DNS records exposing origin IPs:

SELECT 
    d.name,
    d.type,
    d.content
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND d.proxied = false
AND d.proxiable = true
AND d.type IN ('A', 'AAAA', 'CNAME')
AND d.is_deleted = false
AND z.is_deleted = false
ORDER BY d.name;

Flag high-value exposed records containing:
- api, login, account, auth, share, admin, prod, mobile, global, keycloak, signup, myaccount, dashboard
```

### Prompt 2.5: High-Value Zone Deep Dive
```
For each pattern, analyze protection status:
- api.{customer}.* (API endpoints)
- accounts-api.* (Account management)
- login.* (Authentication)
- myaccount.* (User accounts)
- keycloak* (Identity provider)
- signup.* (Registration)
- consents-api.* (Privacy/GDPR)
- share* (Data sharing)
- mobile.* (Mobile backends)

For each matching zone, report:
- Number of active rulesets
- Number of LOG mode rules
- Number of SKIP rules
- Protection status (Protected/Unprotected)
```

---

## Phase 3: Log-Based Analysis (Trino) - If Available

### Prompt 3.1: Attack Volume Analysis
```
If Trino logs are available, analyze attack patterns:

SELECT 
    securityaction,
    COUNT(*) as event_count
FROM huskeys_customers_logs.waf_logs_db.{customer}_waf_logs
WHERE year = 2025 AND month = 12 AND day >= {start_day}
GROUP BY securityaction
ORDER BY event_count DESC;

Calculate:
- Block rate
- Challenge rate
- Allow rate on malicious traffic
- SKIP/bypass volume
```

### Prompt 3.2: Attack Score Analysis
```
Identify high-severity attacks by WAF attack scores:

SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    wafattackscore,
    wafsqliattackscore,
    wafxssattackscore,
    wafrceattackscore
FROM huskeys_customers_logs.waf_logs_db.{customer}_waf_logs
WHERE year = 2025 AND month = 12 AND day = {recent_day}
AND wafattackscore > 80
ORDER BY wafattackscore DESC
LIMIT 100;

Flag:
- High attack scores that were ALLOWED (not blocked)
- Patterns indicating active exploitation attempts
- Targeted endpoints
```

### Prompt 3.3: Geographic Attack Analysis
```
Identify attack sources by geography:

SELECT 
    clientcountry,
    securityaction,
    COUNT(*) as events
FROM huskeys_customers_logs.waf_logs_db.{customer}_waf_logs
WHERE year = 2025 AND month = 12 AND day >= {start_day}
AND wafattackscore > 50
GROUP BY clientcountry, securityaction
ORDER BY events DESC
LIMIT 50;

Flag unusual geographic patterns or high-risk countries.
```

### Prompt 3.4: Targeted Endpoint Analysis
```
Identify most targeted endpoints:

SELECT 
    clientrequesthost,
    clientrequestpath,
    COUNT(*) as attack_attempts,
    COUNT(CASE WHEN securityaction = 'block' THEN 1 END) as blocked,
    COUNT(CASE WHEN securityaction = 'allow' THEN 1 END) as allowed
FROM huskeys_customers_logs.waf_logs_db.{customer}_waf_logs
WHERE year = 2025 AND month = 12 AND day >= {start_day}
AND wafattackscore > 50
GROUP BY clientrequesthost, clientrequestpath
ORDER BY attack_attempts DESC
LIMIT 50;

Cross-reference with misconfiguration findings:
- Are targeted endpoints protected?
- Are there LOG mode rules on these endpoints?
- Are there SKIP rules allowing bypass?
```

---

## Phase 4: Cross-Reference and Validation

### Prompt 4.1: Link Traffic to Misconfigurations
```
For each traffic anomaly found in Trino:

1. Identify the zone and rule involved
2. Query PostgreSQL for that zone's configuration:
   - Is WAF enabled?
   - Are rules in BLOCK or LOG mode?
   - Are there SKIP rules that could allow the traffic?

3. Document the correlation:
   "Traffic finding X on zone Y is explained by misconfiguration Z"
   OR
   "Traffic finding X cannot be explained by known configurations - investigate further"
```

### Prompt 4.2: Validate Findings Against Cloudflare Best Practices
```
For each finding, validate against Cloudflare best practices:

1. CRITICAL: Unprotected zones
   - Best practice: ALL production zones should have managed WAF rulesets
   - Recommendation: Deploy Cloudflare Managed Ruleset (OWASP)

2. HIGH: LOG mode rules
   - Best practice: Production rules should be in BLOCK mode
   - Recommendation: Test in LOG, then transition to BLOCK

3. HIGH: SKIP rules
   - Best practice: Minimize exceptions, use IP-based restrictions
   - Recommendation: Audit and document all bypasses

4. HIGH: Unproxied DNS
   - Best practice: Proxy all A/AAAA/CNAME records
   - Recommendation: Enable proxy or restrict origin firewall

5. MEDIUM: TLS/SSL settings
   - Best practice: TLS 1.2 minimum, Full (Strict) SSL mode
   - Recommendation: Upgrade legacy settings
```

---

## Phase 5: Report Generation

### Report Structure
```markdown
# {CUSTOMER_NAME} Security Deep Dive Report

## Executive Summary
- Total zones
- Protection rate
- Critical findings count
- High findings count

## Critical Findings
### CRITICAL-1: [Finding Title]
- Description
- Affected assets
- Business impact
- Remediation steps
- Validation query

## High Severity Findings
[Same structure as critical]

## Medium Severity Findings
[Same structure]

## Risk Matrix
| Finding | Severity | Likelihood | Impact | Priority |

## Compliance Implications
- HIPAA/GDPR/SOC2 impacts

## Recommendations
- Immediate (24-48 hours)
- Short-term (1 week)
- Medium-term (2-4 weeks)

## Appendix: Validation Queries
[All SQL queries used]
```

---

## Quick Reference: Key Tables

### PostgreSQL (Configuration Data)
| Table | Purpose |
|-------|---------|
| `cloudflare_raw_zones_history` | Zone definitions |
| `cloudflare_raw_rulesets_history` | Ruleset definitions |
| `cloudflare_raw_rulesets_rules_history` | Individual rules |
| `cloudflare_raw_rulesets_instance_history` | Zone-ruleset mapping |
| `cloudflare_raw_dns_records_history` | DNS records |
| `cloudflare_raw_bot_management_history` | Bot config |

### Trino (Log Data)
| Table | Purpose |
|-------|---------|
| `huskeys_customers_logs.cloudflare_waf_logs.raw` | Raw CF logs |
| `huskeys_customers_logs.waf_logs_db.{customer}_waf_logs` | Customer logs |
| `huskeys_aggregated.waf_logs_db.cloudflare_http_requests` | Aggregated logs |

### Key Trino Partition Columns
- `organization` - Customer name
- `zone` - Zone name
- `year`, `month`, `day`, `hour` - Time partitions

---

## Example: Complete Analysis Workflow

```
1. Start: "Analyze WAF security for customer Acme Corp"

2. Identify: 
   - org_id = 'abc-123-def'
   - 45 zones found

3. PostgreSQL Metrics Analysis (CRITICAL FIRST STEP):
   - Total events: 500M
   - SKIP: 200M (40%) ❌ CRITICAL
   - LOG: 50M (10%) ⚠️
   - BLOCK: 5M (1%) ❌ CRITICAL  
   - UNKNOWN: 245M (49%) ❌
   
   → EFFECTIVE PROTECTION: 1% - CRITICAL GAP!

4. Cross-Reference Skip Traffic with Protection:
   - mobile.share.acme.com: 150M SKIP events, NO WAF ❌
   - api.acme.com: 30M SKIP events, HAS WAF (SKIP rules)
   - accounts.acme.com: 20M SKIP events, NO WAF ❌

5. PostgreSQL Config Analysis:
   - 12/45 production zones unprotected ❌
   - 234 LOG mode rules ⚠️
   - 15 SKIP rules on protected zones ⚠️
   - 3 unproxied DNS records ⚠️

6. Trino Raw Logs (if available):
   - 1.2M blocked events (good)
   - 45K high-score events allowed (bad)
   - api.acme.com most targeted

7. Cross-reference:
   - api.acme.com has SKIP rule for /health path
   - High SKIP traffic correlates with this rule
   - Attackers targeting /health?cmd=... 
   - → SKIP rule being exploited!

8. Report:
   - CRITICAL: 200M WAF bypass events (40%)
   - CRITICAL: 1% effective protection rate
   - CRITICAL: 12 unprotected production zones
   - HIGH: 50M attacks detected but not blocked
   - HIGH: 15 excessive SKIP rules
```

---

*Template Version: 1.0*  
*Last Updated: December 30, 2025*

