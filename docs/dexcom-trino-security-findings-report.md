# Dexcom WAF Security Analysis Report - Trino Data Lake

**Generated:** December 30, 2025  
**Customer:** Dexcom  
**Analysis Period:** Last 7 Days  
**Data Source:** Trino Data Lake + Aggregated WAF Metrics  

---

## Executive Summary

| Metric | Value | Severity |
|--------|-------|----------|
| Total Security Events (7 days) | **10.1 Billion** | - |
| WAF Bypass (Skip) Events | **4.35 Billion (42.9%)** | **CRITICAL** |
| Log-Only Events (No Block) | **395 Million (3.9%)** | **HIGH** |
| Actually Blocked Events | **139 Million (1.4%)** | - |
| Unknown/Unclassified Events | **5.25 Billion (51.8%)** | **HIGH** |

### Key Finding
**Only 1.4% of security events result in actual blocking.** The vast majority of traffic (42.9%) is explicitly bypassing WAF protections via skip rules.

---

## Trino Cluster Configuration

**Cluster Details:**
- Host: `trino.internal.dep1.euc1.stg.huskeys.io`
- Port: 443
- Scheme: HTTPS
- User: admin

**Available Catalogs:**
- `aws_waf_logs` - AWS WAF log data
- `huskeys_customers_logs` - Customer-specific log data
- `huskeys_aggregated` - Aggregated analytics data

**Relevant Schemas:**
- `cloudflare_waf_logs` - Cloudflare HTTP request logs
- `waf_logs_db` - Unified WAF log views

**Note:** Direct Dexcom log queries require partition key filters (organization, zone, year, month, day, hour). Aggregated metrics from the Postgres database were used for this analysis.

---

## Finding 1: Massive WAF Bypass (Skip) Volume

### Severity: CRITICAL

### Description

**4.35 billion security events** in the last 7 days were processed with `skip` action, meaning WAF rules were intentionally bypassed. This represents **42.9% of all security events**.

**Top Zones by WAF Bypass Volume:**

| Zone | Skip Events (7 days) | Risk |
|------|---------------------|------|
| `mobile.share-us.dexcom.com` | 2,537,925,868 | Critical - Mobile API |
| `mobile.share-eu.dexcom.com` | 621,141,459 | Critical - Mobile API |
| `global.dexcom.com` | 419,244,599 | High - Global endpoint |
| `accounts-api.dexcom.com` | 329,619,119 | Critical - Authentication |
| `uam2.dexcom.com` | 112,793,840 | High - User management |
| `shareous1.dexcom.com` | 105,062,490 | High - Data sharing |
| `accounts-api.dexcom.eu` | 90,290,805 | Critical - Authentication EU |
| `uam1.dexcom.com` | 45,143,147 | High - User management |
| `watch.share-us.dexcom.com` | 29,947,494 | High - Wearable API |
| `gcs2.dexcom.com` | 17,895,649 | Medium - Data services |

### Business Impact

- **Mobile applications are completely unprotected**: The mobile share APIs handle CGM (Continuous Glucose Monitor) data and are bypassing all WAF protection
- **Authentication endpoints exposed**: `accounts-api.dexcom.com` with 330M+ bypass events means credential attacks aren't being inspected
- **Patient data at risk**: These endpoints handle sensitive health data (PHI) protected under HIPAA
- **Attack surface**: 4.35 billion opportunities for attackers to exploit vulnerabilities without detection

### Risk Assessment

**CRITICAL** - The bypass ratio of 42.9% indicates WAF is functioning as a pass-through for most traffic rather than a security control.

### Remediation

1. **Audit all firewall custom rules** that result in skip actions
2. **Remove or restrict bypass rules** on production mobile and API endpoints
3. **Implement graduated protection**: Use challenge actions instead of skip for trusted sources
4. **Enable strict mode** for authentication endpoints - never bypass
5. **Alert on bypass volume**: Set thresholds and alert when bypass rates exceed 10%

### Trino Validation Query (Template)

```sql
-- Query to analyze skip events by zone and source
-- Requires partition keys: organization, zone, year, month, day, hour
SELECT 
    zonename,
    securityaction,
    COUNT(*) as event_count,
    COUNT(DISTINCT clientip) as unique_ips
FROM huskeys_customers_logs.cloudflare_waf_logs.raw 
WHERE organization = 'Dexcom'
AND zone = '<zone_name>'
AND year = 2025 
AND month = 12
AND day = <day>
AND hour = <hour>
AND securityaction = 'skip'
GROUP BY zonename, securityaction
ORDER BY event_count DESC;

-- Aggregated metrics query (Postgres fallback)
SELECT 
    z.name as zone_name,
    m.security_source,
    SUM(m.metric_value) as skip_events
FROM cloudflare_raw_zone_metrics_history m
JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND m.security_action = 'skip'
AND m.metric_timestamp >= NOW() - INTERVAL '7 days'
GROUP BY z.name, m.security_source
ORDER BY skip_events DESC;
```

---

## Finding 2: Rate Limiting in Log-Only Mode

### Severity: HIGH

### Description

**394.6 million rate limiting events** were logged but not blocked. This represents potential brute-force attempts, credential stuffing, or abuse that was detected but not mitigated.

**Top Zones with Log-Only Rate Limiting:**

| Zone | Log Events (7 days) | Expected Protection |
|------|---------------------|---------------------|
| `uam1.dexcom.com` | 378,525,086 | User account management |
| `shareous1.dexcom.com` | 15,457,844 | Data sharing API |
| `global.dexcom.com` | 455,375 | Global services |
| `keycloak-prod.dexcom.com` | 103,181 | SSO/Authentication |
| `platform.dexcom.com` | 30,434 | Platform services |
| `accounts-api.dexcom.com` | 4,119 | Account API |

### Business Impact

- **Brute-force attacks unmitigated**: 378M events on `uam1.dexcom.com` suggests sustained attack activity
- **Account takeover risk**: Rate limiting on account endpoints should BLOCK, not log
- **Resource abuse**: Log-only mode consumes resources without protection
- **Compliance gap**: HIPAA requires reasonable security measures - logging without action may not qualify

### Risk Assessment

**HIGH** - Rate limiting is designed to prevent abuse. Log-only mode negates its protective value while indicating ongoing attack activity.

### Remediation

1. **Convert log rules to block** for authentication endpoints immediately
2. **Review rate limit thresholds** - 378M events suggests thresholds may be too high
3. **Implement progressive blocking**: Start with challenges, escalate to blocks
4. **Add account lockout**: Integrate with identity systems for repeated offenders
5. **Set up alerting**: Trigger security team review when log-only events spike

### Trino Validation Query (Template)

```sql
-- Analyze rate limiting events
SELECT 
    clientrequesthost,
    clientrequestpath,
    securityaction,
    COUNT(*) as requests,
    COUNT(DISTINCT clientip) as unique_ips
FROM huskeys_customers_logs.cloudflare_waf_logs.raw 
WHERE organization = 'Dexcom'
AND zone = 'uam1.dexcom.com'
AND year = 2025 AND month = 12
AND securityaction = 'log'
AND array_contains(securitysources, 'ratelimit')
GROUP BY clientrequesthost, clientrequestpath, securityaction
ORDER BY requests DESC
LIMIT 50;
```

---

## Finding 3: Low Block Ratio Indicates Ineffective WAF

### Severity: HIGH

### Description

Of 10.1 billion security events, only **139.4 million (1.4%)** resulted in blocking. The security action breakdown reveals systemic misconfiguration:

| Action | Events | Percentage |
|--------|--------|------------|
| Unknown | 5,247,712,289 | 51.8% |
| Skip | 4,346,991,916 | 42.9% |
| Log | 394,876,170 | 3.9% |
| Block | 139,440,525 | 1.4% |
| Managed Challenge | 35,974 | <0.01% |

**Block Sources Breakdown:**

| Source | Blocked Events |
|--------|---------------|
| Rate Limiting | 136,652,089 |
| Firewall Custom | 2,666,722 |
| Firewall Managed | 121,451 |
| Bot/Intelligent Challenge | 263 |

### Business Impact

- **WAF is decorative, not protective**: 1.4% block rate means WAF provides minimal actual security
- **Unknown events are uninspected**: 51.8% of traffic has no security classification
- **Attack detection is passive**: Most attacks are logged or skipped, not stopped
- **False sense of security**: Having WAF deployed without effective blocking creates compliance risk

### Risk Assessment

**HIGH** - The current configuration suggests WAF is not providing meaningful protection. Attack traffic flows through largely unimpeded.

### Remediation

1. **Set target block ratio**: Industry standard is 5-15% of inspected traffic should be blocked
2. **Investigate unknown events**: 5.2B unclassified events need rule coverage
3. **Audit rule effectiveness**: Review which rules are actually triggering
4. **Enable managed rulesets**: Ensure Cloudflare managed rules are in BLOCK mode
5. **Implement security baselines**: Require minimum protection levels per zone type

### Trino Validation Query (Template)

```sql
-- Security action distribution analysis
SELECT 
    securityaction,
    array_join(securitysources, ',') as sources,
    COUNT(*) as events,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(DISTINCT clientrequesthost) as unique_hosts
FROM huskeys_customers_logs.cloudflare_waf_logs.raw 
WHERE organization = 'Dexcom'
AND zone = '<target_zone>'
AND year = 2025 AND month = 12 AND day = <day> AND hour = <hour>
GROUP BY securityaction, array_join(securitysources, ',')
ORDER BY events DESC;
```

---

## Finding 4: Unclassified Traffic (Unknown Action)

### Severity: HIGH

### Description

**5.25 billion events (51.8%)** have `unknown` security action. This traffic bypasses security classification entirely, making it impossible to determine if attacks are occurring.

### Business Impact

- **Blind spots in security monitoring**: Over half of traffic is invisible to security controls
- **Incident response hampered**: Cannot investigate what you cannot see
- **Compliance risk**: Required to maintain security logs - unclassified events may not meet requirements
- **Unknown attack exposure**: Sophisticated attacks may be hiding in unclassified traffic

### Risk Assessment

**HIGH** - Security teams cannot protect against what they cannot see. Half of all traffic being unclassified is unacceptable for a healthcare organization.

### Remediation

1. **Investigate root cause**: Determine why events lack security classification
2. **Enable logging on all phases**: Ensure HTTP request firewall phases are logging
3. **Deploy catch-all rules**: Create rules that classify all traffic (even if action is allow)
4. **Audit zone configurations**: Some zones may have logging disabled
5. **Review Cloudflare log settings**: Ensure complete log export is configured

### Trino Validation Query (Template)

```sql
-- Analyze unknown/unclassified traffic patterns
SELECT 
    clientrequesthost,
    clientrequestmethod,
    clientrequestpath,
    COUNT(*) as requests,
    AVG(wafattackscore) as avg_attack_score,
    AVG(wafsqliattackscore) as avg_sqli_score
FROM huskeys_customers_logs.cloudflare_waf_logs.raw 
WHERE organization = 'Dexcom'
AND zone = '<zone>'
AND year = 2025 AND month = 12 AND day = <day> AND hour = <hour>
AND (securityaction IS NULL OR securityaction = '' OR securityaction = 'unknown')
GROUP BY clientrequesthost, clientrequestmethod, clientrequestpath
ORDER BY requests DESC
LIMIT 100;
```

---

## Security Metrics Dashboard

```
┌──────────────────────────────────────────────────────────────────┐
│                 DEXCOM WAF SECURITY SUMMARY                      │
│                     (Last 7 Days)                                │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Total Events Processed:           10,129,056,874                │
│                                                                  │
│  ████████████████████████░░░░░░░░░░░░░░░░░░░░  Unknown: 51.8%    │
│  ████████████████████░░░░░░░░░░░░░░░░░░░░░░░░  Skip:    42.9%    │
│  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  Log:      3.9%    │
│  █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  Block:    1.4%    │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│  PROTECTION EFFECTIVENESS:                         1.4%          │
│  TARGET PROTECTION LEVEL:                        >10.0%          │
│  GAP:                                              8.6%          │
├──────────────────────────────────────────────────────────────────┤
│  Top Unprotected Zones (by skip volume):                         │
│    1. mobile.share-us.dexcom.com    2.5B events                  │
│    2. mobile.share-eu.dexcom.com    621M events                  │
│    3. global.dexcom.com             419M events                  │
│    4. accounts-api.dexcom.com       330M events                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Recommendations Priority Matrix

| Priority | Finding | Immediate Action | Timeline |
|----------|---------|------------------|----------|
| **P0** | Mobile API WAF bypass | Disable skip rules on `mobile.share-*.dexcom.com` | 24 hours |
| **P0** | Accounts API bypass | Remove bypass rules on `accounts-api.dexcom.*` | 24 hours |
| **P1** | Rate limit log→block | Convert log-only rate limits to block mode | 48 hours |
| **P1** | Unknown event investigation | Audit logging configuration | 1 week |
| **P2** | Block ratio improvement | Enable managed rulesets in block mode | 2 weeks |
| **P2** | Security baseline | Define minimum protection requirements per zone type | 2 weeks |

---

## Appendix: Trino Schema Reference

### Raw Cloudflare Logs Table
**Table:** `huskeys_customers_logs.cloudflare_waf_logs.raw`

| Column | Type | Description |
|--------|------|-------------|
| `organization` | varchar (partition) | Customer organization name |
| `zone` | varchar (partition) | Cloudflare zone name |
| `year`, `month`, `day`, `hour` | integer (partition) | Time partitions |
| `securityaction` | varchar | WAF action taken (block/log/skip/etc) |
| `securitysources` | array(varchar) | Security source (ratelimit/firewallcustom/etc) |
| `securityruledescription` | varchar | Rule that triggered |
| `securityruleid` | varchar | Rule identifier |
| `clientip` | varchar | Source IP address |
| `clientrequesthost` | varchar | Target hostname |
| `clientrequestpath` | varchar | Request URI path |
| `wafattackscore` | integer | Combined WAF attack score (0-100) |
| `wafsqliattackscore` | integer | SQL injection score |
| `wafxssattackscore` | integer | XSS attack score |
| `wafrceattackscore` | integer | RCE attack score |
| `botscore` | integer | Bot detection score |

### Query Requirements
All queries against the raw table require partition predicates for:
- `organization` (exact match)
- `zone` (exact match)
- `year`, `month`, `day`, `hour` (exact match or range)

---

*Report generated by WAF Security Analysis Platform using Trino + Postgres data sources*



