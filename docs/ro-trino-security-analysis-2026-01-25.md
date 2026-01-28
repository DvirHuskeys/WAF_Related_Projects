# RO Customer - Trino Traffic Security Analysis Report

**Date:** January 25, 2026  
**Customer:** RO (Ro Health / Roman Health)  
**Organization ID:** `843cc2aa-34d1-4729-92f1-ac04bc3f3702`  
**Environment:** Development/Staging  
**Analysis Focus:** Trino-based WAF Traffic Analysis  

---

## Executive Summary

| Metric | Value | Status |
|--------|-------|--------|
| **Total Zones** | 55 | - |
| **Trino Connectivity** | FAILED | CRITICAL |
| **Effective Block Rate** | 1.5% | CRITICAL |
| **WAF Bypass Rate (SKIP)** | 20.0% | HIGH |
| **Detection-Only Rate (LOG)** | 3.2% | HIGH |
| **Unknown/No Evaluation** | 74.7% | CRITICAL |

### Critical Issue: Trino Connectivity Failure

**The primary objective of this analysis—querying Trino for raw WAF traffic logs—could not be completed.**

The Trino MCP server at `trino.internal.dep1.euc1.stg.huskeys.io:443` is returning **HTTP 400 Bad Request** errors for all query types:
- `SHOW CATALOGS` - Failed
- `list_schemas` - Failed  
- `execute_query` - Failed

**Recommendation:** Investigate Trino staging environment connectivity. Possible causes:
1. VPN/network access not established
2. Trino server not running or misconfigured
3. Authentication/authorization failure
4. SSL/TLS certificate mismatch

---

## Data Source Availability

| Source | Status | Data Retrieved |
|--------|--------|----------------|
| **PostgreSQL** | Available | Zone configs, metrics, rules, DNS |
| **Trino** | UNAVAILABLE | No raw logs accessible |

Since Trino is unavailable, this report relies on **PostgreSQL aggregated metrics** which provide security action summaries but lack the granular request-level detail needed for deep traffic analysis.

---

## Findings from PostgreSQL Metrics (Last 7 Days)

### CRITICAL-1: Extremely Low Effective Block Rate (1.5%)

**Traffic Security Action Distribution:**

| Action | Events | Percentage | Assessment |
|--------|--------|------------|------------|
| `unknown` | 1,015,848,408 | 74.7% | No WAF evaluation |
| `skip` | 271,718,153 | 20.0% | WAF bypassed |
| `log` | 43,625,502 | 3.2% | Detected, NOT blocked |
| `block` | 20,380,737 | 1.5% | Actually blocked |
| `managed_challenge` | 3,671,914 | 0.3% | Challenged |
| `managed_challenge_bypassed` | 3,634,002 | 0.3% | Challenge bypassed |
| `allow` | 13,441 | <0.01% | Explicitly allowed |

**Total Events:** ~1.36 billion

**Business Impact:**
- 94.7% of traffic either bypasses WAF (`skip`) or receives no security evaluation (`unknown`)
- Only 1.5% of traffic that triggers security rules is actually blocked
- 43.6M potential attacks detected but logged only—not blocked

---

### CRITICAL-2: High SKIP Traffic Volume (271M Events)

**Top Zones with WAF Bypass Traffic:**

| Zone | Security Source | SKIP Events |
|------|-----------------|-------------|
| `rotests.com` | firewallcustom | 267,498,277 |
| `ro.co` | firewallcustom | 4,144,919 |
| `kit.ro.co` | firewallcustom | 71,976 |
| `modernfertility.com` | firewallcustom | 2,981 |

**Analysis:**
- `rotests.com` accounts for **98.4%** of all SKIP traffic
- This appears to be a dev/test environment with broad WAF bypasses for load testing
- `ro.co` (production) has 4.1M SKIP events—requires investigation

---

### HIGH-1: 43.6M LOG-Only Events (Attacks Detected but Not Blocked)

**Zones with Detection-Only Events:**

| Zone | Security Source | LOG Events |
|------|-----------------|------------|
| `ro.co` | firewallmanaged | 41,972,798 |
| `ro.co` | firewallcustom | 1,465,836 |
| `rotests.com` | firewallmanaged | 110,874 |
| `modernfertility.com` | firewallcustom | 43,683 |
| `kit.ro.co` | firewallmanaged | 20,634 |

**Critical CVE Rules in LOG Mode (Not Blocking):**

Several zones have critical CVE protection rules in LOG mode:

| CVE | Rule Description | Zones Affected |
|-----|------------------|----------------|
| CVE-2025-29891 | Apache Camel - Remote Code Execution | dadikit.com, edge.rohsinfra.net, familifertility.com, getroman.com |
| CVE-2025-64459 | Django SQLI | dadikit.com, edge.rohsinfra.net, familifertility.com |
| CVE-2025-55182 | React Server component - Scanner | dadikit.com, edge.rohsinfra.net, familifertility.com |
| CVE-2025-24893 | XWiki - Remote Code Execution | dadikit.com, edge.rohsinfra.net, familifertility.com |
| CVE-2025-5394 | Wordpress - Dangerous File Upload | dadikit.com, edge.rohsinfra.net, familifertility.com |
| - | Malware, Web Shell | dadikit.com, edge.rohsinfra.net, familifertility.com |

**Recommendation:** Review and transition these CVE-related rules from LOG to BLOCK mode after validation.

---

### HIGH-2: SKIP Rules Analysis (24 Active Rules)

**SKIP Rules by Category:**

#### Legitimate Bot/Crawler Bypasses (Well-Configured)
| Zone | Rule | Risk Level |
|------|------|------------|
| getroman.com | [ALLOW] Bingbot UAs (IP-restricted) | Low |
| getroman.com | [ALLOW] Google Bot UAs (IP-restricted) | Low |
| ro.co | [ALLOW] Bingbot UAs (IP-restricted) | Low |
| ro.co | [ALLOW] Google bot UAs (IP-restricted) | Low |
| ro.co | [SKIP] CF Verified Bot traffic | Low |

#### Monitoring/Scanner Bypasses
| Zone | Rule | Risk Assessment |
|------|------|-----------------|
| kit.ro.co | UptimeRobot - Monitoring | Medium (IP-restricted) |
| ro.co | Allow Tenable PCI-ASV Scans | Low (IP-restricted) |
| ro.co | Allow Onetrust Scan | Low (IP-restricted) |

#### Concerning SKIP Rules
| Zone | Rule | Risk Level | Concern |
|------|------|------------|---------|
| **kit.ro.co** | `api.kit.ro.co - allow` | **HIGH** | Entire API host bypasses WAF |
| **modernfertility.com** | Allow ScreamingFrog | **HIGH** | UA-only bypass (spoofable) |
| **modernfertility.com** | Allow Stripe Webhooks | **MEDIUM** | UA-only bypass |
| **modernfertility.com** | Filter high-traffic endpoints | **MEDIUM** | Path-only bypass |
| **ro.co** | [SKIP] Allow Unverified Bots | **HIGH** | Allows Perplexity/Claude bots |
| **ro.co** | [SKIP] BYPASS K6 LOAD TEST | **HIGH** | Static IPs for load testing |
| **ro.co** | [TEMP] Allow India/Poland Google Contractor | **HIGH** | "TEMP" rule still active |
| **ro.co** | [Temp] Allow ahrefs crawler | **HIGH** | "Temp" rule still active |
| **rotests.com** | [SKIP] BYPASS K6 LOAD TEST | **MEDIUM** | Dev environment |
| **rotests.com** | [SKIP] core-service IP bypass | **MEDIUM** | Single IP bypass |

**Key Concerns:**
1. `api.kit.ro.co` has entire hostname WAF bypass
2. Two "TEMP" rules on `ro.co` still active—need review
3. User-agent only bypasses are easily spoofable

---

### HIGH-3: Non-Proxied DNS Records (Origin Exposure)

**Critical Non-Proxied Records:**

| Record | Type | Target | Risk |
|--------|------|--------|------|
| `login.ro.co` | CNAME | Auth0 | **HIGH** - Authentication endpoint |
| `ip.ro.co` | A | 137.184.245.165 | **HIGH** - Direct IP exposure |
| `care.getroman.com` | CNAME | Zendesk | Medium - Support portal |
| `derm.ro.co` | CNAME | Thesis testing | Medium - External service |
| `community.modernfertility.com` | CNAME | Circle.so | Low - Community platform |
| `learn.modernfertility.com` | CNAME | Unbounce | Low - Landing pages |

**Note:** Many non-proxied records are for email (SendGrid, Sparkpost) and domain verification which are expected.

---

### Blocking Activity Summary (Last 7 Days)

**Top Zones by Block Events:**

| Zone | Security Source | Block Events |
|------|-----------------|--------------|
| rotests.com | firewallcustom | 19,740,590 |
| rotests.com | firewallmanaged | 206,313 |
| ro.co | firewallcustom | 151,626 |
| ro.co | firewallmanaged | 116,407 |
| kit.ro.co | firewallmanaged | 94,921 |
| kit.ro.co | firewallcustom | 43,612 |
| modernfertility.com | firewallmanaged | 6,974 |

**Total Blocks:** ~20.4M events

---

### Bot Management Configuration

| Zone | Bot Fight Mode | JS Detection | Latest Model |
|------|----------------|--------------|--------------|
| ro.co | **Enabled** | **Enabled** | Yes |
| rotests.com | Disabled | Disabled | Yes |
| getroman.com | Disabled | Disabled | Yes |
| kit.ro.co | Disabled | Disabled | Yes |
| modernfertility.com | Disabled | Disabled | Yes |

**Finding:** Only `ro.co` has Bot Fight Mode and JS Detection enabled. Other production zones (`getroman.com`, `modernfertility.com`) lack bot protection.

---

## What Trino Analysis Would Provide

If Trino were accessible, we could perform:

1. **Attack Pattern Analysis**
   - Individual request inspection with WAF attack scores
   - SQLi/XSS/RCE score analysis for allowed traffic
   - Identify high-score attacks that bypassed protection

2. **Bot Traffic Deep Dive**
   - Bot score distribution
   - Verified bot category analysis
   - JA3/JA4 fingerprint analysis for automation detection

3. **Geographic Analysis**
   - Attack traffic by country
   - Unusual geographic patterns
   - High-risk country traffic to sensitive endpoints

4. **Credential Stuffing Detection**
   - Login endpoint traffic patterns
   - Leaked credentials check results
   - Authentication endpoint abuse

5. **Real-Time Attack Validation**
   - Correlate SKIP traffic with actual request payloads
   - Identify exploitation of bypass rules
   - Validate LOG-mode rule effectiveness

---

## Risk Assessment

| Finding ID | Severity | Finding | Business Impact |
|------------|----------|---------|-----------------|
| TRINO-001 | CRITICAL | Trino unavailable | Cannot perform raw log analysis |
| METRIC-001 | CRITICAL | 1.5% block rate | 98.5% of threats not blocked |
| METRIC-002 | CRITICAL | 74.7% unknown traffic | No WAF evaluation |
| SKIP-001 | HIGH | 271M bypass events | WAF protection circumvented |
| LOG-001 | HIGH | 43.6M unblocked detections | Active attacks not stopped |
| SKIP-002 | HIGH | TEMP rules still active | Stale bypass configurations |
| SKIP-003 | HIGH | Entire API host bypass | api.kit.ro.co unprotected |
| CVE-001 | HIGH | CVE rules in LOG mode | Known vulnerabilities not blocked |
| BOT-001 | MEDIUM | Limited bot protection | Only ro.co has bot fight mode |

---

## Recommendations

### Immediate (This Week)
1. **Resolve Trino connectivity** to enable raw log analysis
2. **Review "TEMP" SKIP rules** on ro.co—either remove or convert to permanent with proper documentation
3. **Audit `api.kit.ro.co` bypass**—determine if entire host bypass is necessary

### Short-Term (Next 2 Weeks)
4. **Transition CVE rules from LOG to BLOCK** after false-positive validation
5. **Enable Bot Fight Mode** on getroman.com and modernfertility.com
6. **Review all UA-only SKIP rules**—add IP restrictions where possible

### Medium-Term (Next Month)
7. **Reduce SKIP traffic** on ro.co production (4.1M events)
8. **Implement rate limiting** on authentication endpoints
9. **Proxy critical DNS records** where possible (login.ro.co considerations)

---

## Appendix: Validation Queries Used

### Security Action Distribution
```sql
SELECT m.security_action, SUM(m.metric_value) as total_events
FROM cloudflare_raw_zone_metrics_history m
JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
WHERE z.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND m.metric_timestamp >= NOW() - INTERVAL '7 days'
AND m.is_deleted = false
GROUP BY m.security_action
ORDER BY total_events DESC;
```

### SKIP Traffic by Zone
```sql
SELECT z.name as zone_name, m.security_source, SUM(m.metric_value) as skip_events
FROM cloudflare_raw_zone_metrics_history m
JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
WHERE z.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND m.security_action = 'skip'
AND m.metric_timestamp >= NOW() - INTERVAL '7 days'
GROUP BY z.name, m.security_source
ORDER BY skip_events DESC;
```

### SKIP Rules Configuration
```sql
SELECT z.name as zone, r.description as rule, r.action, r.expression, rs.phase
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND r.action = 'SKIP' AND r.enabled = true
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false
ORDER BY z.name;
```

---

**Report Generated:** 2026-01-25  
**Data Source:** PostgreSQL (Trino unavailable)  
**Framework:** WAF Security Analysis Framework v4.0
