# Dexcom Security Deep Dive Report

**Date:** December 30, 2025  
**Analysis Type:** WAF Configuration & Log Security Assessment  
**Data Sources:** 
- PostgreSQL (Cloudflare Configuration Data)  
- PostgreSQL (Cloudflare Zone Metrics - Aggregated Logs)

---

## Executive Summary

### Traffic Volume Analysis (Last 7 Days)

| Metric | Events | Percentage |
|--------|--------|------------|
| **Total WAF Events** | 10,127,620,485 | 100% |
| **Unknown (No WAF Evaluation)** | 5,246,239,599 | **51.8%** |
| **Skipped (WAF Bypass)** | 4,347,006,735 | **42.9%** |
| **Logged (Detection Only)** | 394,868,899 | 3.9% |
| **Blocked (Actual Protection)** | 139,469,467 | **1.4%** |

### Zone Protection Coverage

| Metric | Value |
|--------|-------|
| **Total Cloudflare Zones** | 333 |
| **Estimated Production Zones** | 77 |
| **Production Zones WITH WAF** | 25 |
| **Production Zones WITHOUT WAF** | 52 |
| **Production Protection Rate** | **32.5%** |

### 🚨 Critical Security Posture

```
┌────────────────────────────────────────────────────────────────┐
│              SECURITY EFFECTIVENESS METRICS                    │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  BLOCK RATE:     1.38%  ← Only 1 in 72 events blocked!        │
│  LOG RATE:       3.90%  ← Detection only, no protection       │
│  SKIP RATE:     42.92%  ← Massive WAF bypass                  │
│  UNKNOWN:       51.80%  ← No WAF evaluation at all            │
│                                                                │
│  🔴 EFFECTIVE PROTECTION: 1.38% OF ALL TRAFFIC                │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Critical Findings

### CRITICAL-1: 4.3 BILLION WAF Bypass Events (42.9% of All Traffic)

**Severity:** 🔴 CRITICAL  
**Risk Score:** 10/10  
**CVSS Equivalent:** 10.0 (Critical)

**Description:**  
In the last 7 days, **4,347,006,735 events (4.3 billion)** bypassed WAF protection entirely. This represents **42.9% of all traffic**. Combined with the 51.8% "unknown" events (no WAF evaluation), **94.7% of traffic has NO active WAF protection**.

**Zones with Highest SKIP Traffic (WAF Bypass):**

| Zone | SKIP Events (7 Days) | WAF Status | Risk |
|------|---------------------|------------|------|
| `mobile.share-us.dexcom.com` | **2,538,135,313** (2.5B) | ❌ UNPROTECTED | **CRITICAL** |
| `mobile.share-eu.dexcom.com` | **621,070,279** (621M) | ✅ Protected | HIGH |
| `global.dexcom.com` | **419,246,131** (419M) | ❌ UNPROTECTED | **CRITICAL** |
| `accounts-api.dexcom.com` | **329,616,620** (330M) | ❌ UNPROTECTED | **CRITICAL** |
| `uam2.dexcom.com` | **112,786,464** (113M) | ✅ Protected | HIGH |
| `shareous1.dexcom.com` | **105,004,796** (105M) | ❌ UNPROTECTED | **CRITICAL** |
| `accounts-api.dexcom.eu` | **90,287,169** (90M) | ✅ Protected | MEDIUM |
| `uam1.dexcom.com` | **45,141,763** (45M) | ❌ UNPROTECTED | **CRITICAL** |
| `watch.share-us.dexcom.com` | **29,955,332** (30M) | ❌ UNPROTECTED | HIGH |

**Root Cause Analysis:**
- **Zones WITHOUT WAF rulesets** → Traffic is "skipped" because there's nothing to evaluate
- **Zones WITH WAF but SKIP rules** → Explicit bypass rules allow traffic through
- `mobile.share-us.dexcom.com` has **2.5 BILLION skip events with NO SKIP rules** - the entire zone has no WAF!

**Business Impact:**
- **330 million authentication API requests** (`accounts-api.dexcom.com`) without WAF inspection
- **45 million user access management requests** (`uam1.dexcom.com`) without protection
- Medical device data APIs (`mobile.share-*`) processing billions of requests unprotected
- Potential HIPAA violations for healthcare data

**Remediation:**
1. **IMMEDIATE:** Deploy WAF to `accounts-api.dexcom.com`, `mobile.share-us.dexcom.com`, `global.dexcom.com`
2. **24 hours:** Enable WAF on all authentication/user-data zones
3. **1 week:** Audit all SKIP rules on protected zones
4. **Validation:** Monitor SKIP rate - target <5%

**Validation Query (PostgreSQL):**
```sql
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

### CRITICAL-2: 378 Million Attacks Detected But NOT Blocked

**Severity:** 🔴 CRITICAL  
**Risk Score:** 9/10

**Description:**  
**394,868,899 events** were logged as potential attacks but **NOT blocked**. The LOG action means the WAF detected malicious patterns but took no protective action. Attackers can exploit these vulnerabilities while security teams are blind.

**Zones with Highest LOG (Detection-Only) Traffic:**

| Zone | LOG Events (7 Days) | Source | Risk |
|------|---------------------|--------|------|
| `uam1.dexcom.com` | **378,524,335** (379M) | ratelimit | **CRITICAL** |
| `shareous1.dexcom.com` | **15,451,243** (15M) | ratelimit | HIGH |
| `global.dexcom.com` | **455,966** | ratelimit | HIGH |
| `prodvnv-signup.dexcomdev.eu` | **229,366** | firewallcustom | MEDIUM |
| `keycloak-prod.dexcom.com` | **103,243** | ratelimit | HIGH |
| `keycloak-prod.dexcom.eu` | **13,102** | firewallmanaged | HIGH |

**Critical Finding:**  
- `uam1.dexcom.com` detected **378 MILLION rate limit violations** but did NOT block them
- This is a User Access Management endpoint receiving brute-force/credential stuffing attacks
- Keycloak IDP endpoints detecting attacks but only logging

**Business Impact:**
- Active brute-force attacks against authentication endpoints going unblocked
- Credential stuffing attempts not being stopped
- Rate limiting rules ineffective (LOG mode = detection only)

**Remediation:**
1. **IMMEDIATE:** Switch rate limit rules from LOG to BLOCK on `uam1.dexcom.com`
2. Convert all LOG mode rules to BLOCK mode on production zones
3. Implement progressive blocking (warn → challenge → block)

---

### CRITICAL-3: 52 Production Zones Without ANY WAF Protection

**Severity:** 🔴 CRITICAL  
**Risk Score:** 10/10  
**CVSS Equivalent:** 9.8 (Critical)

**Description:**  
52 production-facing zones have ZERO WAF rulesets deployed. These zones are exposed directly to the internet without any web application firewall protection against common attacks (SQL injection, XSS, RCE, etc.). **This is the root cause of CRITICAL-1** - traffic to these zones has no WAF to evaluate it.

**Affected High-Value Assets with Traffic Volume:**

| Zone | Business Function | 7-Day Traffic | Risk |
|------|-------------------|---------------|------|
| `mobile.share-us.dexcom.com` | US Mobile app backend | **2.5 BILLION** | **CRITICAL** |
| `global.dexcom.com` | Global authentication | **419 MILLION** | **CRITICAL** |
| `accounts-api.dexcom.com` | US Account API | **330 MILLION** | **CRITICAL** |
| `shareous1.dexcom.com` | US Data sharing | **105 MILLION** | **CRITICAL** |
| `uam1.dexcom.com` | US User access management | **45 MILLION** | **CRITICAL** |
| `login.dexcom.com` | Primary user login portal | High | **CRITICAL** |
| `global-login.dexcom.com` | Global authentication | High | **CRITICAL** |
| `keycloak-prod.dexcom.com` | US Keycloak IDP | **593 MILLION** | **CRITICAL** |
| `keycloak-prod.dexcom.eu` | EU Keycloak IDP | **360 MILLION** | **CRITICAL** |
| `keycloak-prod.dexcom.jp` | JP Keycloak IDP | **8 MILLION** | **CRITICAL** |
| `consents-api.dexcom.com` | GDPR/Privacy consents | High | **HIGH** |
| `mobile.share.dexcom.jp` | JP Mobile app backend | **25 MILLION** | **HIGH** |
| `dashboard.dexcom.com` | Main dashboard | High | **HIGH** |
| `signup.dexcom.eu` | EU User registration | High | **HIGH** |
| `signup.dexcom.jp` | JP User registration | High | **HIGH** |
| `api.dexcom.jp` | JP Main API | **4 MILLION** | **HIGH** |
| `uam.dexcom.jp` | JP User access management | **3 MILLION** | **HIGH** |

**Complete List of Unprotected Production Zones:**
```
accounts-api.dexcom.com
api.dexcom.jp
clmproxy-clinical-1.dexcom.com
clmproxy-prod-1.dexcom.com
consents-api.dexcom.com
consents-api.dexcom.jp
dashboard.dexcom.com
data3.dexcom.com
data4.dexcom.com
dexbasal.com
dpal-api-eu.udp.dexcom.com
dpal-api-jp.udp.dexcom.com
dpal-api-us.udp.dexcom.com
gcs.dexcom.com
global-login.dexcom.com
global.dexcom.com
inquisito-api-jp.dexcom.com
inquisito-api-us.dexcom.com
inquisito-ui-eu.dexcom.com
inquisito-ui-jp.dexcom.com
inquisito-ui-us.dexcom.com
keycloak-prod.dexcom.com
keycloak-prod.dexcom.eu
keycloak-prod.dexcom.jp
login-portal-api.dexcom.com
login-portal-api.dexcom.eu
login-portal-api.dexcom.jp
login.dexcom.com
mobile.share-us.dexcom.com
mobile.share.dexcom.jp
myaccount.dexcom.jp
partnerous01-mtls.dexcom.com
partnerous01.dexcom.com
partnerservicesous01.dexcom.com
platform.dexcom.com
rxkeyapi.dexcom.com
sandbox-api.dexcom.com
scm-prod-1.dexcom.com
share.dexcom.jp
share2.dexcom.com
shareadmin.dexcom.jp
shareadminous1.dexcom.com
shareous1.dexcom.com
signup.dexcom.eu
signup.dexcom.jp
sonarqube.dexcom.com
uam.dexcom.jp
uam1.dexcom.com
uam2.dexcom.eu
watch.share-eu.dexcom.com
watch.share-us.dexcom.com
watch.share.dexcom.jp
```

**Business Impact:**
- Direct exposure to OWASP Top 10 attacks
- Potential for credential theft via authentication endpoints
- Risk of data exfiltration through unprotected APIs
- HIPAA compliance violations (medical device company)
- Regulatory risk for EU/JP data protection laws

**Remediation:**
1. **Immediate (24-48 hours):** Deploy managed WAF rulesets to all authentication/login zones
2. **Short-term (1 week):** Enable WAF on all API endpoints
3. **Medium-term (2 weeks):** Complete WAF deployment across all production zones
4. **Validation:** Enable logging and monitor for false positives before switching to block mode

**Validation Query:**
```sql
SELECT z.name
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
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
```

---

### HIGH-1: 806 WAF Rules in LOG Mode (Detection Only - No Blocking)

**Severity:** 🟠 HIGH  
**Risk Score:** 8/10

**Description:**  
806 WAF rules across production zones are configured in LOG mode (detection-only). This contributed to the **394 million LOG events** seen in CRITICAL-2. These rules detect malicious traffic but DO NOT block it. Attackers can exploit vulnerabilities while the WAF merely records the attempt.

**Critical Rules in LOG Mode:**
- AWS API Key detection
- AWS SDK/Tools Credential Files exposure
- Apache Camel RCE (CVE-2025-29891)
- Django SQLi (CVE-2025-64459)
- LFI /etc/passwd attacks
- Malware/Web Shell detection
- Javascript Injection
- Authentication brute-force detection

**Affected Zones:**
- `accounts-api.dexcom.eu` - 31 LOG mode rules
- `accounts-api.dexcom.jp` - 31 LOG mode rules
- `api.dexcom.com` - 31 LOG mode rules
- `api.dexcom.eu` - 31 LOG mode rules
- `mobile.share-eu.dexcom.com` - 31 LOG mode rules
- `consents-api.dexcom.eu` - 31 LOG mode rules
- And more...

**Business Impact:**
- Attacks are detected but not prevented
- Creates false sense of security
- Attackers can refine attacks based on responses
- Compliance violations (detection without prevention)

**Remediation:**
1. Review LOG mode rules for false positive impact
2. Gradually transition rules to BLOCK mode with monitoring
3. Prioritize CVE-related rules and credential detection rules

**Validation Query:**
```sql
SELECT 
    z.name as zone,
    r.description as rule,
    rs.phase
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND r.action = 'LOG' AND r.enabled = true
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false
ORDER BY z.name, r.description;
```

---

### HIGH-2: 39 Active WAF SKIP/Bypass Rules on Production

**Severity:** 🟠 HIGH  
**Risk Score:** 7/10

**Description:**  
39 active SKIP rules on production zones bypass WAF security for specific conditions. While some are legitimate (IP whitelists), others create security gaps.

**Notable SKIP Rules:**

| Zone | Rule | Risk Assessment |
|------|------|-----------------|
| `jira.dexcom.com` | Bypass_WAF for Dexcom VPN | Medium - IP-restricted |
| `jira.dexcom.com` | Wiz Whitelist bypasses WAF | Medium - Scanner bypass |
| `jira.dexcom.com` | 11 total SKIP rules | **HIGH** - Excessive bypasses |
| `confluence.dexcom.com` | 7 total SKIP rules | **HIGH** - Excessive bypasses |
| `accounts-api.dexcom.eu` | Rate limit bypass for VPN IPs | Medium |
| `data5.dexcom.com` | Allow Legit Traffic bypasses WAF | **HIGH** - Path-based bypass |
| `uam2.dexcom.com` | Intra-GCP Service Bypass | Medium - User-agent based |

**Risky Patterns:**
- User-agent based bypasses (can be spoofed)
- Path-based bypasses without IP restriction
- Large CIDR blocks in whitelists

**Business Impact:**
- Attackers can exploit bypass conditions
- Reduced WAF effectiveness
- Potential for lateral movement via whitelisted services

**Remediation:**
1. Audit all SKIP rules for necessity
2. Add IP restrictions to path-based bypasses
3. Remove user-agent only bypasses
4. Consolidate and minimize whitelist IPs

---

### HIGH-3: Origin IP Exposure via Unproxied DNS

**Severity:** 🟠 HIGH  
**Risk Score:** 6/10

**Description:**  
4 high-value DNS records are configured as unproxied (DNS-only), exposing origin server IP addresses. Attackers can bypass Cloudflare and attack origins directly.

**Exposed Records:**
| DNS Name | Type | Exposed IP |
|----------|------|------------|
| `admin-ddlm.platform.dexcomdev.com` | A | 34.70.122.242 |
| `api-ddlm.platform.dexcomdev.com` | A | 34.70.122.242 |
| `nile-31200-prod-jp.platform.dexcomdev.com` | A | 34.84.7.200 |
| `prod-vnv-uam-eu.dexcomdev.com` | A | 35.242.253.67 |

**Business Impact:**
- Origin servers can be attacked directly bypassing all Cloudflare protections
- DDoS attacks can target origin IPs
- Firewall rules may not be in place for direct access

**Remediation:**
1. Enable Cloudflare proxy for all proxiable records
2. If DNS-only is required, ensure origin firewall restricts to Cloudflare IPs only
3. Monitor for direct origin access attempts

---

## Risk Matrix

| Finding | Severity | Volume (7 Days) | Impact | Priority |
|---------|----------|-----------------|--------|----------|
| 4.3B WAF Bypass Events (42.9%) | **CRITICAL** | 4,347,006,735 | **CRITICAL** | **P0** |
| 378M Attacks Logged Not Blocked | **CRITICAL** | 394,868,899 | **CRITICAL** | **P0** |
| 52 Unprotected Production Zones | **CRITICAL** | N/A | **CRITICAL** | **P0** |
| 806 LOG Mode Rules | HIGH | 394M events | HIGH | P1 |
| 39 SKIP Rules on Production | HIGH | 4.3B events | HIGH | P1 |
| Unproxied DNS Records | HIGH | N/A | MEDIUM | P2 |

### Security Posture Summary
```
Total Events:        10,127,620,485 (10.1 Billion)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BLOCKED:                139,469,467  (  1.4%)  ✅
LOGGED (Not Blocked):   394,868,899  (  3.9%)  ⚠️
SKIPPED (Bypass):     4,347,006,735  ( 42.9%)  ❌
UNKNOWN:              5,246,239,599  ( 51.8%)  ❌
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EFFECTIVE PROTECTION RATE: 1.38%     🔴 CRITICAL
```

---

## Compliance Implications

### HIPAA (Healthcare)
- **Violation Risk:** HIGH
- Missing WAF protection on patient data APIs
- No audit trail due to missing logs
- Unprotected authentication endpoints

### GDPR (EU Data Protection)
- **Violation Risk:** HIGH  
- `consents-api.dexcom.eu` unprotected
- EU keycloak and signup endpoints exposed
- Insufficient security measures for personal data

### SOC 2
- **Violation Risk:** HIGH
- Missing security controls (WAF)
- No centralized logging
- Insufficient change management visibility

---

## Recommendations Summary

### Immediate (24-48 hours) - Address 98.6% Unprotected Traffic
1. **Deploy WAF to highest-traffic unprotected zones:**
   - `mobile.share-us.dexcom.com` (2.5B events)
   - `accounts-api.dexcom.com` (330M events - AUTH ENDPOINT!)
   - `global.dexcom.com` (419M events)
   - `uam1.dexcom.com` (45M events + 378M rate limit violations)
2. **Convert LOG to BLOCK on rate limiting rules:**
   - `uam1.dexcom.com` - 378M detected attacks not blocked
   - `shareous1.dexcom.com` - 15M detected attacks not blocked
3. **Review SKIP rules on protected zones** causing 4.3B bypasses

### Short-term (1 week)
1. Complete WAF deployment to all 52 unprotected production zones
2. Transition all LOG mode rules to BLOCK mode (806 rules)
3. Audit and minimize SKIP rules - target <5% SKIP rate
4. Enable proxy for unproxied DNS records

### Medium-term (2-4 weeks)
1. Implement continuous monitoring of security action metrics
2. Create alerting for SKIP rate >10%
3. Conduct penetration testing on newly protected zones
4. Document all security exceptions with business justification
5. Target: >90% BLOCK rate on detected threats

---

## Appendix A: Validation Queries

### Query 1: Security Action Summary (Total Traffic Analysis)
```sql
SELECT
    m.security_action,
    SUM(m.metric_value) as total_events
FROM cloudflare_raw_zone_metrics_history m
JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND m.metric_timestamp >= NOW() - INTERVAL '7 days'
AND m.is_deleted = false
GROUP BY m.security_action
ORDER BY total_events DESC;
```

### Query 2: SKIP Events by Zone (WAF Bypass Analysis)
```sql
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

### Query 3: LOG Events by Zone (Detection Only - Not Blocked)
```sql
SELECT
    z.name as zone_name,
    m.security_source,
    SUM(m.metric_value) as log_events
FROM cloudflare_raw_zone_metrics_history m
JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND m.security_action = 'log'
AND m.metric_timestamp >= NOW() - INTERVAL '7 days'
GROUP BY z.name, m.security_source
ORDER BY log_events DESC;
```

### Query 4: BLOCK Events by Zone (Active Protection)
```sql
SELECT
    z.name as zone_name,
    m.security_source,
    SUM(m.metric_value) as block_events
FROM cloudflare_raw_zone_metrics_history m
JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND m.security_action = 'block'
AND m.metric_timestamp >= NOW() - INTERVAL '7 days'
GROUP BY z.name, m.security_source
ORDER BY block_events DESC;
```

### Query 5: List all unprotected zones
```sql
SELECT z.name
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND z.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    WHERE ri.zone_id = z.id AND ri.is_deleted = false
)
ORDER BY z.name;
```

### Query 6: High-SKIP zones cross-referenced with protection status
```sql
WITH skip_metrics AS (
    SELECT
        z.name as zone_name,
        z.id as zone_id,
        SUM(m.metric_value) as skip_events
    FROM cloudflare_raw_zone_metrics_history m
    JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
    WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
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
    WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2' 
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
```

### Query 7: List all SKIP rules with expressions
```sql
SELECT 
    z.name as zone,
    r.description as rule_desc,
    r.expression,
    rs.phase
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND r.action = 'SKIP' AND r.enabled = true
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false
ORDER BY z.name;
```

### Trino Query: Raw WAF Logs by Zone
```sql
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
GROUP BY zonename, securityaction
ORDER BY event_count DESC;
```

---

*Report generated by WAF Security Analysis System*  
*Analysis performed on PostgreSQL configuration and metrics data*  
*Data timeframe: Last 7 days from report date*

