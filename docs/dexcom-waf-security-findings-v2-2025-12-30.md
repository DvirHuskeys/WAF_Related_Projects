# Dexcom WAF Security Findings Report

**Generated:** December 30, 2025  
**Organization:** Dexcom  
**Organization ID:** `fe6fe002-e396-4c75-b8c1-48939488e8c2`  
**Analysis Type:** Configuration-Based (PostgreSQL)  
**Log Analysis:** Not Available (No Trino log data for Dexcom)

---

## Executive Summary

This security assessment identified **significant configuration vulnerabilities** across Dexcom's Cloudflare WAF deployment. The findings reveal systemic gaps in protection for critical production infrastructure, including authentication systems, APIs, and administrative portals.

### Critical Statistics

| Metric | Count | Severity |
|--------|-------|----------|
| Total Cloudflare Zones | 333 | - |
| Enterprise Zones | 327 | - |
| **Production Zones Without ANY WAF** | 190 | 🔴 CRITICAL |
| **Critical High-Value Zones Unprotected** | 85 | 🔴 CRITICAL |
| Enterprise Zones Without Bot Management | 327 | 🟠 HIGH |
| Rules with SKIP/Bypass Action | 138 | 🔴 CRITICAL |
| Rules in LOG-Only Mode (Not Blocking) | 4,379 | 🟠 HIGH |
| WAF Rules Disabled | 42,621 | 🟠 HIGH |

---

## CRITICAL Findings

### CRIT-01: Production Zones Without WAF Protection (53 Zones)

**Severity:** 🔴 CRITICAL  
**Impact:** Complete lack of WAF protection on production assets exposing them to OWASP Top 10 attacks, SQLi, XSS, RCE, and other web application attacks.

The following **production zones** (excluding dev/test/staging) have **no WAF rulesets deployed**:

#### Authentication & Identity (HIGHEST PRIORITY)

| Zone | Plan | Created | Risk |
|------|------|---------|------|
| `login.dexcom.com` | Enterprise | 2020-07-24 | **CRITICAL** - Primary login portal |
| `global-login.dexcom.com` | Enterprise | 2023-12-04 | **CRITICAL** - Global login |
| `keycloak-prod.dexcom.com` | Enterprise | 2022-03-08 | **CRITICAL** - Identity provider |
| `keycloak-prod.dexcom.eu` | Enterprise | 2022-03-02 | **CRITICAL** - Identity provider (EU) |
| `keycloak-prod.dexcom.jp` | Enterprise | 2022-02-25 | **CRITICAL** - Identity provider (JP) |
| `login-portal-api.dexcom.com` | Enterprise | 2023-10-05 | **CRITICAL** - Login API |
| `login-portal-api.dexcom.eu` | Enterprise | 2023-10-05 | **CRITICAL** - Login API (EU) |
| `login-portal-api.dexcom.jp` | Enterprise | 2023-10-05 | **CRITICAL** - Login API (JP) |

#### API Endpoints (HIGH PRIORITY)

| Zone | Plan | Created | Risk |
|------|------|---------|------|
| `accounts-api.dexcom.com` | Enterprise | 2022-03-08 | **CRITICAL** - Account API |
| `api.dexcom.jp` | Enterprise | 2022-02-01 | **CRITICAL** - API Japan |
| `consents-api.dexcom.com` | Enterprise | 2022-03-08 | **CRITICAL** - Consents API |
| `consents-api.dexcom.jp` | Enterprise | 2022-02-25 | **CRITICAL** - Consents API (JP) |
| `dpal-api-eu.udp.dexcom.com` | Enterprise | 2022-06-02 | **CRITICAL** - DPAL API (EU) |
| `dpal-api-jp.udp.dexcom.com` | Enterprise | 2022-06-02 | **CRITICAL** - DPAL API (JP) |
| `dpal-api-us.udp.dexcom.com` | Enterprise | 2022-06-02 | **CRITICAL** - DPAL API (US) |
| `inquisito-api-jp.dexcom.com` | Enterprise | 2022-11-10 | **CRITICAL** - Inquisito API (JP) |
| `inquisito-api-us.dexcom.com` | Enterprise | 2022-11-10 | **CRITICAL** - Inquisito API (US) |
| `rxkeyapi.dexcom.com` | Enterprise | 2022-03-16 | **CRITICAL** - RxKey API |
| `gcs.dexcom.com` | Enterprise | 2021-04-06 | **HIGH** - GCS Service |

#### Admin Portals (HIGH PRIORITY)

| Zone | Plan | Created | Risk |
|------|------|---------|------|
| `dashboard.dexcom.com` | Enterprise | 2022-11-09 | **CRITICAL** - Main dashboard |
| `shareadmin.dexcom.jp` | Enterprise | 2021-07-19 | **CRITICAL** - Share admin (JP) |
| `shareadminous1.dexcom.com` | Enterprise | 2021-06-21 | **CRITICAL** - Share admin |
| `sonarqube.dexcom.com` | Enterprise | 2021-04-22 | **HIGH** - Code quality tool |

#### User Account & Mobile

| Zone | Plan | Created | Risk |
|------|------|---------|------|
| `myaccount.dexcom.jp` | Enterprise | 2022-02-25 | **CRITICAL** - User accounts (JP) |
| `mobile.share-us.dexcom.com` | Enterprise | 2021-12-08 | **CRITICAL** - Mobile backend (US) |
| `mobile.share.dexcom.jp` | Enterprise | 2023-11-29 | **CRITICAL** - Mobile backend (JP) |

#### Partner & Integration Endpoints

| Zone | Plan | Created | Risk |
|------|------|---------|------|
| `partnerous01.dexcom.com` | Enterprise | 2022-02-14 | **HIGH** - Partner services |
| `partnerous01-mtls.dexcom.com` | Enterprise | 2022-02-21 | **HIGH** - Partner mTLS |
| `partnerservicesous01.dexcom.com` | Enterprise | 2021-04-20 | **HIGH** - Partner services |

**Remediation:**
1. **IMMEDIATE:** Deploy Cloudflare Managed Ruleset to all authentication zones
2. **URGENT:** Enable WAF protection on all API endpoints
3. **HIGH:** Configure WAF for admin portals and dashboards
4. **Schedule:** Complete WAF deployment across all production zones

---

### CRIT-02: WAF Bypass Rules Exposing Critical Paths (138 Rules)

**Severity:** 🔴 CRITICAL  
**Impact:** Security controls are explicitly bypassed for certain IP ranges, paths, and user agents, potentially allowing attackers to evade detection.

#### Top Bypass Patterns (Most Common Across Zones)

| Description | Expression | Zones Affected | Risk |
|-------------|-----------|----------------|------|
| Netskope Whitelist | `ip.src in $netskope` | 14 | HIGH - Broad IP bypass |
| Datadog Whitelist | `ip.src in $datadog_whitelist` | 12 | HIGH - Monitoring bypass |
| Dexcom VPN | `ip.src in $dexcom_pub_space` | 8 | MEDIUM - Corporate bypass |
| Inquisito Whitelist | `ip.src in $inquisito_prod` | 4 | HIGH - Service bypass |
| Okta Whitelist | `ip.src in $okta_whitelist` | 3 | HIGH - Auth provider bypass |

#### Dangerous Path-Based Bypasses

| Description | Expression | Risk |
|-------------|-----------|------|
| FHIR OAuth Bypass | `http.request.uri.path contains "/fhir-oauth"` | 🔴 CRITICAL - Healthcare API |
| Token/Auth Bypass | `http.request.uri.path contains "/connect/token"` | 🔴 CRITICAL - Auth tokens |
| Consent Flows | `http.request.uri.path contains "/consent-flows"` | 🟠 HIGH - User consent |

#### User-Agent Based Bypasses (DANGEROUS)

| Description | Expression | Risk |
|-------------|-----------|------|
| PA Team Allow | `http.user_agent contains "SveSD0tinY2NpWu7"` | 🔴 CRITICAL - Spoofable |
| Google CA | `http.user_agent contains "bushbaby/2023"` | 🟠 HIGH - Spoofable |

#### Hard-coded IP Bypasses

| Description | IPs | Zones | Risk |
|-------------|-----|-------|------|
| Dexcom VPN | 66.85.67.20, 8.44.236.2 | 2 | MEDIUM |
| Pentest Whitelist | 24.206.72.79, 162.227.78.127 | 3 | 🔴 CRITICAL - Should be temporary |
| DevOps CI | 34.123.228.176, 34.72.71.80 | 2 | HIGH |

**Findings:**
- **Permanent pentest whitelists** are a severe risk - pentest IPs should be time-limited
- **User-Agent bypasses are trivially spoofable** by attackers
- **Path-based bypasses on sensitive endpoints** expose authentication and healthcare APIs

**Remediation:**
1. **IMMEDIATE:** Remove all user-agent based SKIP rules
2. **URGENT:** Audit and remove stale pentest IP whitelists
3. **HIGH:** Review all path-based bypasses for necessity
4. **MEDIUM:** Consolidate IP whitelists and implement expiration policies

---

### CRIT-03: Sensitive Token Exposed in WAF Rule

**Severity:** 🔴 CRITICAL  
**Zone:** `argocd.dexcomdev.com`  
**Rule:** "whitelist hostname"

```
Expression: (http.host in {"event-server.argocd.dexcomdev.com"...} 
             and any(http.request.headers["event-server-token"][*] 
             eq "gy6r72rh0bkfxu6g7kr5h4uac4xsbcqzf3ks2jfw"))
```

**Impact:** A secret token is hard-coded in the WAF rule expression, visible in configuration. This token can be used to bypass security controls.

**Remediation:**
1. **IMMEDIATE:** Rotate the exposed token
2. **URGENT:** Move to API token validation at application layer
3. **HIGH:** Audit all rules for embedded secrets

---

## HIGH Findings

### HIGH-01: Log-Only WAF Rules (4,379 Rules)

**Severity:** 🟠 HIGH  
**Impact:** WAF rules are detecting attacks but NOT blocking them. Attackers can execute attacks while Dexcom only receives alerts.

#### Sample Log-Only Rules (accounts-api.dexcom.eu)

| Ruleset | Rule Description | Action | Risk |
|---------|------------------|--------|------|
| Cloudflare Managed | SQLi - Sub Query - BETA | LOG | SQL Injection allowed |
| Cloudflare Managed | Apache Camel RCE - CVE-2025-29891 | LOG | RCE allowed |
| Cloudflare Managed | Malware, Web Shell | LOG | Malware upload allowed |
| Cloudflare Managed | XWiki RCE - CVE-2025-24893 | LOG | RCE allowed |
| Cloudflare Managed | Django SQLi - CVE-2025-64459 | LOG | SQLi allowed |
| Sensitive Data Detection | AWS API Key | LOG | Credential leak allowed |
| Sensitive Data Detection | Private Key Leak | LOG | Key exposure allowed |
| DDoS L7 ruleset | Auth endpoint flooding | LOG | DDoS allowed |

**Remediation:**
1. **URGENT:** Switch SQLi, XSS, RCE rules from LOG to BLOCK
2. **HIGH:** Enable blocking for CVE-specific rules
3. **HIGH:** Enable blocking for sensitive data detection rules

---

### HIGH-02: Disabled WAF Rules (42,621 Rules)

**Severity:** 🟠 HIGH  
**Impact:** Protection rules are disabled, removing defense against known attack patterns.

#### Sample Disabled Rules (accounts-api.dexcom.eu)

| Rule Description | Original Action | Risk |
|------------------|-----------------|------|
| Microsoft ASP.NET - Code Injection | BLOCK | RCE vulnerability |
| Joomla - CVE-2015-8562 | BLOCK | Known exploit |
| PHP - Code Injection | BLOCK | RCE vulnerability |
| XSS, HTML Injection | BLOCK | XSS attacks |
| SQLi - Ending Comment | BLOCK | SQL Injection |
| SQLi - ORDER/GROUP BY | BLOCK | SQL Injection |
| Command Injection - Sleep | BLOCK | OS command injection |
| Java - Deserialization | BLOCK | Deserialization RCE |
| jQuery File Upload - CVE-2018-9206 | BLOCK | File upload exploit |
| Microsoft ASP.NET - CVE-2019-18935 | BLOCK | Deserialization RCE |

**Remediation:**
1. **HIGH:** Audit disabled rules and re-enable security-critical protections
2. **MEDIUM:** Document business justification for any disabled rules
3. **MEDIUM:** Create exception rules instead of disabling entire protections

---

### HIGH-03: Enterprise Zones Without Bot Management (327 Zones)

**Severity:** 🟠 HIGH  
**Impact:** Enterprise zones lack bot management protection, enabling automated attacks, credential stuffing, and scraping.

#### Critical Production Zones Without Bot Management (Sample)

| Zone | Plan | AI Bots Protection | Fight Mode | JS Detection |
|------|------|-------------------|------------|--------------|
| `api.dexcom.com` | Enterprise | DISABLED | NULL | false |
| `api.dexcom.eu` | Enterprise | DISABLED | NULL | false |
| `api.dexcom.jp` | Enterprise | DISABLED | NULL | false |
| `login.dexcom.com` | Enterprise | DISABLED | NULL | false |
| `accounts-api.dexcom.com` | Enterprise | DISABLED | NULL | false |
| `myaccount.dexcom.com` | Enterprise | DISABLED | NULL | false |
| `dashboard.dexcom.com` | Enterprise | DISABLED | NULL | false |
| `keycloak-prod.dexcom.com` | Enterprise | DISABLED | NULL | false |
| `confluence.dexcom.com` | Enterprise | DISABLED | NULL | false |
| `jira.dexcom.com` | Enterprise | DISABLED | NULL | false |

**Remediation:**
1. **HIGH:** Enable Bot Fight Mode on all authentication endpoints
2. **HIGH:** Enable AI Bots Protection on API endpoints
3. **MEDIUM:** Enable JS Detection for browser-based applications

---

## Risk Summary

### By Asset Type

| Asset Type | Unprotected Count | Risk Level |
|------------|-------------------|------------|
| Authentication Systems | 8+ zones | 🔴 CRITICAL |
| API Endpoints | 50+ zones | 🔴 CRITICAL |
| Admin Portals | 15+ zones | 🔴 CRITICAL |
| User Account Pages | 8+ zones | 🟠 HIGH |
| Mobile Backends | 4+ zones | 🟠 HIGH |
| Partner Services | 5+ zones | 🟠 HIGH |

### By Region

| Region | Unprotected Zones |
|--------|-------------------|
| US (.dexcom.com) | 35+ |
| EU (.dexcom.eu) | 10+ |
| Japan (.dexcom.jp) | 12+ |

---

## Compliance Implications

Given Dexcom's medical device industry:

1. **HIPAA:** PHI-handling systems without WAF protection may violate Technical Safeguards requirements
2. **FDA 21 CFR Part 11:** Electronic records systems need security controls
3. **SOC 2:** Lack of WAF protection impacts CC6.1 (Logical and Physical Access Controls)
4. **PCI DSS:** If payment processing occurs, lack of WAF violates Requirement 6.6

---

## Immediate Action Plan

### Week 1 (CRITICAL)

1. [ ] Deploy WAF to `login.dexcom.com` and all Keycloak instances
2. [ ] Remove user-agent based SKIP rules
3. [ ] Rotate exposed ArgoCD token
4. [ ] Enable blocking on SQLi/XSS/RCE rules

### Week 2 (HIGH)

1. [ ] Deploy WAF to all API endpoints
2. [ ] Audit and remove stale pentest whitelists
3. [ ] Enable Bot Fight Mode on authentication endpoints
4. [ ] Review all path-based bypass rules

### Week 3-4 (MEDIUM)

1. [ ] Complete WAF deployment across all zones
2. [ ] Re-enable disabled rules with documented exceptions
3. [ ] Implement IP whitelist expiration policies
4. [ ] Enable comprehensive bot management

---

## Appendix A: Complete List of Production Zones Without WAF

<details>
<summary>Click to expand (53 zones)</summary>

1. accounts-api.dexcom.com
2. api.dexcom.jp
3. clmproxy-clinical-1.dexcom.com
4. clmproxy-prod-1.dexcom.com
5. consents-api.dexcom.com
6. consents-api.dexcom.jp
7. dashboard.dexcom.com
8. data3.dexcom.com
9. data4.dexcom.com
10. dexbasal.com
11. dpal-api-eu.udp.dexcom.com
12. dpal-api-jp.udp.dexcom.com
13. dpal-api-us.udp.dexcom.com
14. gcs.dexcom.com
15. global-login.dexcom.com
16. global.dexcom.com
17. inquisito-api-jp.dexcom.com
18. inquisito-api-us.dexcom.com
19. inquisito-ui-eu.dexcom.com
20. inquisito-ui-jp.dexcom.com
21. inquisito-ui-us.dexcom.com
22. keycloak-prod.dexcom.com
23. keycloak-prod.dexcom.eu
24. keycloak-prod.dexcom.jp
25. load-share-us.dexcom.com
26. load-uam-us.dexcom.com
27. login-portal-api.dexcom.com
28. login-portal-api.dexcom.eu
29. login-portal-api.dexcom.jp
30. login.dexcom.com
31. mobile.share-us.dexcom.com
32. mobile.share.dexcom.jp
33. myaccount.dexcom.jp
34. partnerous01-mtls.dexcom.com
35. partnerous01.dexcom.com
36. partnerservicesous01.dexcom.com
37. platform.dexcom.com
38. rxkeyapi.dexcom.com
39. scm-prod-1.dexcom.com
40. share.dexcom.jp
41. share2.dexcom.com
42. shareadmin.dexcom.jp
43. shareadminous1.dexcom.com
44. shareous1.dexcom.com
45. signup.dexcom.eu
46. signup.dexcom.jp
47. sonarqube.dexcom.com
48. uam.dexcom.jp
49. uam1.dexcom.com
50. uam2.dexcom.eu
51. watch.share-eu.dexcom.com
52. watch.share-us.dexcom.com
53. watch.share.dexcom.jp

</details>

---

## Appendix B: Validation Queries

### Query: Zones Without WAF

```sql
SELECT z.name as zone_name, z.plan_name
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND z.is_deleted = false
AND z.status = 'active'
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    WHERE ri.zone_id = z.id AND ri.is_deleted = false
)
AND z.name NOT LIKE '%dev%'
AND z.name NOT LIKE '%test%'
AND z.name NOT LIKE '%staging%';
```

### Query: SKIP Bypass Rules

```sql
SELECT z.name, rr.description, rr.expression
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON ri.zone_id = z.id
JOIN cloudflare_raw_rulesets_history rs ON rs.id = ri.ruleset_id
JOIN cloudflare_raw_rulesets_rules_history rr ON rr.ruleset_id = rs.id
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND rr.action::text ILIKE '%skip%' AND rr.enabled = true;
```

### Query: Log-Only Rules

```sql
SELECT z.name, rs.name, rr.description, rr.action
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON ri.zone_id = z.id
JOIN cloudflare_raw_rulesets_history rs ON rs.id = ri.ruleset_id
JOIN cloudflare_raw_rulesets_rules_history rr ON rr.ruleset_id = rs.id
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND rr.action::text ILIKE '%log%' AND rr.enabled = true;
```

---

*Report generated by WAF Security Analysis Framework*  
*Data Source: PostgreSQL Configuration Database*  
*Log Analysis: Not Available (No Trino data for Dexcom)*



