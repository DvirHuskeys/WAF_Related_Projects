# Quillbot WAF Security Analysis Report

**Customer:** Quillbot  
**Analysis Date:** 2026-01-26  
**Data Source:** Postgres (Cloudflare Configuration Data)  
**Report Type:** Comprehensive Security Analysis  

---

## Executive Summary

This report provides a comprehensive security analysis of Quillbot's WAF configuration based on Postgres data. **Critical Note:** Trino traffic logs tables (`quillbot_waf_logs`, `quillbot_waf_logs_rcloned`, `quillbot_waf_logs_huskeys_copy`) were found to be **empty** in the staging environment, so this analysis focuses on configuration-based security assessment.

### Key Findings Overview

| Severity | Finding | Count |
|----------|---------|-------|
| **CRITICAL** | Internal Tools Exposed with Security Bypasses | 3 |
| **HIGH** | Excessive WAF SKIP Rules (Security Bypasses) | 40 |
| **HIGH** | WordPress Admin XSS Vector | 1 |
| **MEDIUM** | Rate Limiting Disabled on Dev Domain | 1 |
| **MEDIUM** | Bot Detection Bypasses | 4 |
| **LOW** | Outdated IP Blocklist | 1 |
| **INFO** | Free Plan Zone (quillbot.chat) | 1 |

---

## 1. Zone Inventory

### Active Zones

| Domain | Plan | Status | Created | Security Level |
|--------|------|--------|---------|----------------|
| **quillbot.com** | Enterprise Website | Active | 2018-04-15 | Full |
| **quillbot.dev** | Enterprise Website | Active | 2020-07-08 | Full |
| **quillbot.chat** | **Free Website** | Active | 2024-02-10 | Limited |

**Concern:** `quillbot.chat` is on the Free plan with significantly reduced security capabilities compared to Enterprise zones.

### Zone IDs

| Zone | Cloudflare ID |
|------|---------------|
| quillbot.com | `97237f9c5fec438a430693b274c0a4af` |
| quillbot.dev | `fee421eca7ffe1e78f3d319f8f175b76` |
| quillbot.chat | `0da2bef15056c2fdf4008c23ef057962` |

---

## 2. CRITICAL: Internal Tools Exposed with Security Bypasses

### Finding Description
Multiple internal/administrative tools are exposed to the public internet with WAF security rules explicitly bypassed.

### Affected Hosts

| Host | Tool Type | Risk |
|------|-----------|------|
| `bi.quillbot.com` | **Apache Superset (BI Dashboard)** | Database access, sensitive analytics |
| `datahub.quillbot.com` | **LinkedIn DataHub** | Data governance, metadata |
| `cgs-autocite-api.quillbot.com` | Citation API | API abuse potential |
| `stage-cgs-autocite-api.quillbot.com` | Staging Citation API | Potential staging data leaks |

### Evidence - Active SKIP Rules

```sql
-- bi.quillbot.com - Superset BI Tool
action: SKIP
description: "Allow Superset"
expression: (http.host eq "bi.quillbot.com")
enabled: true

-- datahub.quillbot.com - DataHub
action: SKIP
description: "Allow datahub.quillbot.com"
expression: (http.host eq "datahub.quillbot.com")
enabled: true
```

### Impact
- **Superset** may expose:
  - Database connection strings
  - SQL queries and results
  - Business intelligence dashboards
  - Potentially sensitive user analytics

- **DataHub** may expose:
  - Data lineage information
  - Schema documentation
  - Data governance policies
  - Internal data catalog

### Recommendation
1. **Immediately review** public accessibility of these tools
2. Implement **IP-based restrictions** (VPN/corporate IPs only)
3. Add **authentication requirements** at the WAF level
4. Consider moving these to **internal-only DNS**

---

## 3. HIGH: Excessive WAF SKIP Rules

### Finding Description
**40 active SKIP rules** are configured that bypass security controls across multiple hosts and paths.

### Rule Distribution

| Action | Enabled | Count |
|--------|---------|-------|
| **SKIP** | **Yes** | **40** |
| SKIP | No | 15 |
| REWRITE | Yes | 18 |
| LOG | Yes | 6 |
| BLOCK | Yes | 5 |
| JS_CHALLENGE | Yes | 3 |

### Most Concerning SKIP Rules

#### 3.1 WordPress Admin XSS Bypass (HIGH)
```sql
description: "Allow script tag in wordpress wp-admin post request"
expression: (http.request.uri.path contains "/blog/wp-admin/" and http.host eq "quillbot.com")
action: SKIP
enabled: true
```
**Risk:** Explicitly allows script tags in WordPress admin - potential stored XSS vector.

#### 3.2 Bot Detection Complete Bypass (HIGH)
```sql
description: "Skip Bot detection and by pass all rule (extension)"
expression: (http.request.uri.path eq "/" and http.host contains "stream.quillbot.com") or (http.request.uri.path eq "/com.quillbot.extension")
action: SKIP
enabled: true
```
**Risk:** Complete WAF bypass for specific paths - can be exploited for scraping/abuse.

#### 3.3 Rate Limiting Disabled on Dev (MEDIUM)
```sql
description: "Disable rate limit quillbot.dev"
expression: (http.host contains "quillbot.dev") or (http.host eq "perf-ratelimit.quillbot.dev")
action: SKIP
enabled: true
```
**Risk:** Entire development domain exposed to rate-based attacks.

#### 3.4 PostmanRuntime User-Agent Bypass (MEDIUM)
```sql
description: "allow qa postman request"
expression: (http.user_agent contains "PostmanRuntime" and http.host eq "stage.quillbot.com")
action: SKIP
enabled: true
```
**Risk:** Attackers can spoof this user-agent to bypass WAF on staging.

### Complete List of Active SKIP Rule Targets

| Target | Rule Description |
|--------|------------------|
| `bi.quillbot.com` | Allow Superset |
| `datahub.quillbot.com` | Allow datahub.quillbot.com |
| `libs.quillbot.com` | Allow libs.quillbot.com |
| `assets.quillbot.com` | Allow assets |
| `media.quillbot.com` | Allow media |
| `rest.quillbot.com` | Allow OPTIONS requests |
| `stage.quillbot.com` | PostmanRuntime bypass |
| `stream.quillbot.com` | Bot detection bypass |
| `styleq.quillbot.dev` | Allow styleq |
| `docs.quillbot.dev` | Allow docs |
| `cke-dev.quillbot.dev` | WebSocket bypass |
| `*.quillbot.dev` | Rate limiting disabled |
| `/blog/wp-admin/` | Script tag allowance |
| `stage-cke.quillbot.com` | Bot detection disabled |
| `cgs-autocite-api.quillbot.com` | Citation API bypass |

---

## 4. Managed Rulesets Deployed

### Rulesets per Zone

| Ruleset | quillbot.com | quillbot.dev | quillbot.chat |
|---------|--------------|--------------|---------------|
| Cloudflare Managed Ruleset | Yes | Yes | Yes |
| OWASP Core Ruleset | Yes | Yes | Yes |
| DDoS L7 Ruleset | Yes | Yes | Yes |
| Exposed Credentials Check | Yes | Yes | Yes |
| Cloudflare Normalization | Yes | Yes | Yes |
| Cloudflare Managed Free | Yes | Yes | Yes |

**Positive:** All managed rulesets are deployed across zones.

---

## 5. IP Lists Analysis

### Active Lists

| List Name | Type | Items | Purpose |
|-----------|------|-------|---------|
| gitlabrunner_allow | IP | 70 | GitLab CI/CD runners |
| circleci_ips | IP | 44 | CircleCI CI/CD |
| ip_block_carding | IP | 9 | Carding attack block |
| ip_block_20201222 | IP | 8 | Historical block (2020) |
| seo_urls_redirect | REDIRECT | 8 | SEO redirects |
| scribbrteam | IP | 1 | Partner access |
| cw_share_spam_ip | IP | 0 | Spam prevention (empty) |

### Concerns

1. **Outdated Blocklist:** `ip_block_20201222` dates from December 2020 - 5+ years old
2. **Empty List:** `cw_share_spam_ip` has 0 items - potentially unused
3. **Large CI/CD Allowlists:** 114 combined IPs for CI/CD - verify these are still needed

### IP Block Details

```
ip_block_20201222 (Potentially Stale):
- 141.98.103.162
- 213.248.112.2
- 213.248.112.6
- 213.248.112.38
- 217.212.244.67
```

### IP Block - Carding Prevention
```
ip_block_carding (9 IPs):
- Active protection against payment fraud
```

---

## 6. Rate Limiting Configuration

### Active Rate Limit Rules

```sql
description: "Rate limit rules - Non API (Route path 15 QPS)"
expression: (http.host eq "quillbot.com" and not cf.bot_management.verified_bot 
             and not starts_with(http.request.uri.path, "/api") 
             and not starts_with(http.request.uri.path, "/blog")
             and not http.request.uri.path matches "(.*)(css|js|jpeg|ico|json|png|jpg)$"
             and not http.request.uri.path matches "^/(locales|__/auth)/")
action: JS_CHALLENGE
enabled: true
```

### Rate Limiting Gaps

| Host | Rate Limit Status | Risk |
|------|-------------------|------|
| `quillbot.com` (main) | Partially applied | Medium |
| `quillbot.dev` | **Disabled** | High |
| `/api/*` endpoints | Excluded | Medium |
| `/blog/*` | Excluded | Low |
| Static assets | Excluded | None |

**Concern:** API endpoints are excluded from rate limiting - potential for API abuse.

---

## 7. Bot Management Analysis

### Bot-Related Rules

| Rule | Action | Status |
|------|--------|--------|
| Block bot request on partner sites | LOG (not BLOCK) | Enabled |
| Disable bot for stage-cke | SKIP | Enabled |
| Skip Bot detection (extension) | SKIP | Enabled |

### Concern: Partner Sites Only Logging Bots
```sql
description: "Block bot request on partner sites"
expression: (cf.client.bot and http.host contains "quillbot.scribbr.") or 
            (cf.client.bot and http.host eq "qb.coursehero.com")
action: LOG  -- NOT BLOCK!
enabled: true
```

**Issue:** Rule description says "Block" but action is only "LOG" - bots are not actually being blocked on partner sites.

---

## 8. Anomalous Behaviors to Alert Upon

Based on this configuration analysis, the following behaviors should trigger alerts:

### 8.1 Security Bypass Attempts

| Alert | Expression | Severity |
|-------|------------|----------|
| PostmanRuntime on production | `http.user_agent contains "PostmanRuntime" AND http.host eq "quillbot.com"` | HIGH |
| Script injection in WordPress | `http.request.body contains "<script" AND http.host eq "quillbot.com"` | CRITICAL |
| Direct access to internal tools | `http.host IN ("bi.quillbot.com", "datahub.quillbot.com") AND NOT ip.src in $internal` | HIGH |

### 8.2 Attack Pattern Detection

| Alert | Pattern | Severity |
|-------|---------|----------|
| Path traversal attempts | `http.request.uri contains "../" OR http.request.uri contains "%2e%2e"` | HIGH |
| SQL injection in API | `http.request.uri.path starts_with "/api" AND (http.request.body contains "UNION" OR "SELECT" OR "DROP")` | CRITICAL |
| XSS attempts | `http.request.body contains "<script" OR "javascript:" OR "onerror="` | HIGH |
| Rate abuse (>100 req/min/IP) | IP exceeds threshold on unprotected endpoints | MEDIUM |

### 8.3 Bot/Scraper Detection

| Alert | Pattern | Severity |
|-------|---------|----------|
| Known scanner UA | `http.user_agent contains "Nuclei" OR "sqlmap" OR "nikto"` | HIGH |
| Rapid endpoint enumeration | Same IP hits >50 unique paths in 5 minutes | MEDIUM |
| Low bot score + high volume | `cf.bot_management.score < 30 AND request_count > 100` | HIGH |

### 8.4 Geographic Anomalies

| Alert | Pattern | Severity |
|-------|---------|----------|
| Traffic from unexpected regions | Requests from countries outside normal user base | MEDIUM |
| High-risk country surge | >100 requests from known attack sources | HIGH |

---

## 9. Recommendations Summary

### Immediate Actions (Critical)

| # | Action | Priority |
|---|--------|----------|
| 1 | Restrict access to `bi.quillbot.com` (Superset) to internal IPs only | **CRITICAL** |
| 2 | Restrict access to `datahub.quillbot.com` to internal IPs only | **CRITICAL** |
| 3 | Review WordPress XSS bypass rule - consider removal or stricter conditions | **HIGH** |
| 4 | Change partner bot rule from LOG to BLOCK | **HIGH** |

### Short-Term (1-2 Weeks)

| # | Action | Priority |
|---|--------|----------|
| 5 | Audit all 40 SKIP rules - remove unnecessary bypasses | HIGH |
| 6 | Implement rate limiting on API endpoints | HIGH |
| 7 | Enable rate limiting on `quillbot.dev` with appropriate thresholds | MEDIUM |
| 8 | Review and update `ip_block_20201222` list | MEDIUM |

### Medium-Term (1 Month)

| # | Action | Priority |
|---|--------|----------|
| 9 | Implement proper alerting for anomalous patterns listed above | HIGH |
| 10 | Upgrade `quillbot.chat` to at least Pro plan for better protection | MEDIUM |
| 11 | Implement Bot Management Score-based rules | MEDIUM |
| 12 | Set up regular security configuration audits | LOW |

---

## 10. Appendix: Data Availability

### Trino Data Status

| Table | Status | Note |
|-------|--------|------|
| `quillbot_waf_logs` | **EMPTY** | No traffic data available |
| `quillbot_waf_logs_rcloned` | **EMPTY** | No traffic data available |
| `quillbot_waf_logs_huskeys_copy` | **EMPTY** | No traffic data available |

**Impact:** Traffic-based analysis (attack patterns, geographic distribution, user agent analysis) could not be performed. This report focuses on configuration-based security assessment.

### Postgres Data Used

| Table | Records Analyzed |
|-------|------------------|
| `cloudflare_raw_zones_history` | 3 zones |
| `cloudflare_raw_rulesets_rules_history` | 88 rules |
| `cloudflare_raw_rulesets_instance_history` | 30 instances |
| `cloudflare_raw_lists_history` | 7 lists |
| `cloudflare_raw_list_items_history` | 50+ items |

---

## 11. Report Metadata

| Field | Value |
|-------|-------|
| Report Generated | 2026-01-26 |
| Analysis Method | Postgres Configuration Analysis |
| Trino Traffic Data | Not Available |
| Analyst | AI Security Analysis Agent |
| Next Review | When Trino data becomes available |

---

**END OF REPORT**
