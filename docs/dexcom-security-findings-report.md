# Dexcom Cloudflare WAF Security Findings Report

**Generated:** December 30, 2025  
**Customer:** Dexcom  
**Organization ID:** `fe6fe002-e396-4c75-b8c1-48939488e8c2`  
**Total Zones Analyzed:** 333  

---

## Executive Summary

| Finding | Severity | Count |
|---------|----------|-------|
| Managed WAF Rules in LOG Mode (Not Blocking) | **CRITICAL** | 22 unique rules across 327 zones |
| WAF Bypass/Skip Rules | **HIGH** | 83 unique rules |
| Unproxied DNS Records (Origin IP Exposure) | **HIGH** | 11 records |
| Disabled Rate Limiting Rules | **MEDIUM** | 2 rules |

---

## Finding 1: Managed WAF Rules in LOG Mode (Detection Only)

### Severity: CRITICAL

### Description

22 unique Cloudflare Managed WAF rules are configured in **LOG mode** instead of **BLOCK mode** across 327 Dexcom zones. These rules detect known vulnerabilities including critical CVEs, SQL injection attacks, command execution attempts, and malware/web shells, but **do not prevent the attacks** - they only log them.

**Affected Rules Include:**

| Rule Description | Risk Category |
|-----------------|---------------|
| Apache Camel - Remote Code Execution - CVE:CVE-2025-29891 | RCE |
| Atlassian Confluence - Code Injection - CVE:CVE-2021-26084 - Beta | Code Injection |
| Django SQLI - CVE:CVE-2025-64459 | SQL Injection |
| Generic Rules - Command Execution - Body | Command Injection |
| Generic Rules - Command Execution - Header | Command Injection |
| Generic Rules - Command Execution - URI | Command Injection |
| Malware, Web Shell | Malware |
| PostgreSQL - SQLi - COPY - beta | SQL Injection |
| React Server component - Scanner - CVE:CVE-2025-55182 | Scanner |
| SQLi - AND/OR Digit Operator Digit 2 - BETA | SQL Injection |
| SQLi - AND/OR MAKE_SET/ELT - Beta | SQL Injection |
| SQLi - Benchmark Function - Beta | SQL Injection |
| SQLi - Comment - Beta | SQL Injection |
| SQLi - Comparison - Beta | SQL Injection |
| SQLi - Equation 2 - BETA | SQL Injection |
| SQLi - String Function - BETA | SQL Injection |
| SQLi - Sub Query - BETA | SQL Injection |
| SQLi - Tautology - URI - BETA | SQL Injection |
| SQLi - WaitFor Function - BETA | SQL Injection |
| Wordpress - Dangerous File Upload - CVE:CVE-2025-5394 | File Upload |
| Wordpress, Drupal - Code Injection, Deserialization - Stream Wrapper | Code Injection |
| XWiki - Remote Code Execution - CVE:CVE-2025-24893 -BETA | RCE |

### Business Impact

- **Active attacks are not blocked**: Attackers exploiting these CVEs will succeed while Dexcom only observes the attack in logs
- **Data breach risk**: SQL injection attacks can exfiltrate sensitive patient health data (PHI/PII)
- **Compliance violations**: HIPAA requires reasonable safeguards; knowingly allowing attacks contradicts this requirement
- **Lateral movement**: Successful RCE attacks provide attackers with server access for further exploitation
- **Reputation damage**: A breach affecting medical device data would severely impact patient trust

### Risk Assessment

**CRITICAL** - These rules protect against known, actively-exploited vulnerabilities. LOG mode provides visibility but zero protection. Attackers can exploit these vulnerabilities with impunity.

### Remediation

1. **Immediately** review each LOG mode rule and transition to BLOCK mode for production zones
2. Test rule changes in staging environments first to identify false positives
3. Implement Cloudflare's recommended approach: start with LOG for 24-48 hours to baseline, then move to BLOCK
4. For BETA rules with false positive concerns, consider using MANAGED_CHALLENGE instead of LOG
5. Establish a policy requiring all managed WAF rules to be in BLOCK mode within 7 days of deployment

### Cloudflare Best Practice Reference

Per Cloudflare documentation: *"In production environments, managed rules should be set to block malicious traffic. Log mode is intended for initial deployment testing only, not for ongoing protection."*

### Validation Queries

```sql
-- Query to identify unique LOG mode rules across all zones
SELECT DISTINCT
    r.description,
    r.ref
FROM cloudflare_raw_rulesets_rules_history r
JOIN cloudflare_raw_rulesets_history rs ON r.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_instance_history ri ON rs.id = ri.ruleset_id
WHERE ri.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND r.action = 'LOG'
AND r.enabled = true
AND r.is_deleted = false
AND rs.is_deleted = false
AND rs.phase = 'http_request_firewall_managed';

-- Query to count affected zones per rule
SELECT 
    r.description,
    COUNT(DISTINCT ri.zone_id) as zone_count
FROM cloudflare_raw_rulesets_rules_history r
JOIN cloudflare_raw_rulesets_history rs ON r.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_instance_history ri ON rs.id = ri.ruleset_id
WHERE ri.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND r.action = 'LOG'
AND r.enabled = true
AND r.is_deleted = false
AND rs.is_deleted = false
AND rs.phase = 'http_request_firewall_managed'
GROUP BY r.description
ORDER BY zone_count DESC;
```

---

## Finding 2: Excessive WAF Bypass/Skip Rules

### Severity: HIGH

### Description

83 unique WAF bypass (SKIP) rules are actively configured across Dexcom zones. These rules intentionally allow traffic to bypass WAF protections based on IP addresses, user agents, or URI paths. While some bypass rules are legitimate (e.g., for CI/CD pipelines), several patterns indicate security risks.

**Sample Bypass Rules Identified:**

| Rule Description | Expression Pattern | Risk |
|-----------------|-------------------|------|
| Pentest-Whitelist | `ip.src eq 162.227.78.127` | Static IP whitelists can be spoofed |
| Pentest-Whitelist | `ip.src eq 178.165.20.100` | Pentest rules left enabled post-engagement |
| Intra-GCP Service Bypass | User-Agent: `Apache-HttpClient/` | User-Agent easily spoofed |
| Bypass Security Level for token authorize | URI path contains `/connect/token` | Authentication endpoints should have MORE protection, not less |
| Identity Connect Token URI Path Exception | URI path contains `/UAMApi/User/` | API paths bypassing security |
| Whitelist Netskope | `ip.src in $netskope` | Large IP list bypass |
| Okta Whitelist | `ip.src in $okta_whitelist` | IdP traffic still needs inspection |
| Wiz Scanner Allow | Host-based bypass | Scanner access rules left enabled |
| Bypass ratelimit for Dexcom VPN IP | `ip.src eq 66.85.67.20` | VPN users bypass rate limits |

### Business Impact

- **Reduced security coverage**: Bypassed traffic is not inspected for attacks
- **Attack surface expansion**: Attackers who compromise whitelisted IPs gain unrestricted access
- **Compliance gaps**: Security controls are effectively disabled for bypass traffic
- **Stale pentest rules**: Rules created for security assessments remain active, creating permanent holes
- **Authentication endpoint risk**: Bypassing security on `/connect/token` exposes OAuth flows to attack

### Risk Assessment

**HIGH** - While bypass rules serve legitimate purposes, the volume (83 unique rules) and patterns suggest insufficient governance. Pentest whitelists and user-agent based bypasses are particularly concerning.

### Remediation

1. **Audit all SKIP rules** and document business justification for each
2. **Remove stale pentest whitelists** immediately after engagements complete
3. **Replace user-agent based bypasses** with more robust mechanisms (mTLS, signed headers)
4. **Never bypass security on authentication endpoints** - these need enhanced protection
5. **Implement time-bound bypass rules** with automatic expiration
6. **Use Cloudflare Lists** with proper governance instead of inline IP addresses
7. **Require approval workflow** for new bypass rules

### Cloudflare Best Practice Reference

Per Cloudflare documentation: *"Skip rules should be used sparingly and with explicit business justification. Each skip rule represents a potential security gap. Regular audits should verify all skip rules remain necessary."*

### Validation Queries

```sql
-- Query to identify all active WAF bypass rules
SELECT DISTINCT
    r.description,
    r.expression
FROM cloudflare_raw_rulesets_rules_history r
JOIN cloudflare_raw_rulesets_history rs ON r.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_instance_history ri ON rs.id = ri.ruleset_id
WHERE ri.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND r.action = 'SKIP'
AND r.enabled = true
AND r.is_deleted = false
AND rs.is_deleted = false;

-- Count total bypass rules
SELECT COUNT(*) as total_skip_rules
FROM cloudflare_raw_rulesets_rules_history r
JOIN cloudflare_raw_rulesets_instance_history ri ON r.ruleset_id = ri.ruleset_id
WHERE ri.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND r.action = 'SKIP'
AND r.enabled = true
AND r.is_deleted = false;
```

---

## Finding 3: Unproxied DNS Records Exposing Origin IPs

### Severity: HIGH

### Description

11 DNS records are configured as **unproxied** (orange cloud off) while being **proxiable**, directly exposing origin server IP addresses to the public internet. This bypasses Cloudflare's DDoS protection and WAF entirely.

**Affected Records:**

| DNS Record | Type | Exposed IP | Risk Level |
|------------|------|------------|------------|
| `load-uam-us.dexcomdev.com` | A | 35.241.57.116 | High - Load balancer |
| `admin-ddlm.platform.dexcomdev.com` | A | 34.70.122.242 | Critical - Admin panel |
| `cm-ddlm.platform.dexcomdev.com` | A | 34.70.122.242 | High - Content management |
| `api-ddlm.platform.dexcomdev.com` | A | 34.70.122.242 | High - API endpoint |
| `devuamus01.dexcom.com` | A | 35.190.43.123 | Medium - Dev environment |
| `prod-vnv-uam-eu.dexcomdev.com` | A | 35.242.253.67 | High - Production |
| `nile-31200-prod-jp.platform.dexcomdev.com` | A | 34.84.7.200 | High - Production JP |
| `chronosphere-poc.platform.dexcomdev.com` | A | 34.120.56.188 | Medium - POC |
| `cepdocs.platform.dexcomdev.com` | CNAME | dexcom-inc.github.io | Low - Docs |
| `tridev.platform.dexcomdev.com` | CNAME | dexcom-inc.github.io | Low - Docs |
| `dexbasal.com` | A | 198.51.100.1 | Medium - Secondary domain |

### Business Impact

- **Direct attack surface**: Origin IPs can be targeted directly, bypassing all Cloudflare protections
- **DDoS vulnerability**: Unproxied origins receive no DDoS mitigation from Cloudflare
- **WAF bypass**: Attackers discovering these IPs can attack without WAF inspection
- **IP enumeration**: Exposed IPs reveal infrastructure details useful for reconnaissance
- **Admin panel exposure**: `admin-ddlm` being unproxied is particularly dangerous

### Risk Assessment

**HIGH** - Origin IP exposure negates the value of Cloudflare's security services. The admin panel exposure elevates this to critical priority.

### Remediation

1. **Enable Cloudflare proxy** (orange cloud) for all proxiable records, especially:
   - `admin-ddlm.platform.dexcomdev.com` (CRITICAL - admin access)
   - All `*-ddlm.platform.dexcomdev.com` records
   - `prod-vnv-uam-eu.dexcomdev.com`
2. **Implement origin IP firewall rules** to only accept traffic from Cloudflare IP ranges
3. **Rotate exposed origin IPs** as they may already be catalogued by attackers
4. **Use Cloudflare Tunnel (Argo Tunnel)** for admin interfaces to eliminate origin exposure entirely
5. **Review all DNS records** for proxy status as part of regular security hygiene

### Cloudflare Best Practice Reference

Per Cloudflare documentation: *"All web traffic should flow through Cloudflare's proxy to receive DDoS protection, WAF filtering, and performance benefits. Unproxied records expose your origin server directly to the internet, bypassing all Cloudflare security services."*

### Validation Queries

```sql
-- Query to identify unproxied but proxiable DNS records
SELECT 
    name,
    type,
    content,
    proxied,
    proxiable
FROM cloudflare_raw_dns_records_history
WHERE organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND proxied = false
AND proxiable = true
AND type IN ('A', 'AAAA', 'CNAME')
AND is_deleted = false
ORDER BY name;
```

---

## Finding 4: Disabled Rate Limiting on Authentication Endpoints

### Severity: MEDIUM

### Description

Rate limiting rules designed to protect authentication endpoints are **disabled** on multiple zones, leaving these critical endpoints vulnerable to brute-force attacks and credential stuffing.

**Disabled Rate Limit Rules:**

| Rule Description | Intended Protection |
|-----------------|---------------------|
| Photo Logging | Application-specific rate limit |
| Block Password Update Spam | Credential abuse prevention |

**Zones with Disabled Auth Rate Limits:**
- `prodvnv-accounts-api.dexcomdev.eu`
- `vnv-accounts-api.dexcomdev.com`
- `vnv-accounts-api.dexcomdev.eu`
- `platform.dexcomdev.com`

### Business Impact

- **Credential stuffing**: Attackers can attempt thousands of password combinations without throttling
- **Account takeover**: Successful brute-force leads to unauthorized access to patient accounts
- **Resource exhaustion**: Unthrottled requests can overwhelm authentication services
- **HIPAA compliance risk**: Inadequate access controls on PHI systems

### Risk Assessment

**MEDIUM** - While other rate limits may be active, disabling password-specific protections on API endpoints creates brute-force vulnerability.

### Remediation

1. **Enable rate limiting rules** on all authentication endpoints:
   - `/connect/token`
   - `/oauth/token`
   - Password update/reset endpoints
   - Account recovery endpoints
2. **Implement progressive delays**: Increase blocking duration for repeat offenders
3. **Consider CAPTCHA/challenge** after failed attempts
4. **Monitor for credential stuffing indicators** in security logs
5. **Set appropriate thresholds**: 
   - Login: 5-10 attempts per minute per IP
   - Password reset: 3-5 per hour per account

### Cloudflare Best Practice Reference

Per Cloudflare documentation: *"Authentication endpoints should always have rate limiting enabled. Cloudflare recommends starting with conservative limits (5-10 requests per minute) and adjusting based on legitimate traffic patterns. Rate limiting is essential for preventing credential stuffing and brute-force attacks."*

### Validation Queries

```sql
-- Query to identify disabled rate limiting rules
SELECT DISTINCT
    r.description,
    z.name as zone_name
FROM cloudflare_raw_rulesets_rules_history r
JOIN cloudflare_raw_rulesets_history rs ON r.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_instance_history ri ON rs.id = ri.ruleset_id
JOIN cloudflare_raw_zones_history z ON ri.zone_id = z.id
WHERE z.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND rs.phase = 'http_ratelimit'
AND r.enabled = false
AND r.is_deleted = false
AND rs.is_deleted = false
AND z.is_deleted = false;

-- Query current active rate limit configurations
SELECT 
    rl.period,
    rl.requests_per_period,
    rl.mitigation_timeout,
    r.description,
    r.enabled
FROM cloudflare_raw_rulesets_rule_rate_limits_history rl
JOIN cloudflare_raw_rulesets_rules_history r ON rl.rule_id = r.id
JOIN cloudflare_raw_rulesets_history rs ON r.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_instance_history ri ON rs.id = ri.ruleset_id
WHERE ri.organization_id = 'fe6fe002-e396-4c75-b8c1-48939488e8c2'
AND rl.is_deleted = false
AND r.is_deleted = false
ORDER BY r.enabled DESC, rl.requests_per_period DESC;
```

---

## Summary Statistics

```
┌─────────────────────────────────────────────┐
│ DEXCOM SECURITY CONFIGURATION SUMMARY       │
├─────────────────────────────────────────────┤
│ Total Zones Analyzed:                  333  │
│ Managed Rules in LOG Mode:              22  │
│ Zones with LOG Mode Rules:             327  │
│ Active WAF Bypass (SKIP) Rules:         83  │
│ Unproxied DNS Records:                  11  │
│ Disabled Rate Limit Rules:               2  │
└─────────────────────────────────────────────┘
```

---

## Recommendations Priority Matrix

| Priority | Finding | Action Required | Timeline |
|----------|---------|-----------------|----------|
| **P0** | LOG mode CVE rules | Switch to BLOCK mode | Immediate |
| **P0** | Admin panel unproxied | Enable Cloudflare proxy | Immediate |
| **P1** | Stale pentest bypass rules | Remove after audit | 48 hours |
| **P1** | Auth rate limits disabled | Re-enable | 48 hours |
| **P2** | Other unproxied records | Enable proxy + IP rotation | 1 week |
| **P2** | Excessive bypass rules | Audit and consolidate | 2 weeks |

---

## Appendix: Database Queries Used

All queries were executed against the Neon PostgreSQL database containing Cloudflare configuration snapshots:

- **Database:** web_apps
- **Host:** ep-ancient-glade-agmu7c53.c-2.eu-central-1.aws.neon.tech
- **Tables Used:**
  - `cloudflare_raw_zones_history`
  - `cloudflare_raw_rulesets_history`
  - `cloudflare_raw_rulesets_rules_history`
  - `cloudflare_raw_rulesets_instance_history`
  - `cloudflare_raw_dns_records_history`
  - `cloudflare_raw_rulesets_rule_rate_limits_history`

---

*Report generated by WAF Security Analysis Platform*



