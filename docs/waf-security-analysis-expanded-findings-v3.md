# WAF Security Analysis - Expanded Findings Catalog v3.0
## HIGH & CRITICAL Security Findings Reference

**Purpose:** Comprehensive catalog of security misconfigurations and log-based findings across Cloudflare, Akamai, and AWS WAF.

**Data Sources:**
- PostgreSQL: Configuration analysis (misconfigurations)
- Trino: Log analysis (Cloudflare & AWS WAF only)

---

## Table of Contents

1. [CLOUDFLARE - Configuration Findings](#cloudflare-config)
2. [CLOUDFLARE - Log Analysis Findings](#cloudflare-logs)
3. [AKAMAI - Configuration Findings](#akamai-config)
4. [AWS WAF - Configuration Findings](#aws-config)
5. [AWS WAF - Log Analysis Findings](#aws-logs)
6. [Cross-Vendor Correlation](#cross-vendor)

---

<a name="cloudflare-config"></a>
# CLOUDFLARE Configuration Analysis (PostgreSQL)

## CF-UNPROTECTED: Missing WAF Protection

### CF-UNPROTECTED-1 [CRITICAL] Zones Without ANY WAF Rules
```sql
SELECT 
    z.name as zone_name,
    z.status,
    z.plan_name,
    z.created_on,
    CASE 
        WHEN z.name ~* '(api|auth|login|admin|payment)' THEN 'CRITICAL - High-Value Asset'
        ELSE 'CRITICAL - Production Unprotected'
    END as severity_reason
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    WHERE ri.zone_id = z.id AND ri.is_deleted = false
)
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%', '%stg%', '%uat%', '%sandbox%', '%demo%', '%poc%'])
ORDER BY 
    CASE WHEN z.name ~* '(api|auth|login|admin|payment)' THEN 0 ELSE 1 END,
    z.name;

-- Best Practice: https://developers.cloudflare.com/waf/managed-rules/
```

### CF-UNPROTECTED-2 [CRITICAL] API Zones Without Protection
```sql
SELECT 
    z.name as zone_name,
    z.plan_name,
    'CRITICAL: API zone without WAF protection' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND z.name ~* '(api\.|^api-|apis\.|rest\.|graphql\.|gql\.)'
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    WHERE ri.zone_id = z.id AND ri.is_deleted = false
);
```

### CF-UNPROTECTED-3 [CRITICAL] Authentication Zones Without Protection
```sql
SELECT 
    z.name as zone_name,
    z.plan_name,
    'CRITICAL: Authentication zone without WAF protection' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND z.name ~* '(auth\.|login\.|signin\.|sso\.|oauth\.|keycloak\.|okta\.|identity\.|idp\.)'
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    WHERE ri.zone_id = z.id AND ri.is_deleted = false
);
```

### CF-UNPROTECTED-4 [CRITICAL] Payment/Billing Zones Without Protection  
```sql
SELECT 
    z.name as zone_name,
    z.plan_name,
    'CRITICAL: Payment zone without WAF protection - PCI compliance risk' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND z.name ~* '(pay\.|payment\.|billing\.|checkout\.|stripe\.|card\.)'
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    WHERE ri.zone_id = z.id AND ri.is_deleted = false
);
```

### CF-UNPROTECTED-5 [HIGH] Mobile Backend Zones Without Protection
```sql
SELECT 
    z.name as zone_name,
    z.plan_name,
    'HIGH: Mobile backend zone without WAF protection' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND z.name ~* '(mobile\.|app\.|ios\.|android\.|m\.)'
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    WHERE ri.zone_id = z.id AND ri.is_deleted = false
)
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

## CF-RULESET: Ruleset Configuration Issues

### CF-RULESET-1 [CRITICAL] Missing OWASP Managed Ruleset
```sql
WITH zone_rulesets AS (
    SELECT 
        z.id as zone_id,
        z.name as zone_name,
        rs.name as ruleset_name,
        rs.kind
    FROM cloudflare_raw_zones_history z
    LEFT JOIN cloudflare_raw_rulesets_instance_history ri ON ri.zone_id = z.id AND ri.is_deleted = false
    LEFT JOIN cloudflare_raw_rulesets_history rs ON rs.id = ri.ruleset_id AND rs.is_deleted = false
    WHERE z.organization_id = '{ORGANIZATION_ID}'
    AND z.is_deleted = false
    AND z.status = 'active'
)
SELECT DISTINCT
    zone_name,
    'CRITICAL: Missing OWASP/Managed WAF ruleset' as finding
FROM zone_rulesets zr
WHERE NOT EXISTS (
    SELECT 1 FROM zone_rulesets zr2
    WHERE zr2.zone_id = zr.zone_id
    AND (zr2.ruleset_name ILIKE '%managed%' OR zr2.ruleset_name ILIKE '%owasp%' OR zr2.kind = 'managed')
)
AND zone_name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);

-- Best Practice: https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/
```

### CF-RULESET-2 [HIGH] Only Custom Rules, No Managed Rules
```sql
SELECT 
    z.name as zone_name,
    COUNT(DISTINCT rs.id) as ruleset_count,
    COUNT(DISTINCT CASE WHEN rs.kind = 'custom' THEN rs.id END) as custom_count,
    COUNT(DISTINCT CASE WHEN rs.kind = 'managed' THEN rs.id END) as managed_count,
    'HIGH: Zone has only custom rules, no managed rules' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON ri.zone_id = z.id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON rs.id = ri.ruleset_id AND rs.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
GROUP BY z.name
HAVING COUNT(DISTINCT CASE WHEN rs.kind = 'managed' THEN rs.id END) = 0
   AND COUNT(DISTINCT CASE WHEN rs.kind = 'custom' THEN rs.id END) > 0;
```

## CF-RULES: Individual Rule Issues

### CF-RULES-1 [HIGH] WAF Rules in LOG Mode (Production)
```sql
SELECT 
    z.name as zone_name,
    rs.name as ruleset_name,
    r.description as rule_description,
    r.action::text,
    r.expression,
    'HIGH: WAF rule in LOG mode - attacks detected but not blocked' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text ILIKE '%log%'
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%'])
ORDER BY z.name, rs.name;

-- Best Practice: Rules should transition from LOG to BLOCK after validation
-- https://developers.cloudflare.com/waf/managed-rules/deploy-zone-dashboard/
```

### CF-RULES-2 [CRITICAL] CVE/Vulnerability Rules in LOG Mode
```sql
SELECT 
    z.name as zone_name,
    r.description as rule_description,
    r.ref,
    r.categories::text,
    'CRITICAL: CVE/Vulnerability rule in LOG mode - known exploits not blocked' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text ILIKE '%log%'
AND (
    r.description ILIKE '%cve-%'
    OR r.description ILIKE '%vulnerability%'
    OR r.description ILIKE '%exploit%'
    OR r.description ILIKE '%injection%'
    OR r.description ILIKE '%rce%'
    OR r.description ILIKE '%remote code%'
    OR r.description ILIKE '%shell%'
    OR r.description ILIKE '%traversal%'
    OR r.description ILIKE '%deserialization%'
    OR r.categories::text ILIKE '%cve%'
);
```

### CF-RULES-3 [CRITICAL] RCE/Command Injection Rules in LOG Mode
```sql
SELECT 
    z.name as zone_name,
    r.description,
    r.action::text,
    'CRITICAL: RCE/Command injection rule in LOG mode' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text ILIKE '%log%'
AND (
    r.description ILIKE '%rce%'
    OR r.description ILIKE '%remote code%'
    OR r.description ILIKE '%command injection%'
    OR r.description ILIKE '%os command%'
    OR r.description ILIKE '%shell%'
);
```

### CF-RULES-4 [HIGH] Disabled Security Rules
```sql
SELECT 
    z.name as zone_name,
    rs.name as ruleset_name,
    r.description,
    'HIGH: Security rule disabled' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = false
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%'])
ORDER BY z.name;
```

### CF-RULES-5 [HIGH] Rules with High Position (Late Execution)
```sql
SELECT 
    z.name as zone_name,
    rs.name as ruleset_name,
    r.description,
    r.position,
    r.action::text,
    'HIGH: Critical security rule has high position (executes late)' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text IN ('block', 'challenge', 'managed_challenge')
AND r.position > 50
AND (
    r.description ILIKE '%sqli%'
    OR r.description ILIKE '%xss%'
    OR r.description ILIKE '%rce%'
    OR r.description ILIKE '%injection%'
)
ORDER BY r.position DESC;
```

## CF-BYPASS: WAF Bypass Rules (SKIP)

### CF-BYPASS-1 [HIGH] SKIP Rules Without IP Restrictions
```sql
SELECT 
    z.name as zone_name,
    r.description,
    r.expression,
    r.action_parameters::text as skip_config,
    'HIGH: WAF bypass without IP restriction - easily exploitable' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text ILIKE '%skip%'
AND r.expression NOT LIKE '%ip.src%'
AND r.expression NOT LIKE '%ip.geoip%'
ORDER BY z.name;

-- Best Practice: All WAF exceptions should include IP restrictions
-- https://developers.cloudflare.com/waf/custom-rules/skip/
```

### CF-BYPASS-2 [HIGH] User-Agent Based SKIP Rules (Spoofable)
```sql
SELECT 
    z.name as zone_name,
    r.description,
    r.expression,
    'HIGH: User-Agent based bypass - trivially spoofable' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text ILIKE '%skip%'
AND (
    r.expression ILIKE '%http.user_agent%'
    OR r.expression ILIKE '%user-agent%'
)
AND r.expression NOT LIKE '%ip.src%';
```

### CF-BYPASS-3 [HIGH] Cookie-Based SKIP Rules (Spoofable)
```sql
SELECT 
    z.name as zone_name,
    r.description,
    r.expression,
    'HIGH: Cookie-based bypass - client-controlled and spoofable' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text ILIKE '%skip%'
AND r.expression ILIKE '%http.cookie%'
AND r.expression NOT LIKE '%ip.src%';
```

### CF-BYPASS-4 [HIGH] Header-Based SKIP Rules (Spoofable)
```sql
SELECT 
    z.name as zone_name,
    r.description,
    r.expression,
    'HIGH: Header-based bypass - client-controlled and spoofable' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text ILIKE '%skip%'
AND r.expression ILIKE '%http.request.headers%'
AND r.expression NOT LIKE '%ip.src%';
```

### CF-BYPASS-5 [CRITICAL] SKIP Rules Bypassing Entire WAF Phases
```sql
SELECT 
    z.name as zone_name,
    r.description,
    r.expression,
    spp.phase as skipped_phase,
    'CRITICAL: Rule bypasses entire WAF phase' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
LEFT JOIN cloudflare_raw_rulesets_rule_skip_ap_phases_history spp ON r.id = spp.rule_id AND spp.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text ILIKE '%skip%'
AND spp.phase IS NOT NULL;
```

### CF-BYPASS-6 [HIGH] Excessive SKIP Rules Per Zone
```sql
SELECT 
    z.name as zone_name,
    COUNT(*) as skip_rule_count,
    'HIGH: Excessive bypass rules increase attack surface (' || COUNT(*) || ' rules)' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text ILIKE '%skip%'
GROUP BY z.name
HAVING COUNT(*) > 5
ORDER BY skip_rule_count DESC;
```

### CF-BYPASS-7 [CRITICAL] SKIP Rules on Sensitive Paths
```sql
SELECT 
    z.name as zone_name,
    r.description,
    r.expression,
    'CRITICAL: WAF bypass on sensitive path' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND r.action::text ILIKE '%skip%'
AND (
    r.expression ILIKE '%/api/%'
    OR r.expression ILIKE '%/admin%'
    OR r.expression ILIKE '%/auth%'
    OR r.expression ILIKE '%/login%'
    OR r.expression ILIKE '%/graphql%'
    OR r.expression ILIKE '%/webhook%'
);
```

## CF-DNS: DNS/Origin Exposure

### CF-DNS-1 [HIGH] Unproxied A/AAAA Records
```sql
SELECT 
    z.name as zone_name,
    d.name as dns_record,
    d.type,
    d.content as exposed_ip,
    CASE
        WHEN d.name ~* '(api|auth|login|admin|payment|internal|db|backend)' THEN 'CRITICAL'
        ELSE 'HIGH'
    END as effective_severity,
    'Origin IP exposed - attackers can bypass WAF' as finding
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND d.proxied = false
AND d.proxiable = true
AND d.type IN ('A', 'AAAA')
AND d.is_deleted = false
AND z.is_deleted = false
ORDER BY effective_severity, d.name;

-- Best Practice: All origin-serving records should be proxied
-- https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/
```

### CF-DNS-2 [CRITICAL] Sensitive Subdomains with Exposed IPs
```sql
SELECT 
    z.name as zone_name,
    d.name as dns_record,
    d.content as exposed_ip,
    'CRITICAL: Sensitive subdomain origin exposed' as finding
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND d.proxied = false
AND d.proxiable = true
AND d.type IN ('A', 'AAAA')
AND (
    d.name ~* '(api|apis|auth|oauth|sso|login|signin|admin|root|sudo|internal|backend|db|database|mysql|postgres|mongo|redis|elastic|vault|consul|k8s|kube|jenkins|gitlab|grafana|prometheus|kibana|payment|billing|stripe|checkout)'
)
AND d.is_deleted = false 
AND z.is_deleted = false;
```

### CF-DNS-3 [HIGH] MX Records Pointing to Same IP as Web
```sql
WITH web_ips AS (
    SELECT DISTINCT d.content as ip
    FROM cloudflare_raw_dns_records_history d
    JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
    WHERE z.organization_id = '{ORGANIZATION_ID}'
    AND d.type IN ('A', 'AAAA')
    AND d.is_deleted = false AND z.is_deleted = false
)
SELECT 
    z.name as zone_name,
    d.name as mx_record,
    d.content as mx_value,
    'HIGH: MX record may expose origin infrastructure' as finding
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND d.type = 'MX'
AND d.is_deleted = false AND z.is_deleted = false;
```

### CF-DNS-4 [HIGH] TXT Records with Sensitive Information
```sql
SELECT 
    z.name as zone_name,
    d.name as dns_record,
    LEFT(d.content, 100) as content_preview,
    'HIGH: TXT record may leak sensitive information' as finding
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND d.type = 'TXT'
AND (
    d.content ILIKE '%internal%'
    OR d.content ILIKE '%password%'
    OR d.content ILIKE '%secret%'
    OR d.content ILIKE '%key=%'
    OR d.content ILIKE '%token=%'
)
AND d.is_deleted = false AND z.is_deleted = false;
```

## CF-BOT: Bot Management Gaps

### CF-BOT-1 [CRITICAL] No Bot Management on Production
```sql
SELECT 
    z.name as zone_name,
    z.plan_name,
    'CRITICAL: No bot management configured on production zone' as finding
FROM cloudflare_raw_zones_history z
LEFT JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND bm.id IS NULL
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%', '%demo%']);

-- Best Practice: Enable Bot Management for production zones
-- https://developers.cloudflare.com/bots/get-started/
```

### CF-BOT-2 [HIGH] Bot Fight Mode Disabled
```sql
SELECT 
    z.name as zone_name,
    bm.fight_mode,
    bm.sbfm_definitely_automated::text,
    'HIGH: Bot fight mode disabled' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND bm.fight_mode = false
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

### CF-BOT-3 [HIGH] Definitely Automated Bots Allowed
```sql
SELECT 
    z.name as zone_name,
    bm.sbfm_definitely_automated::text,
    'HIGH: Definite automated bot traffic allowed' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND bm.sbfm_definitely_automated::text = 'allow'
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

### CF-BOT-4 [HIGH] JS Detection Disabled
```sql
SELECT 
    z.name as zone_name,
    bm.enable_js,
    'HIGH: JavaScript bot detection disabled' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND bm.enable_js = false
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

### CF-BOT-5 [HIGH] AI Bots Scraping Allowed
```sql
SELECT 
    z.name as zone_name,
    bm.ai_bots_protection::text,
    'HIGH: AI bot scraping protection disabled' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND bm.ai_bots_protection::text NOT IN ('block')
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

### CF-BOT-6 [HIGH] Crawler Protection Disabled
```sql
SELECT 
    z.name as zone_name,
    bm.crawler_protection::text,
    'HIGH: Crawler protection disabled' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND bm.crawler_protection::text = 'disabled'
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

## CF-RATELIMIT: Rate Limiting Gaps

### CF-RATELIMIT-1 [HIGH] No Rate Limiting on Auth Zones
```sql
SELECT 
    z.name as zone_name,
    'HIGH: Authentication zone without rate limiting' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND z.name ~* '(auth|login|signin|sso|oauth)'
AND NOT EXISTS (
    SELECT 1 
    FROM cloudflare_raw_rulesets_instance_history ri
    JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
    WHERE ri.zone_id = z.id 
    AND ri.is_deleted = false AND rs.is_deleted = false
    AND rs.phase = 'http_ratelimit'
);
```

### CF-RATELIMIT-2 [HIGH] Rate Limits with Very High Thresholds
```sql
SELECT 
    z.name as zone_name,
    r.description,
    rl.requests_per_period,
    rl.period,
    (rl.requests_per_period::float / rl.period * 60) as requests_per_minute,
    'HIGH: Rate limit threshold very permissive (' || rl.requests_per_period || ' per ' || rl.period || 's)' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
JOIN cloudflare_raw_rulesets_rule_rate_limits_history rl ON r.id = rl.rule_id AND rl.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND rl.requests_per_period > 1000
AND rl.period <= 60;
```

### CF-RATELIMIT-3 [HIGH] Short Mitigation Timeout
```sql
SELECT 
    z.name as zone_name,
    r.description,
    rl.mitigation_timeout,
    'HIGH: Rate limit mitigation timeout too short (' || rl.mitigation_timeout || 's)' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
JOIN cloudflare_raw_rulesets_rule_rate_limits_history rl ON r.id = rl.rule_id AND rl.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND r.enabled = true
AND rl.mitigation_timeout < 60;
```

## CF-LISTS: IP List Issues

### CF-LISTS-1 [HIGH] Very Large IP Lists (Performance/Management Risk)
```sql
SELECT 
    l.name as list_name,
    l.kind::text,
    l.num_items,
    'HIGH: Very large IP list may have performance/management issues' as finding
FROM cloudflare_raw_lists_history l
JOIN cloudflare_raw_accounts_history a ON l.account_id = a.id AND a.is_deleted = false
WHERE a.organization_id = '{ORGANIZATION_ID}'
AND l.is_deleted = false
AND l.num_items > 10000;
```

### CF-LISTS-2 [HIGH] Empty IP Lists Referenced in Rules
```sql
SELECT 
    l.name as list_name,
    l.kind::text,
    l.num_items,
    'HIGH: Empty list may cause rule ineffectiveness' as finding
FROM cloudflare_raw_lists_history l
JOIN cloudflare_raw_accounts_history a ON l.account_id = a.id AND a.is_deleted = false
WHERE a.organization_id = '{ORGANIZATION_ID}'
AND l.is_deleted = false
AND l.num_items = 0;
```

---

<a name="cloudflare-logs"></a>
# CLOUDFLARE Log Analysis (Trino)

> **IMPORTANT: Partition Keys Required!**
> All Cloudflare WAF log queries require the `zone` partition key.
> Replace `{ZONE_NAME}` with specific zone (e.g., 'api.example.com').
> For multi-zone analysis, iterate over zones discovered from PostgreSQL.

## CF-LOG-ATTACK: Attack Detection

### CF-LOG-ATTACK-1 [CRITICAL] High Attack Score Traffic ALLOWED
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    clientcountry,
    securityaction,
    wafattackscore,
    wafsqliattackscore,
    wafxssattackscore,
    wafrceattackscore,
    securityruledescription
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND zone = '{ZONE_NAME}'  -- Required partition key
AND year = {YEAR} AND month = {MONTH} AND day = {DAY} AND hour = {HOUR}
AND wafattackscore >= 60
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge', 'drop')
ORDER BY wafattackscore DESC
LIMIT 500;

-- CRITICAL: Attack score >= 60 should trigger blocking
-- https://developers.cloudflare.com/waf/about/waf-attack-score/
-- NOTE: Iterate over multiple hours/days for broader analysis
```

### CF-LOG-ATTACK-2 [CRITICAL] SQL Injection Allowed
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    wafsqliattackscore,
    LEFT(clientrequesturi, 500) as uri_preview
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND wafsqliattackscore >= 50
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge', 'drop')
ORDER BY wafsqliattackscore DESC
LIMIT 200;
```

### CF-LOG-ATTACK-3 [CRITICAL] XSS Attacks Allowed
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    wafxssattackscore,
    LEFT(clientrequesturi, 500) as uri_preview
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND wafxssattackscore >= 50
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge', 'drop')
ORDER BY wafxssattackscore DESC
LIMIT 200;
```

### CF-LOG-ATTACK-4 [CRITICAL] RCE Attempts Allowed
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    wafrceattackscore,
    LEFT(clientrequesturi, 500) as uri_preview
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND wafrceattackscore >= 50
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge', 'drop')
ORDER BY wafrceattackscore DESC
LIMIT 200;
```

### CF-LOG-ATTACK-5 [HIGH] Combined High Scores Allowed
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    wafattackscore,
    wafsqliattackscore,
    wafxssattackscore,
    wafrceattackscore,
    (wafsqliattackscore + wafxssattackscore + wafrceattackscore) as combined_score
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (wafsqliattackscore + wafxssattackscore + wafrceattackscore) >= 100
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge', 'drop')
ORDER BY combined_score DESC
LIMIT 200;
```

## CF-LOG-BOT: Bot Analysis

### CF-LOG-BOT-1 [HIGH] Definite Bots Not Challenged (Score <= 30)
```sql
SELECT 
    clientrequesthost,
    botscore,
    botscoresrc,
    COALESCE(CAST(bottags AS VARCHAR), '') as bot_tags,
    securityaction,
    COUNT(*) as requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND botscore <= 30
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge', 'drop')
GROUP BY clientrequesthost, botscore, botscoresrc, CAST(bottags AS VARCHAR), securityaction
HAVING COUNT(*) > 100
ORDER BY requests DESC
LIMIT 100;

-- Bot Score <= 30 = Definite bot
-- https://developers.cloudflare.com/bots/concepts/bot-score/
```

### CF-LOG-BOT-2 [HIGH] Likely Bots Accessing Sensitive Endpoints
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    botscore,
    securityaction,
    COUNT(*) as requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND botscore <= 50
AND (
    clientrequestpath ILIKE '%/api/%'
    OR clientrequestpath ILIKE '%/login%'
    OR clientrequestpath ILIKE '%/auth%'
    OR clientrequestpath ILIKE '%/admin%'
)
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge')
GROUP BY clientrequesthost, clientrequestpath, botscore, securityaction
ORDER BY requests DESC
LIMIT 100;
```

### CF-LOG-BOT-3 [HIGH] Fraud Detection Triggers Not Blocked
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    fraudattack,
    COALESCE(CAST(frauddetectiontags AS VARCHAR), '') as fraud_tags,
    securityaction,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND fraudattack IS NOT NULL
AND fraudattack != ''
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge')
GROUP BY clientrequesthost, clientrequestpath, fraudattack, CAST(frauddetectiontags AS VARCHAR), securityaction
ORDER BY occurrences DESC;
```

## CF-LOG-CREDENTIAL: Credential Security

### CF-LOG-CREDENTIAL-1 [CRITICAL] Leaked Credentials Not Blocked
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    leakedcredentialcheckresult,
    securityaction,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND leakedcredentialcheckresult IS NOT NULL
AND leakedcredentialcheckresult != ''
AND leakedcredentialcheckresult != 'not_checked'
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge')
GROUP BY clientrequesthost, clientrequestpath, clientip, leakedcredentialcheckresult, securityaction
ORDER BY occurrences DESC;

-- CRITICAL: Leaked credentials must trigger blocking
-- https://developers.cloudflare.com/waf/managed-rules/check-for-exposed-credentials/
```

### CF-LOG-CREDENTIAL-2 [HIGH] Credential Stuffing Patterns
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(*) as total_requests,
    SUM(CASE WHEN edgeresponsestatus >= 400 THEN 1 ELSE 0 END) as failed_requests,
    ROUND(100.0 * SUM(CASE WHEN edgeresponsestatus >= 400 THEN 1 ELSE 0 END) / COUNT(*), 2) as failure_rate
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    clientrequestpath ILIKE '%login%'
    OR clientrequestpath ILIKE '%signin%'
    OR clientrequestpath ILIKE '%auth%'
    OR clientrequestpath ILIKE '%token%'
    OR clientrequestpath ILIKE '%session%'
)
AND clientrequestmethod = 'POST'
GROUP BY clientrequesthost, clientrequestpath
HAVING COUNT(DISTINCT clientip) > 50 AND COUNT(*) > 100
ORDER BY unique_ips DESC;
```

## CF-LOG-BYPASS: Bypass Analysis

### CF-LOG-BYPASS-1 [HIGH] SKIP Actions with High Attack Scores
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    securityaction,
    wafattackscore,
    wafsqliattackscore,
    wafxssattackscore,
    wafrceattackscore,
    COUNT(*) as requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND securityaction = 'skip'
AND wafattackscore > 30
GROUP BY clientrequesthost, clientrequestpath, securityaction, wafattackscore, wafsqliattackscore, wafxssattackscore, wafrceattackscore
HAVING COUNT(*) > 10
ORDER BY wafattackscore DESC, requests DESC;

-- HIGH: SKIP actions on traffic with attack scores indicate bypass exploitation
```

### CF-LOG-BYPASS-2 [CRITICAL] High SKIP Rate on Sensitive Endpoints
```sql
WITH endpoint_stats AS (
    SELECT 
        clientrequesthost,
        clientrequestpath,
        COUNT(*) as total_requests,
        SUM(CASE WHEN securityaction = 'skip' THEN 1 ELSE 0 END) as skip_count
    FROM huskeys_customers_logs.cloudflare_waf_logs.raw
    WHERE organization = '{CUSTOMER_NAME}'
    AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
    AND (
        clientrequestpath ILIKE '%/api/%'
        OR clientrequestpath ILIKE '%/login%'
        OR clientrequestpath ILIKE '%/admin%'
        OR clientrequestpath ILIKE '%/auth%'
    )
    GROUP BY clientrequesthost, clientrequestpath
)
SELECT 
    clientrequesthost,
    clientrequestpath,
    total_requests,
    skip_count,
    ROUND(100.0 * skip_count / total_requests, 2) as skip_percentage
FROM endpoint_stats
WHERE total_requests > 100
AND skip_count > 0
AND (100.0 * skip_count / total_requests) > 20
ORDER BY skip_percentage DESC;
```

## CF-LOG-FINGERPRINT: TLS Fingerprint Analysis

### CF-LOG-FINGERPRINT-1 [HIGH] Suspicious JA3/JA4 Fingerprints
```sql
SELECT 
    ja3hash,
    ja4,
    COUNT(*) as requests,
    COUNT(DISTINCT clientip) as unique_ips,
    AVG(wafattackscore) as avg_attack_score,
    AVG(botscore) as avg_bot_score
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND ja3hash IS NOT NULL
GROUP BY ja3hash, ja4
HAVING AVG(wafattackscore) > 30 OR AVG(botscore) < 30
ORDER BY avg_attack_score DESC
LIMIT 50;
```

### CF-LOG-FINGERPRINT-2 [HIGH] Single JA3 with Many IPs (Bot Network)
```sql
SELECT 
    ja3hash,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(*) as total_requests,
    AVG(botscore) as avg_bot_score
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND ja3hash IS NOT NULL
GROUP BY ja3hash
HAVING COUNT(DISTINCT clientip) > 100
ORDER BY unique_ips DESC
LIMIT 50;
```

## CF-LOG-MTLS: mTLS Analysis

### CF-LOG-MTLS-1 [HIGH] mTLS Failures on Sensitive Endpoints
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientmtlsauthstatus,
    COUNT(*) as failures
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND clientmtlsauthstatus IS NOT NULL
AND clientmtlsauthstatus NOT IN ('', 'valid', 'ok', 'success')
AND (
    clientrequestpath ILIKE '%/api/%'
    OR clientrequestpath ILIKE '%/internal%'
)
GROUP BY clientrequesthost, clientrequestpath, clientmtlsauthstatus
ORDER BY failures DESC;
```

---

<a name="akamai-config"></a>
# AKAMAI Configuration Analysis (PostgreSQL)

> **NOTE:** Akamai logs are NOT YET AVAILABLE in Trino. Analysis is configuration-based only.

## AK-ATTACK: Attack Group Configuration

### AK-ATTACK-1 [CRITICAL] Attack Groups in NONE/Disabled State
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    sp.akamai_id as policy_id,
    ag.name as attack_group,
    ag.action::text,
    'CRITICAL: Attack group protection disabled' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_policy_attack_groups_history ag ON sp.id = ag.security_policy_id AND ag.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND ag.action::text IN ('none', 'NONE');

-- Best Practice: https://techdocs.akamai.com/application-security/docs/attack-groups
```

### AK-ATTACK-2 [HIGH] Attack Groups in ALERT Mode Only
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    ag.name as attack_group,
    ag.action::text,
    'HIGH: Attack group in ALERT mode - detects but does not block' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_policy_attack_groups_history ag ON sp.id = ag.security_policy_id AND ag.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND ag.action::text IN ('alert', 'ALERT');
```

### AK-ATTACK-3 [HIGH] SQLi Attack Group Not Blocking
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    ag.name as attack_group,
    ag.action::text,
    'HIGH: SQL Injection attack group not blocking' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_policy_attack_groups_history ag ON sp.id = ag.security_policy_id AND ag.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND ag.name ILIKE '%sql%'
AND ag.action::text NOT IN ('deny', 'DENY', 'deny_custom');
```

### AK-ATTACK-4 [HIGH] XSS Attack Group Not Blocking
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    ag.name as attack_group,
    ag.action::text,
    'HIGH: XSS attack group not blocking' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_policy_attack_groups_history ag ON sp.id = ag.security_policy_id AND ag.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND ag.name ILIKE '%xss%'
AND ag.action::text NOT IN ('deny', 'DENY', 'deny_custom');
```

## AK-RAPID: Rapid Rules (ASE)

### AK-RAPID-1 [HIGH] Rapid Rules Disabled on Security Policy
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    sp.rapid_rules_enabled,
    'HIGH: Rapid rules (ASE) disabled - no zero-day protection' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND sp.rapid_rules_enabled = false;

-- Best Practice: https://techdocs.akamai.com/application-security/docs/adaptive-security-engine
```

### AK-RAPID-2 [HIGH] Rapid Rules in Non-Deny Mode
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    rr.title as rapid_rule,
    rr.action,
    rr.akamai_id as rule_id,
    'HIGH: Rapid rule not in deny mode' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_policy_rapid_rules_history rr ON sp.id = rr.security_policy_id AND rr.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND rr.action NOT IN ('deny', 'deny_custom')
AND rr.locked = false;
```

## AK-MATCHTARGET: Match Target Issues

### AK-MATCHTARGET-1 [CRITICAL] Match Targets Without Application Layer Controls
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    mt.type::text as match_target_type,
    mt.apply_application_layer_controls,
    'CRITICAL: Application layer controls disabled on match target' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_configuration_match_targets_history mt ON sp.id = mt.security_policy_id AND mt.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND mt.apply_application_layer_controls = false;
```

### AK-MATCHTARGET-2 [HIGH] Match Targets Without Rate Controls
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    mt.type::text as match_target_type,
    mt.apply_rate_controls,
    'HIGH: Rate controls disabled on match target' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_configuration_match_targets_history mt ON sp.id = mt.security_policy_id AND mt.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND mt.apply_rate_controls = false;
```

### AK-MATCHTARGET-3 [HIGH] Match Targets Without Bot Management
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    mt.type::text as match_target_type,
    mt.apply_botman_controls,
    'HIGH: Bot management controls disabled on match target' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_configuration_match_targets_history mt ON sp.id = mt.security_policy_id AND mt.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND mt.apply_botman_controls = false;
```

## AK-RATE: Rate Limiting Issues

### AK-RATE-1 [CRITICAL] Rate Policies with Zero Thresholds
```sql
SELECT 
    sc.name as security_config_name,
    rp.name as rate_policy_name,
    rp.average_threshold,
    rp.burst_threshold,
    'CRITICAL: Rate limiting effectively disabled (zero thresholds)' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_sec_config_rate_policies_history rp ON scv.id = rp.config_version_id AND rp.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND rp.average_threshold = 0
AND rp.burst_threshold = 0
AND rp.used = true;

-- Best Practice: https://techdocs.akamai.com/application-security/docs/rate-limiting
```

### AK-RATE-2 [HIGH] Rate Policies with Very High Thresholds
```sql
SELECT 
    sc.name as security_config_name,
    rp.name as rate_policy_name,
    rp.average_threshold,
    rp.burst_threshold,
    'HIGH: Rate limit thresholds very permissive' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_sec_config_rate_policies_history rp ON scv.id = rp.config_version_id AND rp.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND (rp.average_threshold > 10000 OR rp.burst_threshold > 10000)
AND rp.used = true;
```

### AK-RATE-3 [HIGH] Rate Policy Actions Not Denying
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    rpa.ipv4_action,
    rpa.ipv6_action,
    'HIGH: Rate policy action not set to deny' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_policy_rate_policy_actions_history rpa ON sp.id = rpa.security_policy_id AND rpa.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND (rpa.ipv4_action NOT LIKE '%deny%' OR rpa.ipv6_action NOT LIKE '%deny%');
```

## AK-BOT: Bot Management Issues

### AK-BOT-1 [HIGH] Bad Bot Categories Not Blocking
```sql
SELECT 
    sc.name as security_config_name,
    bc.name as bot_category,
    bca.action::text,
    'HIGH: Malicious bot category not being blocked' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_bot_category_actions_history bca ON sp.id = bca.security_policy_id AND bca.is_deleted = false
JOIN akamai_raw_bot_categories_history bc ON bca.category_id = bc.id AND bc.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND bca.action::text NOT IN ('deny', 'tarpit', 'slow')
AND bc.name NOT LIKE '%verified%';
```

### AK-BOT-2 [HIGH] Bot Detections Not Enforcing
```sql
SELECT 
    sc.name as security_config_name,
    bd.name as bot_detection,
    bd.description,
    bda.action,
    'HIGH: Bot detection not enforcing' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_bot_detection_actions_history bda ON sp.id = bda.security_policy_id AND bda.is_deleted = false
JOIN akamai_raw_bot_detections_history bd ON bda.detection_id = bd.id AND bd.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND bda.action NOT IN ('deny', 'tarpit')
AND bd.is_active_detection = true;
```

## AK-LOGGING: Logging/Visibility Issues

### AK-LOGGING-1 [HIGH] Attack Payload Logging Disabled
```sql
SELECT 
    sc.name as security_config_name,
    apls.enabled as payload_logging_enabled,
    apls.request_body_type::text,
    apls.response_body_type::text,
    'HIGH: Attack payload logging disabled - reduced forensic capability' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
LEFT JOIN akamai_raw_sec_config_attack_payload_log_settings_history apls ON scv.id = apls.config_version_id AND apls.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND (apls.id IS NULL OR apls.enabled = false);
```

## AK-CUSTOM: Custom Rule Issues

### AK-CUSTOM-1 [CRITICAL] Custom Rules Not Activated
```sql
SELECT 
    sc.name as security_config_name,
    cr.name as custom_rule_name,
    cr.description,
    cr.status::text,
    cr.is_activated,
    'CRITICAL: Custom rule not activated' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_sec_config_custom_rules_history cr ON sc.id = cr.config_id AND cr.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND cr.is_activated = false;
```

---

<a name="aws-config"></a>
# AWS WAF Configuration Analysis (PostgreSQL)

## AWS-ACL: Web ACL Issues

### AWS-ACL-1 [CRITICAL] ACLs Not Associated with Resources
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    acl.region::text,
    acl.default_action::text,
    'CRITICAL: WAF ACL not associated with any resources' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_associated_resources_history ar
    WHERE ar.waf_acl_id = acl.id AND ar.is_deleted = false
);

-- Best Practice: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-aws-resource.html
```

### AWS-ACL-2 [CRITICAL] ACLs with Default ALLOW Action
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    acl.region::text,
    acl.default_action::text,
    COUNT(DISTINCT ar.id) as associated_resources,
    'CRITICAL: ACL defaults to ALLOW - fail-open configuration' as finding
FROM aws_raw_waf_acl_history acl
LEFT JOIN aws_raw_waf_acl_associated_resources_history ar ON acl.id = ar.waf_acl_id AND ar.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.default_action::text = 'allow'
AND acl.is_deleted = false
GROUP BY acl.name, acl.arn, acl.region, acl.default_action;

-- Best Practice: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-default-action.html
```

### AWS-ACL-3 [HIGH] ACLs Without Any Rules (Empty Protection)
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    acl.region::text,
    COUNT(r.id) as rule_count,
    'HIGH: WAF ACL has no rules - empty protection' as finding
FROM aws_raw_waf_acl_history acl
LEFT JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id AND r.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
GROUP BY acl.name, acl.arn, acl.region
HAVING COUNT(r.id) = 0;
```

## AWS-CLOUDFRONT: CloudFront Issues

### AWS-CF-1 [CRITICAL] CloudFront Distributions Without WAF
```sql
SELECT 
    cf.aws_distribution_id,
    cf.domain_name,
    cf.comment,
    cf.enabled,
    cf.web_acl_id,
    'CRITICAL: CloudFront distribution has no WAF protection' as finding
FROM aws_raw_cloudfront_distribution_history cf
WHERE cf.organization_id = '{ORGANIZATION_ID}'
AND cf.is_deleted = false
AND cf.enabled = true
AND (cf.web_acl_id IS NULL OR cf.web_acl_id = '');

-- Best Practice: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html
```

## AWS-ALB: Load Balancer Issues

### AWS-ALB-1 [CRITICAL] ALBs Without WAF Protection
```sql
SELECT 
    lb.load_balancer_name,
    lb.load_balancer_arn,
    lb.dns_name,
    lb.scheme,
    lb.type,
    'CRITICAL: Application Load Balancer without WAF protection' as finding
FROM aws_raw_load_balancers_history lb
WHERE lb.organization_id = '{ORGANIZATION_ID}'
AND lb.is_deleted = false
AND lb.type = 'application'
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_associated_resources_history ar
    WHERE ar.arn = lb.load_balancer_arn
    AND ar.is_deleted = false
);
```

### AWS-ALB-2 [HIGH] ALB Security Groups Too Permissive
```sql
SELECT 
    lb.load_balancer_name,
    sg.security_group_name,
    sgi.source::text,
    sgi.from_port,
    sgi.to_port,
    sgi.protocol::text,
    'HIGH: ALB security group has overly permissive inbound rules' as finding
FROM aws_raw_load_balancers_history lb
JOIN aws_raw_load_balancer_security_groups_history lbsg ON lb.id = lbsg.load_balancer_id AND lbsg.is_deleted = false
JOIN aws_raw_security_groups_history sg ON lbsg.security_group_id = sg.id AND sg.is_deleted = false
JOIN aws_raw_security_group_inbounds_history sgi ON sg.id = sgi.security_group_id AND sgi.is_deleted = false
WHERE lb.organization_id = '{ORGANIZATION_ID}'
AND lb.type = 'application'
AND sgi.source::text LIKE '%0.0.0.0/0%'
AND lb.is_deleted = false;
```

## AWS-RULES: Rule Configuration Issues

### AWS-RULES-1 [HIGH] Rules in COUNT Mode (Log Only)
```sql
SELECT 
    acl.name as acl_name,
    r.name as rule_name,
    r.priority,
    r.action::text,
    r.description,
    'HIGH: Rule in COUNT mode - detects but does not block' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id AND r.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND r.action::text = 'count'
AND acl.is_deleted = false
ORDER BY acl.name, r.priority;

-- Best Practice: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-actions.html
```

### AWS-RULES-2 [CRITICAL] Managed Rule Groups Overridden to COUNT
```sql
SELECT 
    acl.name as acl_name,
    r.name as rule_name,
    r.managed_rule_group_vendor_name,
    r.managed_rule_group_name,
    r.override_action::text,
    'CRITICAL: Managed rule group overridden to COUNT - protection disabled' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id AND r.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND r.override_action::text = 'count'
AND r.managed_rule_group_name IS NOT NULL
AND r.managed_rule_group_name != ''
AND acl.is_deleted = false;
```

### AWS-RULES-3 [HIGH] Individual Managed Rule Overrides
```sql
SELECT 
    acl.name as acl_name,
    mro.managed_rule_group_name,
    mro.rule_name,
    mro.override_action::text,
    'HIGH: Individual managed rule overridden' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_acl_managed_rule_group_rule_override_history mro ON acl.id = mro.waf_acl_id AND mro.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND mro.override_action::text = 'count'
AND acl.is_deleted = false;
```

## AWS-MANAGED: Missing Managed Rule Groups

### AWS-MANAGED-1 [CRITICAL] Missing Core Rule Set (CRS)
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    'CRITICAL: Missing AWS Managed Rules Common Rule Set (CRS)' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rules_history r
    WHERE r.waf_acl_id = acl.id
    AND r.is_deleted = false
    AND (
        r.managed_rule_group_name ILIKE '%CommonRuleSet%'
        OR r.managed_rule_group_name ILIKE '%AWSManagedRulesCommonRuleSet%'
    )
);

-- Best Practice: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
```

### AWS-MANAGED-2 [HIGH] Missing Known Bad Inputs Rule Set
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    'HIGH: Missing AWS Known Bad Inputs Rule Set' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rules_history r
    WHERE r.waf_acl_id = acl.id
    AND r.is_deleted = false
    AND r.managed_rule_group_name ILIKE '%KnownBadInputsRuleSet%'
);
```

### AWS-MANAGED-3 [HIGH] Missing SQLi Protection
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    'HIGH: Missing SQL injection protection' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rules_history r
    WHERE r.waf_acl_id = acl.id
    AND r.is_deleted = false
    AND (
        r.managed_rule_group_name ILIKE '%SQLiRuleSet%'
        OR r.managed_rule_group_name ILIKE '%SQLDatabase%'
    )
)
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rule_statements_history rs
    WHERE rs.waf_acl_id = acl.id
    AND rs.is_deleted = false
    AND rs.type::text = 'sqli_match_statement'
);
```

### AWS-MANAGED-4 [HIGH] Missing Bot Control
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    'HIGH: Missing AWS Bot Control rule group' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rules_history r
    WHERE r.waf_acl_id = acl.id
    AND r.is_deleted = false
    AND (
        r.managed_rule_group_name ILIKE '%BotControl%'
        OR r.managed_rule_group_name ILIKE '%Bot%'
    )
);

-- Best Practice: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html
```

## AWS-RATE: Rate Limiting Issues

### AWS-RATE-1 [HIGH] No Rate-Based Rules
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    'HIGH: No rate-based rules configured' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rule_statements_history rs
    WHERE rs.waf_acl_id = acl.id
    AND rs.is_deleted = false
    AND rs.type::text = 'rate_based_statement'
);
```

### AWS-RATE-2 [HIGH] Rate Limits Too High
```sql
SELECT 
    acl.name as acl_name,
    rs.rate_limit,
    rs.evaluation_window_sec,
    (rs.rate_limit::float / rs.evaluation_window_sec * 60) as requests_per_minute,
    'HIGH: Rate limit threshold very permissive' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rule_statements_history rs ON acl.id = rs.waf_acl_id AND rs.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND rs.type::text = 'rate_based_statement'
AND rs.rate_limit > 10000
AND acl.is_deleted = false;
```

## AWS-LOGGING: Logging/Monitoring Issues

### AWS-LOGGING-1 [CRITICAL] WAF Logging Disabled
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    'CRITICAL: WAF logging not configured' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_logging_configurations_history lc
    WHERE lc.waf_acl_id = acl.id AND lc.is_deleted = false
);

-- Best Practice: https://docs.aws.amazon.com/waf/latest/developerguide/logging.html
```

### AWS-LOGGING-2 [HIGH] CloudWatch Metrics Disabled
```sql
SELECT 
    acl.name as acl_name,
    r.name as rule_name,
    r.cloudwatch_metrics_enabled,
    'HIGH: CloudWatch metrics disabled for rule' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id AND r.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND r.cloudwatch_metrics_enabled = false
AND acl.is_deleted = false;
```

### AWS-LOGGING-3 [HIGH] Sample Requests Disabled
```sql
SELECT 
    acl.name as acl_name,
    r.name as rule_name,
    r.sample_request_enabled,
    'HIGH: Sample request collection disabled' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id AND r.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND r.sample_request_enabled = false
AND acl.is_deleted = false;
```

## AWS-IPSET: IP Set Issues

### AWS-IPSET-1 [HIGH] Overly Broad IP Allowlists
```sql
SELECT 
    acl.name as acl_name,
    ips.name as ip_set_name,
    ips.ip_addresses_type::text,
    ips.ip_addresses,
    'HIGH: IP set contains broad CIDR ranges' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rule_statements_history rs ON acl.id = rs.waf_acl_id AND rs.is_deleted = false
JOIN aws_raw_waf_acl_statement_ip_set_history ips ON rs.ip_set_id = ips.id AND ips.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND EXISTS (
    SELECT 1 FROM unnest(ips.ip_addresses) ip
    WHERE ip LIKE '%/8' OR ip LIKE '%/16' OR ip LIKE '%/0'
);
```

### AWS-IPSET-2 [CRITICAL] Empty IP Sets Referenced
```sql
SELECT 
    acl.name as acl_name,
    ips.name as ip_set_name,
    array_length(ips.ip_addresses, 1) as ip_count,
    'CRITICAL: Rule references empty IP set' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rule_statements_history rs ON acl.id = rs.waf_acl_id AND rs.is_deleted = false
JOIN aws_raw_waf_acl_statement_ip_set_history ips ON rs.ip_set_id = ips.id AND ips.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND (ips.ip_addresses IS NULL OR array_length(ips.ip_addresses, 1) = 0)
AND acl.is_deleted = false;
```

---

<a name="aws-logs"></a>
# AWS WAF Log Analysis (Trino)

> **IMPORTANT: Partition Keys Required!**
> All AWS WAF log queries require: `organization`, `accountid`, `region`, `acl`, `year`, `month`, `day`, `hour`
> Replace placeholders with specific values discovered from PostgreSQL.

## AWS-LOG-ACTION: Action Distribution

### AWS-LOG-ACTION-1 [CRITICAL] COUNT Actions on Detected Threats
```sql
SELECT 
    httprequest.host as host,
    httprequest.uri as uri,
    httprequest.httpmethod as method,
    terminatingruleid,
    terminatingruletype,
    action,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.aws_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND accountid = '{AWS_ACCOUNT_ID}'  -- Required partition key
AND region = '{AWS_REGION}'         -- Required partition key
AND acl = '{ACL_NAME}'              -- Required partition key
AND year = {YEAR} AND month = {MONTH} AND day = {DAY} AND hour = {HOUR}
AND action = 'COUNT'
GROUP BY httprequest.host, httprequest.uri, httprequest.httpmethod, 
         terminatingruleid, terminatingruletype, action
HAVING COUNT(*) > 50
ORDER BY occurrences DESC;

-- CRITICAL: COUNT = detected but not blocked
-- NOTE: Iterate over multiple hours/days for broader analysis
```

### AWS-LOG-ACTION-2 [CRITICAL] SQLi/XSS Detections Not Blocked
```sql
SELECT 
    httprequest.host as host,
    httprequest.uri as uri,
    md.conditiontype,
    md.location,
    md.matcheddata,
    action,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.aws_waf_logs.raw
CROSS JOIN UNNEST(terminatingrulematchdetails) AS t(md)
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND md.conditiontype IN ('SQL_INJECTION', 'XSS')
AND action != 'BLOCK'
GROUP BY httprequest.host, httprequest.uri, md.conditiontype, 
         md.location, md.matcheddata, action
ORDER BY occurrences DESC;

-- CRITICAL: SQLi/XSS detections must result in BLOCK
```

## AWS-LOG-LABEL: Label Analysis

### AWS-LOG-LABEL-1 [HIGH] Security Labels on Allowed Traffic
```sql
SELECT 
    label.name as label_name,
    httprequest.host as host,
    httprequest.uri as uri,
    action,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.aws_waf_logs.raw
CROSS JOIN UNNEST(labels) AS l(label)
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    label.name LIKE '%:bot:%'
    OR label.name LIKE '%:sqli:%'
    OR label.name LIKE '%:xss:%'
    OR label.name LIKE '%:lfi:%'
    OR label.name LIKE '%:rfi:%'
    OR label.name LIKE '%:bad-input%'
)
AND action != 'BLOCK'
GROUP BY label.name, httprequest.host, httprequest.uri, action
HAVING COUNT(*) > 20
ORDER BY occurrences DESC;

-- HIGH: Security-related labels should trigger BLOCK action
```

## AWS-LOG-CHALLENGE: Challenge Analysis

### AWS-LOG-CHALLENGE-1 [HIGH] Repeated CAPTCHA Failures
```sql
SELECT 
    httprequest.host as host,
    httprequest.uri as uri,
    captcharesponse.responsecode as captcha_response,
    captcharesponse.failurereason as failure_reason,
    COUNT(*) as failures
FROM huskeys_customers_logs.aws_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND captcharesponse IS NOT NULL
AND captcharesponse.responsecode != '200'
GROUP BY httprequest.host, httprequest.uri, 
         captcharesponse.responsecode, captcharesponse.failurereason
ORDER BY failures DESC
LIMIT 50;
```

---

<a name="cross-vendor"></a>
# Cross-Vendor Correlation

## CROSS-1: Config-to-Log Validation
```sql
-- Step 1: Get SKIP rules from config (PostgreSQL)
SELECT z.name, r.description, r.expression
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action::text ILIKE '%skip%' AND r.enabled = true
AND z.is_deleted = false;

-- Step 2: Check if SKIP rules are being exploited (Trino)
SELECT 
    clientrequesthost,
    clientrequestpath,
    securityaction,
    AVG(wafattackscore) as avg_attack_score,
    COUNT(*) as requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND securityaction = 'skip'
AND wafattackscore > 30
GROUP BY clientrequesthost, clientrequestpath, securityaction
ORDER BY avg_attack_score DESC;

-- FINDING: If SKIP traffic has high attack scores, bypass rules are being exploited
```

---

## Best Practices References

### Cloudflare
- [WAF Managed Rules](https://developers.cloudflare.com/waf/managed-rules/)
- [Bot Management](https://developers.cloudflare.com/bots/get-started/)
- [Rate Limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/)
- [WAF Attack Score](https://developers.cloudflare.com/waf/about/waf-attack-score/)
- [Skip Rules](https://developers.cloudflare.com/waf/custom-rules/skip/)
- [Proxied DNS](https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/)

### Akamai
- [Attack Groups](https://techdocs.akamai.com/application-security/docs/attack-groups)
- [Adaptive Security Engine](https://techdocs.akamai.com/application-security/docs/adaptive-security-engine)
- [Rate Limiting](https://techdocs.akamai.com/application-security/docs/rate-limiting)
- [Bot Manager](https://techdocs.akamai.com/bot-manager/docs/welcome)

### AWS WAF
- [AWS Managed Rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html)
- [Rule Actions](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-actions.html)
- [WAF Logging](https://docs.aws.amazon.com/waf/latest/developerguide/logging.html)
- [Bot Control](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html)
- [Default Action](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-default-action.html)

---

# ADVANCED FINDINGS - Part 2

## CF-LOG-ADVANCED: Advanced Cloudflare Log Analysis

### CF-LOG-ADV-1 [CRITICAL] Path Traversal Attempts Allowed
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientrequesturi,
    clientip,
    securityaction,
    wafattackscore,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    clientrequesturi LIKE '%../%'
    OR clientrequesturi LIKE '%..\\%'
    OR clientrequesturi LIKE '%/etc/passwd%'
    OR clientrequesturi LIKE '%/proc/self%'
    OR clientrequesturi LIKE '%/windows/system32%'
)
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge', 'drop')
GROUP BY clientrequesthost, clientrequestpath, clientrequesturi, clientip, securityaction, wafattackscore
ORDER BY occurrences DESC
LIMIT 100;
```

### CF-LOG-ADV-2 [CRITICAL] Server Side Request Forgery (SSRF) Patterns
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    clientrequesturi LIKE '%http://%'
    OR clientrequesturi LIKE '%https://%'
    OR clientrequesturi LIKE '%127.0.0.1%'
    OR clientrequesturi LIKE '%localhost%'
    OR clientrequesturi LIKE '%169.254.169.254%'  -- AWS metadata
    OR clientrequesturi LIKE '%metadata.google%'   -- GCP metadata
    OR clientrequesturi LIKE '%gopher://%'
    OR clientrequesturi LIKE '%file://%'
)
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge', 'drop')
GROUP BY clientrequesthost, clientrequestpath, clientip, securityaction
HAVING COUNT(*) > 5
ORDER BY occurrences DESC;
```

### CF-LOG-ADV-3 [HIGH] Suspicious File Upload Extensions
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientrequestmethod,
    securityaction,
    COALESCE(CAST(contentscanobjtypes AS VARCHAR), '') as content_types,
    COALESCE(CAST(contentscanobjresults AS VARCHAR), '') as scan_results,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND clientrequestmethod IN ('POST', 'PUT')
AND (
    clientrequestpath LIKE '%.php%'
    OR clientrequestpath LIKE '%.asp%'
    OR clientrequestpath LIKE '%.aspx%'
    OR clientrequestpath LIKE '%.jsp%'
    OR clientrequestpath LIKE '%.exe%'
    OR clientrequestpath LIKE '%.sh%'
    OR clientrequestpath LIKE '%.bat%'
)
AND securityaction NOT IN ('block', 'drop')
GROUP BY clientrequesthost, clientrequestpath, clientrequestmethod, securityaction, 
         CAST(contentscanobjtypes AS VARCHAR), CAST(contentscanobjresults AS VARCHAR)
ORDER BY occurrences DESC;
```

### CF-LOG-ADV-4 [HIGH] XML External Entity (XXE) Patterns
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    wafattackscore,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    clientrequesturi LIKE '%<!ENTITY%'
    OR clientrequesturi LIKE '%SYSTEM%file://%'
    OR clientrequesturi LIKE '%SYSTEM%http://%'
    OR clientrequesturi LIKE '%<!DOCTYPE%'
)
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge', 'drop')
GROUP BY clientrequesthost, clientrequestpath, clientip, securityaction, wafattackscore
ORDER BY occurrences DESC;
```

### CF-LOG-ADV-5 [HIGH] Open Redirect Patterns
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    clientrequesturi LIKE '%redirect=%'
    OR clientrequesturi LIKE '%url=%'
    OR clientrequesturi LIKE '%next=%'
    OR clientrequesturi LIKE '%return=%'
    OR clientrequesturi LIKE '%goto=%'
    OR clientrequesturi LIKE '%target=%'
)
AND (
    clientrequesturi LIKE '%http://%'
    OR clientrequesturi LIKE '%https://%'
    OR clientrequesturi LIKE '%//%'
)
AND securityaction NOT IN ('block', 'challenge')
GROUP BY clientrequesthost, clientrequestpath, clientip, securityaction
HAVING COUNT(*) > 10
ORDER BY occurrences DESC;
```

### CF-LOG-ADV-6 [CRITICAL] Log4Shell/JNDI Injection Patterns
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    clientrequestuseragent,
    securityaction,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    clientrequesturi LIKE '%${jndi:%'
    OR clientrequesturi LIKE '%$%7bjndi%'
    OR clientrequestuseragent LIKE '%${jndi:%'
    OR clientrequestuseragent LIKE '%$%7bjndi%'
)
AND securityaction NOT IN ('block', 'drop')
GROUP BY clientrequesthost, clientrequestpath, clientip, clientrequestuseragent, securityaction
ORDER BY occurrences DESC;
```

### CF-LOG-ADV-7 [HIGH] WebShell Detection Patterns
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    clientrequestpath LIKE '%cmd=%'
    OR clientrequestpath LIKE '%exec=%'
    OR clientrequestpath LIKE '%shell=%'
    OR clientrequestpath LIKE '%system=%'
    OR clientrequestpath LIKE '%passthru=%'
    OR clientrequestpath LIKE '%eval=%'
    OR clientrequesturi LIKE '%whoami%'
    OR clientrequesturi LIKE '%id%20%'
    OR clientrequesturi LIKE '%uname%'
)
AND securityaction NOT IN ('block', 'challenge', 'drop')
GROUP BY clientrequesthost, clientrequestpath, clientip, securityaction
ORDER BY occurrences DESC;
```

## CF-LOG-GEO: Geographic Analysis

### CF-LOG-GEO-1 [HIGH] High-Risk Country Traffic to Sensitive Endpoints
```sql
SELECT 
    clientcountry,
    clientrequesthost,
    clientrequestpath,
    COUNT(*) as requests,
    COUNT(DISTINCT clientip) as unique_ips,
    SUM(CASE WHEN wafattackscore > 30 THEN 1 ELSE 0 END) as suspicious_requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND clientcountry IN ('RU', 'CN', 'KP', 'IR', 'CU', 'SY')  -- Adjust as needed
AND (
    clientrequestpath ILIKE '%/api/%'
    OR clientrequestpath ILIKE '%/admin%'
    OR clientrequestpath ILIKE '%/login%'
    OR clientrequestpath ILIKE '%/auth%'
)
AND securityaction NOT IN ('block', 'challenge', 'drop')
GROUP BY clientcountry, clientrequesthost, clientrequestpath
HAVING COUNT(*) > 50
ORDER BY requests DESC;
```

### CF-LOG-GEO-2 [HIGH] Authentication from Multiple Countries (Account Compromise)
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    COUNT(DISTINCT clientcountry) as country_count,
    COUNT(DISTINCT clientip) as ip_count,
    ARRAY_AGG(DISTINCT clientcountry) as countries
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND clientrequestpath ILIKE ANY(ARRAY['%login%', '%signin%', '%auth%', '%token%'])
AND clientrequestmethod = 'POST'
AND edgeresponsestatus IN (200, 302, 303)
GROUP BY clientrequesthost, clientrequestpath
HAVING COUNT(DISTINCT clientcountry) > 10
ORDER BY country_count DESC;
```

## CF-LOG-TLS: TLS/SSL Analysis

### CF-LOG-TLS-1 [HIGH] Weak TLS Versions Still Allowed
```sql
SELECT 
    clientrequesthost,
    clientsslprotocol,
    COUNT(*) as requests,
    COUNT(DISTINCT clientip) as unique_ips
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND clientsslprotocol IN ('TLSv1', 'TLSv1.1', 'SSLv3')
GROUP BY clientrequesthost, clientsslprotocol
ORDER BY requests DESC;

-- Best Practice: Disable TLS 1.0 and 1.1
-- https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/
```

### CF-LOG-TLS-2 [HIGH] Weak Cipher Suites Still Allowed
```sql
SELECT 
    clientrequesthost,
    clientsslcipher,
    COUNT(*) as requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    clientsslcipher LIKE '%RC4%'
    OR clientsslcipher LIKE '%DES%'
    OR clientsslcipher LIKE '%MD5%'
    OR clientsslcipher LIKE '%NULL%'
    OR clientsslcipher LIKE '%EXPORT%'
)
GROUP BY clientrequesthost, clientsslcipher
ORDER BY requests DESC;
```

### CF-LOG-TLS-3 [HIGH] Non-HTTPS Traffic to Sensitive Endpoints
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientrequestscheme,
    COUNT(*) as requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND clientrequestscheme = 'http'
AND (
    clientrequestpath ILIKE '%/api/%'
    OR clientrequestpath ILIKE '%/auth%'
    OR clientrequestpath ILIKE '%/login%'
    OR clientrequestpath ILIKE '%/admin%'
    OR clientrequestpath ILIKE '%/payment%'
)
GROUP BY clientrequesthost, clientrequestpath, clientrequestscheme
ORDER BY requests DESC;
```

## CF-LOG-PERFORMANCE: Performance Impact Analysis

### CF-LOG-PERF-1 [HIGH] Slow Origin Responses (Potential DoS Target)
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    AVG(originresponsedurationms) as avg_origin_time_ms,
    MAX(originresponsedurationms) as max_origin_time_ms,
    COUNT(*) as requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND originresponsedurationms > 5000  -- > 5 seconds
GROUP BY clientrequesthost, clientrequestpath
HAVING COUNT(*) > 100
ORDER BY avg_origin_time_ms DESC;

-- Slow endpoints are potential targets for application DoS
```

### CF-LOG-PERF-2 [HIGH] Large Request Bodies (Potential DoS)
```sql
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientrequestmethod,
    AVG(clientrequestbytes) as avg_request_size,
    MAX(clientrequestbytes) as max_request_size,
    COUNT(*) as requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND clientrequestbytes > 1048576  -- > 1MB
GROUP BY clientrequesthost, clientrequestpath, clientrequestmethod
ORDER BY max_request_size DESC
LIMIT 50;
```

## AWS-LOG-ADVANCED: Advanced AWS WAF Log Analysis

### AWS-LOG-ADV-1 [CRITICAL] Excluded Rules with High Match Counts
```sql
SELECT 
    httprequest.host as host,
    rg.rulegroupid,
    er.ruleid as excluded_rule,
    er.exclusiontype,
    COUNT(*) as match_count
FROM huskeys_customers_logs.aws_waf_logs.raw
CROSS JOIN UNNEST(rulegrouplist) AS r(rg)
CROSS JOIN UNNEST(rg.excludedrules) AS e(er)
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND er.ruleid IS NOT NULL
GROUP BY httprequest.host, rg.rulegroupid, er.ruleid, er.exclusiontype
ORDER BY match_count DESC
LIMIT 50;

-- CRITICAL: Excluded rules that match frequently may indicate misconfiguration or bypass exploitation
```

### AWS-LOG-ADV-2 [HIGH] Overridden Rules Matching Traffic
```sql
SELECT 
    httprequest.host as host,
    rg.rulegroupid,
    nmr.ruleid,
    nmr.action as actual_action,
    nmr.overriddenaction as original_action,
    COUNT(*) as match_count
FROM huskeys_customers_logs.aws_waf_logs.raw
CROSS JOIN UNNEST(rulegrouplist) AS r(rg)
CROSS JOIN UNNEST(rg.nonterminatingmatchingrules) AS n(nmr)
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND nmr.overriddenaction IS NOT NULL
AND nmr.overriddenaction != ''
GROUP BY httprequest.host, rg.rulegroupid, nmr.ruleid, nmr.action, nmr.overriddenaction
ORDER BY match_count DESC;

-- HIGH: Rules whose actions were overridden from BLOCK to COUNT
```

### AWS-LOG-ADV-3 [CRITICAL] Sensitive Data in Request URIs
```sql
SELECT 
    httprequest.host as host,
    httprequest.uri as uri,
    httprequest.httpmethod as method,
    action,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.aws_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    httprequest.uri LIKE '%password=%'
    OR httprequest.uri LIKE '%apikey=%'
    OR httprequest.uri LIKE '%api_key=%'
    OR httprequest.uri LIKE '%secret=%'
    OR httprequest.uri LIKE '%token=%'
    OR httprequest.uri LIKE '%jwt=%'
)
GROUP BY httprequest.host, httprequest.uri, httprequest.httpmethod, action
ORDER BY occurrences DESC;

-- CRITICAL: Sensitive data in URIs - data exposure and logging risk
```

### AWS-LOG-ADV-4 [HIGH] Request Body Size Truncation
```sql
SELECT 
    httprequest.host as host,
    httprequest.uri as uri,
    requestbodysize,
    requestbodysizeinspectedbywaf,
    (requestbodysize - requestbodysizeinspectedbywaf) as bytes_not_inspected,
    oversizefields,
    COUNT(*) as occurrences
FROM huskeys_customers_logs.aws_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND requestbodysize > requestbodysizeinspectedbywaf
AND requestbodysizeinspectedbywaf > 0
GROUP BY httprequest.host, httprequest.uri, requestbodysize, 
         requestbodysizeinspectedbywaf, oversizefields
ORDER BY bytes_not_inspected DESC;

-- HIGH: Large payloads may bypass WAF inspection
```

### AWS-LOG-ADV-5 [HIGH] Bot Label Analysis
```sql
SELECT 
    label.name as bot_label,
    httprequest.host as host,
    httprequest.uri as uri,
    action,
    COUNT(*) as detections
FROM huskeys_customers_logs.aws_waf_logs.raw
CROSS JOIN UNNEST(labels) AS l(label)
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND label.name LIKE '%:bot:%'
AND action != 'BLOCK'
GROUP BY label.name, httprequest.host, httprequest.uri, action
HAVING COUNT(*) > 100
ORDER BY detections DESC;
```

---

# ADDITIONAL CLOUDFLARE CONFIG FINDINGS

## CF-SECURITY: Zone Security Settings

### CF-SEC-1 [HIGH] Development Mode Enabled in Production
```sql
SELECT 
    z.name as zone_name,
    z.development_mode,
    'HIGH: Development mode enabled on production zone' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND z.development_mode > 0
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);

-- Development mode disables caching and may affect security features
```

## CF-ZONE: Zone Configuration Analysis

### CF-ZONE-1 [HIGH] Paused Zones Still Receiving Traffic
```sql
SELECT 
    z.name as zone_name,
    z.paused,
    z.status,
    'HIGH: Paused zone may have inconsistent protection' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.paused = true
AND z.status = 'active';
```

### CF-ZONE-2 [HIGH] Non-Active Zone Status
```sql
SELECT 
    z.name as zone_name,
    z.status,
    z.plan_name,
    'HIGH: Zone not in active status' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status != 'active'
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

### CF-ZONE-3 [HIGH] Zones Without Enterprise Plan on Sensitive Domains
```sql
SELECT 
    z.name as zone_name,
    z.plan_name,
    'HIGH: Sensitive zone without Enterprise plan features' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND z.plan_name NOT LIKE '%Enterprise%'
AND z.name ~* '(api|auth|login|admin|payment|prod|production)';
```

---

# ADDITIONAL AKAMAI FINDINGS

## AK-WAF: WAF Core Issues

### AK-WAF-1 [HIGH] Policies Without Application Layer Controls
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    sp.apply_application_layer_controls,
    'HIGH: Security policy missing application layer controls' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND sp.apply_application_layer_controls = false;
```

### AK-WAF-2 [HIGH] Policies Without Slow POST Controls
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    sp.apply_slow_post_controls,
    'HIGH: Security policy missing slow POST controls' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND sp.apply_slow_post_controls = false;

-- Best Practice: https://techdocs.akamai.com/application-security/docs/slow-post-protection
```

### AK-WAF-3 [HIGH] Policies Without Reputation Controls
```sql
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    sp.apply_reputation_controls,
    'HIGH: Security policy missing reputation controls' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND sp.apply_reputation_controls = false;
```

---

# ADDITIONAL AWS WAF FINDINGS

## AWS-SPECIFIC: Specific Rule Issues

### AWS-SPEC-1 [HIGH] Geo Match Rules Too Permissive
```sql
SELECT 
    acl.name as acl_name,
    r.name as rule_name,
    rs.country_codes,
    'HIGH: Geo match rule may be too permissive' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id AND r.is_deleted = false
JOIN aws_raw_waf_acl_rule_statements_history rs ON acl.id = rs.waf_acl_id AND rs.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND rs.type::text = 'geo_match_statement'
AND array_length(rs.country_codes, 1) > 100
AND acl.is_deleted = false;
```

### AWS-SPEC-2 [HIGH] Size Constraint Rules Missing
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    'HIGH: No size constraint rules - vulnerable to large payload attacks' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rule_statements_history rs
    WHERE rs.waf_acl_id = acl.id
    AND rs.is_deleted = false
    AND rs.type::text = 'size_constraint_statement'
);
```

### AWS-SPEC-3 [HIGH] Missing Anonymous IP List
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    'HIGH: Missing AWS IP reputation list rule (anonymous proxies)' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rules_history r
    WHERE r.waf_acl_id = acl.id
    AND r.is_deleted = false
    AND (
        r.managed_rule_group_name ILIKE '%AnonymousIPList%'
        OR r.managed_rule_group_name ILIKE '%AmazonIpReputationList%'
    )
);

-- Best Practice: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-ip-rep.html
```

### AWS-SPEC-4 [HIGH] Missing Account Takeover Prevention
```sql
SELECT 
    acl.name as acl_name,
    acl.arn,
    'HIGH: Missing AWS Managed Rules for account takeover prevention' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rules_history r
    WHERE r.waf_acl_id = acl.id
    AND r.is_deleted = false
    AND r.managed_rule_group_name ILIKE '%ATP%'
);

-- Best Practice: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-atp.html
```

---

## Appendix: Trino Partition Key Reference

### Cloudflare WAF Logs
```
Partition Keys (ALL REQUIRED): organization, zone, year, month, day, hour
Example: WHERE organization = 'customer' AND zone = 'api.example.com' AND year = 2024 AND month = 12 AND day = 29

IMPORTANT: The 'zone' partition key is REQUIRED for all Cloudflare queries.
To query across all zones, first discover zones from PostgreSQL:
  SELECT DISTINCT z.name FROM cloudflare_raw_zones_history z 
  WHERE z.organization_id = '{ORG_ID}' AND z.is_deleted = false;
Then iterate over zones or use UNION queries.
```

### AWS WAF Logs
```
Partition Keys (ALL REQUIRED): organization, accountid, region, acl, year, month, day, hour
Example: WHERE organization = 'customer' AND accountid = '123456789012' AND region = 'us-east-1' AND acl = 'my-waf-acl' AND year = 2024 AND month = 12 AND day = 29

IMPORTANT: The accountid, region, and acl partition keys are REQUIRED.
To discover ACLs, query PostgreSQL:
  SELECT DISTINCT acl.name, acl.region FROM aws_raw_waf_acl_history acl
  WHERE acl.organization_id = '{ORG_ID}' AND acl.is_deleted = false;
```

---

*Document Version: 3.0*  
*Last Updated: December 30, 2025*

