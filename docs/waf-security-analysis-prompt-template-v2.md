# WAF Security Analysis Prompt Template v2.0
## Multi-Vendor Edition: Cloudflare | Akamai | AWS WAF

**Purpose:** Comprehensive prompt for performing deep-dive WAF security analysis across multiple vendors using PostgreSQL (configurations) and Trino (logs).

**Severity Focus:** HIGH and CRITICAL findings only.

**Data Sources:**
- **PostgreSQL**: Configuration state (misconfigurations)
- **Trino**: Runtime behavior (log analysis) - *Cloudflare & AWS WAF only; Akamai logs not yet available*

**Related Documents:**
- 📋 [**Expanded Findings Catalog v3.0**](./waf-security-analysis-expanded-findings-v3.md) - Complete catalog of 100+ HIGH/CRITICAL findings with verified SQL queries

---

## Table of Contents

1. [Phase 1: Customer Identification & Vendor Detection](#phase-1)
2. [Phase 2: CLOUDFLARE Analysis](#phase-2-cloudflare)
3. [Phase 3: AKAMAI Analysis](#phase-3-akamai)
4. [Phase 4: AWS WAF Analysis](#phase-4-aws)
5. [Phase 5: Cross-Vendor Log Analysis (Trino)](#phase-5-trino)
6. [Phase 6: Cross-Reference & Validation](#phase-6)
7. [Appendix: Complete Finding Catalog](#appendix)

---

## Variables Reference

```
{CUSTOMER_NAME}     - Customer/Organization name
{ORGANIZATION_ID}   - PostgreSQL organization UUID
{ZONE_NAME}         - Specific zone/domain name
{YEAR}              - Current year (2025)
{MONTH}             - Current month
{DAY}               - Current/recent day
{LOOKBACK_DAYS}     - Analysis window (default: 7)
```

---

<a name="phase-1"></a>
## Phase 1: Customer Identification & Vendor Detection

### 1.1 Identify Customer Organization
```sql
-- Find organization by name across ALL vendor integrations
SELECT 
    o.id as organization_id,
    o.org_name,
    o.org_display_name,
    CASE 
        WHEN cf.id IS NOT NULL THEN 'Cloudflare'
        WHEN ak.id IS NOT NULL THEN 'Akamai'
        WHEN aws.id IS NOT NULL THEN 'AWS'
    END as vendor,
    COALESCE(cf.is_active, ak.is_active, aws.is_active) as integration_active
FROM organization o
LEFT JOIN organization_cloudflare_integration cf ON o.id = cf.organization_id AND cf.is_deleted = false
LEFT JOIN organization_akamai_integration ak ON o.id = ak.organization_id AND ak.is_deleted = false
LEFT JOIN organization_aws_integration aws ON o.id = aws.organization_id AND aws.is_deleted = false
WHERE lower(o.org_name) LIKE '%{customer_name_lowercase}%'
   OR lower(o.org_display_name) LIKE '%{customer_name_lowercase}%'
AND o.is_deleted = false;
```

### 1.2 Detect Active WAF Vendors for Customer
```sql
-- Cloudflare zones count
SELECT COUNT(*) as cloudflare_zones
FROM cloudflare_raw_zones_history 
WHERE organization_id = '{ORGANIZATION_ID}' AND is_deleted = false;

-- Akamai security configs count
SELECT COUNT(DISTINCT sc.id) as akamai_security_configs
FROM akamai_raw_security_configurations_history sc
WHERE sc.organization_id = '{ORGANIZATION_ID}' AND sc.is_deleted = false;

-- AWS WAF ACLs count
SELECT COUNT(*) as aws_waf_acls
FROM aws_raw_waf_acl_history
WHERE organization_id = '{ORGANIZATION_ID}' AND is_deleted = false;
```

### 1.3 Verify Trino Log Availability
```sql
-- Cloudflare logs check
SELECT organization, zone, year, month, day, COUNT(*) as events
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH}
GROUP BY organization, zone, year, month, day
ORDER BY year DESC, month DESC, day DESC
LIMIT 10;

-- AWS WAF logs check  
SELECT organization, accountid, region, acl, year, month, day, COUNT(*) as events
FROM huskeys_customers_logs.aws_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH}
GROUP BY organization, accountid, region, acl, year, month, day
ORDER BY year DESC, month DESC, day DESC
LIMIT 10;

-- NOTE: Akamai logs NOT YET AVAILABLE in Trino
```

---

<a name="phase-2-cloudflare"></a>
## Phase 2: CLOUDFLARE Configuration Analysis (PostgreSQL)

### Category CF-1: Unprotected Assets

#### CF-1.1 [CRITICAL] Production Zones Without ANY WAF Rulesets
```sql
-- Zones with ZERO WAF protection
SELECT 
    z.name as zone_name,
    z.status,
    z.plan_name,
    z.created_on,
    'CRITICAL: No WAF rulesets deployed' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    WHERE ri.zone_id = z.id AND ri.is_deleted = false
)
-- Exclude non-production environments
AND z.name NOT LIKE '%dev%'
AND z.name NOT LIKE '%test%'
AND z.name NOT LIKE '%staging%'
AND z.name NOT LIKE '%stg%'
AND z.name NOT LIKE '%uat%'
AND z.name NOT LIKE '%sandbox%'
AND z.name NOT LIKE '%demo%'
AND z.name NOT LIKE '%poc%'
AND z.name NOT LIKE '%internal%'
ORDER BY z.name;

-- Best Practice Reference: Cloudflare recommends enabling WAF Managed Rules on all production zones
-- https://developers.cloudflare.com/waf/managed-rules/
```

#### CF-1.2 [CRITICAL] High-Value Zones Without Protection
```sql
-- API, Auth, and sensitive zones without WAF
SELECT 
    z.name as zone_name,
    CASE
        WHEN z.name ~* '(api|apis)' THEN 'API Endpoint'
        WHEN z.name ~* '(auth|login|signin|sso|oauth|keycloak|okta)' THEN 'Authentication'
        WHEN z.name ~* '(account|myaccount|profile|user)' THEN 'User Account'
        WHEN z.name ~* '(admin|management|console|dashboard)' THEN 'Admin Portal'
        WHEN z.name ~* '(payment|pay|checkout|billing|stripe)' THEN 'Payment'
        WHEN z.name ~* '(mobile|app|ios|android)' THEN 'Mobile Backend'
        WHEN z.name ~* '(upload|file|storage|cdn|assets)' THEN 'File Upload'
        WHEN z.name ~* '(webhook|callback|notify)' THEN 'Webhook Endpoint'
    END as asset_type,
    'CRITICAL: High-value zone unprotected' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND (
    z.name ~* '(api|apis|auth|login|signin|sso|oauth|keycloak|okta|account|myaccount|profile|user|admin|management|console|dashboard|payment|pay|checkout|billing|mobile|app|upload|file|webhook)'
)
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    WHERE ri.zone_id = z.id AND ri.is_deleted = false
)
ORDER BY asset_type, z.name;
```

#### CF-1.3 [CRITICAL] Missing OWASP Core Ruleset
```sql
-- Zones without OWASP/Managed WAF ruleset
SELECT 
    z.name as zone_name,
    COALESCE(
        (SELECT COUNT(*) FROM cloudflare_raw_rulesets_instance_history ri 
         JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
         WHERE ri.zone_id = z.id AND ri.is_deleted = false AND rs.is_deleted = false
         AND (rs.name ILIKE '%managed%' OR rs.name ILIKE '%owasp%' OR rs.kind = 'managed')),
        0
    ) as managed_ruleset_count,
    'CRITICAL: Missing OWASP/Managed ruleset' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.status = 'active'
AND z.name NOT LIKE '%dev%' AND z.name NOT LIKE '%test%' AND z.name NOT LIKE '%staging%'
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
    WHERE ri.zone_id = z.id AND ri.is_deleted = false AND rs.is_deleted = false
    AND (rs.name ILIKE '%managed%' OR rs.name ILIKE '%owasp%' OR rs.kind = 'managed')
);

-- Best Practice: Deploy Cloudflare Managed Ruleset which includes OWASP Top 10 protection
-- https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/
```

### Category CF-2: Detection Without Protection (LOG Mode)

#### CF-2.1 [HIGH] WAF Rules in LOG Mode on Production
```sql
-- Rules detecting attacks but not blocking
SELECT 
    z.name as zone_name,
    rs.name as ruleset_name,
    rs.phase,
    r.description as rule_description,
    r.action,
    r.expression,
    'HIGH: Rule in LOG mode - attacks detected but not blocked' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'log'
AND r.enabled = true
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false
AND z.name NOT LIKE '%dev%' AND z.name NOT LIKE '%test%' AND z.name NOT LIKE '%staging%'
ORDER BY z.name, rs.name, r.description;

-- Best Practice: Rules should transition from LOG to BLOCK after validation period
-- https://developers.cloudflare.com/waf/managed-rules/deploy-zone-dashboard/#configure-a-rule
```

#### CF-2.2 [CRITICAL] CVE/Vulnerability Rules in LOG Mode
```sql
-- Security-critical rules only logging, not blocking
SELECT 
    z.name as zone_name,
    r.description as rule_description,
    r.ref as rule_ref,
    r.categories::text,
    'CRITICAL: Vulnerability/CVE rule in LOG mode' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'log'
AND r.enabled = true
AND (
    r.description ILIKE '%cve-%'
    OR r.description ILIKE '%vulnerability%'
    OR r.description ILIKE '%exploit%'
    OR r.description ILIKE '%injection%'
    OR r.description ILIKE '%rce%'
    OR r.description ILIKE '%remote code%'
    OR r.description ILIKE '%shell%'
    OR r.categories::text ILIKE '%cve%'
)
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false
ORDER BY z.name;

-- Best Practice: CVE-related rules should ALWAYS be in BLOCK mode
```

#### CF-2.3 [HIGH] Credential Leak Detection Rules in LOG Mode
```sql
-- Leaked credential detection not blocking
SELECT 
    z.name as zone_name,
    r.description,
    r.action,
    'HIGH: Credential leak detection in LOG mode' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'log'
AND (
    r.description ILIKE '%credential%'
    OR r.description ILIKE '%leaked%'
    OR r.description ILIKE '%password%'
    OR r.description ILIKE '%exposed%'
)
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false;
```

### Category CF-3: WAF Bypass Rules (SKIP)

#### CF-3.1 [HIGH] SKIP Rules Without IP Restrictions
```sql
-- WAF bypass rules that don't restrict by source IP
SELECT 
    z.name as zone_name,
    r.description as rule_description,
    r.expression,
    r.action_parameters::text as skip_config,
    'HIGH: WAF bypass without IP restriction - easily exploitable' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'skip'
AND r.enabled = true
AND r.expression NOT LIKE '%ip.src%'
AND r.expression NOT LIKE '%ip.geoip%'
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false
ORDER BY z.name;

-- Best Practice: All WAF exceptions should include IP-based restrictions
-- https://developers.cloudflare.com/waf/custom-rules/skip/
```

#### CF-3.2 [HIGH] User-Agent Based Bypass Rules (Spoofable)
```sql
-- SKIP rules based on easily-spoofed User-Agent header
SELECT 
    z.name as zone_name,
    r.description,
    r.expression,
    'HIGH: User-Agent based bypass - trivially spoofable' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'skip'
AND r.enabled = true
AND (
    r.expression ILIKE '%http.user_agent%'
    OR r.expression ILIKE '%user-agent%'
)
AND r.expression NOT LIKE '%ip.src%'
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false;
```

#### CF-3.3 [HIGH] Overly Broad Path-Based Bypass
```sql
-- SKIP rules with broad path patterns
SELECT 
    z.name as zone_name,
    r.description,
    r.expression,
    'HIGH: Overly broad path bypass - potential attack vector' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'skip'
AND r.enabled = true
AND (
    r.expression LIKE '%starts_with%"/%'
    OR r.expression LIKE '%http.request.uri.path eq "/"'
    OR r.expression LIKE '%http.request.uri.path contains ""'
    OR r.expression ~ 'uri\.path\s+(eq|contains)\s+"/"'
)
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false;
```

#### CF-3.4 [CRITICAL] SKIP Rules Bypassing All WAF Phases
```sql
-- Rules that skip ALL WAF protection
SELECT 
    z.name as zone_name,
    r.description,
    r.expression,
    spp.phase as skipped_phase,
    'CRITICAL: Rule bypasses entire WAF phase' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
LEFT JOIN cloudflare_raw_rulesets_rule_skip_action_parameters_phases spp ON r.id = spp.rule_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'skip'
AND r.enabled = true
AND spp.phase IS NOT NULL
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false;
```

#### CF-3.5 [HIGH] Zones with Excessive SKIP Rules
```sql
-- Zones with too many bypass rules (attack surface expansion)
SELECT 
    z.name as zone_name,
    COUNT(*) as skip_rule_count,
    'HIGH: Excessive SKIP rules increase attack surface' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'skip'
AND r.enabled = true
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false
GROUP BY z.name
HAVING COUNT(*) > 5
ORDER BY skip_rule_count DESC;
```

### Category CF-4: DNS/Origin Exposure

#### CF-4.1 [HIGH] Unproxied DNS Records Exposing Origin IPs
```sql
-- A/AAAA records not behind Cloudflare proxy
SELECT 
    z.name as zone_name,
    d.name as dns_record,
    d.type,
    d.content as exposed_ip,
    CASE
        WHEN d.name ~* '(api|auth|login|admin|payment|internal|db|database|backend)' THEN 'CRITICAL'
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

#### CF-4.2 [CRITICAL] Sensitive Subdomain Origins Exposed
```sql
-- High-value subdomains with exposed IPs
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
AND d.is_deleted = false AND z.is_deleted = false;
```

### Category CF-5: Bot Management Gaps

#### CF-5.1 [HIGH] Bot Management Disabled or Misconfigured
```sql
-- Zones without proper bot management
SELECT 
    z.name as zone_name,
    bm.fight_mode,
    bm.enable_js as js_detection_enabled,
    bm.sbfm_definitely_automated,
    bm.sbfm_likely_automated,
    bm.sbfm_verified_bots,
    bm.ai_bots_protection,
    CASE
        WHEN bm.id IS NULL THEN 'CRITICAL: No bot management configured'
        WHEN bm.fight_mode = false AND bm.sbfm_definitely_automated = 'allow' THEN 'HIGH: Bot fight mode disabled'
        WHEN bm.sbfm_definitely_automated = 'allow' THEN 'HIGH: Automated bots allowed'
        WHEN bm.enable_js = false THEN 'HIGH: JS detection disabled'
        ELSE 'OK'
    END as finding
FROM cloudflare_raw_zones_history z
LEFT JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.name NOT LIKE '%dev%' AND z.name NOT LIKE '%test%'
AND (
    bm.id IS NULL
    OR bm.fight_mode = false
    OR bm.sbfm_definitely_automated = 'allow'
);

-- Best Practice: Enable Super Bot Fight Mode and JS detection
-- https://developers.cloudflare.com/bots/get-started/
```

#### CF-5.2 [HIGH] AI Bot Scraping Allowed
```sql
-- Zones allowing AI/ML scraping bots
SELECT 
    z.name as zone_name,
    bm.ai_bots_protection,
    'HIGH: AI bot scraping protection disabled' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND bm.ai_bots_protection != 'block'
AND z.is_deleted = false AND bm.is_deleted = false
AND z.name NOT LIKE '%dev%' AND z.name NOT LIKE '%test%';
```

### Category CF-6: Rate Limiting Gaps

#### CF-6.1 [HIGH] No Rate Limiting on Authentication Endpoints
```sql
-- Auth zones/paths without rate limiting rules
SELECT 
    z.name as zone_name,
    'HIGH: No rate limiting detected on authentication zone' as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND z.is_deleted = false
AND z.name ~* '(auth|login|signin|sso|oauth)'
AND NOT EXISTS (
    SELECT 1 
    FROM cloudflare_raw_rulesets_instance_history ri
    JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
    JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
    LEFT JOIN cloudflare_raw_rulesets_rule_rate_limits rl ON r.id = rl.rule_id
    WHERE ri.zone_id = z.id 
    AND ri.is_deleted = false AND rs.is_deleted = false AND r.is_deleted = false
    AND (rl.id IS NOT NULL OR rs.phase = 'http_ratelimit')
);
```

#### CF-6.2 [HIGH] Rate Limits with High Thresholds
```sql
-- Rate limits that are too permissive
SELECT 
    z.name as zone_name,
    r.description,
    rl.requests_per_period,
    rl.period,
    (rl.requests_per_period::float / rl.period * 60) as requests_per_minute,
    'HIGH: Rate limit threshold too high' as finding
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
JOIN cloudflare_raw_rulesets_rule_rate_limits rl ON r.id = rl.rule_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND rl.requests_per_period > 1000
AND rl.period <= 60
AND r.enabled = true
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false AND rl.is_deleted = false;

-- Best Practice: Auth endpoints should have strict rate limits (e.g., 5-10 req/min)
```

### Category CF-7: Traffic Metrics Analysis

#### CF-7.1 [CRITICAL] High SKIP Rate (WAF Bypass Traffic)
```sql
-- Zones with excessive WAF bypass traffic
WITH zone_metrics AS (
    SELECT 
        z.name as zone_name,
        m.security_action,
        SUM(m.metric_value) as total_events
    FROM cloudflare_raw_zone_metrics_history m
    JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
    WHERE z.organization_id = '{ORGANIZATION_ID}'
    AND m.metric_timestamp >= NOW() - INTERVAL '{LOOKBACK_DAYS} days'
    AND m.is_deleted = false AND z.is_deleted = false
    GROUP BY z.name, m.security_action
),
zone_totals AS (
    SELECT zone_name, SUM(total_events) as grand_total
    FROM zone_metrics
    GROUP BY zone_name
)
SELECT 
    zm.zone_name,
    zm.total_events as skip_events,
    zt.grand_total as total_events,
    ROUND(100.0 * zm.total_events / NULLIF(zt.grand_total, 0), 2) as skip_percentage,
    'CRITICAL: High WAF bypass rate' as finding
FROM zone_metrics zm
JOIN zone_totals zt ON zm.zone_name = zt.zone_name
WHERE zm.security_action = 'skip'
AND (100.0 * zm.total_events / NULLIF(zt.grand_total, 0)) > 30
ORDER BY skip_percentage DESC;
```

#### CF-7.2 [HIGH] High LOG Rate (Detection Without Blocking)
```sql
-- Zones detecting but not blocking attacks
WITH zone_metrics AS (
    SELECT 
        z.name as zone_name,
        m.security_action,
        m.security_source,
        SUM(m.metric_value) as total_events
    FROM cloudflare_raw_zone_metrics_history m
    JOIN cloudflare_raw_zones_history z ON m.zone_id = z.id
    WHERE z.organization_id = '{ORGANIZATION_ID}'
    AND m.metric_timestamp >= NOW() - INTERVAL '{LOOKBACK_DAYS} days'
    AND m.security_action = 'log'
    AND m.is_deleted = false AND z.is_deleted = false
    GROUP BY z.name, m.security_action, m.security_source
)
SELECT 
    zone_name,
    security_source,
    total_events as logged_attacks,
    'HIGH: Attacks being logged but not blocked' as finding
FROM zone_metrics
WHERE total_events > 1000
ORDER BY total_events DESC;
```

---

<a name="phase-3-akamai"></a>
## Phase 3: AKAMAI Configuration Analysis (PostgreSQL)

> **NOTE:** Akamai logs are NOT YET AVAILABLE in Trino. Analysis is configuration-based only.

### Category AK-1: Unprotected Assets

#### AK-1.1 [CRITICAL] Security Policies with No Attack Group Protection
```sql
-- Security policies with attack groups in NONE/disabled state
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    sp.akamai_id as policy_id,
    ag.name as attack_group,
    ag.action,
    'CRITICAL: Attack group protection disabled' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id
JOIN akamai_raw_security_policy_attack_groups_history ag ON sp.id = ag.security_policy_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND ag.action IN ('none', 'alert')  -- ALERT = LOG mode equivalent
AND sc.is_deleted = false AND sp.is_deleted = false AND ag.is_deleted = false
ORDER BY sc.name, sp.name, ag.name;

-- Best Practice: Akamai attack groups should be in DENY mode for production
-- https://techdocs.akamai.com/application-security/docs/attack-groups
```

#### AK-1.2 [CRITICAL] Match Targets Without WAF Protection Controls
```sql
-- Match targets with application layer controls disabled
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    mt.type as match_target_type,
    mt.apply_application_layer_controls,
    mt.apply_rate_controls,
    mt.apply_reputation_controls,
    mt.apply_slow_post_controls,
    mt.apply_botman_controls,
    'CRITICAL: WAF protection controls disabled on match target' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id
JOIN akamai_raw_security_configuration_match_targets_history mt ON sp.id = mt.security_policy_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND (
    mt.apply_application_layer_controls = false
    OR mt.apply_rate_controls = false
    OR mt.apply_reputation_controls = false
)
AND sc.is_deleted = false AND sp.is_deleted = false AND mt.is_deleted = false;
```

#### AK-1.3 [HIGH] Hostnames Without Security Policy Coverage
```sql
-- Hostnames in security config but not covered by match targets
SELECT 
    sc.name as security_config_name,
    sc.production_hostnames,
    'HIGH: Review hostname coverage against match targets' as finding
FROM akamai_raw_security_configurations_history sc
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false
AND array_length(sc.production_hostnames, 1) > 0;

-- Cross-reference with match target hostnames
SELECT 
    sc.name as security_config_name,
    mth.hostname,
    'Covered hostname' as status
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id
JOIN akamai_raw_security_configuration_match_targets_history mt ON sp.id = mt.security_policy_id
JOIN akamai_raw_security_config_match_target_hostnames_history mth ON mt.id = mth.match_target_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sc.is_deleted = false AND mth.is_deleted = false;
```

### Category AK-2: Detection Without Protection (ALERT Mode)

#### AK-2.1 [HIGH] Attack Groups in ALERT Mode
```sql
-- Attack groups only alerting, not denying
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    ag.name as attack_group,
    ag.action,
    'HIGH: Attack group in ALERT mode - detects but does not block' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id
JOIN akamai_raw_security_policy_attack_groups_history ag ON sp.id = ag.security_policy_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND ag.action = 'alert'
AND sc.is_deleted = false AND sp.is_deleted = false AND ag.is_deleted = false
ORDER BY sc.name, ag.name;

-- Best Practice: ALERT mode should only be used during initial deployment/testing
```

#### AK-2.2 [HIGH] Rapid Rules in Non-Deny Mode
```sql
-- Rapid/ASE rules not blocking
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    rr.title as rapid_rule,
    rr.action,
    rr.akamai_id as rule_id,
    'HIGH: Rapid rule not in deny mode' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id
JOIN akamai_raw_security_policy_rapid_rules_history rr ON sp.id = rr.security_policy_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND rr.action NOT IN ('deny', 'deny_custom')
AND rr.locked = false
AND sc.is_deleted = false AND sp.is_deleted = false AND rr.is_deleted = false;
```

#### AK-2.3 [CRITICAL] Custom Rules in ALERT Mode
```sql
-- Custom security rules not blocking
SELECT 
    sc.name as security_config_name,
    cr.name as custom_rule_name,
    cr.description,
    cr.status,
    cr.is_activated,
    'CRITICAL: Custom rule not activated or in non-blocking mode' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_sec_config_custom_rules_history cr ON sc.id = cr.config_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND (cr.is_activated = false OR cr.status != 'activated')
AND sc.is_deleted = false AND cr.is_deleted = false;
```

### Category AK-3: Rate Limiting Gaps

#### AK-3.1 [HIGH] Rate Policies with Zero/High Thresholds
```sql
-- Rate policies with ineffective thresholds
SELECT 
    sc.name as security_config_name,
    rp.name as rate_policy_name,
    rp.average_threshold,
    rp.burst_threshold,
    rp.burst_window,
    rp.counter_type,
    CASE
        WHEN rp.average_threshold = 0 AND rp.burst_threshold = 0 THEN 'CRITICAL: Rate limiting disabled'
        WHEN rp.average_threshold > 10000 OR rp.burst_threshold > 10000 THEN 'HIGH: Threshold too permissive'
        ELSE 'OK'
    END as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_sec_config_rate_policies_history rp ON scv.id = rp.config_version_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND (
    (rp.average_threshold = 0 AND rp.burst_threshold = 0)
    OR rp.average_threshold > 10000
    OR rp.burst_threshold > 10000
)
AND rp.used = true
AND sc.is_deleted = false AND rp.is_deleted = false;

-- Best Practice: Rate limits should be tuned based on legitimate traffic patterns
-- https://techdocs.akamai.com/application-security/docs/rate-limiting
```

#### AK-3.2 [HIGH] Rate Policy Actions Not Denying
```sql
-- Rate policy actions set to alert instead of deny
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    rpa.ipv4_action,
    rpa.ipv6_action,
    'HIGH: Rate policy action not set to deny' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id
JOIN akamai_raw_security_policy_rate_policy_actions_history rpa ON sp.id = rpa.security_policy_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND (rpa.ipv4_action NOT LIKE '%deny%' OR rpa.ipv6_action NOT LIKE '%deny%')
AND sc.is_deleted = false AND sp.is_deleted = false AND rpa.is_deleted = false;
```

### Category AK-4: Bot Management Gaps

#### AK-4.1 [HIGH] Bot Category Actions Not Blocking
```sql
-- Bot categories set to allow/monitor instead of block
SELECT 
    sc.name as security_config_name,
    bc.name as bot_category,
    bca.action,
    'HIGH: Bot category not being blocked' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id
JOIN akamai_raw_bot_category_actions_history bca ON sp.id = bca.security_policy_id
JOIN akamai_raw_bot_categories_history bc ON bca.category_id = bc.id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND bca.action NOT IN ('deny', 'tarpit', 'slow')
AND bc.name NOT LIKE '%verified%'
AND sc.is_deleted = false AND sp.is_deleted = false AND bca.is_deleted = false AND bc.is_deleted = false;
```

#### AK-4.2 [HIGH] Bot Detection Actions Not Enforcing
```sql
-- Bot detections not taking blocking action
SELECT 
    sc.name as security_config_name,
    bd.name as bot_detection,
    bd.description,
    bda.action,
    'HIGH: Bot detection not enforcing' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id
JOIN akamai_raw_bot_detection_actions_history bda ON sp.id = bda.security_policy_id
JOIN akamai_raw_bot_detections_history bd ON bda.detection_id = bd.id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND bda.action NOT IN ('deny', 'tarpit')
AND bd.is_active_detection = true
AND sc.is_deleted = false AND sp.is_deleted = false AND bda.is_deleted = false AND bd.is_deleted = false;
```

### Category AK-5: WAF Bypass/Exceptions

#### AK-5.1 [HIGH] URL Protection Policy Bypass Conditions
```sql
-- URL protection policies with broad bypass conditions
SELECT 
    sc.name as security_config_name,
    upp.name as protection_policy_name,
    upbc.condition_type,
    upbc.positive_match,
    upbc.check_ips,
    'HIGH: URL protection bypass condition detected' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_sec_config_url_prot_pols_history upp ON scv.id = upp.config_version_id
JOIN akamai_raw_sec_config_url_prot_pol_bypass_conds_history upbc ON upp.id = upbc.url_prot_pol_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND upbc.check_ips != 'ip'  -- Not restricted by IP
AND sc.is_deleted = false AND upp.is_deleted = false AND upbc.is_deleted = false;
```

#### AK-5.2 [HIGH] Rapid Rules Disabled
```sql
-- Security policies with rapid rules disabled
SELECT 
    sc.name as security_config_name,
    sp.name as security_policy_name,
    sp.rapid_rules_enabled,
    'HIGH: Rapid rules (ASE) disabled on security policy' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND sp.rapid_rules_enabled = false
AND sc.is_deleted = false AND sp.is_deleted = false;

-- Best Practice: Rapid Rules provide zero-day protection
-- https://techdocs.akamai.com/application-security/docs/adaptive-security-engine
```

### Category AK-6: Logging & Visibility Gaps

#### AK-6.1 [HIGH] Attack Payload Logging Disabled
```sql
-- Security configs without attack payload logging
SELECT 
    sc.name as security_config_name,
    apls.enabled as payload_logging_enabled,
    apls.request_body_type,
    apls.response_body_type,
    'HIGH: Attack payload logging configuration issue' as finding
FROM akamai_raw_security_configurations_history sc
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id
LEFT JOIN akamai_raw_sec_config_attack_payload_log_settings_history apls ON scv.id = apls.config_version_id
WHERE sc.organization_id = '{ORGANIZATION_ID}'
AND (apls.id IS NULL OR apls.enabled = false)
AND sc.is_deleted = false;
```

### Category AK-7: DNS Exposure

#### AK-7.1 [HIGH] DNS Records Exposing Origin Infrastructure
```sql
-- Akamai DNS records potentially exposing origin
SELECT 
    dz.zone_name,
    dr.record_name,
    dr.record_type,
    dr.record_value,
    CASE
        WHEN dr.record_name ~* '(api|auth|login|admin|db|internal|backend)' THEN 'CRITICAL'
        ELSE 'HIGH'
    END as severity,
    'Origin infrastructure potentially exposed via DNS' as finding
FROM akamai_raw_dns_zones_history dz
JOIN akamai_raw_dns_records_history dr ON dz.id = dr.zone_id
WHERE dz.organization_id = '{ORGANIZATION_ID}'
AND dr.record_type IN ('A', 'AAAA', 'CNAME')
AND dr.record_value NOT LIKE '%.akamaiedge.%'
AND dr.record_value NOT LIKE '%.akamai.%'
AND dr.record_value NOT LIKE '%.edgekey.%'
AND dr.record_value NOT LIKE '%.edgesuite.%'
AND dz.is_deleted = false AND dr.is_deleted = false;
```

---

<a name="phase-4-aws"></a>
## Phase 4: AWS WAF Configuration Analysis (PostgreSQL)

### Category AWS-1: Unprotected Assets

#### AWS-1.1 [CRITICAL] Web ACLs Without Associated Resources
```sql
-- WAF ACLs not protecting any resources
SELECT 
    acl.name as acl_name,
    acl.arn,
    acl.region,
    acl.default_action,
    'CRITICAL: WAF ACL not associated with any resources' as finding
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_associated_resources_history ar
    WHERE ar.waf_acl_id = acl.id AND ar.is_deleted = false
);

-- Best Practice: WAF ACLs should be associated with ALB, CloudFront, or API Gateway
-- https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-aws-resource.html
```

#### AWS-1.2 [CRITICAL] Web ACLs with Default ALLOW Action
```sql
-- ACLs that allow traffic by default (fail-open)
SELECT 
    acl.name as acl_name,
    acl.arn,
    acl.region,
    acl.default_action,
    COUNT(DISTINCT ar.id) as associated_resources,
    'CRITICAL: ACL defaults to ALLOW - fail-open configuration' as finding
FROM aws_raw_waf_acl_history acl
LEFT JOIN aws_raw_waf_acl_associated_resources_history ar ON acl.id = ar.waf_acl_id AND ar.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.default_action = 'allow'
AND acl.is_deleted = false
GROUP BY acl.name, acl.arn, acl.region, acl.default_action;

-- Best Practice: Production ACLs should default to BLOCK
-- https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-default-action.html
```

#### AWS-1.3 [CRITICAL] CloudFront Distributions Without WAF
```sql
-- CloudFront distributions without WAF protection
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

-- Best Practice: All CloudFront distributions should have WAF enabled
-- https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html
```

#### AWS-1.4 [CRITICAL] Load Balancers Without WAF Protection
```sql
-- ALBs without WAF (cross-reference with ACL associations)
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

#### AWS-1.5 [HIGH] ACLs Without Any Rules
```sql
-- WAF ACLs with no rules defined (empty protection)
SELECT 
    acl.name as acl_name,
    acl.arn,
    acl.region,
    COUNT(r.id) as rule_count,
    'HIGH: WAF ACL has no rules - empty protection' as finding
FROM aws_raw_waf_acl_history acl
LEFT JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id AND r.is_deleted = false
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false
GROUP BY acl.name, acl.arn, acl.region
HAVING COUNT(r.id) = 0;
```

### Category AWS-2: Detection Without Protection (COUNT Mode)

#### AWS-2.1 [HIGH] Rules in COUNT Mode (Log Only)
```sql
-- Rules that count but don't block
SELECT 
    acl.name as acl_name,
    r.name as rule_name,
    r.priority,
    r.action,
    r.description,
    'HIGH: Rule in COUNT mode - detects but does not block' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'count'
AND acl.is_deleted = false AND r.is_deleted = false
ORDER BY acl.name, r.priority;

-- Best Practice: COUNT mode should only be used for testing/tuning
-- https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-actions.html
```

#### AWS-2.2 [CRITICAL] Managed Rule Groups with Override to COUNT
```sql
-- AWS Managed Rules overridden to COUNT
SELECT 
    acl.name as acl_name,
    r.name as rule_name,
    r.managed_rule_group_vendor_name,
    r.managed_rule_group_name,
    r.override_action,
    'CRITICAL: Managed rule group overridden to COUNT' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND r.override_action = 'count'
AND r.managed_rule_group_name != ''
AND acl.is_deleted = false AND r.is_deleted = false;

-- Best Practice: Managed rules should use NONE override (allow rules to execute)
```

#### AWS-2.3 [HIGH] Individual Managed Rule Overrides
```sql
-- Specific rules within managed groups overridden
SELECT 
    acl.name as acl_name,
    mro.managed_rule_group_name,
    mro.rule_name,
    mro.override_action,
    'HIGH: Individual managed rule overridden' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_acl_managed_rule_group_rule_override_history mro ON acl.id = mro.waf_acl_id
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND mro.override_action = 'count'
AND acl.is_deleted = false AND mro.is_deleted = false;
```

### Category AWS-3: Missing Managed Rule Groups

#### AWS-3.1 [CRITICAL] Missing Core Rule Set (CRS)
```sql
-- ACLs without AWS Core Rule Set
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

-- Best Practice: Deploy AWS Managed Rules Common Rule Set
-- https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
```

#### AWS-3.2 [HIGH] Missing Known Bad Inputs Rule Set
```sql
-- ACLs without Known Bad Inputs protection
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

#### AWS-3.3 [HIGH] Missing SQLi Protection
```sql
-- ACLs without SQL injection protection
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
    AND rs.type = 'sqli_match_statement'
);
```

#### AWS-3.4 [HIGH] Missing Bot Control
```sql
-- ACLs without bot protection
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

-- Best Practice: Enable AWS Bot Control for automated threat protection
-- https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html
```

### Category AWS-4: Rate Limiting Gaps

#### AWS-4.1 [HIGH] No Rate-Based Rules
```sql
-- ACLs without any rate limiting
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
    AND rs.type = 'rate_based_statement'
);
```

#### AWS-4.2 [HIGH] Rate Limits Too High
```sql
-- Rate limits with very high thresholds
SELECT 
    acl.name as acl_name,
    rs.rate_limit,
    rs.evaluation_window_sec,
    (rs.rate_limit::float / rs.evaluation_window_sec * 60) as requests_per_minute,
    'HIGH: Rate limit threshold too permissive' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rule_statements_history rs ON acl.id = rs.waf_acl_id
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND rs.type = 'rate_based_statement'
AND rs.rate_limit > 10000
AND acl.is_deleted = false AND rs.is_deleted = false;

-- Best Practice: Rate limits should be tuned to legitimate traffic patterns
-- https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html
```

### Category AWS-5: IP Set Issues

#### AWS-5.1 [HIGH] Overly Broad IP Allowlists
```sql
-- IP sets with very large CIDR blocks
SELECT 
    acl.name as acl_name,
    ips.name as ip_set_name,
    ips.ip_addresses_type,
    ips.ip_addresses,
    'HIGH: IP set contains broad CIDR ranges' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rule_statements_history rs ON acl.id = rs.waf_acl_id
JOIN aws_raw_waf_acl_statement_ip_set_history ips ON rs.ip_set_id = ips.id
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND acl.is_deleted = false AND rs.is_deleted = false AND ips.is_deleted = false
AND EXISTS (
    SELECT 1 FROM unnest(ips.ip_addresses) ip
    WHERE ip LIKE '%/8' OR ip LIKE '%/16' OR ip LIKE '%/0'
);
```

#### AWS-5.2 [CRITICAL] Empty IP Sets Referenced
```sql
-- Rules referencing empty IP sets
SELECT 
    acl.name as acl_name,
    ips.name as ip_set_name,
    array_length(ips.ip_addresses, 1) as ip_count,
    'CRITICAL: Rule references empty IP set' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rule_statements_history rs ON acl.id = rs.waf_acl_id
JOIN aws_raw_waf_acl_statement_ip_set_history ips ON rs.ip_set_id = ips.id
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND (ips.ip_addresses IS NULL OR array_length(ips.ip_addresses, 1) = 0)
AND acl.is_deleted = false AND rs.is_deleted = false AND ips.is_deleted = false;
```

### Category AWS-6: Logging & Monitoring Gaps

#### AWS-6.1 [CRITICAL] WAF Logging Disabled
```sql
-- ACLs without logging configuration
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

-- Best Practice: Enable WAF logging to S3, CloudWatch, or Kinesis
-- https://docs.aws.amazon.com/waf/latest/developerguide/logging.html
```

#### AWS-6.2 [HIGH] CloudWatch Metrics Disabled
```sql
-- Rules without CloudWatch metrics
SELECT 
    acl.name as acl_name,
    r.name as rule_name,
    r.cloudwatch_metrics_enabled,
    'HIGH: CloudWatch metrics disabled for rule' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND r.cloudwatch_metrics_enabled = false
AND acl.is_deleted = false AND r.is_deleted = false;
```

#### AWS-6.3 [HIGH] Sample Requests Disabled
```sql
-- Rules without sampled request logging
SELECT 
    acl.name as acl_name,
    r.name as rule_name,
    r.sample_request_enabled,
    'HIGH: Sample request collection disabled' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.waf_acl_id
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND r.sample_request_enabled = false
AND acl.is_deleted = false AND r.is_deleted = false;
```

### Category AWS-7: Custom Rule Issues

#### AWS-7.1 [HIGH] Regex Patterns Without Rate Limiting
```sql
-- Regex rules that could be used for ReDoS without rate limits
SELECT 
    acl.name as acl_name,
    rs.regex_string,
    'HIGH: Complex regex pattern without rate limiting' as finding
FROM aws_raw_waf_acl_history acl
JOIN aws_raw_waf_acl_rule_statements_history rs ON acl.id = rs.waf_acl_id
WHERE acl.organization_id = '{ORGANIZATION_ID}'
AND rs.type = 'regex_pattern_set_reference_statement'
AND rs.regex_string != ''
AND acl.is_deleted = false AND rs.is_deleted = false;
```

### Category AWS-8: Security Group Integration

#### AWS-8.1 [HIGH] ALB Security Groups Too Permissive
```sql
-- Security groups with open inbound rules
SELECT 
    lb.load_balancer_name,
    sg.security_group_name,
    sgi.source,
    sgi.from_port,
    sgi.to_port,
    sgi.protocol,
    'HIGH: ALB security group has overly permissive inbound rules' as finding
FROM aws_raw_load_balancers_history lb
JOIN aws_raw_load_balancer_security_groups_history lbsg ON lb.id = lbsg.load_balancer_id
JOIN aws_raw_security_groups_history sg ON lbsg.security_group_id = sg.id
JOIN aws_raw_security_group_inbounds_history sgi ON sg.id = sgi.security_group_id
WHERE lb.organization_id = '{ORGANIZATION_ID}'
AND lb.type = 'application'
AND sgi.source::text LIKE '%0.0.0.0/0%'
AND lb.is_deleted = false AND sg.is_deleted = false AND sgi.is_deleted = false;
```

---

<a name="phase-5-trino"></a>
## Phase 5: Log-Based Analysis (Trino)

> **IMPORTANT:** Akamai logs are NOT YET AVAILABLE. This section covers Cloudflare and AWS WAF only.

### Partition Strategy

Always use partition columns for efficient queries:
```sql
-- Cloudflare partitions: organization, zone, year, month, day, hour
-- AWS WAF partitions: organization, accountid, region, acl, year, month, day, hour
```

---

### CLOUDFLARE Log Analysis (Trino)

#### CF-LOG-1: Security Action Distribution

##### CF-LOG-1.1 [CRITICAL] Overall Protection Effectiveness
```sql
-- Calculate actual protection rate
SELECT 
    securityaction,
    COUNT(*) as event_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
GROUP BY securityaction
ORDER BY event_count DESC;

-- CRITICAL if: block < 80% of detected threats
-- CRITICAL if: skip > 20% of total traffic
-- CRITICAL if: allow on high attack score > 5%
```

##### CF-LOG-1.2 [CRITICAL] High Attack Score Events ALLOWED
```sql
-- Attacks with high WAF scores that were NOT blocked
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
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND wafattackscore >= 60
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge')
ORDER BY wafattackscore DESC
LIMIT 500;

-- CRITICAL: Any event with wafattackscore >= 60 that was allowed
-- Best Practice Reference: https://developers.cloudflare.com/waf/about/waf-attack-score/
```

##### CF-LOG-1.3 [CRITICAL] SQL Injection Attempts Allowed
```sql
-- SQLi attacks not blocked
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    wafsqliattackscore,
    clientrequesturi
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND wafsqliattackscore >= 50
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge')
ORDER BY wafsqliattackscore DESC
LIMIT 200;

-- CRITICAL: SQLi detection without blocking = active vulnerability
```

##### CF-LOG-1.4 [CRITICAL] XSS Attempts Allowed
```sql
-- XSS attacks not blocked
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    wafxssattackscore,
    clientrequesturi
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND wafxssattackscore >= 50
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge')
ORDER BY wafxssattackscore DESC
LIMIT 200;
```

##### CF-LOG-1.5 [CRITICAL] RCE Attempts Allowed
```sql
-- Remote Code Execution attempts not blocked
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientip,
    securityaction,
    wafrceattackscore,
    clientrequesturi
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND wafrceattackscore >= 50
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge')
ORDER BY wafrceattackscore DESC
LIMIT 200;

-- CRITICAL: RCE is highest severity - must be blocked
```

#### CF-LOG-2: Bot & Automated Traffic Analysis

##### CF-LOG-2.1 [HIGH] Low Bot Score Traffic NOT Challenged
```sql
-- Definite bots (low score) not being challenged
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
AND botscore <= 30  -- Definite bot
AND securityaction NOT IN ('block', 'challenge', 'managed_challenge')
GROUP BY clientrequesthost, botscore, botscoresrc, CAST(bottags AS VARCHAR), securityaction
HAVING COUNT(*) > 100
ORDER BY requests DESC
LIMIT 100;

-- HIGH: Definite bots (score ≤30) should be challenged/blocked
-- https://developers.cloudflare.com/bots/concepts/bot-score/
```

##### CF-LOG-2.2 [HIGH] Credential Stuffing Detection
```sql
-- Multiple IPs hitting login endpoints with failures
SELECT 
    clientrequesthost,
    clientrequestpath,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(*) as total_requests,
    SUM(CASE WHEN edgeresponsestatus >= 400 THEN 1 ELSE 0 END) as failed_requests
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
HAVING COUNT(DISTINCT clientip) > 50
ORDER BY unique_ips DESC;

-- HIGH: Multiple IPs targeting auth = potential credential stuffing
```

##### CF-LOG-2.3 [CRITICAL] Leaked Credentials Detected But Not Blocked
```sql
-- Leaked credential detections that weren't blocked
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

#### CF-LOG-3: Targeted Endpoint Analysis

##### CF-LOG-3.1 [HIGH] Most Attacked Endpoints
```sql
-- Endpoints receiving most attack traffic
SELECT 
    clientrequesthost,
    clientrequestpath,
    COUNT(*) as total_attacks,
    SUM(CASE WHEN securityaction = 'block' THEN 1 ELSE 0 END) as blocked,
    SUM(CASE WHEN securityaction NOT IN ('block', 'challenge') THEN 1 ELSE 0 END) as allowed,
    ROUND(100.0 * SUM(CASE WHEN securityaction = 'block' THEN 1 ELSE 0 END) / COUNT(*), 2) as block_rate
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND wafattackscore >= 40
GROUP BY clientrequesthost, clientrequestpath
HAVING COUNT(*) > 50
ORDER BY total_attacks DESC
LIMIT 50;

-- HIGH if block_rate < 80% on attacked endpoints
```

##### CF-LOG-3.2 [CRITICAL] Admin/Sensitive Paths Under Attack
```sql
-- Attacks on admin and sensitive endpoints
SELECT 
    clientrequesthost,
    clientrequestpath,
    securityaction,
    COUNT(*) as attacks,
    COUNT(DISTINCT clientip) as unique_attackers
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    clientrequestpath ILIKE '%admin%'
    OR clientrequestpath ILIKE '%wp-admin%'
    OR clientrequestpath ILIKE '%phpmyadmin%'
    OR clientrequestpath ILIKE '%/api/v%'
    OR clientrequestpath ILIKE '%graphql%'
    OR clientrequestpath ILIKE '%/internal/%'
    OR clientrequestpath ILIKE '%/.env%'
    OR clientrequestpath ILIKE '%/config%'
    OR clientrequestpath ILIKE '%/debug%'
    OR clientrequestpath ILIKE '%/actuator%'
)
AND wafattackscore >= 30
GROUP BY clientrequesthost, clientrequestpath, securityaction
ORDER BY attacks DESC;
```

##### CF-LOG-3.3 [HIGH] API Endpoints Attack Analysis
```sql
-- API-specific attack patterns
SELECT 
    clientrequesthost,
    clientrequestpath,
    clientrequestmethod,
    securityaction,
    AVG(wafattackscore) as avg_attack_score,
    COUNT(*) as requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND (
    clientrequestpath ILIKE '%/api/%'
    OR clientrequestpath ILIKE '%/v1/%'
    OR clientrequestpath ILIKE '%/v2/%'
    OR clientrequestpath ILIKE '%/graphql%'
    OR clientrequestpath ILIKE '%/rest/%'
)
AND wafattackscore >= 30
GROUP BY clientrequesthost, clientrequestpath, clientrequestmethod, securityaction
HAVING COUNT(*) > 20
ORDER BY avg_attack_score DESC;
```

#### CF-LOG-4: Security Rule Effectiveness

##### CF-LOG-4.1 [HIGH] Rules Triggering But Not Blocking
```sql
-- Rules detecting threats but not blocking
SELECT 
    securityruleid,
    securityruledescription,
    securityaction,
    COUNT(*) as triggers
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND securityruleid IS NOT NULL
AND securityruleid != ''
AND securityaction = 'log'
GROUP BY securityruleid, securityruledescription, securityaction
HAVING COUNT(*) > 100
ORDER BY triggers DESC;

-- HIGH: Rules in LOG mode with high trigger count should be promoted to BLOCK
```

##### CF-LOG-4.2 [HIGH] WAF Bypass Patterns
```sql
-- Requests bypassing WAF (SKIP action analysis)
SELECT 
    clientrequesthost,
    clientrequestpath,
    COALESCE(CAST(securitysources AS VARCHAR), 'none') as security_sources,
    COUNT(*) as skip_count,
    AVG(wafattackscore) as avg_attack_score
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND securityaction = 'skip'
GROUP BY clientrequesthost, clientrequestpath, CAST(securitysources AS VARCHAR)
HAVING AVG(wafattackscore) > 20 OR COUNT(*) > 10000
ORDER BY skip_count DESC;

-- HIGH: High attack scores with SKIP action = bypass exploitation
```

#### CF-LOG-5: Origin Exposure Detection

##### CF-LOG-5.1 [CRITICAL] Direct Origin IP Access
```sql
-- Requests that might indicate direct origin access
SELECT 
    clientrequesthost,
    originip,
    COUNT(*) as requests,
    COUNT(DISTINCT clientip) as unique_clients
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND originip IS NOT NULL
AND originip != ''
GROUP BY clientrequesthost, originip
ORDER BY requests DESC
LIMIT 50;

-- CRITICAL if originip is publicly known or matches unproxied DNS
```

#### CF-LOG-6: Anomaly Detection

##### CF-LOG-6.1 [HIGH] Unusual User-Agent Patterns
```sql
-- Suspicious user agents with high attack correlation
SELECT 
    clientrequestuseragent,
    COUNT(*) as requests,
    AVG(wafattackscore) as avg_attack_score,
    SUM(CASE WHEN wafattackscore >= 50 THEN 1 ELSE 0 END) as high_score_requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
GROUP BY clientrequestuseragent
HAVING AVG(wafattackscore) > 30 OR SUM(CASE WHEN wafattackscore >= 50 THEN 1 ELSE 0 END) > 50
ORDER BY avg_attack_score DESC
LIMIT 100;
```

##### CF-LOG-6.2 [HIGH] JA3/JA4 Fingerprint Analysis
```sql
-- Suspicious TLS fingerprints
SELECT 
    ja3hash,
    ja4,
    COUNT(*) as requests,
    COUNT(DISTINCT clientip) as unique_ips,
    AVG(wafattackscore) as avg_attack_score
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND ja3hash IS NOT NULL
GROUP BY ja3hash, ja4
HAVING AVG(wafattackscore) > 30
ORDER BY avg_attack_score DESC
LIMIT 50;

-- HIGH: Known malicious JA3 fingerprints should be blocked
```

---

### AWS WAF Log Analysis (Trino)

#### AWS-LOG-1: Action Distribution

##### AWS-LOG-1.1 [CRITICAL] Protection Effectiveness
```sql
-- Overall action distribution
SELECT 
    action,
    COUNT(*) as event_count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as percentage
FROM huskeys_customers_logs.aws_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
GROUP BY action
ORDER BY event_count DESC;

-- CRITICAL if: BLOCK < 80% of detected threats
-- CRITICAL if: ALLOW on rules that should block
```

##### AWS-LOG-1.2 [CRITICAL] COUNT Actions (Logged but Not Blocked)
```sql
-- Requests that were COUNTed but not blocked
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
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND action = 'COUNT'
GROUP BY httprequest.host, httprequest.uri, httprequest.httpmethod, 
         terminatingruleid, terminatingruletype, action
HAVING COUNT(*) > 50
ORDER BY occurrences DESC;

-- CRITICAL: COUNT = detected but not blocked
```

#### AWS-LOG-2: Rule Group Analysis

##### AWS-LOG-2.1 [HIGH] Managed Rule Triggers Not Blocking
```sql
-- Managed rules that matched but didn't block
SELECT 
    rg.rulegroupid,
    rg.terminatingrule.ruleid as terminating_rule,
    rg.terminatingrule.action as rule_action,
    COUNT(*) as triggers
FROM huskeys_customers_logs.aws_waf_logs.raw
CROSS JOIN UNNEST(rulegrouplist) AS t(rg)
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND rg.terminatingrule IS NOT NULL
AND rg.terminatingrule.action != 'BLOCK'
GROUP BY rg.rulegroupid, rg.terminatingrule.ruleid, rg.terminatingrule.action
HAVING COUNT(*) > 100
ORDER BY triggers DESC;
```

##### AWS-LOG-2.2 [HIGH] Excluded Rules Analysis
```sql
-- Rules that were excluded from evaluation
SELECT 
    rg.rulegroupid,
    excluded.ruleid as excluded_rule,
    excluded.exclusiontype,
    COUNT(*) as exclusion_count
FROM huskeys_customers_logs.aws_waf_logs.raw
CROSS JOIN UNNEST(rulegrouplist) AS t(rg)
CROSS JOIN UNNEST(rg.excludedrules) AS e(excluded)
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
GROUP BY rg.rulegroupid, excluded.ruleid, excluded.exclusiontype
ORDER BY exclusion_count DESC
LIMIT 50;

-- HIGH: Frequent rule exclusions may indicate overly broad exceptions
```

#### AWS-LOG-3: Attack Pattern Analysis

##### AWS-LOG-3.1 [CRITICAL] SQLi/XSS Detections Not Blocked
```sql
-- SQL injection and XSS matches that weren't blocked
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

##### AWS-LOG-3.2 [HIGH] Targeted Endpoints
```sql
-- Most targeted URIs
SELECT 
    httprequest.host as host,
    httprequest.uri as uri,
    httprequest.httpmethod as method,
    action,
    COUNT(*) as requests,
    COUNT(DISTINCT httprequest.clientip) as unique_ips
FROM huskeys_customers_logs.aws_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND terminatingruleid IS NOT NULL
GROUP BY httprequest.host, httprequest.uri, httprequest.httpmethod, action
HAVING COUNT(*) > 100
ORDER BY requests DESC
LIMIT 100;
```

#### AWS-LOG-4: Label Analysis

##### AWS-LOG-4.1 [HIGH] Security Labels on Allowed Traffic
```sql
-- Requests with security labels that were allowed
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
-- https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-label-match-examples.html
```

#### AWS-LOG-5: Challenge/CAPTCHA Effectiveness

##### AWS-LOG-5.1 [HIGH] Failed Challenge Attempts
```sql
-- CAPTCHA/Challenge failures
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

-- HIGH: Repeated CAPTCHA failures may indicate bot activity
```

#### AWS-LOG-6: Geographic Analysis

##### AWS-LOG-6.1 [HIGH] High-Risk Country Traffic
```sql
-- Requests from countries with high attack rates
SELECT 
    httprequest.country as country,
    action,
    COUNT(*) as requests,
    COUNT(DISTINCT httprequest.clientip) as unique_ips
FROM huskeys_customers_logs.aws_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND terminatingruleid IS NOT NULL  -- Only WAF-evaluated traffic
GROUP BY httprequest.country, action
ORDER BY requests DESC
LIMIT 50;

-- HIGH if high-risk countries have low block rates
```

---

<a name="phase-6"></a>
## Phase 6: Cross-Reference & Validation

### 6.1 Configuration-to-Log Correlation

#### 6.1.1 Validate SKIP Rules Against Log Traffic
```sql
-- PostgreSQL: Get SKIP rules
SELECT z.name, r.description, r.expression
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'skip' AND r.enabled = true
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false;

-- Trino: Check if SKIP rules are being exploited
SELECT 
    clientrequesthost,
    clientrequestpath,
    securityaction,
    wafattackscore,
    COUNT(*) as requests
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND securityaction = 'skip'
AND wafattackscore > 30
GROUP BY clientrequesthost, clientrequestpath, securityaction, wafattackscore
ORDER BY requests DESC;

-- FINDING: If SKIP traffic has high attack scores, the bypass rule is being exploited
```

#### 6.1.2 Validate LOG Mode Rules Against Actual Attacks
```sql
-- PostgreSQL: Get LOG mode rules
SELECT z.name, r.description, r.expression
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '{ORGANIZATION_ID}'
AND r.action = 'log' AND r.enabled = true
AND z.is_deleted = false AND ri.is_deleted = false 
AND rs.is_deleted = false AND r.is_deleted = false;

-- Trino: Check volume of attacks being logged but not blocked
SELECT 
    securityruleid,
    securityruledescription,
    COUNT(*) as logged_attacks,
    COUNT(DISTINCT clientip) as unique_attackers
FROM huskeys_customers_logs.cloudflare_waf_logs.raw
WHERE organization = '{CUSTOMER_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day >= {DAY} - {LOOKBACK_DAYS}
AND securityaction = 'log'
AND wafattackscore >= 40
GROUP BY securityruleid, securityruledescription
ORDER BY logged_attacks DESC;

-- FINDING: High attack volume on LOG rules = urgent need to switch to BLOCK
```

### 6.2 Best Practices Validation Checklist

#### Cloudflare Best Practices
| Check | Query | Best Practice Reference |
|-------|-------|------------------------|
| OWASP Core Ruleset deployed | CF-1.3 | [Managed Rules](https://developers.cloudflare.com/waf/managed-rules/) |
| No production zones unprotected | CF-1.1 | [WAF Overview](https://developers.cloudflare.com/waf/) |
| Bot Fight Mode enabled | CF-5.1 | [Bot Management](https://developers.cloudflare.com/bots/) |
| All DNS records proxied | CF-4.1 | [Proxied DNS](https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/) |
| Rate limiting on auth endpoints | CF-6.1 | [Rate Limiting](https://developers.cloudflare.com/waf/rate-limiting-rules/) |
| No CVE rules in LOG mode | CF-2.2 | [Security Best Practices](https://developers.cloudflare.com/fundamentals/basic-tasks/protect-your-origin-server/) |

#### Akamai Best Practices
| Check | Query | Best Practice Reference |
|-------|-------|------------------------|
| Attack groups in DENY mode | AK-2.1 | [Attack Groups](https://techdocs.akamai.com/application-security/docs/attack-groups) |
| Rapid Rules enabled | AK-5.2 | [ASE](https://techdocs.akamai.com/application-security/docs/adaptive-security-engine) |
| Rate policies configured | AK-3.1 | [Rate Limiting](https://techdocs.akamai.com/application-security/docs/rate-limiting) |
| Bot detection enforcing | AK-4.1 | [Bot Manager](https://techdocs.akamai.com/bot-manager/docs/welcome) |

#### AWS WAF Best Practices
| Check | Query | Best Practice Reference |
|-------|-------|------------------------|
| Common Rule Set deployed | AWS-3.1 | [AWS Managed Rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html) |
| No rules in COUNT mode | AWS-2.1 | [Rule Actions](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-actions.html) |
| WAF logging enabled | AWS-6.1 | [WAF Logging](https://docs.aws.amazon.com/waf/latest/developerguide/logging.html) |
| Bot Control enabled | AWS-3.4 | [Bot Control](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html) |
| Default action is BLOCK | AWS-1.2 | [Default Action](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-default-action.html) |

---

<a name="appendix"></a>
## Appendix A: Complete Finding Catalog

### CRITICAL Findings (Immediate Action Required)

| ID | Vendor | Category | Finding | Query |
|----|--------|----------|---------|-------|
| CF-1.1 | Cloudflare | Unprotected Assets | Production zones without WAF rulesets | PostgreSQL |
| CF-1.2 | Cloudflare | Unprotected Assets | High-value zones (API/Auth) unprotected | PostgreSQL |
| CF-1.3 | Cloudflare | Unprotected Assets | Missing OWASP/Managed ruleset | PostgreSQL |
| CF-2.2 | Cloudflare | LOG Mode | CVE/Vulnerability rules in LOG mode | PostgreSQL |
| CF-3.4 | Cloudflare | WAF Bypass | SKIP rules bypassing entire WAF phases | PostgreSQL |
| CF-4.2 | Cloudflare | DNS Exposure | Sensitive subdomain origins exposed | PostgreSQL |
| CF-7.1 | Cloudflare | Traffic | High SKIP rate (>30%) | PostgreSQL |
| CF-LOG-1.2 | Cloudflare | Log Analysis | High attack scores ALLOWED | Trino |
| CF-LOG-1.3 | Cloudflare | Log Analysis | SQLi attempts allowed | Trino |
| CF-LOG-1.5 | Cloudflare | Log Analysis | RCE attempts allowed | Trino |
| CF-LOG-2.3 | Cloudflare | Log Analysis | Leaked credentials not blocked | Trino |
| AK-1.1 | Akamai | Unprotected Assets | Attack groups disabled | PostgreSQL |
| AK-1.2 | Akamai | Unprotected Assets | Match targets without WAF controls | PostgreSQL |
| AK-2.3 | Akamai | ALERT Mode | Custom rules not activated | PostgreSQL |
| AWS-1.1 | AWS WAF | Unprotected Assets | ACLs without associated resources | PostgreSQL |
| AWS-1.2 | AWS WAF | Default Action | ACLs with default ALLOW | PostgreSQL |
| AWS-1.3 | AWS WAF | Unprotected Assets | CloudFront without WAF | PostgreSQL |
| AWS-1.4 | AWS WAF | Unprotected Assets | ALB without WAF | PostgreSQL |
| AWS-2.2 | AWS WAF | COUNT Mode | Managed rules overridden to COUNT | PostgreSQL |
| AWS-3.1 | AWS WAF | Missing Rules | Missing Core Rule Set | PostgreSQL |
| AWS-6.1 | AWS WAF | Logging | WAF logging disabled | PostgreSQL |
| AWS-LOG-1.2 | AWS WAF | Log Analysis | COUNT actions on detected threats | Trino |
| AWS-LOG-3.1 | AWS WAF | Log Analysis | SQLi/XSS detections not blocked | Trino |

### HIGH Findings (Action Required Within 48 Hours)

| ID | Vendor | Category | Finding | Query |
|----|--------|----------|---------|-------|
| CF-2.1 | Cloudflare | LOG Mode | WAF rules in LOG mode on production | PostgreSQL |
| CF-2.3 | Cloudflare | LOG Mode | Credential leak rules in LOG mode | PostgreSQL |
| CF-3.1 | Cloudflare | WAF Bypass | SKIP rules without IP restrictions | PostgreSQL |
| CF-3.2 | Cloudflare | WAF Bypass | User-agent based bypass (spoofable) | PostgreSQL |
| CF-3.3 | Cloudflare | WAF Bypass | Overly broad path-based bypass | PostgreSQL |
| CF-3.5 | Cloudflare | WAF Bypass | Excessive SKIP rules (>5) | PostgreSQL |
| CF-4.1 | Cloudflare | DNS Exposure | Unproxied DNS records | PostgreSQL |
| CF-5.1 | Cloudflare | Bot Management | Bot management disabled/misconfigured | PostgreSQL |
| CF-5.2 | Cloudflare | Bot Management | AI bot scraping allowed | PostgreSQL |
| CF-6.1 | Cloudflare | Rate Limiting | No rate limiting on auth endpoints | PostgreSQL |
| CF-6.2 | Cloudflare | Rate Limiting | Rate limits too high | PostgreSQL |
| CF-7.2 | Cloudflare | Traffic | High LOG rate (detection without blocking) | PostgreSQL |
| CF-LOG-1.4 | Cloudflare | Log Analysis | XSS attempts allowed | Trino |
| CF-LOG-2.1 | Cloudflare | Log Analysis | Low bot score traffic not challenged | Trino |
| CF-LOG-2.2 | Cloudflare | Log Analysis | Credential stuffing patterns | Trino |
| CF-LOG-3.1 | Cloudflare | Log Analysis | Attacked endpoints with low block rate | Trino |
| CF-LOG-4.1 | Cloudflare | Log Analysis | Rules triggering but not blocking | Trino |
| CF-LOG-4.2 | Cloudflare | Log Analysis | WAF bypass with high attack scores | Trino |
| CF-LOG-6.1 | Cloudflare | Log Analysis | Suspicious user-agent patterns | Trino |
| AK-1.3 | Akamai | Coverage | Hostname coverage gaps | PostgreSQL |
| AK-2.1 | Akamai | ALERT Mode | Attack groups in ALERT mode | PostgreSQL |
| AK-2.2 | Akamai | ALERT Mode | Rapid rules in non-deny mode | PostgreSQL |
| AK-3.1 | Akamai | Rate Limiting | Rate policies with zero/high thresholds | PostgreSQL |
| AK-3.2 | Akamai | Rate Limiting | Rate policy actions not denying | PostgreSQL |
| AK-4.1 | Akamai | Bot Management | Bot categories not blocking | PostgreSQL |
| AK-4.2 | Akamai | Bot Management | Bot detections not enforcing | PostgreSQL |
| AK-5.1 | Akamai | WAF Bypass | URL protection bypass conditions | PostgreSQL |
| AK-5.2 | Akamai | Configuration | Rapid rules disabled | PostgreSQL |
| AK-6.1 | Akamai | Logging | Attack payload logging disabled | PostgreSQL |
| AK-7.1 | Akamai | DNS Exposure | Origin infrastructure exposed | PostgreSQL |
| AWS-1.5 | AWS WAF | Configuration | ACLs with no rules | PostgreSQL |
| AWS-2.1 | AWS WAF | COUNT Mode | Rules in COUNT mode | PostgreSQL |
| AWS-2.3 | AWS WAF | COUNT Mode | Individual managed rule overrides | PostgreSQL |
| AWS-3.2 | AWS WAF | Missing Rules | Missing Known Bad Inputs | PostgreSQL |
| AWS-3.3 | AWS WAF | Missing Rules | Missing SQLi protection | PostgreSQL |
| AWS-3.4 | AWS WAF | Missing Rules | Missing Bot Control | PostgreSQL |
| AWS-4.1 | AWS WAF | Rate Limiting | No rate-based rules | PostgreSQL |
| AWS-4.2 | AWS WAF | Rate Limiting | Rate limits too high | PostgreSQL |
| AWS-5.1 | AWS WAF | IP Sets | Overly broad IP allowlists | PostgreSQL |
| AWS-6.2 | AWS WAF | Monitoring | CloudWatch metrics disabled | PostgreSQL |
| AWS-6.3 | AWS WAF | Monitoring | Sample requests disabled | PostgreSQL |
| AWS-8.1 | AWS WAF | Security Groups | ALB security groups too permissive | PostgreSQL |
| AWS-LOG-2.1 | AWS WAF | Log Analysis | Managed rules not blocking | Trino |
| AWS-LOG-2.2 | AWS WAF | Log Analysis | Excluded rules analysis | Trino |
| AWS-LOG-4.1 | AWS WAF | Log Analysis | Security labels on allowed traffic | Trino |
| AWS-LOG-5.1 | AWS WAF | Log Analysis | Failed challenge attempts | Trino |

---

## Appendix B: Quick Reference Tables

### PostgreSQL Tables by Vendor

| Vendor | Table | Purpose |
|--------|-------|---------|
| **Cloudflare** | cloudflare_raw_zones_history | Zone definitions |
| | cloudflare_raw_rulesets_history | Ruleset definitions |
| | cloudflare_raw_rulesets_rules_history | Individual rules |
| | cloudflare_raw_rulesets_instance_history | Zone-ruleset mapping |
| | cloudflare_raw_dns_records_history | DNS records |
| | cloudflare_raw_bot_management_history | Bot config |
| | cloudflare_raw_zone_metrics_history | Traffic metrics |
| | cloudflare_raw_rulesets_rule_rate_limits | Rate limit config |
| **Akamai** | akamai_raw_security_configurations_history | Security configs |
| | akamai_raw_security_policies_history | Security policies |
| | akamai_raw_security_policy_attack_groups_history | Attack group actions |
| | akamai_raw_security_policy_rapid_rules_history | Rapid/ASE rules |
| | akamai_raw_sec_config_rate_policies_history | Rate policies |
| | akamai_raw_bot_category_actions_history | Bot category actions |
| | akamai_raw_dns_records_history | DNS records |
| **AWS WAF** | aws_raw_waf_acl_history | WAF ACLs |
| | aws_raw_waf_acl_rules_history | ACL rules |
| | aws_raw_waf_acl_rule_statements_history | Rule statements |
| | aws_raw_waf_managed_rule_groups_history | Managed rule groups |
| | aws_raw_waf_acl_associated_resources_history | Resource associations |
| | aws_raw_waf_acl_logging_configurations_history | Logging config |
| | aws_raw_cloudfront_distribution_history | CloudFront distributions |
| | aws_raw_load_balancers_history | Load balancers |

### Trino Tables

| Catalog/Schema | Table | Purpose |
|----------------|-------|---------|
| huskeys_customers_logs.cloudflare_waf_logs | raw | Raw Cloudflare logs |
| huskeys_customers_logs.aws_waf_logs | raw | Raw AWS WAF logs |
| huskeys_aggregated.waf_logs_db | Various | Aggregated customer logs |

### Trino Partition Columns

| Vendor | Partitions |
|--------|------------|
| Cloudflare | organization, zone, year, month, day, hour |
| AWS WAF | organization, accountid, region, acl, year, month, day, hour |

---

## Appendix C: Severity Classification Criteria

### CRITICAL
- Immediate risk of breach
- No WAF protection on production assets
- Known vulnerabilities detectable but not blocked
- Origin IP directly accessible
- Complete WAF bypass possible

### HIGH
- Protection gaps that could be exploited
- Detection without blocking (LOG/COUNT mode)
- Excessive or poorly configured exceptions
- Missing essential rule sets
- Monitoring/logging disabled

---

*Template Version: 2.0*  
*Last Updated: December 30, 2025*  
*Authors: WAF Security Analysis Team*

---

## Usage Instructions

1. **Identify Customer**: Use Phase 1 queries to find organization ID and detect active vendors
2. **Run Vendor-Specific Checks**: Execute PostgreSQL queries for each detected vendor
3. **Analyze Logs**: If Trino logs available, run log analysis queries for Cloudflare/AWS
4. **Cross-Reference**: Correlate configuration findings with log evidence
5. **Validate Against Best Practices**: Check findings against vendor documentation
6. **Generate Report**: Document all CRITICAL and HIGH findings with remediation steps

**Pro Tips:**
- Always use partition columns in Trino queries for performance
- Run PostgreSQL config checks BEFORE log analysis to understand expected behavior
- Document the correlation between config findings and log evidence
- Prioritize CRITICAL findings for immediate remediation

