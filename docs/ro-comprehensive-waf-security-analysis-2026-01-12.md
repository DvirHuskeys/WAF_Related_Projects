# RO Comprehensive WAF Security Analysis Report
## Date: January 12, 2026
## Analysis Type: PostgreSQL Configuration Checks (AWS + Cloudflare)

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Total Cloudflare Zones** | 55 |
| **Enterprise Zones** | 7 |
| **Business Zones** | 3 |
| **Free Zones** | 45 |
| **AWS WAF ACLs** | 8 (across 3 regions) |
| **Critical Findings** | 18+ |
| **High Findings** | 50+ |
| **Medium Findings** | 20+ |
| **Low Findings** | 6 |
| **Total Checks Executed** | 44 PostgreSQL checks |
| **Total Individual Findings** | 94+ |

---

## CRITICAL FINDINGS

### 1. CF-ZONE-002: 45 Zones on Free Plan (Limited WAF Features)
**Severity**: HIGH  
**Security Value**: Free plan zones have very limited WAF capabilities - no managed rules, limited rate limiting, basic bot protection only. These zones are vulnerable to sophisticated attacks.

**Customer Impact**: 82% of RO's Cloudflare zones (45/55) are on Free plans. These include:
- `ablink.email.ro.co`, `ablink.notifications.ro.co` - Email infrastructure
- `healthbyro.com`, `hellorory.com` - Healthcare-related domains
- Multiple pricing domains (ozempicpricing.com, wegovypricing.com, etc.)

**Query Used**:
```sql
SELECT z.name as zone_name, z.plan_name, z.status,
    CASE 
        WHEN z.plan_name ILIKE '%free%' THEN 'HIGH: Free plan - very limited WAF'
        WHEN z.plan_name ILIKE '%pro%' THEN 'MEDIUM: Pro plan - limited WAF features'
        ELSE 'OK'
    END as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND z.status = 'active'
AND (z.plan_name ILIKE '%free%' OR z.plan_name ILIKE '%pro%')
ORDER BY z.plan_name, z.name;
```

---

### 2. CF-ZONE-003/004: Non-Proxied DNS Records Exposing Origin IPs
**Severity**: CRITICAL  
**Security Value**: Non-proxied (grey-cloud) DNS records bypass ALL Cloudflare security: WAF, DDoS protection, Bot Management, Rate Limiting. Traffic goes directly to origin, exposing IP addresses.

**Customer Impact**: 50+ non-proxied records discovered, including:

| Zone | Record | IP/Target | Risk |
|------|--------|-----------|------|
| dadikit.com | shopify.dadikit.com | 23.227.38.65 | Origin IP exposed |
| ro.co | ip.ro.co | 137.184.245.165 | **Direct origin IP exposure** |
| rotests.com | puppet.rotests.com | 3.16.8.38 | Origin IP exposed |
| smsro.co | smsro.co | 151.101.x.x (4 IPs) | Origin IPs exposed |

**Query Used**:
```sql
SELECT z.name as zone_name, d.name as record_name, d.type::text as record_type,
    d.content as ip_address, d.proxied,
    CASE 
        WHEN d.proxied = false AND d.content ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' 
            THEN 'CRITICAL: Non-proxied A record exposes origin IP'
        ELSE 'HIGH: Non-proxied record may expose origin'
    END as finding
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id AND z.is_deleted = false
JOIN organization o ON z.organization_id = o.id
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND d.is_deleted = false AND d.type::text IN ('A', 'AAAA') AND d.proxied = false;
```

---

### 3. CF-DNS-004: Non-Proxied Records to AWS (Complete Cloudflare Bypass)
**Severity**: CRITICAL  
**Security Value**: DNS records pointing directly to AWS infrastructure (ELB, CloudFront, Elastic Beanstalk) completely bypass Cloudflare's security stack. Attackers can target these endpoints directly.

**Customer Impact**: 11 non-proxied AWS records found:

| Zone | Record | AWS Target |
|------|--------|------------|
| getroman.com | roman-airflow.getroman.com | airflow-1418779007.us-east-2.elb.amazonaws.com |
| healthbyro.com | 1pass-scim.cyberit.healthbyro.com | 1pw-alb-1289934217.us-east-2.elb.amazonaws.com |
| kit.ro.co | ifu.kit.ro.co | dc8y4js4fn8r7.cloudfront.net |
| modernfertility.com | production3.modernfertility.com | production-mf-py3.t2tfpqzttp.us-west-1.elasticbeanstalk.com |
| ro.co | panorama.ro.co | panorama-lb-1080710422.us-east-1.elb.amazonaws.com |
| rotests.com | webhook-airflow.rotests.com | data-airflow-1313693980.us-east-2.elb.amazonaws.com |

**Query Used**:
```sql
SELECT z.name as zone_name, d.name as record_name, d.type::text as record_type, d.content
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id AND z.is_deleted = false
JOIN organization o ON z.organization_id = o.id
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND d.is_deleted = false AND d.proxied = false
AND (d.content ILIKE '%amazonaws.com%' OR d.content ILIKE '%elasticbeanstalk.com%' 
     OR d.content ILIKE '%elb.amazonaws.com%' OR d.content ILIKE '%cloudfront.net%');
```

---

### 4. CF-BOT-002/008: Bot Fight Mode Disabled (50+ Zones)
**Severity**: CRITICAL/HIGH  
**Security Value**: Bot Fight Mode is the primary automated bot protection. When disabled, credential stuffing, scraping, form spam, and automated attacks have unrestricted access.

**Customer Impact**: 
- **45 Free zones** - CRITICAL: No Bot Fight Mode
- **6 Business/Enterprise zones** - HIGH: Bot Fight Mode disabled on paid plans

| Plan | Zone | Status |
|------|------|--------|
| Enterprise | dadikit.com, kit.ro.co, modernfertility.com, rohs.co, rotests.com, v4.ro.co | Bot Fight Mode NULL |
| Business | edge.rohsinfra.net, familifertility.com, getroman.com | Bot Fight Mode NULL |
| Free (45 zones) | All 45 Free zones | No protection available |

**Query Used**:
```sql
SELECT z.name as zone_name, z.plan_name, bm.fight_mode, bm.enable_js,
    CASE 
        WHEN z.plan_name ILIKE '%free%' AND (bm.fight_mode = false OR bm.fight_mode IS NULL)
            THEN 'CRITICAL: Free zone without Bot Fight Mode'
        WHEN bm.fight_mode = false OR bm.fight_mode IS NULL
            THEN 'HIGH: Bot Fight Mode disabled'
        ELSE 'OK'
    END as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
LEFT JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND z.status = 'active'
AND (bm.fight_mode = false OR bm.fight_mode IS NULL);
```

---

### 5. CF-BOT-017: Enterprise Zones Without Bot Management Configuration
**Severity**: HIGH  
**Security Value**: Enterprise zones have full Super Bot Fight Mode capabilities. When not configured, RO is paying for Enterprise bot protection but not using it - ALL automated traffic passes through.

**Customer Impact**: 7 Enterprise zones with no bot management actions configured:
- dadikit.com
- kit.ro.co
- modernfertility.com
- ro.co (only has fight_mode=true, but sbfm settings are NULL)
- rohs.co
- rotests.com
- v4.ro.co

**Query Used**:
```sql
SELECT z.name as zone_name, z.plan_name,
    bm.sbfm_definitely_automated::text as definitely_automated,
    bm.sbfm_likely_automated::text as likely_automated,
    bm.fight_mode as super_bot_fight_mode
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND z.plan_name ILIKE '%enterprise%'
AND (bm.sbfm_definitely_automated IS NULL AND bm.sbfm_likely_automated IS NULL);
```

---

### 6. CF-ZONE-007: Enterprise Zones Without Rate Limiting
**Severity**: HIGH  
**Security Value**: Rate limiting is essential protection against brute force, credential stuffing, API abuse, and resource exhaustion. Enterprise zones without rate limits are vulnerable to volumetric attacks.

**Customer Impact**: 7 Enterprise zones without any rate limiting rules:
- dadikit.com
- kit.ro.co
- modernfertility.com
- ro.co
- rohs.co
- rotests.com
- v4.ro.co

**Query Used**:
```sql
SELECT z.name as zone_name, z.plan_name
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND z.status = 'active' AND z.plan_name ILIKE '%enterprise%'
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
    JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
    WHERE ri.zone_id = z.id AND ri.is_deleted = false AND r.action::text = 'RATELIMIT'
);
```

---

## HIGH FINDINGS

### 7. CF-RULE-001: SKIP Rules Without IP Restriction
**Severity**: CRITICAL  
**Security Value**: SKIP rules that bypass WAF without IP restrictions allow ANYONE to exploit the bypass condition. This is the #1 misconfiguration pattern.

**Customer Impact**: 11 SKIP rules without IP restrictions found:

| Zone | Description | Expression |
|------|-------------|------------|
| kit.ro.co | api.kit.ro.co - allow | `(http.host eq "api.kit.ro.co")` |
| kit.ro.co | generated from pagerules | `(http.request.full_uri contains "kit.ro.co/api/sse")` |
| modernfertility.com | Filter high-traffic endpoints | `(http.request.uri.path in {"/api/survey/response" ...})` |
| modernfertility.com | Allow ScreamingFrog | `(http.user_agent contains "Screaming Frog SEO Spider")` |
| modernfertility.com | Allow Stripe Webhooks | `(http.user_agent contains "Stripe/1.0")` |
| ro.co | [TEMP] Allow India/Poland | `(ip.geoip.country in {"IN" "PL"} and ...)` |
| ro.co | [SKIP] CF Verified Bot traffic | Complex bot bypass |
| ro.co | [ALLOW] /svc/ro-fdb/ | Path-based bypass |
| ro.co | Allow Ro-Experiments | Path with referer |
| ro.co | Allow RHP | Path + User-Agent |
| rotests.com | Allow GitHub Webhook | Host + UA + Geo |

**Query Used**:
```sql
SELECT z.name as zone_name, r.description, r.expression, r.action::text
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = true AND r.action::text = 'SKIP'
AND r.expression NOT ILIKE '%ip.src%';
```

---

### 8. CF-RULE-014: SKIP Rules with User-Agent Conditions (Spoofable)
**Severity**: HIGH  
**Security Value**: User-Agent strings are trivially spoofed. SKIP rules based on UA matching can be bypassed by any attacker simply setting their UA to match.

**Customer Impact**: 13 UA-based SKIP rules found across RO zones:
- `[ALLOW] Bingbot UAs` - getroman.com, ro.co
- `[ALLOW] Google Bot UAs` - getroman.com, ro.co
- `Allow Stripe Webhooks` - modernfertility.com (UA only, no IP)
- `Allow ScreamingFrog` - modernfertility.com (UA only, no IP)
- `[Temp] Allow ahrefs crawler` - ro.co (UA + IP - better)
- `[SKIP] Allow Unverfied Bots` - ro.co (complex)
- `Allow GitHub Webhook` - rotests.com (UA + IP + Geo - acceptable)

**Query Used**:
```sql
SELECT z.name as zone_name, r.description, r.expression, r.action::text
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = true AND r.action::text = 'SKIP'
AND r.expression ILIKE '%http.user_agent%';
```

---

### 9. CF-RULE-003: Log-Only WAF Rules (No Protection)
**Severity**: HIGH  
**Security Value**: Rules in LOG mode detect attacks but don't block them. This provides visibility but zero protection - attackers succeed while you watch.

**Customer Impact**: 30+ LOG-only rules found, including critical CVE protections:
- `Django SQLI - CVE:CVE-2025-64459` - dadikit.com (LOG only!)
- `SQLi - Sub Query - BETA` - dadikit.com (LOG only!)
- `React Server component - Scanner - CVE:CVE-2025-55182` - multiple zones
- `Malware, Web Shell` - dadikit.com (LOG only!)
- `Apache Camel - Remote Code Execution - CVE:CVE-2025-29891` - dadikit.com
- DDoS protection rules in LOG mode across 20+ zones

**Query Used**:
```sql
SELECT z.name as zone_name, r.description, r.expression, r.action::text
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = true AND r.action::text = 'LOG';
```

---

### 10. CF-SKIP-008: SKIP Rule Bypassing Entire Host
**Severity**: HIGH  
**Security Value**: SKIP rules matching only `http.host eq "hostname"` without additional restrictions bypass ALL WAF protection for an entire subdomain/host.

**Customer Impact**: 1 host-level bypass found:
- **kit.ro.co**: `api.kit.ro.co - allow` - Expression: `(http.host eq "api.kit.ro.co")`
  - This bypasses ALL security for the entire API subdomain with no IP restriction

**Query Used**:
```sql
SELECT z.name as zone_name, r.description, r.expression, r.action::text
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = true AND r.action::text = 'SKIP'
AND (r.expression ~* 'http\.host\s+eq\s+[''"]' AND r.expression NOT ILIKE '%http.request.uri%')
AND r.expression NOT ILIKE '%ip.src%';
```

---

### 11. CF-SKIP-009: Temporary SKIP Rules Still Active
**Severity**: MEDIUM  
**Security Value**: Rules marked as "temporary" should have expiration dates. Long-running temp rules indicate forgotten security exceptions.

**Customer Impact**: 2 temporary SKIP rules still active on ro.co:
1. `[Temp] Allow ahrefs crawler` - Created: 2026-01-06
2. `[TEMP] Allow India / Poland Google Contractor Ad Clicks` - Created: 2026-01-06

**Query Used**:
```sql
SELECT z.name as zone_name, r.description, r.expression, r.action::text, r.creation_date
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = true AND r.action::text = 'SKIP'
AND (r.description ILIKE '%temp%' OR r.description ILIKE '%temporary%');
```

---

## AWS WAF FINDINGS

### 12. AWS-ACL-001: Orphaned ACLs (Not Associated with Resources)
**Severity**: CRITICAL  
**Security Value**: ACLs not associated with any resources provide no protection. They may indicate:
- Resources deployed without WAF protection
- Stale configurations after resource deletion
- Failed deployments

**Customer Impact**: 6 orphaned ACLs found across multiple regions:

| ACL Name | Region | Default Action |
|----------|--------|----------------|
| apigateway-waf | US_EAST_2 | BLOCK |
| apigateway-waf | US_EAST_2 | BLOCK |
| apigateway-waf | US_WEST_1 | BLOCK |
| apigateway-waf | US_WEST_1 | BLOCK |
| apigateway-waf | US_WEST_2 | BLOCK |
| apigateway-waf | US_WEST_2 | BLOCK |

**Query Used**:
```sql
SELECT acl.name as acl_name, acl.region::text, acl.default_action::text
FROM aws_raw_waf_acl acl
WHERE acl.organization_name ILIKE 'ro'
AND acl.id NOT IN (
    SELECT DISTINCT ar.waf_acl_id FROM aws_raw_waf_acl_associated_resources ar
    WHERE ar.waf_acl_id IS NOT NULL
)
AND acl.arn NOT IN (
    SELECT DISTINCT cf.web_acl_id FROM aws_raw_cloudfront_distribution cf
    WHERE cf.web_acl_id IS NOT NULL AND cf.web_acl_id != ''
);
```

---

### 13. AWS-ACL-002: ACL Without Logging
**Severity**: CRITICAL  
**Security Value**: ACLs without logging have zero visibility into attacks, rule triggers, and security events. Incident response is impossible without logs.

**Customer Impact**: 1 ACL without logging:
- `retool-beta-allow-ipset-a0675b0` (US_EAST_2)

**Query Used**:
```sql
SELECT acl.name as acl_name, acl.region::text
FROM aws_raw_waf_acl acl
WHERE acl.organization_name ILIKE 'ro'
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_logging_configurations lc
    WHERE lc.waf_acl_id = acl.id
);
```

---

### 14. AWS-ACL-005: CloudWatch Metrics Disabled
**Severity**: MEDIUM  
**Security Value**: CloudWatch metrics enable alerting on attack volume, rule triggers, and anomalies. Disabled metrics = no real-time visibility or alerting.

**Customer Impact**: 2 ACLs with metrics disabled:
- `retool-beta-allow-ipset-a0675b0` (US_EAST_2)
- `retool-staging-allow-ipset-ad12c36` (US_EAST_2)

**Query Used**:
```sql
SELECT acl.name as acl_name, acl.region::text, acl.cloudwatch_metrics_enabled
FROM aws_raw_waf_acl acl
WHERE acl.organization_name ILIKE 'ro'
AND acl.cloudwatch_metrics_enabled = false;
```

---

### 15. AWS-ACL-016: Under-Configured ACLs (≤3 Rules)
**Severity**: HIGH  
**Security Value**: ACLs with very few rules (1-3) are likely under-configured and may not provide adequate protection. Properly configured ACLs typically have 5-10+ rules.

**Customer Impact**: 3 under-configured ACLs found:

| ACL Name | Region | Rule Count |
|----------|--------|------------|
| apigateway-waf | US_EAST_2 | 2 |
| apigateway-waf | US_WEST_1 | 2 |
| apigateway-waf | US_WEST_2 | 2 |

**Query Used**:
```sql
SELECT acl.name as acl_name, acl.region::text, COUNT(r.id) as rule_count
FROM aws_raw_waf_acl acl
LEFT JOIN aws_raw_waf_acl_rules r ON r.waf_acl_id = acl.id
WHERE acl.organization_name ILIKE 'ro'
GROUP BY acl.name, acl.region
HAVING COUNT(r.id) BETWEEN 1 AND 3;
```

---

### 16. AWS-RULE-007: Priority-Zero ALLOW Rules (Bypass All Protections)
**Severity**: HIGH  
**Security Value**: AWS WAF evaluates rules in priority order (lowest first). ALLOW rules at priority 0-5 execute BEFORE all security rules - matching traffic completely bypasses all protection.

**Customer Impact**: 10 high-priority ALLOW rules found:

| ACL Name | Rule Name | Priority |
|----------|-----------|----------|
| retool-beta-allow-ipset-a0675b0 | allow-cloudflare | 1 |
| retool-staging-allow-ipset-ad12c36 | allow-cloudflare | 1 |
| retool-beta-allow-ipset-a0675b0 | allow-cloudflare-ipv6 | 2 |
| retool-staging-allow-ipset-ad12c36 | allow-cloudflare-ipv6 | 2 |
| retool-beta-allow-ipset-a0675b0 | allow-okta-scim | 3 |
| retool-staging-allow-ipset-ad12c36 | allow-okta-scim | 3 |
| retool-beta-allow-ipset-a0675b0 | allow-warp | 4 |
| retool-staging-allow-ipset-ad12c36 | allow-warp | 4 |
| retool-beta-allow-ipset-a0675b0 | allow-warp-ipv6 | 5 |
| retool-staging-allow-ipset-ad12c36 | allow-warp-ipv6 | 5 |

**Query Used**:
```sql
SELECT acl.name as acl_name, acl.region::text, r.name as rule_name, r.priority, r.action::text
FROM aws_raw_waf_acl acl
JOIN aws_raw_waf_acl_rules r ON r.waf_acl_id = acl.id
WHERE acl.organization_name ILIKE 'ro'
AND r.action::text = 'ALLOW' AND r.managed_rule_group_name IS NULL AND r.priority <= 5;
```

---

### 17. AWS-MRG-001: ACLs Without AWS Managed Rules
**Severity**: CRITICAL  
**Security Value**: ACLs without managed rules have no baseline protection against common attacks. AWS Managed Rules provide essential SQLi, XSS, LFI, and threat intelligence detection.

**Customer Impact**: 8 ACLs without any AWS managed rules:

| ACL Name | Region |
|----------|--------|
| apigateway-waf | US_EAST_2 (x2) |
| apigateway-waf | US_WEST_1 (x2) |
| apigateway-waf | US_WEST_2 (x2) |
| retool-beta-allow-ipset-a0675b0 | US_EAST_2 |
| retool-staging-allow-ipset-ad12c36 | US_EAST_2 |

**Query Used**:
```sql
SELECT acl.name as acl_name, acl.region::text
FROM aws_raw_waf_acl acl
WHERE acl.organization_name ILIKE 'ro'
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rules r
    WHERE r.waf_acl_id = acl.id AND r.managed_rule_group_name IS NOT NULL
);
```

---

### 18. AWS-MRG-011: ACLs Missing IP Reputation List Protection
**Severity**: HIGH  
**Security Value**: AWS IP Reputation List blocks requests from known malicious IPs (botnets, scanners, attacker infrastructure). Anonymous IP List blocks anonymous proxies.

**Customer Impact**: 5 ACLs without IP reputation protection:
- apigateway-waf (US_EAST_2, US_WEST_1, US_WEST_2)
- retool-beta-allow-ipset-a0675b0 (US_EAST_2)
- retool-staging-allow-ipset-ad12c36 (US_EAST_2)

**Query Used**:
```sql
WITH acl_rules AS (
    SELECT acl.name as acl_name, acl.region::text,
        COUNT(CASE WHEN r.managed_rule_group_name = 'AWSManagedRulesAmazonIpReputationList' THEN 1 END) as has_ip_reputation,
        COUNT(CASE WHEN r.managed_rule_group_name = 'AWSManagedRulesAnonymousIpList' THEN 1 END) as has_anonymous_ip
    FROM aws_raw_waf_acl acl
    LEFT JOIN aws_raw_waf_acl_rules r ON r.waf_acl_id = acl.id
    WHERE acl.organization_name ILIKE 'ro'
    GROUP BY acl.name, acl.region
)
SELECT * FROM acl_rules WHERE has_ip_reputation = 0 OR has_anonymous_ip = 0;
```

---

### 19. CF-RULE-020: Enterprise Zones Without Challenge Actions
**Severity**: MEDIUM  
**Security Value**: Cloudflare offers graduated responses (BLOCK, MANAGED_CHALLENGE, JS_CHALLENGE, CHALLENGE). Using ONLY BLOCK creates more false positives - legitimate users can't pass challenges.

**Customer Impact**: 3 Enterprise zones using BLOCK-only approach:

| Zone | Block Rules | Challenge Rules | Total Rules |
|------|-------------|-----------------|-------------|
| dadikit.com | 574 | 0 | 816 |
| rohs.co | 574 | 0 | 816 |
| v4.ro.co | 574 | 0 | 816 |

**Query Used**:
```sql
SELECT z.name as zone_name, z.plan_name,
    COUNT(CASE WHEN r.action::text IN ('MANAGED_CHALLENGE', 'JS_CHALLENGE', 'CHALLENGE') THEN 1 END) as challenge_rules,
    COUNT(CASE WHEN r.action::text = 'BLOCK' THEN 1 END) as block_rules,
    COUNT(r.id) as total_rules
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
LEFT JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
LEFT JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
LEFT JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false AND r.enabled = true
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND z.status = 'active' AND z.plan_name ILIKE '%enterprise%'
GROUP BY z.name, z.plan_name
HAVING COUNT(CASE WHEN r.action::text IN ('MANAGED_CHALLENGE', 'JS_CHALLENGE', 'CHALLENGE') THEN 1 END) = 0
AND COUNT(r.id) > 0;
```

---

## ADDITIONAL FINDINGS (Supplemental Analysis)

### 20. CF-BOT-004: AI Bot Protection Disabled (10 Zones)
**Severity**: MEDIUM  
**Security Value**: AI bot protection blocks AI scrapers and crawlers (OpenAI, Anthropic, etc.) that may be harvesting content for training. This is especially important for healthcare content.

**Customer Impact**: 10 Business/Enterprise zones have no AI bot protection configured:

| Zone | Plan |
|------|------|
| edge.rohsinfra.net | Business |
| familifertility.com | Business |
| getroman.com | Business |
| dadikit.com | Enterprise |
| kit.ro.co | Enterprise |
| modernfertility.com | Enterprise |
| ro.co | Enterprise |
| rohs.co | Enterprise |
| rotests.com | Enterprise |
| v4.ro.co | Enterprise |

**Query Used**:
```sql
SELECT z.name as zone_name, z.plan_name, bm.ai_bots_protection::text
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND z.status = 'active'
AND (bm.ai_bots_protection IS NULL OR bm.ai_bots_protection::text IN ('disabled', 'allow'))
AND z.plan_name NOT ILIKE '%free%';
```

---

### 21. CF-BOT-005: Static Resource Protection Disabled (10 Zones)
**Severity**: HIGH  
**Security Value**: Static resource protection extends bot detection to JavaScript, CSS, and images. When disabled, bots can load these resources without challenge, enabling more sophisticated scraping.

**Customer Impact**: 10 Business/Enterprise zones have static resource protection disabled:
- edge.rohsinfra.net, familifertility.com, getroman.com (Business)
- dadikit.com, kit.ro.co, modernfertility.com, ro.co, rohs.co, rotests.com, v4.ro.co (Enterprise)

**Query Used**:
```sql
SELECT z.name as zone_name, z.plan_name, bm.sbfm_static_resource_protection
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND z.status = 'active'
AND bm.sbfm_static_resource_protection = false AND z.plan_name NOT ILIKE '%free%';
```

---

### 22. CF-BOT-006: JavaScript Detection Disabled (9 Zones)
**Severity**: MEDIUM  
**Security Value**: JS detection injects JavaScript challenges to identify automated browsers. When disabled, headless browsers and automation frameworks can operate undetected.

**Customer Impact**: 9 Business/Enterprise zones have JS detection disabled:
- edge.rohsinfra.net, familifertility.com, getroman.com (Business)
- dadikit.com, kit.ro.co, modernfertility.com, rohs.co, rotests.com, v4.ro.co (Enterprise)

**Query Used**:
```sql
SELECT z.name as zone_name, z.plan_name, bm.enable_js
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND z.status = 'active'
AND bm.enable_js = false AND z.plan_name NOT ILIKE '%free%';
```

---

### 23. CF-SKIP-010: SKIP Rule Based on Spoofable HTTP Referer
**Severity**: HIGH  
**Security Value**: HTTP Referer headers are trivially spoofed. SKIP rules that rely solely on referer validation can be bypassed by any attacker.

**Customer Impact**: 1 rule found on ro.co:
- **Allow Ro-Experiments**: `(http.request.uri.path eq "/svc/ro-experiments/public/roexp.min.js" and http.request.method eq "GET" and http.referer matches "^(https?://)?ro\.co(/.*|$)")`
- This rule allows requests based on referer matching `ro.co` - easily spoofed

**Query Used**:
```sql
SELECT z.name as zone_name, r.description, r.expression
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = true AND r.action::text = 'SKIP'
AND r.expression ILIKE '%http.referer%' AND r.expression NOT ILIKE '%ip.src%';
```

---

### 24. CF-SKIP-002: SKIP Rules for Load Testing (Permanent Rules)
**Severity**: HIGH  
**Security Value**: Load testing bypass rules should be temporary and time-limited. Permanent load test rules provide an avenue for attackers who discover the test IP ranges.

**Customer Impact**: 2 permanent K6 load test bypass rules:
- **ro.co**: `[SKIP] BYPASS K6 LOAD TEST` - IPs: 3.134.47.204, 18.224.245.87, 3.19.156.11, 2600:1f16:23e:2300::/56
- **rotests.com**: `[SKIP] BYPASS K6 LOAD TEST` - Same IP ranges

These rules should be disabled when not actively load testing.

**Query Used**:
```sql
SELECT z.name as zone_name, r.description, r.expression
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = true AND r.action::text = 'SKIP'
AND (r.expression ILIKE '%load%test%' OR r.description ILIKE '%load%test%');
```

---

### 25. CF-SKIP-001: SKIP Rule for Third-Party Scanner (Tenable)
**Severity**: HIGH  
**Security Value**: Scanner bypass rules with broad IP ranges can be abused if the scanner's IP ranges leak or overlap with attacker infrastructure.

**Customer Impact**: 1 Tenable PCI-ASV bypass rule on ro.co:
- **Allow Tenable PCI-ASV Scans**: `(ip.src in $tenable_ip_ranges)`
- No path or method restrictions - full site bypass for any traffic from Tenable IPs

**Recommendation**: Add path restrictions to limit scanner access to specific endpoints.

**Query Used**:
```sql
SELECT z.name as zone_name, r.description, r.expression
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = true AND r.action::text = 'SKIP'
AND r.expression ILIKE '%tenable%';
```

---

### 26. CF-SKIP-015: Broad Partner IP List Bypass (No Path Restriction)
**Severity**: HIGH  
**Security Value**: SKIP rules that use IP lists without path restrictions bypass all security for any traffic from those IPs - even malicious requests.

**Customer Impact**: 8 broad IP list bypass rules found:

| Zone | Description | Risk |
|------|-------------|------|
| getroman.com | [ALLOW] Bingbot UAs | IP + UA (no path restriction) |
| getroman.com | [ALLOW] Google Bot UAs | IP + UA (no path restriction) |
| kit.ro.co | UptimeRobot - Monitoring | IP only (no restrictions) |
| ro.co | [Temp] Allow ahrefs crawler | IP + UA (no path restriction) |
| ro.co | Allow Tenable PCI-ASV Scans | IP only (full bypass) |
| ro.co | [SKIP] Allow Unverfied Bots | Complex multi-bot rule |
| ro.co | [ALLOW] Google bot UAs | IP + UA (no path restriction) |
| ro.co | [ALLOW] Bingbot UAs | IP + UA (no path restriction) |

**Query Used**:
```sql
SELECT z.name as zone_name, r.description, r.expression
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = true AND r.action::text = 'SKIP'
AND r.expression ILIKE '%ip.src in $%' AND r.expression NOT ILIKE '%uri.path%';
```

---

### 27. AWS-ACL-015: ACLs Without Rate Limiting Rules (8 ACLs)
**Severity**: HIGH  
**Security Value**: Rate limiting is essential defense against brute force, credential stuffing, and API abuse. ACLs without rate limits allow unlimited request volume.

**Customer Impact**: 8 AWS WAF ACLs have no rate limiting rules:

| ACL Name | Region |
|----------|--------|
| apigateway-waf | US_EAST_2 (x2) |
| apigateway-waf | US_WEST_1 (x2) |
| apigateway-waf | US_WEST_2 (x2) |
| retool-beta-allow-ipset-a0675b0 | US_EAST_2 |
| retool-staging-allow-ipset-ad12c36 | US_EAST_2 |

**Query Used**:
```sql
SELECT acl.name as acl_name, acl.region::text
FROM aws_raw_waf_acl acl
WHERE acl.organization_name ILIKE 'ro'
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rules r 
    WHERE r.waf_acl_id = acl.id AND r.name ILIKE '%rate%'
);
```

---

### 28. CF-DNS-002: Wildcard DNS Records (2 Records)
**Severity**: MEDIUM  
**Security Value**: Wildcard DNS records can expose unexpected subdomains. If proxied, they're protected; if not proxied, they bypass Cloudflare entirely.

**Customer Impact**: 2 wildcard records found (both proxied - OK):
- `*.staging-api.dadikit.com` → ghs.googlehosted.com (proxied)
- `*.efe.rotests.com` → rotests-ephemeral-frontend.s3.us-east-2.amazonaws.com (proxied)

These are acceptable as they're proxied through Cloudflare.

---

### 29. CF-LIST-002: Empty Security Lists (1 List)
**Severity**: MEDIUM  
**Security Value**: Empty lists indicate potential misconfiguration - rules referencing empty lists won't match any traffic.

**Customer Impact**: 1 empty list found:
- **tiff_test_disable_quic** (REDIRECT type) - 0 items

**Query Used**:
```sql
SELECT l.name as list_name, l.kind::text as list_type, l.num_items
FROM cloudflare_raw_lists_history l
JOIN organization o ON l.organization_id = o.id
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND l.is_deleted = false AND l.num_items = 0;
```

---

### 30. CF-SKIP-016: Webhook SKIP Rule Without Full IP Restriction
**Severity**: MEDIUM  
**Security Value**: Webhook endpoints are common attack targets. SKIP rules for webhooks should have strict IP restrictions for the webhook provider.

**Customer Impact**: 1 GitHub webhook rule on rotests.com:
- **Allow GitHub Webhook**: Has geo restriction (US) but relies on UA spoofable condition
- Expression: `(http.user_agent contains "GitHub-Hookshot/760256b" and ssl and ip.geoip.country eq "US")`

**Recommendation**: Add GitHub webhook IPs from official documentation instead of relying on UA + geo.

---

### 31. CF-RULE-005: Overly Broad Single-IP SKIP Rules
**Severity**: HIGH  
**Security Value**: Single-IP or minimal-condition SKIP rules provide complete WAF bypass with no additional restrictions.

**Customer Impact**: 2 overly broad SKIP rules found:

| Zone | Description | Expression |
|------|-------------|------------|
| kit.ro.co | UptimeRobot - Monitoring | `(ip.src in $uptime_robot)` |
| rotests.com | [SKIP] core-service IP bypass | `(ip.src eq 3.135.7.123)` |

**Risk**: Any traffic from these IPs/lists bypasses ALL security regardless of request content, path, or method.

---

### 32. AWS-MRG-005: AWS WAF Bot Control Not Configured (5 ACLs)
**Severity**: MEDIUM  
**Security Value**: AWS Managed Rules Bot Control provides automated bot detection and mitigation. Without it, ACLs rely only on custom rules or have no bot protection.

**Customer Impact**: 5 ACLs without AWS Bot Control:
- apigateway-waf (US_EAST_2, US_WEST_1, US_WEST_2)
- retool-beta-allow-ipset-a0675b0 (US_EAST_2)
- retool-staging-allow-ipset-ad12c36 (US_EAST_2)

**Query Used**:
```sql
SELECT acl.name as acl_name, acl.region::text
FROM aws_raw_waf_acl acl
WHERE acl.organization_name ILIKE 'ro'
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rules r
    WHERE r.waf_acl_id = acl.id 
    AND r.managed_rule_group_name = 'AWSManagedRulesBotControlRuleSet'
);
```

---

### 33. CF-BOT-010: Organization-Wide Bot Protection Gap (98% Zones)
**Severity**: CRITICAL  
**Security Value**: When the vast majority of zones lack bot protection, the entire organization is vulnerable to automated attacks, credential stuffing, scraping, and API abuse.

**Customer Impact**: 
- **Total Zones**: 55
- **Protected Zones**: 1 (only 1 zone has bot protection configured!)
- **Unprotected Percentage**: 98.18%

This is an organization-wide vulnerability. Only 1 out of 55 zones has any form of bot protection enabled.

**Query Used**:
```sql
WITH zone_bot_status AS (
    SELECT 
        COUNT(*) as total_zones,
        COUNT(CASE WHEN bm.fight_mode = true OR bm.sbfm_definitely_automated IS NOT NULL THEN 1 END) as protected_zones
    FROM cloudflare_raw_zones_history z
    JOIN organization o ON z.organization_id = o.id
    LEFT JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
    WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
    AND z.is_deleted = false AND z.status = 'active'
)
SELECT total_zones, protected_zones, 
    ROUND((1 - protected_zones::numeric / NULLIF(total_zones, 0)) * 100, 2) as unprotected_percentage
FROM zone_bot_status;
```

---

### 34. CF-SKIP-018: SEO Crawler SKIP Without IP Verification
**Severity**: HIGH  
**Security Value**: SEO crawler user-agents are easily spoofed. Without IP verification, attackers can impersonate SEO tools to bypass WAF protection.

**Customer Impact**: 1 rule on modernfertility.com:
- **Allow ScreamingFrog**: `(http.user_agent contains "Screaming Frog SEO Spider")`
- No IP restriction - anyone claiming to be ScreamingFrog bypasses all security

**Recommendation**: Add IP verification using ScreamingFrog's official IP ranges or use `cf.verified_bot_category`.

---

### 35. CF-SKIP-019: AI Bot SKIP Rules Without Proper Verification
**Severity**: HIGH  
**Security Value**: AI bot user-agents can be spoofed. SKIP rules for AI crawlers need cryptographic verification via `cf.verified_bot_category`.

**Customer Impact**: 2 rules on ro.co:

1. **[SKIP] Allow Unverified Bots**: Allows Perplexity and Claude bots based on IP + UA
   - Uses `ip.src in $perplexity_ips` and ASN checks, but UA can still be spoofed
   
2. **[SKIP] CF Verified Bot traffic**: Uses `cf.verified_bot_category` (GOOD) but also relies on UA matching
   - Includes GPTBot, ChatGPT-User, ClaudeBot, DuckAssistBot, etc.

**Note**: The second rule properly uses `cf.verified_bot_category` which is the recommended approach.

---

### 36. AWS-ACL-014: ACLs with Only Custom Rules (No Managed Protection)
**Severity**: HIGH  
**Security Value**: ACLs without AWS Managed Rules lack baseline protection against known attacks. Custom rules alone cannot cover the breadth of AWS Managed Rules' threat intelligence.

**Customer Impact**: 5 ACLs have only custom rules with zero managed rules:

| ACL Name | Region | Total Rules | Managed | Custom |
|----------|--------|-------------|---------|--------|
| apigateway-waf | US_EAST_2 | 2 | 0 | 2 |
| apigateway-waf | US_WEST_1 | 2 | 0 | 2 |
| apigateway-waf | US_WEST_2 | 2 | 0 | 2 |
| retool-beta-allow-ipset-a0675b0 | US_EAST_2 | 5 | 0 | 5 |
| retool-staging-allow-ipset-ad12c36 | US_EAST_2 | 5 | 0 | 5 |

**Query Used**:
```sql
SELECT acl.name as acl_name, acl.region::text,
    COUNT(r.id) as total_rules,
    COUNT(CASE WHEN r.managed_rule_group_name IS NOT NULL THEN 1 END) as managed_rules,
    COUNT(CASE WHEN r.managed_rule_group_name IS NULL THEN 1 END) as custom_rules
FROM aws_raw_waf_acl acl
LEFT JOIN aws_raw_waf_acl_rules r ON r.waf_acl_id = acl.id
WHERE acl.organization_name ILIKE 'ro'
GROUP BY acl.name, acl.region
HAVING COUNT(r.id) > 0 AND COUNT(CASE WHEN r.managed_rule_group_name IS NOT NULL THEN 1 END) = 0;
```

---

### 37. CF-BOT-013: Verified Bots Action Not Configured (10 Zones)
**Severity**: MEDIUM  
**Security Value**: The `sbfm_verified_bots` setting controls how verified search engine and AI crawlers are handled. When not configured, default behavior may not match security policy.

**Customer Impact**: 10 Business/Enterprise zones without verified bots configuration:
- edge.rohsinfra.net, familifertility.com, getroman.com (Business)
- dadikit.com, kit.ro.co, modernfertility.com, ro.co, rohs.co, rotests.com, v4.ro.co (Enterprise)

**Query Used**:
```sql
SELECT z.name as zone_name, z.plan_name, bm.sbfm_verified_bots::text
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND z.status = 'active'
AND z.plan_name NOT ILIKE '%free%' AND bm.sbfm_verified_bots IS NULL;
```

---

### 38. CF-LIST-003: Large IP Lists (Performance Concern)
**Severity**: MEDIUM  
**Security Value**: Very large IP lists (>200 entries) can impact rule evaluation performance and may indicate lists that need segmentation.

**Customer Impact**: 3 large IP lists found:

| List Name | Type | Items |
|-----------|------|-------|
| okta_us_cell_7 | IP | 352 |
| google_ips | IP | 307 |

**Note**: These are not security issues but may impact performance if used in complex rule expressions.

---

### 39. AWS-RULE-002: Rules Without Labels for Tracking (16 Rules)
**Severity**: HIGH  
**Security Value**: AWS WAF rule labels enable tracking, alerting, and cross-rule coordination. Rules without labels are harder to monitor and debug.

**Customer Impact**: 16 custom rules without any labels:

| ACL | Rules Without Labels |
|-----|---------------------|
| apigateway-waf (3 regions) | allow-cloudflare-ips-and-extra-logic |
| retool-beta-allow-ipset-a0675b0 | allow-cloudflare, allow-cloudflare-ipv6, allow-okta-scim, allow-warp, allow-warp-ipv6 |
| retool-staging-allow-ipset-ad12c36 | allow-cloudflare, allow-cloudflare-ipv6, allow-okta-scim, allow-warp, allow-warp-ipv6 |

**Query Used**:
```sql
SELECT acl.name as acl_name, r.name as rule_name
FROM aws_raw_waf_acl acl
JOIN aws_raw_waf_acl_rules r ON r.waf_acl_id = acl.id
WHERE acl.organization_name ILIKE 'ro'
AND NOT EXISTS (SELECT 1 FROM aws_raw_waf_acl_rule_labels rl WHERE rl.waf_acl_rule_id = r.id)
AND r.managed_rule_group_name IS NULL;
```

---

### 40. CF-SKIP-011: SKIP Rule with Custom Header Token (Secret May Leak)
**Severity**: HIGH  
**Security Value**: SKIP rules that rely on custom headers with secret tokens are risky - the secret can leak through logs, error messages, or client-side code.

**Customer Impact**: 1 rule on ro.co:
- **Sentry API bypass**: Uses `any(http.request.headers["authorization"][*] matches "^Bearer (c6e458680f574dd2|53b6b1b5).*")`
- Bearer tokens are embedded in rule expression and could be extracted

**Query Used**:
```sql
SELECT z.name as zone_name, r.description, r.expression
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = true AND r.action::text = 'SKIP'
AND r.expression ILIKE '%http.request.headers%contains%';
```

---

### 41. CF-DNS-001: Non-Proxied CNAMEs to External Services (7 Records)
**Severity**: HIGH  
**Security Value**: Non-proxied CNAMEs to external services (Zendesk, GitHub Pages) bypass Cloudflare security. Attackers can target these endpoints directly.

**Customer Impact**: 7 non-proxied CNAMEs found:

| Zone | Record | Target |
|------|--------|--------|
| getroman.com | care.getroman.com | getroman.zendesk.com |
| modernfertility.com | support.modernfertility.com | modernfertility0.zendesk.com |
| ro.co | zendesk1.ro.co | mail1.zendesk.com |
| ro.co | zendesk2.ro.co | mail2.zendesk.com |
| ro.co | zendesk3.ro.co | mail3.zendesk.com |
| ro.co | zendesk4.ro.co | mail4.zendesk.com |
| rotests.com | datadocs.rotests.com | healthbyro.github.io |

**Query Used**:
```sql
SELECT z.name as zone_name, dns.name as record_name, dns.content
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_dns_records_history dns ON z.id = dns.zone_id AND dns.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND dns.type = 'CNAME' AND dns.proxied = false
AND (dns.content ILIKE '%zendesk%' OR dns.content ILIKE '%github.io%');
```

---

### 42. AWS-ACL-012: High Percentage of Orphan ACLs (75%)
**Severity**: HIGH  
**Security Value**: When most ACLs are orphaned (not protecting any resources), it indicates either misconfiguration or resources deployed without WAF protection.

**Customer Impact**: 
- **Total ACLs**: 8
- **Orphan ACLs**: 6
- **Orphan Percentage**: 75%

This means only 2 out of 8 ACLs are actually protecting resources. The remaining 6 ACLs exist but provide no protection.

**Query Used**:
```sql
WITH acl_stats AS (
    SELECT COUNT(*) as total_acls,
        COUNT(CASE WHEN acl.id NOT IN (
            SELECT DISTINCT ar.waf_acl_id FROM aws_raw_waf_acl_associated_resources ar
        ) THEN 1 END) as orphan_acls
    FROM aws_raw_waf_acl acl WHERE acl.organization_name ILIKE 'ro'
)
SELECT total_acls, orphan_acls, 
    ROUND(orphan_acls::numeric / NULLIF(total_acls, 0) * 100, 2) as orphan_percentage
FROM acl_stats;
```

---

### 43. AWS-ACL-007: ACLs Without Description (6 ACLs)
**Severity**: LOW  
**Security Value**: ACLs without descriptions are harder to manage and audit. Good naming and descriptions are essential for operational clarity.

**Customer Impact**: 6 ACLs (all apigateway-waf instances across regions) have no description.

---

### 44. CF-RULE-002: Disabled Managed Ruleset Rules (280+ Per Zone!)
**Severity**: HIGH  
**Security Value**: Cloudflare's Managed Ruleset contains hundreds of security rules. When most are disabled, the zone loses protection against known attacks, CVEs, and common vulnerabilities.

**Customer Impact**: 10 Business/Enterprise zones have 280+ managed rules DISABLED each:

| Zone | Disabled Rules |
|------|----------------|
| ro.co | 283 |
| rotests.com | 282 |
| familifertility.com | 281 |
| getroman.com | 281 |
| kit.ro.co | 281 |
| modernfertility.com | 281 |
| rohs.co | 281 |
| dadikit.com | 281 |
| v4.ro.co | 281 |
| edge.rohsinfra.net | 281 |

**Examples of Disabled Rules**:
- `SQLi - DROP - 2`
- `GraphQL Injection - 2`
- `React - DoS - CVE:CVE-2025-55184`
- `Anomaly:Body - ReGeorg webshell`
- `vBulletin - SQLi - CVE:CVE-2020-12720`
- `Wordpress - DoS - CVE:CVE-2018-6389`

**Query Used**:
```sql
SELECT z.name as zone_name, COUNT(*) as disabled_rules_count
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE o.id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND z.is_deleted = false AND r.enabled = false
AND rs.phase::text = 'http_request_firewall_managed'
GROUP BY z.name ORDER BY disabled_rules_count DESC;
```

---

## Summary of Findings by Severity

| Severity | Count | Key Issues |
|----------|-------|------------|
| **CRITICAL** | 18+ | Origin IP exposure, No managed rules, AWS bypass records, Bot protection disabled (98% of zones!), Organization-wide bot gap |
| **HIGH** | 50+ | SKIP rules without IP restriction, UA-based bypasses, No rate limiting, LOG-only rules, Static resource protection off, Load test bypasses, Scanner bypasses, SEO crawler bypasses, AI bot bypasses, ACLs with only custom rules, Rules without labels, Header token bypasses, 75% orphan ACLs, External service CNAMEs, **280+ managed rules disabled per zone!** |
| **MEDIUM** | 20+ | Temporary rules, CloudWatch disabled, BLOCK-only zones, JS detection off, AI bot protection off, Empty lists, Verified bots not configured, Large IP lists |
| **LOW** | 6 | ACLs without descriptions |

**Total PostgreSQL Checks Executed**: 44

## Recommendations

### Immediate Actions (CRITICAL)
1. **Proxy all A/AAAA records** exposing origin IPs (ip.ro.co, puppet.rotests.com, etc.)
2. **Enable AWS Managed Rules** on all 8 ACLs (currently 0% coverage)
3. **URGENT: Address 98% bot protection gap** - only 1 of 55 zones has bot protection enabled!
4. **Configure Bot Fight Mode** on all Business/Enterprise zones (10 zones need attention)
5. **Add IP reputation lists** to all AWS WAF ACLs
6. **Review AWS bypass records** pointing to ELB/Beanstalk - proxy through Cloudflare

### Short-Term Actions (HIGH)
1. **URGENT: Review 280+ disabled managed rules** on each Business/Enterprise zone - many critical security rules are disabled
2. **Add IP restrictions** to all SKIP rules or convert to verified bot checks
3. **Convert LOG-only CVE rules to BLOCK** (Django SQLI, React Scanner, etc.)
4. **Enable rate limiting** on all 7 Enterprise zones AND all 8 AWS WAF ACLs
5. **Configure SBFM settings** on Enterprise zones (definitely_automated, likely_automated)
6. **Enable CloudWatch metrics** on retool ACLs
7. **Enable static resource protection** on all 10 Business/Enterprise zones
8. **Disable or time-limit load test bypass rules** (K6 rules on ro.co, rotests.com)
9. **Add path restrictions to scanner bypass rules** (Tenable PCI-ASV)
10. **Replace referer-based SKIP rules** with proper authentication (Ro-Experiments)
11. **Add IP verification to SEO crawler SKIP rules** (ScreamingFrog on modernfertility.com)
12. **Add AWS Managed Rules** to all 5 ACLs that have only custom rules (apigateway-waf, retool ACLs)
13. **Add labels to AWS WAF rules** for better tracking (16 rules without labels)
14. **Proxy Zendesk and GitHub Pages CNAMEs** or ensure they don't handle sensitive data

### Medium-Term Actions (MEDIUM)
1. **Review and expire temporary SKIP rules** (ahrefs, India/Poland contractors)
2. **Upgrade critical Free zones** to paid plans (healthbyro.com, pricing domains)
3. **Add challenge actions** to Enterprise zones (currently BLOCK-only)
4. **Enable logging** on retool-beta ACL
5. **Enable JavaScript detection** on all 9 Business/Enterprise zones
6. **Configure AI bot protection** if blocking AI crawlers is desired
7. **Review empty lists** and remove unused configurations
8. **Add path restrictions** to broad IP list bypasses (Google/Bing/Ahrefs/UptimeRobot)
9. **Configure verified bots action** on all 10 Business/Enterprise zones (sbfm_verified_bots)
10. **Review large IP lists** (okta_us_cell_7, google_ips) for potential segmentation

---

*Report generated by WAF Security Analysis Agent*
*Analysis Date: January 12, 2026*
*Data Source: PostgreSQL Configuration Database (Cloudflare + AWS WAF)*

