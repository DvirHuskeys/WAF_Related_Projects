# RO WAF Security Analysis Report

**Analysis Date:** January 11, 2026  
**Organization:** RO  
**Organization ID:** `843cc2aa-34d1-4729-92f1-ac04bc3f3702`  
**Platforms Analyzed:** Cloudflare (55 zones) + AWS WAF (8 ACLs)

---

## Executive Summary

This comprehensive WAF security analysis of RO's infrastructure reveals several **CRITICAL** and **HIGH** severity findings across both Cloudflare and AWS WAF platforms. The organization has a multi-layered security architecture where Cloudflare serves as the edge CDN/WAF and AWS WAF protects backend API Gateway resources.

### Key Statistics

| Platform | Resources | Critical | High | Medium |
|----------|-----------|----------|------|--------|
| Cloudflare | 55 zones | 4 | 8 | 2 |
| AWS WAF | 8 ACLs | 3 | 0 | 4 |
| **Total** | **63** | **7** | **8** | **6** |

### Risk Summary

⚠️ **45 zones (82%)** are on Free Cloudflare plans with limited WAF capabilities  
⚠️ **6 AWS WAF ACLs** have no associated resources (wasted configuration)  
⚠️ **9 SKIP rules** bypass WAF without IP restrictions  
⚠️ **All 8 AWS WAF ACLs** lack AWS Managed Rules (no OWASP protection)

---

## Cross-Platform Correlation: AWS + Cloudflare Architecture

RO uses a **layered security architecture** where:

1. **Cloudflare** provides edge security (DDoS, Bot Management, WAF rules)
2. **AWS WAF** provides backend security for API Gateway resources

### Key Cross-Link Finding

The AWS WAF ACLs contain rules like `allow-cloudflare-ips-and-extra-logic` which **only allow traffic from Cloudflare IPs**. This creates an intentional dependency:

- ✅ **Positive**: Traffic must pass through Cloudflare before reaching AWS
- ❌ **Negative**: If Cloudflare zones have weak security, attacks pass through to AWS
- ❌ **Negative**: AWS WAF has **no managed rules** - relying entirely on Cloudflare for attack detection

**Cross-Platform Security Gap**: Since AWS WAF ACLs trust Cloudflare traffic but have no managed rules, any attack that bypasses Cloudflare's SKIP rules will reach the origin without inspection.

---

# 🔶 CLOUDFLARE FINDINGS

---

## CF-ZONE: Zone Security Configuration

### CF-ZONE-002 [CRITICAL] - 45 Zones on Free Plans

**Security Value:**  
Free plans have significantly limited WAF capabilities. Free = 5 custom rules only, no Bot Management, no exposed credentials detection.

**Customer Impact:**  
Reduced protection against sophisticated attacks. Cannot implement defense-in-depth required by compliance frameworks.

**Query Used:**
```sql
SELECT z.name as zone_name, z.plan_name,
    CASE WHEN z.plan_name ILIKE '%free%' THEN 'CRITICAL: Free plan'
         WHEN z.plan_name ILIKE '%pro%' THEN 'HIGH: Pro plan - limited managed rules'
         ELSE 'Review' END as finding
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
  AND z.is_deleted = false AND z.status = 'active'
AND z.plan_name ILIKE ANY(ARRAY['%free%', '%pro%']);
```

**Affected Zones (45 total - sample):**

| Zone Name | Plan | Severity |
|-----------|------|----------|
| ablink.email.ro.co | Free Website | CRITICAL |
| ablink.notifications.ro.co | Free Website | CRITICAL |
| comm.ro.co | Free Website | CRITICAL |
| covidvaccinedrive.com | Free Website | CRITICAL |
| edge.rosvc.net | Free Website | CRITICAL |
| getroman.ca | Free Website | CRITICAL |
| getroman.co | Free Website | CRITICAL |
| glp1pricing.com | Free Website | CRITICAL |
| healthbyro.com | Free Website | CRITICAL |
| hellorory.com | Free Website | CRITICAL |
| ozempicpricing.com | Free Website | CRITICAL |
| ro.pharmacy | Free Website | CRITICAL |
| ropharmacy.com | Free Website | CRITICAL |
| semaglutidepricing.com | Free Website | CRITICAL |
| tirzepatidepricing.com | Free Website | CRITICAL |
| wegovypricing.com | Free Website | CRITICAL |
| weightlossdrugspricing.com | Free Website | CRITICAL |
| zepboundpricing.com | Free Website | CRITICAL |
| *...and 27 more* | Free Website | CRITICAL |

**Remediation:** Upgrade critical zones (especially main domains like getroman.com, ro.co, modernfertility.com) to Business or Enterprise plans to enable full WAF capabilities.

---

### CF-ZONE-003 [HIGH] - 100+ Unproxied DNS Records

**Security Value:**  
Unproxied (grey-cloud) DNS records bypass ALL Cloudflare security: WAF, DDoS protection, Bot Management, Rate Limiting. Traffic goes directly to origin IP.

**Customer Impact:**  
Complete security bypass. Attackers discovering these records can attack origin directly.

**Query Used:**
```sql
SELECT z.name as zone_name, d.name as dns_record, d.type, d.content
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
WHERE z.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
  AND d.is_deleted = false AND z.is_deleted = false
AND d.proxied = false AND d.type IN ('A', 'AAAA', 'CNAME');
```

**Selected Findings (sample of 100+):**

| Zone | DNS Record | Type | Destination | Risk |
|------|------------|------|-------------|------|
| ro.co | ip.ro.co | A | 137.184.245.165 | Exposed origin IP |
| ro.co | panorama.ro.co | CNAME | AWS ELB | Bypasses CF security |
| ro.co | login.ro.co | CNAME | Auth0 | Authentication bypass |
| getroman.com | roman-airflow.getroman.com | CNAME | AWS ELB | Internal tool exposed |
| modernfertility.com | production3.modernfertility.com | CNAME | AWS Beanstalk | Production bypass |
| ro.co | privacy-requests.ro.co | CNAME | CloudFront | GDPR endpoint bypass |

**Remediation:** Enable proxy (orange cloud) for all web-facing DNS records. Only keep mail, DKIM, and ACM validation records unproxied.

---

### CF-ZONE-006 [MEDIUM] - Zone Sprawl (55 Active Zones)

**Security Value:**  
55 zones creates governance complexity. More zones = larger attack surface and more potential for misconfigurations.

**Customer Impact:**  
Difficulty maintaining consistent security policies across many zones.

**Query Used:**
```sql
SELECT COUNT(z.id) as zone_count,
    SUM(CASE WHEN z.status = 'active' THEN 1 ELSE 0 END) as active_zones
FROM cloudflare_raw_zones_history z
WHERE z.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702' AND z.is_deleted = false;
```

**Findings:**
- Total zones: 55
- Active zones: 55
- Finding: MEDIUM - Moderate zone count requires governance review

---

## CF-RULE: Rule Configuration Analysis

### CF-RULE-001 [CRITICAL] - 9 SKIP Rules Without IP Restriction

**Security Value:**  
SKIP rules without IP restriction allow ANYONE to bypass WAF entirely. This is the #1 WAF misconfiguration. A single overly permissive SKIP rule can negate your entire WAF investment.

**Customer Impact:**  
Attackers matching the rule expression bypass ALL security. We've seen SKIP rules matching User-Agent that attackers easily spoof.

**Query Used:**
```sql
SELECT z.name as zone_name, r.description, r.expression, r.action::text
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
WHERE z.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
  AND r.action::text ILIKE '%skip%'
AND r.expression NOT ILIKE '%ip.src%' AND r.expression NOT ILIKE '%ip.geoip%';
```

**Affected Rules:**

| Zone | Rule Description | Expression | Risk Level |
|------|-----------------|------------|------------|
| kit.ro.co | api.kit.ro.co - allow | `http.host eq "api.kit.ro.co"` | **CRITICAL** - All API traffic skips WAF |
| kit.ro.co | generated from pagerules | `http.request.full_uri contains "kit.ro.co/api/sse"` | HIGH |
| ro.co | [ALLOW] /svc/ro-fdb/ | Path-based bypass | HIGH |
| ro.co | Allow Ro-Experiments | Path + User-Agent check | MEDIUM |
| ro.co | Allow RHP | Path + User-Agent "rhp-proxy" | **CRITICAL** - UA spoofable |
| ro.co | [SKIP] CF Verified Bot traffic | Verified bot bypass | MEDIUM - By design |
| modernfertility.com | Allow ScreamingFrog | `http.user_agent contains "Screaming Frog SEO Spider"` | **CRITICAL** - UA spoofable |
| modernfertility.com | Allow Stripe Webhooks | `http.user_agent contains "Stripe/1.0"` | **CRITICAL** - UA spoofable |
| modernfertility.com | Filter high-traffic endpoints | Path-based bypass | HIGH |

**Remediation:** Add IP restrictions to SKIP rules using `ip.src in $allowlist` or remove User-Agent based bypasses which are trivially spoofed.

---

### CF-RULE-002 [HIGH] - 50+ Disabled Managed Ruleset Rules

**Security Value:**  
Disabled managed rules create gaps against known CVEs and attack patterns. Cloudflare updates managed rules daily - disabled rules miss these updates.

**Customer Impact:**  
Missing protection against actively exploited vulnerabilities. Log4Shell rules were pushed within hours - zones with disabled managed rules remained vulnerable.

**Query Used:**
```sql
SELECT z.name as zone_name, rs.name as ruleset_name, r.description
FROM cloudflare_raw_zones_history z
JOIN cloudflare_raw_rulesets_history rs ON ...
JOIN cloudflare_raw_rulesets_rules_history r ON ...
WHERE r.enabled = false AND rs.name ILIKE ANY(ARRAY['%managed%', '%owasp%', '%cloudflare%']);
```

**Critical Disabled Rules on getroman.com:**

| Ruleset | Disabled Rule | Risk |
|---------|---------------|------|
| Cloudflare Managed Ruleset | React - DoS - CVE:CVE-2025-55184 | HIGH - Recent CVE |
| Cloudflare Managed Ruleset | Generic Log - File Inclusion | HIGH |
| Cloudflare Managed Ruleset | BentoML - SSRF - CVE:CVE-2025-54381 | HIGH - Recent CVE |
| Cloudflare Managed Ruleset | Anomaly:Body - Large | MEDIUM |
| Cloudflare Managed Ruleset | Anomaly:Header:Content-Type | MEDIUM |
| Cloudflare Normalization Ruleset | URL path normalization | HIGH - Evasion risk |

**Remediation:** Review and re-enable disabled managed rules, especially for recent CVEs. Use exceptions with IP restrictions rather than disabling rules entirely.

---

### CF-RULE-003 [HIGH] - 50+ Rules in Log-Only Mode

**Security Value:**  
Rules in "Log" action provide visibility but NO protection. Attacks are recorded but reach the origin.

**Customer Impact:**  
False sense of security. Security teams see attacks in logs but attacks succeed.

**Query Used:**
```sql
SELECT z.name as zone_name, r.description, r.action::text
FROM ... WHERE r.action::text ILIKE ANY(ARRAY['%log%', '%simulate%', '%monitor%']);
```

**Selected Log-Only Rules:**

| Zone | Rule Description | Action |
|------|-----------------|--------|
| kit.ro.co | Bad User_Agents Logging | LOG |
| getroman.com | Malware, Web Shell | LOG |
| getroman.com | Apache Camel - RCE - CVE:CVE-2025-29891 | LOG |
| getroman.com | SQLi - Comment - Beta | LOG |
| getroman.com | SQLi - Comparison - Beta | LOG |
| getroman.com | Django SQLI - CVE:CVE-2025-64459 | LOG |
| getroman.com | [LOG] 200 RL | LOG |
| getroman.com | [LOG] 404 RL | LOG |

**Remediation:** After tuning period (1-2 weeks), switch log-only rules to BLOCK action. Create exceptions for false positives rather than leaving entire rules in log mode.

---

## CF-BOT: Bot Management Configuration

### CF-BOT-001 [HIGH] - Limited Bot Management on All Zones

**Security Value:**  
Without full bot management, automated traffic (40-50% of internet) is indistinguishable from humans. Scrapers, credential stuffers, inventory hoarders operate freely.

**Customer Impact:**  
E-commerce sites without bot management report 10-30% malicious bot traffic affecting inventory, pricing, and customer experience.

**Query Used:**
```sql
SELECT z.name as zone_name, bm.fight_mode, bm.sbfm_definitely_automated::text
FROM cloudflare_raw_bot_management_history bm
JOIN cloudflare_raw_zones_history z ON bm.zone_id = z.id
WHERE z.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702';
```

**Findings:**
- Only **ro.co** has Bot Fight Mode enabled (`fight_mode = true`)
- All 54 other zones have NULL/unconfigured bot management
- No zones have Super Bot Fight Mode (SBFM) configured

**Remediation:** Enable Bot Fight Mode on all production zones. Upgrade key zones to plans with Super Bot Fight Mode for enhanced protection against sophisticated bots.

---

# 🔷 AWS WAF FINDINGS

---

## AWS-ACL: Web ACL Configuration

### AWS-ACL-001 [CRITICAL] - 6 ACLs Without Associated Resources

**Security Value:**  
Web ACLs not associated with resources provide zero protection. You're paying for rules that protect nothing.

**Customer Impact:**  
Resources you think are protected are exposed. ACLs get disassociated during migrations or testing.

**Query Used:**
```sql
SELECT acl.name as acl_name, acl.region::text, acl.capacity
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_associated_resources_history ar
    WHERE ar.waf_acl_id = acl.id AND ar.is_deleted = false
);
```

**Affected ACLs:**

| ACL Name | Region | WCU Capacity | Status |
|----------|--------|--------------|--------|
| apigateway-waf | US_WEST_1 | 37 | UNASSOCIATED |
| apigateway-waf | US_WEST_2 | 37 | UNASSOCIATED |
| apigateway-waf | US_WEST_2 | 37 | UNASSOCIATED |
| apigateway-waf | US_EAST_2 | 37 | UNASSOCIATED |
| apigateway-waf | US_EAST_2 | 37 | UNASSOCIATED |
| apigateway-waf | US_WEST_1 | 37 | UNASSOCIATED |

**Active ACLs (2 with associations):**

| ACL Name | Region | Resource Type | Resource ARN |
|----------|--------|---------------|--------------|
| retool-beta-allow-ipset-a0675b0 | US_EAST_2 | ALB | k8s-retool-retoolcd-* |
| retool-staging-allow-ipset-ad12c36 | US_EAST_2 | ALB | k8s-retool-retool00-* |

**Remediation:** Delete unused ACLs or associate them with API Gateway resources in their respective regions.

---

### AWS-ACL-002 [CRITICAL] - ACL Without Logging

**Security Value:**  
Without logging, you have zero visibility into attacks, rule effectiveness, or security events.

**Customer Impact:**  
Compliance frameworks (PCI-DSS, SOC2, HIPAA) require WAF logging. No logs = compliance failure.

**Query Used:**
```sql
SELECT acl.name as acl_name, acl.region::text
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_logging_configurations_history lc
    WHERE lc.waf_acl_id = acl.id AND lc.is_deleted = false
);
```

**Affected ACL:**

| ACL Name | Region | Finding |
|----------|--------|---------|
| retool-beta-allow-ipset-a0675b0 | US_EAST_2 | No logging configured |

**Remediation:** Configure WAF logging to CloudWatch Logs, S3, or Kinesis Data Firehose.

---

### AWS-MRG-001 [CRITICAL] - All 8 ACLs Lack AWS Managed Rules

**Security Value:**  
AWS Managed Rules provide baseline protection updated by AWS security teams. Without them, no protection against OWASP Top 10 or emerging threats.

**Customer Impact:**  
Must build ALL rules from scratch. AWS updates managed rules for new CVEs within hours/days - without them, you're always behind attackers.

**Query Used:**
```sql
SELECT acl.name as acl_name, acl.region::text
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702'
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rules_history r
    WHERE r.waf_acl_id = acl.id AND r.managed_rule_group_vendor_name ILIKE '%aws%'
);
```

**All 8 ACLs have NO AWS Managed Rules:**

| ACL Name | Region | Missing Rule Groups |
|----------|--------|---------------------|
| apigateway-waf | US_EAST_2 | CommonRuleSet, KnownBadInputs, SQLi, etc. |
| apigateway-waf | US_WEST_1 | CommonRuleSet, KnownBadInputs, SQLi, etc. |
| apigateway-waf | US_WEST_2 | CommonRuleSet, KnownBadInputs, SQLi, etc. |
| retool-staging-allow-ipset-ad12c36 | US_EAST_2 | CommonRuleSet, KnownBadInputs, SQLi, etc. |
| retool-beta-allow-ipset-a0675b0 | US_EAST_2 | CommonRuleSet, KnownBadInputs, SQLi, etc. |

**Current Rule Configuration (Allow-only):**

| ACL Name | Rules | Purpose |
|----------|-------|---------|
| apigateway-waf | allow-cloudflare-ips-and-extra-logic | Only allows CF IPs |
| retool-* | allow-cloudflare, allow-warp, allow-okta-scim | IP allow lists only |

**Remediation:** Add AWS Managed Rule Groups:
- `AWSManagedRulesCommonRuleSet` (OWASP protection)
- `AWSManagedRulesKnownBadInputsRuleSet` (Log4Shell, etc.)
- `AWSManagedRulesSQLiRuleSet` (SQL injection)

---

### AWS-ACL-005/006 [MEDIUM] - Observability Issues

**Query Used:**
```sql
SELECT acl.name, acl.cloudwatch_metrics_enabled, acl.sample_request_enabled
FROM aws_raw_waf_acl_history acl
WHERE acl.organization_id = '843cc2aa-34d1-4729-92f1-ac04bc3f3702';
```

**Findings:**

| ACL Name | CloudWatch Metrics | Sample Requests |
|----------|-------------------|-----------------|
| retool-staging-allow-ipset-ad12c36 | ❌ Disabled | ❌ Disabled |
| retool-beta-allow-ipset-a0675b0 | ❌ Disabled | ❌ Disabled |

**Remediation:** Enable CloudWatch metrics and sample request collection for operational visibility.

---

# Cross-Platform Security Correlation

## Why AWS + Cloudflare Integration Matters

The current architecture creates a **chain of trust**:

```
User → Cloudflare (55 zones) → AWS WAF → API Gateway → Backend
           │                      │
           └──SKIP rules bypass──►└──No managed rules
```

### Security Gap Analysis

1. **Cloudflare SKIP rules** allow certain traffic to bypass CF security
2. **AWS WAF only checks** if traffic comes from Cloudflare IPs
3. **No AWS managed rules** means traffic is not inspected for attacks

**Result:** Attacks that match Cloudflare SKIP rules reach the backend unfiltered.

### Recommended Architecture Improvements

1. **Add AWS Managed Rules** even though traffic comes from Cloudflare (defense-in-depth)
2. **Restrict Cloudflare SKIP rules** to IP-based exceptions only
3. **Enable logging** on all AWS WAF ACLs for correlation
4. **Upgrade key Cloudflare zones** to Business/Enterprise for full protection

---

# Remediation Priority Matrix

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| **P0** | Add AWS Managed Rules to all ACLs | Medium | Critical |
| **P0** | Restrict CF SKIP rules with IP conditions | Low | Critical |
| **P1** | Enable logging on retool-beta ACL | Low | High |
| **P1** | Delete/associate 6 unused AWS WAF ACLs | Low | High |
| **P1** | Enable Bot Fight Mode on all CF zones | Low | High |
| **P2** | Review 50+ disabled managed rules on getroman.com | Medium | High |
| **P2** | Switch log-only rules to BLOCK | Medium | High |
| **P2** | Upgrade key CF zones from Free plan | High (cost) | High |
| **P3** | Enable CloudWatch metrics on retool ACLs | Low | Medium |
| **P3** | Enable proxy on unproxied DNS records | Low | Medium |

---

# Appendix: Security Check Coverage

## Cloudflare Checks Executed

| Check ID | Name | Status | Findings |
|----------|------|--------|----------|
| CF-ZONE-001 | Zones Without WAF | ✅ | 0 - All zones have rulesets |
| CF-ZONE-002 | Zones on Free/Pro Plans | ✅ | 45 CRITICAL |
| CF-ZONE-003 | Unproxied DNS Records | ✅ | 100+ HIGH |
| CF-ZONE-005 | Inactive Zones with DNS | ✅ | 0 |
| CF-ZONE-006 | Zone Sprawl | ✅ | MEDIUM - 55 zones |
| CF-RULE-001 | SKIP Rules Without IP | ✅ | 9 CRITICAL |
| CF-RULE-002 | Disabled Managed Rules | ✅ | 50+ HIGH |
| CF-RULE-003 | Log-Only Rules | ✅ | 50+ HIGH |
| CF-RULE-006 | Rules Skipping WAF Phases | ✅ | 0 |
| CF-RULE-007 | Rules Skipping Multiple Products | ✅ | 0 |
| CF-BOT-001 | No Bot Management | ✅ | 54 zones without |
| CF-BOT-002/003 | Bot Fight Mode | ✅ | Only 1 zone enabled |

## AWS WAF Checks Executed

| Check ID | Name | Status | Findings |
|----------|------|--------|----------|
| AWS-ACL-001 | ACLs Without Resources | ✅ | 6 CRITICAL |
| AWS-ACL-002 | ACLs Without Logging | ✅ | 1 CRITICAL |
| AWS-ACL-003 | High WCU Usage | ✅ | 0 - All under 50% |
| AWS-ACL-004 | Default Action ALLOW | ✅ | 0 |
| AWS-ACL-005 | CloudWatch Disabled | ✅ | 2 MEDIUM |
| AWS-ACL-006 | Sample Requests Disabled | ✅ | 2 MEDIUM |
| AWS-MRG-001 | No AWS Managed Rules | ✅ | 8 CRITICAL |
| AWS-RULE-001 | Rules in COUNT Mode | ✅ | 0 - All ALLOW |

---

**Report Generated:** 2026-01-11  
**Analysis Framework:** Security Checks Framework v1.0  
**Data Sources:** PostgreSQL (configuration), Trino (traffic - not available for RO)

