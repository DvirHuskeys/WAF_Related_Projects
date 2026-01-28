# 🔥 TOP 10 RECOMMENDED NEW SECURITY CHECKS

> **Priority SQL Queries for High-Value Unused Tables**
> 
> Generated: 2026-01-04
> 
> These queries target the highest-value unused tables identified in the schema analysis.
> Each query is production-ready and includes severity ratings and remediation guidance.

---

## Quick Reference

| # | Check Name | Vendor | Severity | Table(s) Used |
|---|-----------|--------|----------|---------------|
| 1 | Cloudflare Bot Management Not in Fight Mode | Cloudflare | 🔴 CRITICAL | `cloudflare_raw_bot_management_history` |
| 2 | Cloudflare Overly Broad WAF Skip Rules | Cloudflare | 🔴 CRITICAL | `cloudflare_raw_rulesets_rule_skip_ap_rules_history` |
| 3 | Cloudflare Weak Rate Limits | Cloudflare | 🟠 HIGH | `cloudflare_raw_rulesets_rule_rate_limits_history` |
| 4 | AWS WAF Logging Not Configured | AWS | 🔴 CRITICAL | `aws_raw_waf_acl_logging_configurations_history` |
| 5 | AWS Managed Rules Overridden to COUNT | AWS | 🔴 CRITICAL | `aws_raw_acl_managed_rule_group_rule_override_history` |
| 6 | AWS ALB with Weak SSL Policy | AWS | 🟠 HIGH | `aws_raw_load_balancer_listener_history` |
| 7 | Azure WAF Exclusions Too Broad | Azure | 🔴 CRITICAL | `azure_app_gateway_waf_managed_rule_exclusions` |
| 8 | Akamai Bot Categories Not Blocking | Akamai | 🔴 CRITICAL | `akamai_raw_bot_category_actions_history` |
| 9 | Akamai Rate Policies in Alert Only | Akamai | 🟠 HIGH | `akamai_raw_security_policy_rate_policy_actions_history` |
| 10 | Akamai Attack Payload Logging Disabled | Akamai | 🟠 HIGH | `akamai_raw_sec_config_attack_payload_log_settings_history` |

---

## 1. 🔴 Cloudflare Bot Management Not in Fight Mode

**Severity:** CRITICAL | **Risk:** Automated attacks, credential stuffing, scraping

**Description:** Identifies Cloudflare zones where bot management is not properly configured in "fight mode" which actively challenges suspicious bots.

```sql
-- CF-NEW-001: Cloudflare Bot Management Not in Fight Mode
SELECT 
    z.name AS zone_name,
    z.cf_id AS zone_cf_id,
    bm.fight_mode,
    bm.enable_js,
    bm.ai_bots_protection,
    bm.sbfm_definitely_automated,
    bm.sbfm_likely_automated,
    bm.sbfm_verified_bots,
    bm.using_latest_model,
    z.organization_name,
    z.organization_id
FROM cloudflare_raw_bot_management_history bm
INNER JOIN cloudflare_raw_zones_history z ON z.id = bm.zone_id
WHERE z.is_deleted = false
  AND z.status = 'active'
  AND z.paused = false
  AND bm.is_deleted = false
  AND (
    bm.fight_mode = false 
    OR bm.enable_js = false
    OR bm.sbfm_definitely_automated NOT IN ('BLOCK', 'MANAGED_CHALLENGE')
    OR bm.sbfm_likely_automated = 'ALLOW'
  )
ORDER BY z.organization_name, z.name;
```

**Remediation:**
- Enable fight mode for active bot protection
- Enable JavaScript detection (`enable_js = true`)
- Set `sbfm_definitely_automated` to BLOCK or MANAGED_CHALLENGE
- Ensure `sbfm_likely_automated` is not set to ALLOW

---

## 2. 🔴 Cloudflare Overly Broad WAF Skip Rules

**Severity:** CRITICAL | **Risk:** WAF bypass, unprotected attack surface

**Description:** Identifies skip rules that bypass multiple WAF phases or products, creating security gaps.

```sql
-- CF-NEW-002: Cloudflare Overly Broad WAF Skip Rules
WITH skip_rule_analysis AS (
    SELECT 
        r.id AS rule_id,
        r.cf_id AS rule_cf_id,
        r.description AS rule_description,
        r.expression AS rule_expression,
        r.enabled,
        rs.name AS ruleset_name,
        rs.phase AS ruleset_phase,
        z.name AS zone_name,
        z.cf_id AS zone_cf_id,
        z.organization_name,
        z.organization_id,
        -- Count skipped rulesets
        (SELECT COUNT(*) FROM cloudflare_raw_rulesets_rule_skip_ap_rules_history skip 
         WHERE skip.rule_id = r.id AND skip.is_deleted = false) AS skipped_ruleset_count,
        -- Check if skipping current ruleset
        EXISTS (SELECT 1 FROM cloudflare_raw_rulesets_rule_skip_ap_rules_history skip 
                WHERE skip.rule_id = r.id AND skip.skip_current = true AND skip.is_deleted = false) AS skips_current
    FROM cloudflare_raw_rulesets_rules_history r
    INNER JOIN cloudflare_raw_rulesets_history rs ON rs.id = r.ruleset_id
    INNER JOIN cloudflare_raw_rulesets_instance_history ri ON ri.ruleset_id = rs.id
    INNER JOIN cloudflare_raw_zones_history z ON z.id = ri.zone_id
    WHERE r.is_deleted = false
      AND r.action = 'SKIP'
      AND r.enabled = true
      AND z.is_deleted = false
      AND z.status = 'active'
)
SELECT *
FROM skip_rule_analysis
WHERE skipped_ruleset_count > 2  -- Skipping more than 2 rulesets
   OR skips_current = true       -- Or skipping current ruleset entirely
   OR rule_expression = 'true'   -- Or expression matches everything
ORDER BY skipped_ruleset_count DESC, organization_name, zone_name;
```

**Remediation:**
- Review and narrow skip rule expressions
- Avoid skipping entire phases or multiple rulesets
- Use targeted IP allowlists instead of broad skip rules

---

## 3. 🟠 Cloudflare Weak Rate Limits

**Severity:** HIGH | **Risk:** DDoS, brute force attacks, API abuse

**Description:** Identifies rate limiting rules with thresholds that are too high to be effective.

```sql
-- CF-NEW-003: Cloudflare Weak Rate Limits
SELECT 
    r.id AS rule_id,
    r.cf_id AS rule_cf_id,
    r.description AS rule_description,
    r.expression AS rule_expression,
    rl.requests_per_period,
    rl.period AS period_seconds,
    rl.mitigation_timeout,
    rl.counting_expression,
    -- Calculate requests per minute for comparison
    ROUND((rl.requests_per_period::float / rl.period) * 60) AS requests_per_minute,
    rs.name AS ruleset_name,
    z.name AS zone_name,
    z.organization_name,
    z.organization_id
FROM cloudflare_raw_rulesets_rule_rate_limits_history rl
INNER JOIN cloudflare_raw_rulesets_rules_history r ON r.id = rl.rule_id
INNER JOIN cloudflare_raw_rulesets_history rs ON rs.id = r.ruleset_id
INNER JOIN cloudflare_raw_rulesets_instance_history ri ON ri.ruleset_id = rs.id
INNER JOIN cloudflare_raw_zones_history z ON z.id = ri.zone_id
WHERE rl.is_deleted = false
  AND r.is_deleted = false
  AND r.enabled = true
  AND z.is_deleted = false
  AND z.status = 'active'
  AND (
    -- Requests per minute > 1000 (very high)
    (rl.requests_per_period::float / rl.period) * 60 > 1000
    -- Or very short mitigation timeout (< 60 seconds)
    OR rl.mitigation_timeout < 60
    -- Or no counting expression (counts all requests)
    OR rl.counting_expression IS NULL OR rl.counting_expression = ''
  )
ORDER BY requests_per_minute DESC NULLS LAST, z.organization_name, z.name;
```

**Remediation:**
- Lower rate limit thresholds to reasonable levels (100-500 requests/minute for APIs)
- Increase mitigation timeout to at least 300 seconds
- Add specific counting expressions to target sensitive endpoints

---

## 4. 🔴 AWS WAF Logging Not Configured

**Severity:** CRITICAL | **Risk:** No visibility into attacks, compliance gaps

**Description:** Identifies AWS WAF ACLs without logging configured.

```sql
-- AWS-NEW-001: AWS WAF ACLs Without Logging Configuration
SELECT 
    acl.name AS acl_name,
    acl.arn AS acl_arn,
    acl.region,
    acl.default_action,
    acl.capacity,
    acl.aws_account_id,
    acl.organization_name,
    acl.organization_id,
    CASE 
        WHEN log.id IS NULL THEN 'NO LOGGING CONFIGURED'
        WHEN log.log_scope = 'SECURITY_HEADERS' THEN 'PARTIAL - Headers Only'
        ELSE 'CONFIGURED'
    END AS logging_status,
    log.log_destination_config,
    log.log_scope
FROM aws_raw_waf_acl_history acl
LEFT JOIN aws_raw_waf_acl_logging_configurations_history log 
    ON log.waf_acl_id = acl.id AND log.is_deleted = false
WHERE acl.is_deleted = false
  AND (log.id IS NULL OR log.log_scope != 'ALL')
ORDER BY 
    CASE WHEN log.id IS NULL THEN 0 ELSE 1 END,
    acl.organization_name, 
    acl.name;
```

**Remediation:**
- Enable WAF logging for all ACLs
- Configure log destination (S3, CloudWatch Logs, or Kinesis Data Firehose)
- Set log_scope to capture full request data for security analysis

---

## 5. 🔴 AWS Managed Rules Overridden to COUNT

**Severity:** CRITICAL | **Risk:** Known attacks not blocked, false sense of security

**Description:** Identifies managed rule group rules that have been overridden from BLOCK to COUNT.

```sql
-- AWS-NEW-002: AWS Managed Rules Overridden to COUNT Mode
SELECT 
    acl.name AS acl_name,
    acl.arn AS acl_arn,
    acl.region,
    override.managed_rule_group_name,
    override.rule_name,
    override.override_action,
    acl.aws_account_id,
    acl.organization_name,
    acl.organization_id,
    -- Count total overrides for this ACL
    COUNT(*) OVER (PARTITION BY acl.id) AS total_overrides_in_acl
FROM aws_raw_acl_managed_rule_group_rule_override_history override
INNER JOIN aws_raw_waf_acl_history acl ON acl.id = override.waf_acl_id
WHERE override.is_deleted = false
  AND acl.is_deleted = false
  AND override.override_action = 'COUNT'
ORDER BY total_overrides_in_acl DESC, acl.organization_name, acl.name, override.managed_rule_group_name;
```

**Remediation:**
- Review each overridden rule and determine if COUNT is truly necessary
- Consider using labels instead of COUNT for monitoring
- Document business justification for any rule set to COUNT
- Regularly review and re-enable rules that are no longer causing false positives

---

## 6. 🟠 AWS ALB with Weak SSL Policy

**Severity:** HIGH | **Risk:** Man-in-the-middle attacks, protocol downgrade attacks

**Description:** Identifies Application Load Balancers using outdated or weak SSL/TLS policies.

```sql
-- AWS-NEW-003: AWS ALB Listeners with Weak SSL Policies
SELECT 
    lb.load_balancer_name,
    lb.dns_name,
    lb.scheme,
    listener.listener_arn,
    listener.port,
    listener.protocol,
    listener.ssl_policy,
    lb.region,
    lb.aws_account_id,
    lb.organization_name,
    lb.organization_id,
    -- Categorize SSL policy security level
    CASE 
        WHEN listener.ssl_policy IS NULL THEN 'NO SSL'
        WHEN listener.ssl_policy LIKE '%2016%' THEN 'OUTDATED (2016)'
        WHEN listener.ssl_policy LIKE '%TLS-1-0%' THEN 'CRITICAL - TLS 1.0'
        WHEN listener.ssl_policy LIKE '%TLS-1-1%' THEN 'HIGH - TLS 1.1'
        WHEN listener.ssl_policy = 'ELBSecurityPolicy-2016-08' THEN 'OUTDATED DEFAULT'
        WHEN listener.ssl_policy LIKE '%FS%' THEN 'GOOD - Forward Secrecy'
        WHEN listener.ssl_policy LIKE '%TLS13%' THEN 'EXCELLENT - TLS 1.3'
        ELSE 'REVIEW NEEDED'
    END AS security_level
FROM aws_raw_load_balancer_listener_history listener
INNER JOIN aws_raw_load_balancers_history lb ON lb.id = listener.load_balancer_id
WHERE listener.is_deleted = false
  AND lb.is_deleted = false
  AND listener.protocol IN ('HTTPS', 'TLS')
  AND lb.scheme = 'internet-facing'
  AND (
    listener.ssl_policy IS NULL
    OR listener.ssl_policy LIKE '%2016%'
    OR listener.ssl_policy LIKE '%TLS-1-0%'
    OR listener.ssl_policy LIKE '%TLS-1-1%'
    OR listener.ssl_policy = 'ELBSecurityPolicy-2016-08'
  )
ORDER BY 
    CASE 
        WHEN listener.ssl_policy LIKE '%TLS-1-0%' THEN 1
        WHEN listener.ssl_policy LIKE '%TLS-1-1%' THEN 2
        WHEN listener.ssl_policy LIKE '%2016%' THEN 3
        ELSE 4
    END,
    lb.organization_name, lb.load_balancer_name;
```

**Remediation:**
- Upgrade to `ELBSecurityPolicy-TLS13-1-2-2021-06` or newer
- Disable TLS 1.0 and TLS 1.1
- Use policies with Forward Secrecy (FS)
- Test client compatibility before changes

---

## 7. 🔴 Azure WAF Exclusions Too Broad

**Severity:** CRITICAL | **Risk:** WAF bypass, known attacks not blocked

**Description:** Identifies WAF exclusions that are overly permissive.

```sql
-- AZURE-NEW-001: Azure WAF Overly Broad Exclusions
SELECT 
    waf.name AS waf_policy_name,
    waf.mode,
    waf.state,
    exc.match_variable,
    exc.selector_match_operator,
    exc.selector,
    waf.organization_id,
    -- Assess exclusion risk
    CASE 
        WHEN exc.selector IS NULL OR exc.selector = '' OR exc.selector = '*' THEN 'CRITICAL - Matches All'
        WHEN exc.selector_match_operator = 'CONTAINS' AND LENGTH(exc.selector) < 3 THEN 'HIGH - Very Broad Pattern'
        WHEN exc.selector_match_operator = 'STARTS_WITH' AND LENGTH(exc.selector) < 5 THEN 'HIGH - Broad Prefix'
        WHEN exc.match_variable IN ('REQUEST_HEADERS', 'REQUEST_COOKIES') AND exc.selector = '*' THEN 'CRITICAL - All Headers/Cookies'
        ELSE 'MEDIUM - Review Recommended'
    END AS risk_level,
    rg.name AS resource_group
FROM azure_app_gateway_waf_managed_rule_exclusions exc
INNER JOIN azure_app_gateway_waf_policies waf ON waf.id = exc.waf_policy_id
INNER JOIN azure_rgs rg ON rg.id = waf.rg_id
WHERE exc.is_deleted = false
  AND waf.is_deleted = false
  AND (
    exc.selector IS NULL 
    OR exc.selector = '' 
    OR exc.selector = '*'
    OR (exc.selector_match_operator = 'CONTAINS' AND LENGTH(exc.selector) < 3)
    OR (exc.selector_match_operator = 'STARTS_WITH' AND LENGTH(exc.selector) < 5)
  )
ORDER BY 
    CASE 
        WHEN exc.selector IS NULL OR exc.selector = '' OR exc.selector = '*' THEN 1
        ELSE 2
    END,
    waf.organization_id, waf.name;
```

**Remediation:**
- Replace wildcard exclusions with specific field names
- Use exact match operators instead of CONTAINS where possible
- Document business justification for each exclusion
- Regularly review and remove unnecessary exclusions

---

## 8. 🔴 Akamai Bot Categories Not Blocking

**Severity:** CRITICAL | **Risk:** Bot attacks, credential stuffing, scraping

**Description:** Identifies Akamai security policies where bot categories are set to monitor/allow instead of block.

```sql
-- AKAMAI-NEW-001: Akamai Bot Categories Not Blocking
SELECT 
    sp.name AS security_policy_name,
    sp.akamai_id AS policy_akamai_id,
    bc.name AS bot_category_name,
    bc.description AS category_description,
    bca.action AS current_action,
    sc.name AS security_config_name,
    sc.organization_name,
    sc.organization_id,
    -- Risk assessment
    CASE 
        WHEN bca.action = 'MONITOR' AND bc.name LIKE '%malicious%' THEN 'CRITICAL - Malicious Bots Not Blocked'
        WHEN bca.action = 'MONITOR' AND bc.name LIKE '%scraper%' THEN 'HIGH - Scrapers Not Blocked'
        WHEN bca.action = 'MONITOR' THEN 'MEDIUM - Monitoring Only'
        WHEN bca.action IS NULL THEN 'HIGH - No Action Configured'
        ELSE 'LOW'
    END AS risk_level
FROM akamai_raw_bot_category_actions_history bca
INNER JOIN akamai_raw_security_policies_history sp ON sp.id = bca.security_policy_id
INNER JOIN akamai_raw_security_configuration_versions_history scv ON scv.id = sp.config_version_id
INNER JOIN akamai_raw_security_configurations_history sc ON sc.id = scv.config_id
INNER JOIN akamai_raw_bot_categories_history bc ON bc.id = bca.category_id
WHERE bca.is_deleted = false
  AND sp.is_deleted = false
  AND sc.is_deleted = false
  AND bc.is_deleted = false
  AND sp.apply_botman_controls = true
  AND (bca.action IN ('MONITOR', 'ALLOW') OR bca.action IS NULL)
ORDER BY 
    CASE bca.action WHEN 'ALLOW' THEN 1 WHEN NULL THEN 2 ELSE 3 END,
    sc.organization_name, sc.name, sp.name;
```

**Remediation:**
- Set malicious bot categories to DENY action
- Configure appropriate challenge actions for suspicious bots
- Enable bot management controls on all security policies
- Review bot category definitions and update actions accordingly

---

## 9. 🟠 Akamai Rate Policies in Alert Only Mode

**Severity:** HIGH | **Risk:** DDoS attacks, brute force not mitigated

**Description:** Identifies rate policies that are configured to alert but not block.

```sql
-- AKAMAI-NEW-002: Akamai Rate Policies in Alert-Only Mode
SELECT 
    rp.name AS rate_policy_name,
    rp.akamai_id AS policy_akamai_id,
    rp.description,
    rp.type AS policy_type,
    rp.match_type,
    rp.average_threshold,
    rp.burst_threshold,
    rp.burst_window,
    rpa.ipv4_action,
    rpa.ipv6_action,
    sp.name AS security_policy_name,
    sc.name AS security_config_name,
    sc.organization_name,
    sc.organization_id,
    -- Calculate effective protection
    CASE 
        WHEN rpa.ipv4_action = 'ALERT' AND rpa.ipv6_action = 'ALERT' THEN 'NO PROTECTION - Alert Only'
        WHEN rpa.ipv4_action = 'ALERT' OR rpa.ipv6_action = 'ALERT' THEN 'PARTIAL - One Protocol Alert Only'
        WHEN rpa.ipv4_action IS NULL OR rpa.ipv6_action IS NULL THEN 'INCOMPLETE - Missing Action'
        ELSE 'PROTECTED'
    END AS protection_status
FROM akamai_raw_security_policy_rate_policy_actions_history rpa
INNER JOIN akamai_raw_sec_config_rate_policies_history rp ON rp.id = rpa.rate_policy_id
INNER JOIN akamai_raw_security_policies_history sp ON sp.id = rpa.security_policy_id
INNER JOIN akamai_raw_security_configuration_versions_history scv ON scv.id = sp.config_version_id
INNER JOIN akamai_raw_security_configurations_history sc ON sc.id = scv.config_id
WHERE rpa.is_deleted = false
  AND rp.is_deleted = false
  AND sp.is_deleted = false
  AND sc.is_deleted = false
  AND sp.apply_rate_controls = true
  AND (
    rpa.ipv4_action = 'ALERT' 
    OR rpa.ipv6_action = 'ALERT'
    OR rpa.ipv4_action IS NULL 
    OR rpa.ipv6_action IS NULL
  )
ORDER BY sc.organization_name, sc.name, sp.name, rp.name;
```

**Remediation:**
- Change alert-only rate policies to DENY or DENY_CUSTOM
- Ensure both IPv4 and IPv6 actions are configured
- Review thresholds and adjust based on legitimate traffic patterns
- Start with higher thresholds and gradually lower them

---

## 10. 🟠 Akamai Attack Payload Logging Disabled

**Severity:** HIGH | **Risk:** Cannot analyze attacks, poor incident response

**Description:** Identifies security configurations where attack payload logging is disabled.

```sql
-- AKAMAI-NEW-003: Akamai Attack Payload Logging Disabled
SELECT 
    sc.name AS security_config_name,
    sc.akamai_id AS config_akamai_id,
    scv.version,
    apl.enabled AS payload_logging_enabled,
    apl.request_body_type,
    apl.response_body_type,
    sc.organization_name,
    sc.organization_id,
    sc.production_hostnames,
    -- Risk assessment
    CASE 
        WHEN apl.enabled = false THEN 'HIGH - No Attack Payload Logging'
        WHEN apl.request_body_type = 'NONE' THEN 'MEDIUM - No Request Body Logging'
        WHEN apl.response_body_type = 'NONE' THEN 'LOW - No Response Body Logging'
        ELSE 'OK'
    END AS logging_gap
FROM akamai_raw_sec_config_attack_payload_log_settings_history apl
INNER JOIN akamai_raw_security_configuration_versions_history scv ON scv.id = apl.config_version_id
INNER JOIN akamai_raw_security_configurations_history sc ON sc.id = scv.config_id
WHERE apl.is_deleted = false
  AND scv.is_deleted = false
  AND sc.is_deleted = false
  AND scv.version = sc.production_version  -- Only check production version
  AND (
    apl.enabled = false
    OR apl.request_body_type = 'NONE'
  )
ORDER BY 
    CASE WHEN apl.enabled = false THEN 1 ELSE 2 END,
    sc.organization_name, sc.name;
```

**Remediation:**
- Enable attack payload logging
- Set request_body_type to capture attack payloads
- Ensure logs are being shipped to your SIEM
- Review storage retention policies for compliance

---

## Summary: Implementation Priority

| Priority | Checks | Estimated Effort |
|----------|--------|------------------|
| 🔴 **Week 1** | #1, #2, #4, #5, #7, #8 | Critical security gaps |
| 🟠 **Week 2** | #3, #6, #9, #10 | High-value improvements |

## Next Steps

1. **Validate Queries**: Run each query against your production database to verify data availability
2. **Create Recipes**: Use the recipe templates in `recipe-templates.md` to implement these checks
3. **Set Up Alerting**: Configure alerts for new findings
4. **Schedule Reviews**: Set up periodic reviews for findings that require human judgment

---

*Generated by WAF Security Analysis Team - 2026-01-04*



