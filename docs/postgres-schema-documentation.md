# Postgres Database Schema Documentation

**Generated:** 2025-12-28 11:11:09 | **Updated:** 2026-01-04 (Recipe Usage Analysis)

**Database:** web_apps (Neon PostgreSQL)

**Total Tables:** 336

---

# 🔥 HIGH-VALUE UNUSED TABLES (Priority for New Security Checks!)

> **These tables contain critical security data but are NOT yet used by any production recipes. High ROI for new security checks!**

## 🚨 CRITICAL Priority (Immediate Security Value)

| Table | Vendor | Key Security Fields | Why It Matters | Recommended Check |
|-------|--------|---------------------|----------------|-------------------|
| `cloudflare_raw_bot_management_history` | Cloudflare | `ai_bots_protection`, `fight_mode`, `enable_js`, `sbfm_*` | Bot protection config - detect weak/disabled protection | Bot mgmt not in fight mode |
| `cloudflare_raw_rulesets_rule_skip_ap_rules_history` | Cloudflare | `skip_current`, `skipped_ruleset_id`, `skipped_rule_id` | WAF bypass rules - security gaps | Overly broad skip rules |
| `cloudflare_raw_rulesets_rule_rate_limits_history` | Cloudflare | `requests_per_period`, `period`, `mitigation_timeout` | Rate limiting config - DDoS protection | Weak rate limits (<100 RPM) |
| `aws_raw_waf_acl_logging_configurations_history` | AWS | `log_destination_config`, `log_scope`, `default_behavior` | WAF logging - visibility gaps | Missing/incomplete logging |
| `aws_raw_acl_managed_rule_group_rule_override_history` | AWS | `override_action` | Rule overrides - weakened protection | Rules overridden to COUNT |
| `azure_app_gateway_waf_managed_rule_exclusions` | Azure | `match_variable`, `selector`, `selector_match_operator` | Rule exclusions - bypass conditions | Overly broad exclusions |
| `akamai_raw_bot_category_actions_history` | Akamai | `action`, `category_id` | Bot category actions | Bot categories not blocking |
| `akamai_raw_security_policy_rate_policy_actions_history` | Akamai | `ipv4_action`, `ipv6_action`, `rate_policy_id` | Rate policy enforcement | Rate policies in alert-only |

## ⚠️ HIGH Priority (Strong Security Value)

| Table | Vendor | Key Security Fields | Why It Matters | Recommended Check |
|-------|--------|---------------------|----------------|-------------------|
| `cloudflare_raw_rulesets_rule_block_action_parameters_history` | Cloudflare | `content`, `status_code`, `content_type` | Block response config | Custom block pages leaking info |
| `aws_raw_load_balancer_listener_history` | AWS | `ssl_policy`, `protocol`, `certificate_arns` | TLS configuration | Weak/outdated SSL policies |
| `aws_raw_security_group_inbounds_history` | AWS | `source`, `from_port`, `to_port`, `protocol` | Network access rules | 0.0.0.0/0 on sensitive ports |
| `azure_fd_waf_managed_rules` | Azure | `default_action`, `default_state`, `rule_id` | Managed rule config | Rules disabled by default |
| `azure_app_gateway_waf_managed_rule_set_overrides` | Azure | `action`, `state`, `sensitivity` | Rule overrides | Rules downgraded to Log |
| `akamai_raw_bot_detection_actions_history` | Akamai | `action`, `detection_id` | Bot detection actions | Detections not taking action |
| `akamai_raw_sec_config_rate_policies_history` | Akamai | `burst_threshold`, `average_threshold`, `same_action_on_ipv6` | Rate policy config | Weak thresholds |
| `akamai_raw_sec_config_attack_payload_log_settings_history` | Akamai | `enabled`, `request_body_type`, `response_body_type` | Attack logging | Payload logging disabled |

## 📊 MEDIUM Priority (Operational Security Value)

| Table | Vendor | Key Security Fields | Why It Matters | Recommended Check |
|-------|--------|---------------------|----------------|-------------------|
| `cloudflare_raw_rulesets_rule_execute_action_parameters_history` | Cloudflare | `ruleset_id_to_execute`, `version` | Managed ruleset execution | Missing managed rulesets |
| `aws_raw_waf_acl_rule_statements_history` | AWS | `excluded_rules`, `rate_limit`, `type` | Rule statement details | Excluded rules in managed groups |
| `aws_raw_waf_rule_group_rules_history` | AWS | `action`, `priority`, `rule_statements_hash` | Custom rule groups | Rules in Count mode |
| `azure_fd_waf_custom_rules` | Azure | `action`, `enabled_state`, `rate_limit_threshold` | Custom rules | Rate limits too high |
| `azure_app_gateway_waf_custom_rules` | Azure | `action`, `rate_limit_duration`, `rate_limit_threshold` | Custom rules | Custom rules in Log mode |
| `akamai_raw_security_policy_rapid_rules_history` | Akamai | `action`, `locked`, `condition_exception` | Rapid rules | Rapid rules not in deny |
| `akamai_raw_sec_config_custom_rules_history` | Akamai | `sampling_rate`, `status`, `is_activated` | Custom rules | Custom rules not activated |

---

# 📋 TABLES CURRENTLY USED BY RECIPES

> **Reference: Which recipes use which tables**

## Cloudflare Tables (11 tables in use)

| Table | Recipe(s) Using It |
|-------|-------------------|
| `CloudflareZoneTable` | missing-managed-rulesets, skip-rules-with-broad-ip-list, cf-zones-paused, missing-rate-limit, non-proxied-dns, empty-custom-lists, waf-rule-always-true, skip-rules-agent-based |
| `CloudflareAccountTable` | missing-managed-rulesets, skip-rules-with-broad-ip-list, cf-zones-paused, empty-custom-lists |
| `CloudflareWafRulesRegularTable` | skip-rules-with-broad-ip-list, skip-rules-agent-based, waf-rule-always-true |
| `CloudflareWafRulesTable` | waf-rule-always-true |
| `CloudflareDnsRecordsTable` | non-proxied-dns-record-pointing-to-unprotected-web-assets |
| `CloudflareListTable` | skip-rules-with-broad-ip-list, empty-custom-lists |
| `CloudflareListItemTable` | skip-rules-with-broad-ip-list |
| `RulesetTable` / `RulesetRegularTable` | missing-managed-rulesets, skip-rules-with-broad-ip-list, waf-rule-always-true |
| `CloudflareRulesetInstanceTable` / `CloudflareRulesetInstanceRegularTable` | missing-managed-rulesets, skip-rules-with-broad-ip-list |
| `CloudflareRawZoneMetricsTable` | missing-managed-rulesets |

## AWS Tables (16 tables in use)

| Table | Recipe(s) Using It |
|-------|-------------------|
| `WafAclTable` | internet-facing-alb-without-waf, cloudfront-waf-bypass-via-alb-origin, log-analysis-recipe, multiple AWS recipes |
| `WafAclRuleTable` | waf-rules-not-blocking, managed-rules-count-mode |
| `WafAclAssociatedResourceTable` | internet-facing-alb-without-waf, cloudfront-without-waf |
| `CloudFrontDistributionTable` | cloudfront-without-waf, cloudfront-waf-bypass-via-alb-origin |
| `LoadBalancerTable` | internet-facing-alb-without-waf, cloudfront-waf-bypass-via-alb-origin |
| `CloudwatchMetricsTable` | waf-rules-not-blocking |
| `WafIpSetTable` | overly-permissive-ip-allowlist |
| `WafRuleGroupTable` | waf-rules-not-blocking |
| `WafManagedRuleGroupTable` | managed-rules-count-mode |
| `AclRuleOverrideManagedRuleGroupRuleTable` | managed-rules-count-mode |
| `SecurityGroupInboundsTable` | (via join in ALB recipes) |
| `LoadBalancerSecurityGroupsTable` | (via join in ALB recipes) |

## Azure Tables (12 tables in use)

| Table | Recipe(s) Using It |
|-------|-------------------|
| `AzureAppGatewayTable` | az-waf-no-custom-rules, az-app-gateway-without-waf |
| `AzureAppGatewayWafPoliciesTable` | az-waf-no-custom-rules, az-waf-detection-mode |
| `AzureAppGatewayWafCustomRulesTable` | az-waf-no-custom-rules |
| `AzureAppGatewayHttpListenersTable` | az-app-gateway-listeners-without-waf |
| `AzureAppGatewayRoutingRulesTable` | az-app-gateway-routing-rules |
| `AzureAppGatewayFrontendsTable` | az-app-gateway-without-waf |
| `AzureWafPoliciesTable` | az-fd-waf-detection-mode |
| `AzureFrontDoorSecurityPoliciesTable` | az-fd-without-waf |
| `AzureFrontDoorWafCustomRulesTable` | az-fd-no-custom-rules |
| `AzureFdWafMetricsTable` | az-fd-waf-metrics |
| `AzureResourceGroupsTable` | (common join for Azure recipes) |
| `OrgAzureIntegrationTable` | (common join for Azure recipes) |

## Akamai Tables (7 tables in use)

| Table | Recipe(s) Using It |
|-------|-------------------|
| `AkamaiRawSecurityConfigurationTable` | properties-without-waf, waf-rules-not-in-deny |
| `AkamaiRawSecurityConfigurationVersionTable` | properties-without-waf, waf-rules-not-in-deny |
| `AkamaiRawSecurityPolicyTable` | waf-rules-not-in-deny |
| `AkamaiRawSecurityConfigurationMatchTargetTable` | properties-without-waf |
| `AkamaiRawSecurityConfigMatchTargetHostnameTable` | properties-without-waf |
| `AkamaiRawSecurityPolicyAttackGroupsTable` | waf-rules-not-in-deny |
| `AkamaiPropertiesTable` | properties-without-waf |

---

## 📊 Executive Summary

| Category | Count |
|----------|-------|
| ✅ **Fresh Tables (Active Data)** | 142 |
| ⚠️ Stale/View Tables | 33 |
| ❌ Empty Tables | 41 |
| 🔥 **High-Value Unused Tables** | 24 |
| ✅ **Tables Used by Recipes** | 46 |

### Provider Coverage

| Provider | Tables | Key Security Data | Tables in Use |
|----------|--------|-------------------|---------------|
| **Akamai** | 101 | WAF policies, Bot management, Rate limiting, Custom rules | 7 |
| **AWS** | 98 | WAF ACLs, CloudFront, ALB, Security Groups, Route53 | 16 |
| **Azure** | 89 | Front Door, App Gateway WAF, Custom rules, Managed rules | 12 |
| **Cloudflare** | 36 | Rulesets, DNS records, Bot management, Rate limits | 11 |
| **Organization** | 9 | Integration configs per cloud provider | - |

## 🔍 Quick Reference: Misconfiguration Detection

### Critical Fields to Monitor

| Field Pattern | What to Check | Risk if Misconfigured |
|--------------|---------------|----------------------|
| `mode`, `action`, `enabled_state` | Prevention vs Detection mode | Attacks not blocked |
| `bypass_*`, `skip_*`, `exclude_*` | WAF bypass rules | Security gaps |
| `rate_*`, `threshold_*`, `limit_*` | Rate limiting thresholds | DDoS/brute-force exposure |
| `proxied` | DNS proxy status | Origin IP exposure |
| `inbound_*`, `0.0.0.0/0` | Security group rules | Open to internet |
| `ssl_*`, `https_*`, `certificate_*` | TLS configuration | MitM attacks |
| `bot_*`, `challenge_*` | Bot protection | Automated attacks |

---

# ✅ FRESH TABLES (Active Data - Last 24h)

**142 tables with recent data - these are your primary data sources**

## Cloudflare (15 fresh tables)

### `cloudflare_raw_zone_metrics_history`

📊 **433,357 rows** | 🕐 Last updated: 2025-12-28 09:05:49.164713

| Field | Type | Purpose |
|-------|------|---------|
| `security_action` | USER-DEFINED | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `metric_timestamp` | timestamp without time zone | 📊 Metric/count value |
| `security_source` | USER-DEFINED | 📄 Data field |
| `metric_period` | integer | 📊 Metric/count value |
| `metric_value` | integer | 📊 Metric/count value |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `account_id` | uuid | 👤 Account reference |
| `integration_id` | uuid | 🔗 Integration reference |
| `zone_id` | uuid | 🌐 Zone/Domain reference |

### `cloudflare_raw_rules_metrics_history`

📊 **254,259 rows** | 🕐 Last updated: 2025-12-28 09:05:39.269496

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `account_id` | uuid | 👤 Account reference |
| `zone_id` | uuid | 🌐 Zone/Domain reference |
| `ruleset_id` | uuid | 📜 Rule reference - track rule coverage |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `source` | USER-DEFINED | 📄 Data field |
| `metric_timestamp` | timestamp without time zone | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `metric_value` | integer | 📊 Metric/count value |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `cloudflare_raw_dns_records_history`

📊 **26,544 rows** | 🕐 Last updated: 2025-12-28 08:02:34.655409

| Field | Type | Purpose |
|-------|------|---------|
| `proxied` | boolean | ⚠️ **IMPORTANT** - Proxy status (origin exposure) |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `zone_id` | uuid | 🌐 Zone/Domain reference |
| `cf_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `content` | character varying | 📄 Content/payload data |
| `proxiable` | boolean | 🔘 Feature flag/toggle |
| `ttl` | integer | 🔢 Numeric value |
| `comment` | text | 📝 Documentation/notes |
| `tags` | json | 🏷️ Resource tagging |
| `settings` | json | ⚙️ Configuration setting |
| `settings_flatten_cname` | boolean | 🔗 CNAME - check for dangling records |
| `cf_creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `cf_modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `account_id` | uuid | 👤 Account reference |
| `integration_id` | uuid | 🔗 Integration reference |

### `cloudflare_raw_rulesets_instance_history`

📊 **15,605 rows** | 🕐 Last updated: 2025-12-28 08:04:16.084678

| Field | Type | Purpose |
|-------|------|---------|
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `account_id` | uuid | 👤 Account reference |
| `integration_id` | uuid | 🔗 Integration reference |
| `zone_id` | uuid | 🌐 Zone/Domain reference |
| `ruleset_id` | uuid | 📜 Rule reference - track rule coverage |

### `cloudflare_raw_rulesets_rules_history`

📊 **11,554 rows** | 🕐 Last updated: 2025-12-28 08:02:42.564907

| Field | Type | Purpose |
|-------|------|---------|
| **`enabled`** | boolean | 🔴 **CRITICAL** - Security feature toggle |
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `action_parameters` | json | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `ratelimit_parameters` | json | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `cf_id` | character varying | 🔗 Foreign key reference |
| `description` | text | 🌐 IP/Network - check for overly broad ranges |
| `expression` | text | 🔍 Match pattern - verify coverage |
| `position` | integer | 🔢 Numeric value |
| `categories` | json | 📦 Complex nested data |
| `ref` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `ruleset_id` | uuid | 📜 Rule reference - track rule coverage |
| `version` | integer | 🔢 Numeric value |
| `last_updated` | timestamp with time zone | 📅 Timestamp |
| `password_expression` | character varying | 🔍 Match pattern - verify coverage |
| `username_expression` | character varying | 🔍 Match pattern - verify coverage |
| `logging_enabled` | boolean | 📝 Logging configuration |

### `cloudflare_raw_list_items_history`

📊 **1,445 rows** | 🕐 Last updated: 2025-12-28 08:02:15.764479

| Field | Type | Purpose |
|-------|------|---------|
| `cf_id` | character varying | 🔗 Foreign key reference |
| `value` | character varying | 📄 Data field |
| `ip` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `comment` | text | 📝 Documentation/notes |
| `redirect_data` | json | 📦 Complex nested data |
| `created_on` | character varying | 📅 Creation tracking - detect age/staleness |
| `modified_on` | character varying | 📅 Change tracking - detect drift |
| `item_metadata` | json | 📦 Complex nested data |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `account_id` | uuid | 👤 Account reference |
| `integration_id` | uuid | 🔗 Integration reference |
| `list_id` | uuid | 🔗 Foreign key reference |

### `cloudflare_raw_rulesets_history`

📊 **1,370 rows** | 🕐 Last updated: 2025-12-28 08:04:15.306296

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `cf_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | text | 🌐 IP/Network - check for overly broad ranges |
| `kind` | USER-DEFINED | 🏷️ Classification/type |
| `phase` | character varying | 📄 Data field |
| `last_updated` | timestamp without time zone | 📅 Timestamp |
| `version` | character varying | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `cloudflare_raw_rulesets_rule_execute_action_parameters_history`

📊 **881 rows** | 🕐 Last updated: 2025-12-28 08:02:26.022656

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `ruleset_id_to_execute` | uuid | 📜 Rule reference - track rule coverage |
| `ruleset_cf_id_to_execute` | character varying | 📜 Rule reference - track rule coverage |
| `version` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `cloudflare_raw_zones_history`

📊 **584 rows** | 🕐 Last updated: 2025-12-28 08:01:56.594165

| Field | Type | Purpose |
|-------|------|---------|
| `cf_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `status` | character varying | 📊 Resource state tracking |
| `created_on` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modified_on` | timestamp without time zone | 📅 Change tracking - detect drift |
| `activated_on` | timestamp without time zone | 📅 Timestamp |
| `paused` | boolean | 🔘 Feature flag/toggle |
| `type` | character varying | 🏷️ Classification/type |
| `development_mode` | double precision | 📄 Data field |
| `name_servers` | json | 📦 Complex nested data |
| `original_name_servers` | json | 📦 Complex nested data |
| `original_registrar` | character varying | 📄 Data field |
| `original_dnshost` | character varying | 🌐 DNS configuration |
| `plan_name` | character varying | 📄 Data field |
| `plan_price` | double precision | 📄 Data field |
| `meta` | json | 📦 Complex nested data |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `account_id` | uuid | 👤 Account reference |
| `integration_id` | uuid | 🔗 Integration reference |

### `cloudflare_raw_bot_management_history`

📊 **340 rows** | 🕐 Last updated: 2025-12-28 08:01:52.530387

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `account_id` | uuid | 👤 Account reference |
| `zone_id` | uuid | 🌐 Zone/Domain reference |
| `cf_id` | character varying | 🔗 Foreign key reference |
| `ai_bots_protection` | USER-DEFINED | 🤖 Bot detection/protection config |
| `cf_robots_variant` | USER-DEFINED | 🤖 Bot detection/protection config |
| `crawler_protection` | USER-DEFINED | 📄 Data field |
| `enable_js` | boolean | 🛡️ JS detection - bot protection feature |
| `fight_mode` | boolean | 🔘 Feature flag/toggle |
| `is_robots_txt_managed` | boolean | 🤖 Bot detection/protection config |
| `optimize_wordpress` | boolean | 🔘 Feature flag/toggle |
| `sbfm_definitely_automated` | USER-DEFINED | 📄 Data field |
| `sbfm_likely_automated` | USER-DEFINED | 📄 Data field |
| `sbfm_static_resource_protection` | boolean | 🔘 Feature flag/toggle |
| `sbfm_verified_bots` | USER-DEFINED | 🤖 Bot detection/protection config |
| `suppress_session_score` | boolean | 🔘 Feature flag/toggle |
| `using_latest_model` | boolean | 🔘 Feature flag/toggle |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `cloudflare_raw_lists_history`

📊 **102 rows** | 🕐 Last updated: 2025-12-28 08:01:59.145511

| Field | Type | Purpose |
|-------|------|---------|
| `cf_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | text | 🌐 IP/Network - check for overly broad ranges |
| `kind` | USER-DEFINED | 🏷️ Classification/type |
| `num_items` | integer | 🔢 Numeric value |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `account_id` | uuid | 👤 Account reference |
| `integration_id` | uuid | 🔗 Integration reference |

### `cloudflare_raw_rulesets_rule_skip_ap_rules_history`

📊 **83 rows** | 🕐 Last updated: 2025-12-28 08:02:28.119707

| Field | Type | Purpose |
|-------|------|---------|
| `skip_current` | boolean | ⚠️ **IMPORTANT** - Bypass/exclusion - potential security gap |
| `id` | uuid | 🔑 Primary identifier |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `skipped_ruleset_id` | uuid | 📜 Rule reference - track rule coverage |
| `skipped_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `cloudflare_raw_rulesets_rule_rate_limits_history`

📊 **64 rows** | 🕐 Last updated: 2025-12-28 08:02:30.941272

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `period` | integer | 🔢 Numeric value |
| `counting_expression` | character varying | 🔍 Match pattern - verify coverage |
| `mitigation_timeout` | integer | 🔢 Numeric value |
| `requests_per_period` | integer | 🔢 Numeric value |
| `requests_to_origin` | boolean | 🔘 Feature flag/toggle |
| `score_per_period` | integer | 🔢 Numeric value |
| `score_response_header_name` | character varying | 📄 Data field |
| `characteristics` | json | 📦 Complex nested data |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `cloudflare_raw_rulesets_rule_block_action_parameters_history`

📊 **44 rows** | 🕐 Last updated: 2025-12-28 08:02:24.710378

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `content` | text | 📄 Content/payload data |
| `content_type` | character varying | 📄 Content/payload data |
| `status_code` | integer | 🔢 Numeric value |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `cloudflare_raw_accounts_history`

📊 **33 rows** | 🕐 Last updated: 2025-12-28 08:01:25.733845

| Field | Type | Purpose |
|-------|------|---------|
| `cf_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `created_on` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `enforce_twofactor` | boolean | 🔘 Feature flag/toggle |
| `abuse_contact_email` | character varying | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `integration_id` | uuid | 🔗 Integration reference |

## AWS (42 fresh tables)

### `aws_raw_cloudwatch_waf_metrics_history`

📊 **5,078,961 rows** | 🕐 Last updated: 2025-12-28 09:01:39.011404

| Field | Type | Purpose |
|-------|------|---------|
| `metric_type` | USER-DEFINED | 🏷️ Classification/type |
| `metric_date` | timestamp without time zone | 📊 Metric/count value |
| `metric_value` | double precision | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `entity_type` | USER-DEFINED | 🏷️ Classification/type |
| `waf_acl_id` | uuid | 🔗 Foreign key reference |
| `waf_managed_rule_group_id` | uuid | 📜 Rule reference - track rule coverage |
| `waf_managed_rule_group_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `waf_rule_group_id` | uuid | 📜 Rule reference - track rule coverage |
| `waf_rule_group_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `waf_acl_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_cloudwatch_cloudfront_metrics_history`

📊 **1,036,633 rows** | 🕐 Last updated: 2025-12-28 09:01:51.353543

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `metric_type` | USER-DEFINED | 🏷️ Classification/type |
| `metric_date` | timestamp without time zone | 📊 Metric/count value |
| `metric_value` | double precision | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `cloudfront_distribution_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_route53_resource_records_values_history`

📊 **494,209 rows** | 🕐 Last updated: 2025-12-28 08:13:36.483885

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `hosted_resource_record_hash` | character varying | 🌐 DNS configuration |
| `resource_record` | text | 🌐 DNS configuration |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_route53_hosted_resource_records_history`

📊 **184,114 rows** | 🕐 Last updated: 2025-12-28 08:13:36.421074

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `hosted_zone_id` | uuid | 🌐 Zone/Domain reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `record_type` | character varying | 🌐 DNS configuration |
| `unique_hash` | character varying | 📄 Data field |
| `set_identifier` | character varying | 🔗 Foreign key reference |
| `weight` | integer | 🔢 Numeric value |
| `routing_region` | character varying | 📄 Data field |
| `geo_location` | jsonb | 📦 Complex nested data |
| `failover` | character varying | 📄 Data field |
| `multi_value_answer` | boolean | 🔘 Feature flag/toggle |
| `ttl` | integer | 🔢 Numeric value |
| `alias_target_hosted_zone_id` | character varying | 🌐 Zone/Domain reference |
| `alias_target_dns_name` | character varying | 🌐 DNS configuration |
| `alias_target_evaluate_target_health` | boolean | 🔘 Feature flag/toggle |
| `health_check_id` | character varying | 🔗 Foreign key reference |
| `traffic_policy_instance_id` | character varying | 🔗 Foreign key reference |
| `cidr_routing_collection_id` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `cidr_routing_location_name` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `geo_proximity_aws_region` | character varying | 📄 Data field |
| `geo_proximity_local_zone_group` | character varying | 📄 Data field |
| `geo_proximity_coordinates_latitude` | character varying | 📄 Data field |
| `geo_proximity_coordinates_longitude` | character varying | 📄 Data field |
| `geo_proximity_bias` | integer | 🔢 Numeric value |
| `raw_json` | jsonb | 📦 Complex nested data |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_acl_rule_statements_history`

📊 **64,326 rows** | 🕐 Last updated: 2025-12-28 08:15:49.227556

| Field | Type | Purpose |
|-------|------|---------|
| `excluded_rules` | ARRAY | ⚠️ **IMPORTANT** - Bypass/exclusion - potential security gap |
| `rate_limit` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `waf_acl_id` | uuid | 🔗 Foreign key reference |
| `waf_acl_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `root_statement_id` | uuid | 🔗 Foreign key reference |
| `parent_statement_id` | uuid | 🔗 Foreign key reference |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `additional_config` | jsonb | ⚙️ Configuration setting |
| `rule_statements_hash` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `search_string` | bytea | 📄 Data field |
| `positional_constraint` | USER-DEFINED | 📄 Data field |
| `field_to_match_type` | USER-DEFINED | 🏷️ Classification/type |
| `country_codes` | ARRAY | 📊 Metric/count value |
| `ip_set_id` | uuid | 🌐 IP/Network - check for overly broad ranges |
| `arn` | character varying | 📄 Data field |
| `header_name` | character varying | 📄 Data field |
| `fallback_behavior` | USER-DEFINED | 📄 Data field |
| `position` | USER-DEFINED | 📄 Data field |
| `scope` | character varying | 📄 Data field |
| `key` | character varying | 📄 Data field |
| `vendor_name` | character varying | 📄 Data field |
| `managed_rule_group_name` | character varying | 📄 Data field |
| `managed_rule_group_config` | jsonb | ⚙️ Configuration setting |
| `evaluation_window_sec` | integer | 🔢 Numeric value |
| `aggregate_key_type` | USER-DEFINED | 🏷️ Classification/type |
| `regex_string` | character varying | 🔍 Match pattern - verify coverage |
| `pattern_set_id` | uuid | 🔍 Match pattern - verify coverage |
| `pattern_set_arn` | character varying | 🔍 Match pattern - verify coverage |
| `rule_group_arn` | character varying | 📄 Data field |
| `comparison_operator` | USER-DEFINED | 📄 Data field |
| `size` | integer | 🔢 Numeric value |
| `sensitivity_level` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_load_balancer_listener_rules_ass_target_groups_history`

📊 **52,977 rows** | 🕐 Last updated: 2025-12-28 08:19:18.428213

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `region` | character varying | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `load_balancer_listener_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `load_balancer_target_group_id` | uuid | 🔗 Foreign key reference |
| `weight` | integer | 🔢 Numeric value |
| `percent` | integer | 🔢 Numeric value |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_security_group_inbounds_history`

📊 **16,604 rows** | 🕐 Last updated: 2025-12-28 08:11:24.687311

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `security_group_id` | uuid | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `ip_version` | USER-DEFINED | 🌐 IP/Network - check for overly broad ranges |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `protocol` | USER-DEFINED | 🔒 Protocol - verify HTTPS enforcement |
| `source` | cidr | 📄 Data field |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `from_port` | integer | 🔌 Port config - verify restricted ports |
| `to_port` | integer | 🔌 Port config - verify restricted ports |
| `prefix_list_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_load_balancer_listener_rules_conditions_history`

📊 **13,358 rows** | 🕐 Last updated: 2025-12-28 08:19:17.110953

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `region` | character varying | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `listener_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `condition_type` | character varying | 🏷️ Classification/type |
| `values` | jsonb | 📦 Complex nested data |
| `values_mapping` | jsonb | 📦 Complex nested data |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_acl_rule_statement_text_transform_history`

📊 **12,228 rows** | 🕐 Last updated: 2025-12-28 08:15:55.629248

| Field | Type | Purpose |
|-------|------|---------|
| `transformation_priority` | integer | 🔢 Numeric value |
| `transformation_type` | USER-DEFINED | 🏷️ Classification/type |
| `transformation_config` | jsonb | ⚙️ Configuration setting |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_rule_statement_field_to_match_history`

📊 **11,607 rows** | 🕐 Last updated: 2025-12-28 08:15:54.619424

| Field | Type | Purpose |
|-------|------|---------|
| `acl_statement_id` | uuid | 🔗 Foreign key reference |
| `rule_group_statement_id` | uuid | 📜 Rule reference - track rule coverage |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `name` | character varying | 🏷️ Resource name/identifier |
| `value` | character varying | 📄 Data field |
| `additional_config` | jsonb | ⚙️ Configuration setting |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `header_name` | character varying | 📄 Data field |
| `argument_name` | character varying | 📄 Data field |
| `match_pattern` | jsonb | 🔍 Match pattern - verify coverage |
| `match_scope` | USER-DEFINED | 📄 Data field |
| `invalid_fallback_behavior` | USER-DEFINED | 📄 Data field |
| `oversize_handling` | USER-DEFINED | 📄 Data field |
| `fallback_behavior` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_load_balancer_listener_rules_history`

📊 **9,612 rows** | 🕐 Last updated: 2025-12-28 08:19:15.134363

| Field | Type | Purpose |
|-------|------|---------|
| `action_type` | character varying | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `region` | character varying | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `load_balancer_id` | uuid | 🔗 Foreign key reference |
| `listener_id` | uuid | 🔗 Foreign key reference |
| `rule_arn` | character varying | 📄 Data field |
| `priority` | integer | 🔢 Numeric value |
| `is_default` | boolean | 🔘 Feature flag/toggle |
| `has_auth` | boolean | 🔘 Feature flag/toggle |
| `auth_type` | character varying | 🏷️ Classification/type |
| `auth_config` | jsonb | ⚙️ Configuration setting |
| `fixed_response_content_type` | character varying | 📄 Content/payload data |
| `fixed_response_body` | character varying | 📄 Content/payload data |
| `fixed_response_code` | character varying | 📄 Data field |
| `forward_target_groups_arns` | jsonb | 📦 Complex nested data |
| `redirect_protocol` | character varying | 🔒 Protocol - verify HTTPS enforcement |
| `redirect_port` | integer | 🔌 Port config - verify restricted ports |
| `redirect_host` | character varying | 📄 Data field |
| `redirect_path` | character varying | 📄 Data field |
| `redirect_query` | character varying | 📄 Data field |
| `redirect_status_code` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_prefix_list_entries_history`

📊 **6,204 rows** | 🕐 Last updated: 2025-12-28 08:11:24.698455

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `prefix_list_id` | uuid | 🔗 Foreign key reference |
| `cidr` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_security_groups_history`

📊 **5,811 rows** | 🕐 Last updated: 2025-12-28 08:11:24.624237

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `security_group_id` | character varying | 🔗 Foreign key reference |
| `security_group_name` | character varying | 📄 Data field |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `vpc_id` | character varying | 🔗 Foreign key reference |
| `owner_id` | character varying | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_load_balancer_availability_zones_history`

📊 **4,984 rows** | 🕐 Last updated: 2025-12-28 08:13:48.166713

| Field | Type | Purpose |
|-------|------|---------|
| `load_balancer_id` | uuid | 🔗 Foreign key reference |
| `zone_name` | character varying | 📄 Data field |
| `subnet_id` | character varying | 🔗 Foreign key reference |
| `load_balancer_addresses` | jsonb | 📦 Complex nested data |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_load_balancer_listener_rules_target_groups_history`

📊 **4,893 rows** | 🕐 Last updated: 2025-12-28 08:11:24.391477

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `region` | character varying | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `target_group_arn` | character varying | 📄 Data field |
| `target_group_name` | character varying | 📄 Data field |
| `target_arns` | jsonb | 📦 Complex nested data |
| `port` | integer | 🔌 Port config - verify restricted ports |
| `protocol` | character varying | 🔒 Protocol - verify HTTPS enforcement |
| `protocol_version` | character varying | 🔒 Protocol - verify HTTPS enforcement |
| `vpc_id` | character varying | 🔗 Foreign key reference |
| `created_time` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `last_modified_time` | timestamp without time zone | 📅 Change tracking - detect drift |
| `status` | character varying | 📊 Resource state tracking |
| `target_group_type` | character varying | 🏷️ Classification/type |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_acl_rules_history`

📊 **2,978 rows** | 🕐 Last updated: 2025-12-28 08:15:32.706108

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `override_action` | USER-DEFINED | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `waf_acl_id` | uuid | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `priority` | integer | 🔢 Numeric value |
| `sample_request_enabled` | boolean | 🔘 Feature flag/toggle |
| `cloudwatch_metrics_enabled` | boolean | 🔘 Feature flag/toggle |
| `metrics_name` | character varying | 📊 Metric/count value |
| `captcha_config` | jsonb | 🛡️ Challenge mechanism config |
| `rule_group_arn` | character varying | 📄 Data field |
| `managed_rule_group_name` | character varying | 📄 Data field |
| `managed_rule_group_vendor_name` | character varying | 📄 Data field |
| `rule_statements_hash` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `ai_description` | text | 🌐 IP/Network - check for overly broad ranges |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `ai_suggested_name` | character varying | 📄 Data field |
| `ai_suggested_explanation` | character varying | 📄 Data field |
| `ai_suggested_severity` | integer | 🔢 Numeric value |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_load_balancer_security_groups_history`

📊 **2,345 rows** | 🕐 Last updated: 2025-12-28 08:13:49.656895

| Field | Type | Purpose |
|-------|------|---------|
| `load_balancer_id` | uuid | 🔗 Foreign key reference |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `security_group_id` | uuid | 🔗 Foreign key reference |

### `aws_raw_load_balancer_listener_history`

📊 **1,967 rows** | 🕐 Last updated: 2025-12-28 08:15:58.026658

| Field | Type | Purpose |
|-------|------|---------|
| `ssl_policy` | character varying | 🔒 **IMPORTANT** - SSL/TLS config |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `region` | character varying | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `load_balancer_id` | uuid | 🔗 Foreign key reference |
| `listener_arn` | character varying | 📄 Data field |
| `port` | integer | 🔌 Port config - verify restricted ports |
| `protocol` | character varying | 🔒 Protocol - verify HTTPS enforcement |
| `certificate_arns` | jsonb | 🔒 Certificate tracking |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_region_metadata_history`

📊 **1,856 rows** | 🕐 Last updated: 2025-12-28 05:03:15.819192

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `region` | character varying | 📄 Data field |
| `is_accessible` | boolean | 🔘 Feature flag/toggle |
| `has_assets` | boolean | 🔘 Feature flag/toggle |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |

### `aws_raw_load_balancers_history`

📊 **1,694 rows** | 🕐 Last updated: 2025-12-28 08:13:47.326553

| Field | Type | Purpose |
|-------|------|---------|
| `load_balancer_arn` | character varying | 📄 Data field |
| `dns_name` | character varying | 🌐 DNS configuration |
| `canonical_hosted_zone_id` | character varying | 🌐 Zone/Domain reference |
| `created_time` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `load_balancer_name` | character varying | 📄 Data field |
| `scheme` | character varying | 📄 Data field |
| `vpc_id` | character varying | 🔗 Foreign key reference |
| `state` | USER-DEFINED | 📊 Resource state tracking |
| `type` | character varying | 🏷️ Classification/type |
| `ip_address_type` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `enable_prefix_for_ipv6_source_nat` | USER-DEFINED | 🌐 IP/Network - check for overly broad ranges |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_prefix_lists_history`

📊 **1,339 rows** | 🕐 Last updated: 2025-12-28 08:11:24.638100

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `prefix_list_id` | character varying | 🔗 Foreign key reference |
| `address_family` | character varying | 📄 Data field |
| `state` | character varying | 📊 Resource state tracking |
| `state_message` | character varying | 📄 Data field |
| `prefix_list_arn` | character varying | 📄 Data field |
| `prefix_list_name` | character varying | 📄 Data field |
| `max_entries` | integer | 🔢 Numeric value |
| `version` | bigint | 🔢 Numeric value |
| `tags` | ARRAY | 🏷️ Resource tagging |
| `owner_id` | character varying | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_cloudfront_distribution_origin_history`

📊 **1,091 rows** | 🕐 Last updated: 2025-12-28 08:15:08.577693

| Field | Type | Purpose |
|-------|------|---------|
| `distribution_id` | uuid | 🔗 Foreign key reference |
| `aws_origin_id` | character varying | 🔗 Foreign key reference |
| `domain_name` | character varying | 📄 Data field |
| `origin_path` | character varying | 📄 Data field |
| `connection_attempts` | integer | 🔢 Numeric value |
| `connection_timeout` | integer | 🔢 Numeric value |
| `custom_headers` | json | 📦 Complex nested data |
| `custom_origin_config` | json | ⚙️ Configuration setting |
| `s3_origin_config` | json | ⚙️ Configuration setting |
| `origin_shield` | json | 📦 Complex nested data |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_acl_managed_rule_group_rule_override_history`

📊 **1,049 rows** | 🕐 Last updated: 2025-12-28 08:15:36.295634

| Field | Type | Purpose |
|-------|------|---------|
| `override_action` | USER-DEFINED | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `managed_rule_group_name` | character varying | 📄 Data field |
| `rule_name` | character varying | 📄 Data field |
| `waf_acl_id` | uuid | 🔗 Foreign key reference |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_cloudfront_distribution_alias_history`

📊 **700 rows** | 🕐 Last updated: 2025-12-28 08:15:11.435883

| Field | Type | Purpose |
|-------|------|---------|
| `distribution_id` | uuid | 🔗 Foreign key reference |
| `alias` | character varying | 📄 Data field |
| `icp_recordal_status` | character varying | 🌐 DNS configuration |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_cloudfront_distribution_history`

📊 **668 rows** | 🕐 Last updated: 2025-12-28 08:11:19.268612

| Field | Type | Purpose |
|-------|------|---------|
| **`enabled`** | boolean | 🔴 **CRITICAL** - Security feature toggle |
| `aws_distribution_id` | character varying | 🔗 Foreign key reference |
| `arn` | character varying | 📄 Data field |
| `status` | character varying | 📊 Resource state tracking |
| `domain_name` | character varying | 📄 Data field |
| `aws_last_modified_time` | character varying | 📅 Change tracking - detect drift |
| `comment` | character varying | 📝 Documentation/notes |
| `price_class` | character varying | 📄 Data field |
| `http_version` | character varying | 📄 Data field |
| `is_ipv6_enabled` | boolean | 🌐 IP/Network - check for overly broad ranges |
| `staging` | boolean | 🏷️ Resource tagging |
| `web_acl_id` | character varying | 🔗 Foreign key reference |
| `viewer_certificate` | json | 🔒 Certificate tracking |
| `restrictions` | json | 📦 Complex nested data |
| `custom_error_responses` | json | 📦 Complex nested data |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_acl_rule_labels_history`

📊 **576 rows** | 🕐 Last updated: 2025-12-28 08:15:37.277816

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `name` | character varying | 🏷️ Resource name/identifier |
| `organization_name` | character varying | 📄 Data field |
| `waf_acl_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `waf_acl_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `region` | USER-DEFINED | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_route53_hosted_zones_history`

📊 **495 rows** | 🕐 Last updated: 2025-12-28 08:11:14.495860

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `aws_hosted_zone_id` | character varying | 🌐 Zone/Domain reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `caller_reference` | character varying | 📄 Data field |
| `resource_record_set_count` | integer | 🌐 DNS configuration |
| `description` | text | 🌐 IP/Network - check for overly broad ranges |
| `private_zone` | boolean | 🔘 Feature flag/toggle |
| `vpcs` | jsonb | 📦 Complex nested data |
| `delegation_set_id` | character varying | 🔗 Foreign key reference |
| `raw_json` | jsonb | 📦 Complex nested data |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_acl_history`

📊 **390 rows** | 🕐 Last updated: 2025-12-28 08:15:31.342072

| Field | Type | Purpose |
|-------|------|---------|
| `default_action` | USER-DEFINED | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `sample_request_enabled` | boolean | 🔘 Feature flag/toggle |
| `cloudwatch_metrics_enabled` | boolean | 🔘 Feature flag/toggle |
| `metrics_name` | character varying | 📊 Metric/count value |
| `managed_by_firewall_manager` | boolean | 🔘 Feature flag/toggle |
| `retrofitted_by_firewall_manager` | boolean | 🔘 Feature flag/toggle |
| `application_integration_url` | character varying | 📄 Data field |
| `waf_aws_id` | uuid | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `arn` | character varying | 📄 Data field |
| `capacity` | integer | 🔢 Numeric value |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `raw_web_acl_json` | json | 📦 Complex nested data |
| `raw_associated_resources_json` | json | 📦 Complex nested data |
| `ai_description` | text | 🌐 IP/Network - check for overly broad ranges |
| `ai_hash` | character varying | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_acl_statement_ip_set_history`

📊 **366 rows** | 🕐 Last updated: 2025-12-28 08:11:21.713126

| Field | Type | Purpose |
|-------|------|---------|
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `arn` | character varying | 📄 Data field |
| `ip_addresses_type` | USER-DEFINED | 🌐 IP/Network - check for overly broad ranges |
| `ip_addresses` | ARRAY | 🌐 IP/Network - check for overly broad ranges |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_acl_associated_resources_history`

📊 **329 rows** | 🕐 Last updated: 2025-12-28 08:14:07.093799

| Field | Type | Purpose |
|-------|------|---------|
| `waf_acl_aws_id` | uuid | 🔗 Foreign key reference |
| `waf_acl_id` | uuid | 🔗 Foreign key reference |
| `arn` | character varying | 📄 Data field |
| `resource_type` | USER-DEFINED | 🏷️ Classification/type |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_managed_rule_group_rule_labels_history`

📊 **249 rows** | 🕐 Last updated: 2025-12-28 08:11:38.483943

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `name` | character varying | 🏷️ Resource name/identifier |
| `organization_name` | character varying | 📄 Data field |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `waf_managed_rule_group_id` | uuid | 📜 Rule reference - track rule coverage |
| `organization_id` | uuid | 🏢 Organization linkage |
| `region` | USER-DEFINED | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_acl_logging_configurations_history`

📊 **243 rows** | 🕐 Last updated: 2025-12-28 08:15:32.182774

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `waf_acl_id` | uuid | 🔗 Foreign key reference |
| `log_destination_config` | character varying | 📝 Logging configuration |
| `managed_by_firewall_manager` | boolean | 🔘 Feature flag/toggle |
| `log_scope` | character varying | 📝 Logging configuration |
| `default_behavior` | USER-DEFINED | 📄 Data field |

### `aws_raw_waf_managed_rule_group_rules_history`

📊 **190 rows** | 🕐 Last updated: 2025-12-28 08:11:35.058486

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `waf_managed_rule_group_id` | uuid | 📜 Rule reference - track rule coverage |
| `name` | character varying | 🏷️ Resource name/identifier |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_rule_group_rules_history`

📊 **152 rows** | 🕐 Last updated: 2025-12-28 08:11:34.631775

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `priority` | integer | 🔢 Numeric value |
| `sampled_requests_enabled` | boolean | 🔘 Feature flag/toggle |
| `cloudwatch_metrics_enabled` | boolean | 🔘 Feature flag/toggle |
| `metric_name` | character varying | 📊 Metric/count value |
| `waf_rule_group_id` | uuid | 📜 Rule reference - track rule coverage |
| `rule_statements_hash` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_acl_logging_configurations_filters_history`

📊 **104 rows** | 🕐 Last updated: 2025-12-28 08:15:32.230137

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `waf_acl_logging_configurations_id` | uuid | 📝 Logging configuration |
| `behavior` | USER-DEFINED | 📄 Data field |
| `requirement` | character varying | 📄 Data field |
| `conditions` | json | 📦 Complex nested data |

### `aws_raw_waf_managed_rule_group_versions_history`

📊 **101 rows** | 🕐 Last updated: 2025-12-28 08:11:32.093185

| Field | Type | Purpose |
|-------|------|---------|
| `waf_managed_rule_group_id` | uuid | 📜 Rule reference - track rule coverage |
| `name` | character varying | 🏷️ Resource name/identifier |
| `aws_managed_rule_group_last_updated` | timestamp without time zone | 📅 Timestamp |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_rule_groups_history`

📊 **89 rows** | 🕐 Last updated: 2025-12-28 08:11:17.224765

| Field | Type | Purpose |
|-------|------|---------|
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `arn` | character varying | 📄 Data field |
| `aws_id` | character varying | 🔗 Foreign key reference |
| `label_namespace` | character varying | 🏷️ Resource tagging |
| `capacity` | integer | 🔢 Numeric value |
| `sampled_requests_enabled` | boolean | 🔘 Feature flag/toggle |
| `cloudwatch_metrics_enabled` | boolean | 🔘 Feature flag/toggle |
| `metric_name` | character varying | 📊 Metric/count value |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_rule_group_rule_labels_history`

📊 **55 rows** | 🕐 Last updated: 2025-12-28 08:11:36.331814

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `name` | character varying | 🏷️ Resource name/identifier |
| `organization_name` | character varying | 📄 Data field |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `waf_rule_group_id` | uuid | 📜 Rule reference - track rule coverage |
| `organization_id` | uuid | 🏢 Organization linkage |
| `region` | USER-DEFINED | 📄 Data field |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_acl_logging_configurations_redacted_fields_history`

📊 **36 rows** | 🕐 Last updated: 2025-12-28 08:14:08.598626

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `waf_acl_logging_configurations_id` | uuid | 📝 Logging configuration |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `header_name` | character varying | 📄 Data field |

### `aws_raw_waf_acl_statement_regex_pattern_set_history`

📊 **22 rows** | 🕐 Last updated: 2025-12-28 08:11:24.275885

| Field | Type | Purpose |
|-------|------|---------|
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `regex_strings` | ARRAY | 🔍 Match pattern - verify coverage |
| `arn` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_waf_managed_rule_groups_history`

📊 **17 rows** | 🕐 Last updated: 2025-12-28 08:11:17.672000

| Field | Type | Purpose |
|-------|------|---------|
| `name` | character varying | 🏷️ Resource name/identifier |
| `vendor_name` | character varying | 📄 Data field |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `capacity` | integer | 🔢 Numeric value |
| `version_supported` | boolean | 🔌 Port config - verify restricted ports |
| `label_namespace` | character varying | 🏷️ Resource tagging |
| `region` | USER-DEFINED | 📄 Data field |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_raw_acl_rule_group_rule_override_history`

📊 **14 rows** | 🕐 Last updated: 2025-12-28 08:15:36.635235

| Field | Type | Purpose |
|-------|------|---------|
| `override_action` | USER-DEFINED | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `rule_group_arn` | character varying | 📄 Data field |
| `rule_name` | character varying | 📄 Data field |
| `waf_acl_id` | uuid | 🔗 Foreign key reference |
| `region` | USER-DEFINED | 📄 Data field |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

## Azure (48 fresh tables)

### `azure_fd_waf_custom_rules_metrics`

📊 **269,156 rows** | 🕐 Last updated: 2025-12-27 22:11:34.976619

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `metric_type` | USER-DEFINED | 🏷️ Classification/type |
| `metric_date` | timestamp without time zone | 📊 Metric/count value |
| `metric_value` | double precision | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `custom_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `policy_name` | character varying | 📄 Data field |
| `rule_name` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_waf_managed_rules_metrics`

📊 **194,434 rows** | 🕐 Last updated: 2025-12-27 22:11:34.231197

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `metric_type` | USER-DEFINED | 🏷️ Classification/type |
| `metric_date` | timestamp without time zone | 📊 Metric/count value |
| `metric_value` | double precision | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `managed_rule_set_id` | uuid | 📜 Rule reference - track rule coverage |
| `managed_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `policy_name` | character varying | 📄 Data field |
| `rule_name` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_waf_metrics`

📊 **167,875 rows** | 🕐 Last updated: 2025-12-27 22:11:27.925684

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `metric_type` | USER-DEFINED | 🏷️ Classification/type |
| `metric_date` | timestamp without time zone | 📊 Metric/count value |
| `metric_value` | double precision | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `policy_name` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_metrics`

📊 **58,365 rows** | 🕐 Last updated: 2025-12-27 22:11:24.182067

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `metric_type` | USER-DEFINED | 🏷️ Classification/type |
| `metric_date` | timestamp without time zone | 📊 Metric/count value |
| `metric_value` | double precision | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_waf_policy_managed_rule_metrics`

📊 **53,971 rows** | 🕐 Last updated: 2025-12-28 08:02:38.302694

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `metric_date` | timestamp without time zone | 📊 Metric/count value |
| `metric_value` | double precision | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `managed_rule_id` | character varying | 📜 Rule reference - track rule coverage |
| `managed_rule_group_id` | character varying | 📜 Rule reference - track rule coverage |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `managed_rule_set_name` | character varying | 📄 Data field |

### `azure_app_gateway_waf_policy_metrics`

📊 **26,935 rows** | 🕐 Last updated: 2025-12-28 08:02:40.167323

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `metric_date` | timestamp without time zone | 📊 Metric/count value |
| `metric_value` | double precision | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_waf_policy_custom_rule_metrics`

📊 **7,681 rows** | 🕐 Last updated: 2025-12-28 08:02:27.941635

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `custom_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `metric_date` | timestamp without time zone | 📊 Metric/count value |
| `metric_value` | double precision | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_waf_managed_rules`

📊 **2,997 rows** | 🕐 Last updated: 2025-12-27 22:09:23.457512

| Field | Type | Purpose |
|-------|------|---------|
| `default_action` | character varying | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `managed_rule_set_id` | uuid | 📜 Rule reference - track rule coverage |
| `rule_id` | character varying | 📜 Rule reference - track rule coverage |
| `default_state` | USER-DEFINED | 📄 Data field |
| `description` | text | 🌐 IP/Network - check for overly broad ranges |
| `rule_group_name` | character varying | 📄 Data field |
| `rule_set_type` | character varying | 🏷️ Classification/type |
| `rule_set_version` | character varying | 📄 Data field |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_rg_tags`

📊 **1,242 rows** | 🕐 Last updated: 2025-12-27 22:04:32.289564

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `name` | character varying | 🏷️ Resource name/identifier |
| `value` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_custom_domains`

📊 **870 rows** | 🕐 Last updated: 2025-12-27 22:06:24.430551

| Field | Type | Purpose |
|-------|------|---------|
| `tls_certificate_type` | USER-DEFINED | 🔒 **IMPORTANT** - SSL/TLS config |
| `tls_minimum_version` | USER-DEFINED | 🔒 **IMPORTANT** - SSL/TLS config |
| `tls_secret_reference_id` | character varying | 🔒 **IMPORTANT** - SSL/TLS config |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `profile_name` | character varying | 📄 Data field |
| `host_name` | character varying | 📄 Data field |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `deployment_status` | USER-DEFINED | 📄 Data field |
| `domain_validation_state` | USER-DEFINED | 📄 Data field |
| `azure_dns_zone_reference_id` | character varying | 🌐 DNS configuration |
| `pre_validated_custom_domain_resource_id` | character varying | 🔗 Foreign key reference |
| `validation_token` | character varying | 📄 Data field |
| `validation_expiration_date` | character varying | 📄 Data field |
| `system_data_created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `system_data_created_by_type` | USER-DEFINED | 📅 Creation tracking - detect age/staleness |
| `system_data_created_at` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `system_data_last_modified_by` | character varying | 📅 Change tracking - detect drift |
| `system_data_last_modified_by_type` | USER-DEFINED | 📅 Change tracking - detect drift |
| `system_data_last_modified_at` | timestamp with time zone | 📅 Change tracking - detect drift |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_dns_zones`

📊 **351 rows** | 🕐 Last updated: 2025-12-28 08:01:40.043646

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `location` | character varying | 📄 Data field |
| `etag` | character varying | 🏷️ Resource tagging |
| `max_number_of_record_sets` | integer | 🌐 DNS configuration |
| `max_number_of_records_per_record_set` | integer | 🌐 DNS configuration |
| `number_of_record_sets` | integer | 🌐 DNS configuration |
| `zone_type` | USER-DEFINED | 🏷️ Classification/type |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `rg_id` | uuid | 🔗 Foreign key reference |

### `azure_app_gateway_http_listeners`

📊 **259 rows** | 🕐 Last updated: 2025-12-28 08:02:27.943775

| Field | Type | Purpose |
|-------|------|---------|
| `ssl_certificate_azure_id` | character varying | 🔒 **IMPORTANT** - SSL/TLS config |
| `ssl_profile_azure_id` | character varying | 🔒 **IMPORTANT** - SSL/TLS config |
| `id` | uuid | 🔑 Primary identifier |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `frontend_ip_configuration_id` | uuid | 🌐 IP/Network - check for overly broad ranges |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `etag` | character varying | 🏷️ Resource tagging |
| `type` | character varying | 🏷️ Classification/type |
| `listener_type` | USER-DEFINED | 🏷️ Classification/type |
| `protocol` | USER-DEFINED | 🔒 Protocol - verify HTTPS enforcement |
| `frontend_port` | integer | 🔌 Port config - verify restricted ports |
| `require_server_name_indication` | boolean | 🔘 Feature flag/toggle |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_routing_rules`

📊 **258 rows** | 🕐 Last updated: 2025-12-28 08:02:31.408996

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `listener_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `etag` | character varying | 🏷️ Resource tagging |
| `type` | character varying | 🏷️ Classification/type |
| `rule_type` | USER-DEFINED | 🏷️ Classification/type |
| `priority` | integer | 🔢 Numeric value |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `redirect_configuration_id` | uuid | ⚙️ Configuration setting |
| `default_backend_address_pool_id` | uuid | 🔗 Foreign key reference |
| `default_backend_http_settings_id` | uuid | ⚙️ Configuration setting |
| `default_redirect_configuration_id` | uuid | ⚙️ Configuration setting |
| `default_rewrite_rule_set_id` | uuid | 📜 Rule reference - track rule coverage |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_rgs`

📊 **257 rows** | 🕐 Last updated: 2025-12-28 08:01:26.323633

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `location` | character varying | 📄 Data field |
| `type` | character varying | 🏷️ Classification/type |
| `managed_by` | character varying | 📄 Data field |
| `properties` | character varying | 📄 Data field |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_http_listener_host_names`

📊 **242 rows** | 🕐 Last updated: 2025-12-28 08:02:28.981399

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `listener_id` | uuid | 🔗 Foreign key reference |
| `host_name` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_backend_http_settings`

📊 **188 rows** | 🕐 Last updated: 2025-12-28 08:02:30.287348

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `etag` | character varying | 🏷️ Resource tagging |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `port` | integer | 🔌 Port config - verify restricted ports |
| `protocol` | USER-DEFINED | 🔒 Protocol - verify HTTPS enforcement |
| `cookie_based_affinity` | USER-DEFINED | 📄 Data field |
| `request_timeout` | integer | 🔢 Numeric value |
| `probe_id` | uuid | 🔗 Foreign key reference |
| `host_name` | character varying | 📄 Data field |
| `pick_host_name_from_backend_address` | boolean | 🔘 Feature flag/toggle |
| `affinity_cookie_name` | character varying | 📄 Data field |
| `path` | character varying | 📄 Data field |
| `connection_draining_enabled` | boolean | 🔘 Feature flag/toggle |
| `connection_draining_timeout` | integer | 🔢 Numeric value |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_probes`

📊 **175 rows** | 🕐 Last updated: 2025-12-28 08:02:24.634856

| Field | Type | Purpose |
|-------|------|---------|
| `unhealthy_threshold` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `etag` | character varying | 🏷️ Resource tagging |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `protocol` | USER-DEFINED | 🔒 Protocol - verify HTTPS enforcement |
| `host` | character varying | 📄 Data field |
| `path` | character varying | 📄 Data field |
| `port` | integer | 🔌 Port config - verify restricted ports |
| `interval` | integer | 🔢 Numeric value |
| `timeout` | integer | 🔢 Numeric value |
| `min_servers` | integer | 🔢 Numeric value |
| `pick_host_name_from_backend_http_settings` | boolean | ⚙️ Configuration setting |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_waf_managed_rule_set_overrides`

📊 **144 rows** | 🕐 Last updated: 2025-12-28 08:01:45.425823

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `managed_ruleset_id` | uuid | 📜 Rule reference - track rule coverage |
| `rule_group_name` | character varying | 📄 Data field |
| `managed_rule_id` | character varying | 📜 Rule reference - track rule coverage |
| `state` | USER-DEFINED | 📊 Resource state tracking |
| `sensitivity` | USER-DEFINED | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_backend_pool_addresses`

📊 **128 rows** | 🕐 Last updated: 2025-12-28 08:02:28.007506

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `backend_pool_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `address_type` | USER-DEFINED | 🏷️ Classification/type |
| `address` | character varying | 📄 Data field |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_waf_custom_rules`

📊 **122 rows** | 🕐 Last updated: 2025-12-27 22:05:27.981348

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | character varying | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| **`enabled_state`** | USER-DEFINED | 🔴 **CRITICAL** - Security feature toggle |
| `rate_limit_duration_in_minutes` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `rate_limit_threshold` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `priority` | integer | 🔢 Numeric value |
| `rule_type` | character varying | 🏷️ Classification/type |
| `match_conditions` | json | 📦 Complex nested data |
| `name` | character varying | 🏷️ Resource name/identifier |
| `group_by` | json | 📦 Complex nested data |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_waf_custom_rule_match_condition_values`

📊 **116 rows** | 🕐 Last updated: 2025-12-28 08:01:48.018983

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `match_condition_id` | uuid | 🔗 Foreign key reference |
| `value` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_backend_pools`

📊 **115 rows** | 🕐 Last updated: 2025-12-28 08:02:24.601398

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `etag` | character varying | 🏷️ Resource tagging |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_redirect_configs`

📊 **115 rows** | 🕐 Last updated: 2025-12-28 08:02:28.946066

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `etag` | character varying | 🏷️ Resource tagging |
| `type` | character varying | 🏷️ Classification/type |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `redirect_type` | USER-DEFINED | 🏷️ Classification/type |
| `target_url` | character varying | 📄 Data field |
| `target_listener_id` | uuid | 🔗 Foreign key reference |
| `include_path` | boolean | 🔘 Feature flag/toggle |
| `include_query_string` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_waf_managed_rule_exclusions`

📊 **95 rows** | 🕐 Last updated: 2025-12-28 08:01:43.950186

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `match_variable` | USER-DEFINED | 📄 Data field |
| `selector_match_operator` | USER-DEFINED | 📄 Data field |
| `selector` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_endpoints`

📊 **82 rows** | 🕐 Last updated: 2025-12-27 22:06:02.795408

| Field | Type | Purpose |
|-------|------|---------|
| **`enabled_state`** | USER-DEFINED | 🔴 **CRITICAL** - Security feature toggle |
| `auto_generated_domain_name_label_scope` | USER-DEFINED | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `location` | character varying | 📄 Data field |
| `profile_name` | character varying | 📄 Data field |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `deployment_status` | USER-DEFINED | 📄 Data field |
| `host_name` | character varying | 📄 Data field |
| `system_data_created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `system_data_created_by_type` | USER-DEFINED | 📅 Creation tracking - detect age/staleness |
| `system_data_created_at` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `system_data_last_modified_by` | character varying | 📅 Change tracking - detect drift |
| `system_data_last_modified_by_type` | USER-DEFINED | 📅 Change tracking - detect drift |
| `system_data_last_modified_at` | timestamp with time zone | 📅 Change tracking - detect drift |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_endpoint_tags`

📊 **67 rows** | 🕐 Last updated: 2025-12-27 22:06:04.712462

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `endpoint_id` | uuid | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `value` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_path_rule_paths`

📊 **57 rows** | 🕐 Last updated: 2025-12-28 08:02:33.957130

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `path_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `path` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_path_rules`

📊 **57 rows** | 🕐 Last updated: 2025-12-28 08:02:32.696375

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `routing_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `etag` | character varying | 🏷️ Resource tagging |
| `type` | character varying | 🏷️ Classification/type |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `backend_address_pool_id` | uuid | 🔗 Foreign key reference |
| `backend_http_settings_id` | uuid | ⚙️ Configuration setting |
| `redirect_configuration_id` | uuid | ⚙️ Configuration setting |
| `rewrite_rule_set_id` | uuid | 📜 Rule reference - track rule coverage |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_tags`

📊 **57 rows** | 🕐 Last updated: 2025-12-28 08:02:24.701823

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `value` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_waf_custom_rule_match_condition_variables`

📊 **40 rows** | 🕐 Last updated: 2025-12-28 08:01:47.941899

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `match_condition_id` | uuid | 🔗 Foreign key reference |
| `variable_name` | USER-DEFINED | 📄 Data field |
| `selector` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_waf_custom_rule_match_conditions`

📊 **40 rows** | 🕐 Last updated: 2025-12-28 08:01:45.726077

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `custom_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `operator` | USER-DEFINED | 📄 Data field |
| `negation_condition` | boolean | 🔘 Feature flag/toggle |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `index` | integer | 🔢 Numeric value |

### `azure_app_gateway_waf_policy_tags`

📊 **37 rows** | 🕐 Last updated: 2025-12-28 08:01:45.046296

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `value` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_waf_custom_rule_match_condition_transforms`

📊 **36 rows** | 🕐 Last updated: 2025-12-28 08:01:47.852800

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `match_condition_id` | uuid | 🔗 Foreign key reference |
| `transform` | USER-DEFINED | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `azure_app_gateway_waf_custom_rules`

📊 **32 rows** | 🕐 Last updated: 2025-12-28 08:01:42.114875

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `rate_limit_duration` | USER-DEFINED | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `rate_limit_threshold` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `group_by_rate_limit` | USER-DEFINED | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `priority` | integer | 🔢 Numeric value |
| `state` | USER-DEFINED | 📊 Resource state tracking |
| `rule_type` | USER-DEFINED | 🏷️ Classification/type |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_waf_policy_tags`

📊 **32 rows** | 🕐 Last updated: 2025-12-27 22:04:23.482873

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `value` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_exclusion_managed_rule_sets_rules`

📊 **28 rows** | 🕐 Last updated: 2025-12-28 08:01:55.891026

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `managed_rule_exclusion_id` | uuid | 📜 Rule reference - track rule coverage |
| `rule_group_name` | character varying | 📄 Data field |
| `rule_id` | character varying | 📜 Rule reference - track rule coverage |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_waf_managed_rule_sets`

📊 **28 rows** | 🕐 Last updated: 2025-12-27 22:04:24.310321

| Field | Type | Purpose |
|-------|------|---------|
| `rule_set_action` | character varying | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `rule_set_type` | character varying | 🏷️ Classification/type |
| `rule_set_version` | character varying | 📄 Data field |
| `exclusions` | json | 📦 Complex nested data |
| `rule_group_overrides` | json | 📜 Rule reference - track rule coverage |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_tags`

📊 **27 rows** | 🕐 Last updated: 2025-12-27 22:05:38.046751

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `value` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_frontends`

📊 **24 rows** | 🕐 Last updated: 2025-12-28 08:02:26.133526

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `app_gateway_id` | uuid | 🔗 Foreign key reference |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `etag` | character varying | 🏷️ Resource tagging |
| `private_ip_address` | inet | 🌐 IP/Network - check for overly broad ranges |
| `private_ip_allocation_method` | USER-DEFINED | 🌐 IP/Network - check for overly broad ranges |
| `public_ip_address` | inet | 🌐 IP/Network - check for overly broad ranges |
| `public_ip_resource_id` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `ip_type` | USER-DEFINED | 🌐 IP/Network - check for overly broad ranges |

### `azure_app_gateway_waf_managed_rule_sets`

📊 **20 rows** | 🕐 Last updated: 2025-12-28 08:01:45.643888

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `rule_set_type` | character varying | 🏷️ Classification/type |
| `rule_set_version` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_waf_policies`

📊 **19 rows** | 🕐 Last updated: 2025-12-27 22:04:23.839510

| Field | Type | Purpose |
|-------|------|---------|
| **`enabled_state`** | USER-DEFINED | 🔴 **CRITICAL** - Security feature toggle |
| **`mode`** | character varying | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `location` | character varying | 📄 Data field |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `resource_state` | USER-DEFINED | 📄 Data field |
| `etag` | character varying | 🏷️ Resource tagging |
| `sku` | character varying | 📄 Data field |
| `redirect_url` | character varying | 📄 Data field |
| `custom_block_response_status_code` | integer | 🔢 Numeric value |
| `custom_block_response_body` | text | 📄 Content/payload data |
| `request_body_check` | USER-DEFINED | 📄 Content/payload data |
| `state` | USER-DEFINED | 📊 Resource state tracking |
| `javascript_challenge_expiration_in_minutes` | integer | 🌐 IP/Network - check for overly broad ranges |
| `frontend_endpoint_links` | json | 🔗 Resource linkage |
| `routing_rule_links` | json | 🔗 Resource linkage |
| `security_policy_links` | json | 🔗 Resource linkage |
| `system_data_created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `system_data_created_by_type` | USER-DEFINED | 📅 Creation tracking - detect age/staleness |
| `system_data_created_at` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `system_data_last_modified_by` | character varying | 📅 Change tracking - detect drift |
| `system_data_last_modified_by_type` | USER-DEFINED | 📅 Change tracking - detect drift |
| `system_data_last_modified_at` | timestamp with time zone | 📅 Change tracking - detect drift |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateways`

📊 **18 rows** | 🕐 Last updated: 2025-12-28 08:02:23.630838

| Field | Type | Purpose |
|-------|------|---------|
| `default_predefined_ssl_policy` | character varying | 🔒 **IMPORTANT** - SSL/TLS config |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `location` | character varying | 📄 Data field |
| `resource_guid` | uuid | 🔑 UUID reference |
| `etag` | character varying | 🏷️ Resource tagging |
| `tier` | USER-DEFINED | 📄 Data field |
| `sku_name` | USER-DEFINED | 📄 Data field |
| `sku_capacity` | integer | 🔢 Numeric value |
| `operational_state` | USER-DEFINED | 📄 Data field |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `autoscale_min_capacity` | integer | 🔢 Numeric value |
| `autoscale_max_capacity` | integer | 🔢 Numeric value |
| `zones` | ARRAY | 📄 Data field |
| `enable_http2` | boolean | 🔘 Feature flag/toggle |
| `enable_fips` | boolean | 🌐 IP/Network - check for overly broad ranges |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `force_firewall_policy_association` | boolean | 🔗 Resource linkage |
| `deprecated_web_application_firewall_configuration` | jsonb | ⚙️ Configuration setting |
| `enable_request_buffering` | boolean | 🔘 Feature flag/toggle |
| `enable_response_buffering` | boolean | 🔘 Feature flag/toggle |
| `custom_error_configurations` | jsonb | ⚙️ Configuration setting |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `subnet_id` | uuid | 🔗 Foreign key reference |

### `azure_fds`

📊 **16 rows** | 🕐 Last updated: 2025-12-27 22:05:27.396415

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `location` | character varying | 📄 Data field |
| `sku` | character varying | 📄 Data field |
| `kind` | character varying | 🏷️ Classification/type |
| `fd_type` | USER-DEFINED | 🏷️ Classification/type |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `resource_state` | USER-DEFINED | 📄 Data field |
| `etag` | character varying | 🏷️ Resource tagging |
| `front_door_id` | character varying | 🔗 Foreign key reference |
| `origin_response_timeout_seconds` | integer | 🔢 Numeric value |
| `system_identity_principal_id` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `system_identity_tenant_id` | character varying | 🔗 Foreign key reference |
| `system_identity_enabled` | boolean | 🔗 Foreign key reference |
| `log_scrubbing_enabled` | boolean | 📝 Logging configuration |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_app_gateway_waf_policies`

📊 **14 rows** | 🕐 Last updated: 2025-12-28 08:01:39.542076

| Field | Type | Purpose |
|-------|------|---------|
| **`mode`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `request_body_inspect_limit_in_kb` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `file_upload_limit_in_mb` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `location` | character varying | 📄 Data field |
| `etag` | character varying | 🏷️ Resource tagging |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `resource_state` | USER-DEFINED | 📄 Data field |
| `state` | USER-DEFINED | 📊 Resource state tracking |
| `request_body_check` | boolean | 📄 Content/payload data |
| `request_body_enforcement` | boolean | 📄 Content/payload data |
| `max_request_body_size_in_kb` | integer | 📄 Content/payload data |
| `file_upload_enforcement` | boolean | 🔘 Feature flag/toggle |
| `custom_block_response_status_code` | integer | 🔢 Numeric value |
| `custom_block_response_body` | character varying | 📄 Content/payload data |
| `js_challenge_cookie_expiration_in_mins` | integer | 🛡️ Challenge mechanism config |
| `log_scrubbing_state` | USER-DEFINED | 📝 Logging configuration |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_vnet_subnets`

📊 **9 rows** | 🕐 Last updated: 2025-12-28 08:02:10.107814

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `vnet_id` | uuid | 🔗 Foreign key reference |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_vnets`

📊 **9 rows** | 🕐 Last updated: 2025-12-28 08:02:09.235259

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `rg_id` | uuid | 🔗 Foreign key reference |

### `azure_app_gateway_waf_managed_rule_exclusion_managed_rule_sets`

📊 **5 rows** | 🕐 Last updated: 2025-12-28 08:01:51.100354

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `managed_rule_exclusion_id` | uuid | 📜 Rule reference - track rule coverage |
| `rule_set_type` | character varying | 🏷️ Classification/type |
| `rule_set_version` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_extended_properties`

📊 **4 rows** | 🕐 Last updated: 2025-12-27 22:05:38.331362

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `property_key` | character varying | 📄 Data field |
| `property_value` | character varying | 📄 Data field |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

## Akamai (36 fresh tables)

### `akamai_raw_property_rule_behaviors_history`

📊 **171,423 rows** | 🕐 Last updated: 2025-12-28 08:55:46.766281

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `property_id` | uuid | 🔗 Foreign key reference |
| `property_version` | integer | 🔢 Numeric value |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `name` | character varying | 🏷️ Resource name/identifier |
| `options` | json | ⚙️ Configuration setting |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_property_rules_history`

📊 **109,265 rows** | 🕐 Last updated: 2025-12-28 08:53:19.495344

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `property_id` | uuid | 🔗 Foreign key reference |
| `property_version` | integer | 🔢 Numeric value |
| `rule_format` | character varying | 📄 Data field |
| `is_secure` | boolean | 🔘 Feature flag/toggle |
| `comments` | character varying | 📝 Documentation/notes |
| `name` | character varying | 🏷️ Resource name/identifier |
| `root_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `parent_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `criteria_locked` | boolean | 🔘 Feature flag/toggle |
| `criteria_match` | USER-DEFINED | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_security_policy_rate_policy_actions_history`

📊 **21,114 rows** | 🕐 Last updated: 2025-12-27 09:41:09.928623

| Field | Type | Purpose |
|-------|------|---------|
| `rate_policy_id` | uuid | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `ipv4_action` | character varying | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `ipv6_action` | character varying | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `security_policy_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_bot_category_actions_history`

📊 **12,946 rows** | 🕐 Last updated: 2025-12-27 10:38:07.003843

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `security_policy_id` | uuid | 🔗 Foreign key reference |
| `category_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |

### `akamai_raw_bot_detection_actions_history`

📊 **10,005 rows** | 🕐 Last updated: 2025-12-27 10:20:44.142909

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | character varying | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `security_policy_id` | uuid | 🔗 Foreign key reference |
| `detection_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |

### `akamai_raw_security_policy_rapid_rules_history`

📊 **9,167 rows** | 🕐 Last updated: 2025-12-27 10:46:45.046072

| Field | Type | Purpose |
|-------|------|---------|
| **`action`** | character varying | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `security_policy_id` | uuid | 🔗 Foreign key reference |
| `akamai_id` | integer | 🔗 Foreign key reference |
| `locked` | boolean | 🔘 Feature flag/toggle |
| `title` | character varying | 📄 Data field |
| `version` | integer | 🔢 Numeric value |
| `condition_exception` | json | 📦 Complex nested data |
| `risk_score_groups` | json | 📦 Complex nested data |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_properties_history`

📊 **8,523 rows** | 🕐 Last updated: 2025-12-28 08:00:50.762167

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `akamai_asset_id` | character varying | 🔗 Foreign key reference |
| `akamai_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `latest_version` | integer | 🔢 Numeric value |
| `production_version` | integer | 🔢 Numeric value |
| `staging_version` | integer | 🏷️ Resource tagging |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_property_rule_variables_history`

📊 **7,755 rows** | 🕐 Last updated: 2025-12-28 08:55:05.657797

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `property_id` | uuid | 🔗 Foreign key reference |
| `property_version` | integer | 🔢 Numeric value |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `name` | character varying | 🏷️ Resource name/identifier |
| `value` | character varying | 📄 Data field |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `hidden` | boolean | 🔘 Feature flag/toggle |
| `sensitive` | boolean | 🔘 Feature flag/toggle |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_security_config_match_target_hostnames_history`

📊 **5,626 rows** | 🕐 Last updated: 2025-12-27 10:39:05.644730

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `match_target_id` | uuid | 🔗 Foreign key reference |
| `hostname` | character varying | 🏷️ Resource name/identifier |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_rate_policy_add_match_opt_vals_history`

📊 **3,638 rows** | 🕐 Last updated: 2025-12-28 08:35:52.464861

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `additional_match_option_id` | uuid | ⚙️ Configuration setting |
| `value` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_property_rule_criteria_history`

📊 **2,850 rows** | 🕐 Last updated: 2025-12-28 08:23:57.356490

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `property_id` | uuid | 🔗 Foreign key reference |
| `property_version` | integer | 🔢 Numeric value |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `name` | character varying | 🏷️ Resource name/identifier |
| `options` | json | ⚙️ Configuration setting |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_rate_policy_paths_history`

📊 **2,216 rows** | 🕐 Last updated: 2025-12-28 08:35:47.600645

| Field | Type | Purpose |
|-------|------|---------|
| `rate_policy_id` | uuid | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `path` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_rate_policy_add_match_opts_history`

📊 **1,179 rows** | 🕐 Last updated: 2025-12-28 08:35:49.168045

| Field | Type | Purpose |
|-------|------|---------|
| `rate_policy_id` | uuid | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `positive_match` | boolean | 🔘 Feature flag/toggle |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_security_policies_history`

📊 **769 rows** | 🕐 Last updated: 2025-12-28 08:34:19.081344

| Field | Type | Purpose |
|-------|------|---------|
| `has_rate_policy_with_api_key` | boolean | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `apply_rate_controls` | boolean | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `config_version_id` | uuid | ⚙️ Configuration setting |
| `akamai_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `apply_api_constraints` | boolean | 🔘 Feature flag/toggle |
| `apply_application_layer_controls` | boolean | 🔘 Feature flag/toggle |
| `apply_botman_controls` | boolean | 🤖 Bot detection/protection config |
| `apply_network_layer_controls` | boolean | 🔘 Feature flag/toggle |
| `apply_reputation_controls` | boolean | 🔘 Feature flag/toggle |
| `apply_slow_post_controls` | boolean | 🔘 Feature flag/toggle |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `rapid_rules_enabled` | boolean | 📜 Rule reference - track rule coverage |

### `akamai_raw_security_configuration_match_targets_history`

📊 **613 rows** | 🕐 Last updated: 2025-12-27 10:39:04.958922

| Field | Type | Purpose |
|-------|------|---------|
| `apply_rate_controls` | boolean | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `config_version_id` | uuid | ⚙️ Configuration setting |
| `akamai_id` | integer | 🔗 Foreign key reference |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `sequence_position` | integer | 🔢 Numeric value |
| `security_policy_id` | uuid | 🔗 Foreign key reference |
| `is_negative_path_match` | boolean | 🔘 Feature flag/toggle |
| `is_negative_file_extension_match` | boolean | 🔘 Feature flag/toggle |
| `apply_api_constraints` | boolean | 🔘 Feature flag/toggle |
| `apply_application_layer_controls` | boolean | 🔘 Feature flag/toggle |
| `apply_network_layer_controls` | boolean | 🔘 Feature flag/toggle |
| `apply_reputation_controls` | boolean | 🔘 Feature flag/toggle |
| `apply_slow_post_controls` | boolean | 🔘 Feature flag/toggle |
| `default_file` | USER-DEFINED | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `apply_url_protection_controls` | boolean | 🔘 Feature flag/toggle |
| `apply_account_protection_controls` | boolean | 🔘 Feature flag/toggle |
| `apply_botman_controls` | boolean | 🤖 Bot detection/protection config |

### `akamai_raw_sec_config_rate_policies_history`

📊 **611 rows** | 🕐 Last updated: 2025-12-28 08:35:40.434930

| Field | Type | Purpose |
|-------|------|---------|
| `same_action_on_ipv6` | boolean | ⚠️ **IMPORTANT** - Rule action (block/allow/log) |
| `burst_threshold` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `average_threshold` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `config_version_id` | uuid | ⚙️ Configuration setting |
| `akamai_id` | integer | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `match_type` | USER-DEFINED | 🏷️ Classification/type |
| `used` | boolean | 🔘 Feature flag/toggle |
| `use_xff` | boolean | 🔘 Feature flag/toggle |
| `update_date` | timestamp with time zone | 📅 Timestamp |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `request_type` | USER-DEFINED | 🏷️ Classification/type |
| `penalty_box_duration` | USER-DEFINED | 📄 Data field |
| `path_uri_positive_match` | boolean | 🔘 Feature flag/toggle |
| `path_match_type` | USER-DEFINED | 🏷️ Classification/type |
| `hosts_positive_match` | boolean | 🔘 Feature flag/toggle |
| `file_extension_positive_match` | boolean | 🔘 Feature flag/toggle |
| `created_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `counter_type` | USER-DEFINED | 🏷️ Classification/type |
| `burst_window` | integer | 🔢 Numeric value |
| `condition_positive_match` | boolean | 🔘 Feature flag/toggle |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_bots_history`

📊 **580 rows** | 🕐 Last updated: 2025-12-28 08:00:16.897396

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `bot_category_id` | uuid | 🤖 Bot detection/protection config |
| `akamai_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `added_date` | timestamp with time zone | 📅 Timestamp |
| `updated_date` | timestamp with time zone | 📅 Timestamp |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_custom_rule_cond_vals_history`

📊 **445 rows** | 🕐 Last updated: 2025-12-28 09:03:14.047553

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `condition_id` | uuid | 🔗 Foreign key reference |
| `value` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_dns_records_history`

📊 **334 rows** | 🕐 Last updated: 2025-12-28 08:30:33.689174

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `zone_id` | uuid | 🌐 Zone/Domain reference |
| `record_name` | character varying | 🌐 DNS configuration |
| `record_type` | character varying | 🌐 DNS configuration |
| `record_value` | character varying | 🌐 DNS configuration |
| `ttl` | integer | 🔢 Numeric value |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_custom_rule_conditions_history`

📊 **229 rows** | 🕐 Last updated: 2025-12-28 09:03:12.615125

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `custom_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `condition_type` | USER-DEFINED | 🏷️ Classification/type |
| `positive_match` | boolean | 🔘 Feature flag/toggle |
| `name` | character varying | 🏷️ Resource name/identifier |
| `name_case_sensitive` | boolean | 🔘 Feature flag/toggle |
| `name_wildcard` | boolean | 🔘 Feature flag/toggle |
| `value_case_sensitive` | boolean | 🔘 Feature flag/toggle |
| `value_wildcard` | boolean | 🔘 Feature flag/toggle |
| `value_exact_match` | boolean | 🔘 Feature flag/toggle |
| `value_ignore_segment` | boolean | 🔘 Feature flag/toggle |
| `value_normalize` | boolean | 🔘 Feature flag/toggle |
| `value_recursive` | boolean | 🔘 Feature flag/toggle |
| `use_xff_headers` | boolean | 🔘 Feature flag/toggle |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_custom_rules_history`

📊 **188 rows** | 🕐 Last updated: 2025-12-28 09:03:11.658938

| Field | Type | Purpose |
|-------|------|---------|
| `sampling_rate` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `akamai_id` | integer | 🔗 Foreign key reference |
| `config_id` | uuid | ⚙️ Configuration setting |
| `name` | character varying | 🏷️ Resource name/identifier |
| `version` | integer | 🔢 Numeric value |
| `status` | USER-DEFINED | 📊 Resource state tracking |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `effective_start_date` | timestamp with time zone | 📅 Timestamp |
| `effective_end_date` | timestamp with time zone | 📅 Timestamp |
| `effective_time_period_status` | USER-DEFINED | 📄 Data field |
| `inspect_request` | boolean | 🔘 Feature flag/toggle |
| `inspect_response` | boolean | 🔘 Feature flag/toggle |
| `is_activated` | boolean | 🔘 Feature flag/toggle |
| `staging_only` | boolean | 🏷️ Resource tagging |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_rate_policy_hostnames_history`

📊 **178 rows** | 🕐 Last updated: 2025-12-28 08:35:46.725729

| Field | Type | Purpose |
|-------|------|---------|
| `rate_policy_id` | uuid | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `hostname` | character varying | 🏷️ Resource name/identifier |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_security_configuration_versions_history`

📊 **86 rows** | 🕐 Last updated: 2025-12-28 08:30:40.986018

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `config_id` | uuid | ⚙️ Configuration setting |
| `version` | integer | 🔢 Numeric value |
| `notes` | character varying | 📝 Documentation/notes |
| `version_created_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `production_activation_date` | timestamp with time zone | 📅 Timestamp |
| `staging_activation_date` | timestamp with time zone | 🏷️ Resource tagging |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_attack_payload_log_settings_history`

📊 **78 rows** | 🕐 Last updated: 2025-12-28 08:31:14.886509

| Field | Type | Purpose |
|-------|------|---------|
| **`enabled`** | boolean | 🔴 **CRITICAL** - Security feature toggle |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `config_version_id` | uuid | ⚙️ Configuration setting |
| `request_body_type` | USER-DEFINED | 📄 Content/payload data |
| `response_body_type` | USER-DEFINED | 📄 Content/payload data |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_http_header_log_settings_history`

📊 **78 rows** | 🕐 Last updated: 2025-12-28 08:31:36.497297

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `config_version_id` | uuid | ⚙️ Configuration setting |
| `allow_sampling` | boolean | 🔘 Feature flag/toggle |
| `cookies_type` | USER-DEFINED | 🏷️ Classification/type |
| `custom_headers_type` | USER-DEFINED | 🏷️ Classification/type |
| `standard_headers_type` | USER-DEFINED | 🏷️ Classification/type |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_contract_group_mapping_history`

📊 **46 rows** | 🕐 Last updated: 2025-12-28 08:00:12.320687

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `integration_id` | uuid | 🔗 Integration reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `akamai_raw_groups_history`

📊 **46 rows** | 🕐 Last updated: 2025-12-28 08:00:11.333316

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `integration_id` | uuid | 🔗 Integration reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `akamai_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `parent_group_id` | uuid | 🔗 Foreign key reference |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `organization_name` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `akamai_raw_dns_zones_history`

📊 **31 rows** | 🕐 Last updated: 2025-12-28 08:00:11.279145

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `zone_name` | character varying | 📄 Data field |
| `zone_type` | USER-DEFINED | 🏷️ Classification/type |
| `activation_state` | USER-DEFINED | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_security_configurations_history`

📊 **25 rows** | 🕐 Last updated: 2025-12-28 08:00:14.056487

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `akamai_id` | integer | 🔗 Foreign key reference |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `name` | character varying | 🏷️ Resource name/identifier |
| `latest_version` | integer | 🔢 Numeric value |
| `production_version` | integer | 🔢 Numeric value |
| `staging_version` | integer | 🏷️ Resource tagging |
| `production_hostnames` | ARRAY | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_bot_categories_history`

📊 **17 rows** | 🕐 Last updated: 2025-12-28 08:00:13.297112

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `akamai_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `notes` | character varying | 📝 Documentation/notes |
| `rule_id` | character varying | 📜 Rule reference - track rule coverage |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_bot_detections_history`

📊 **15 rows** | 🕐 Last updated: 2025-12-27 10:38:08.844859

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `akamai_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `group` | character varying | 📄 Data field |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `is_active_detection` | boolean | 🔘 Feature flag/toggle |
| `rule_id` | character varying | 📜 Rule reference - track rule coverage |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | jsonb | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_rate_policy_conditions_history`

📊 **13 rows** | 🕐 Last updated: 2025-12-28 08:35:48.390477

| Field | Type | Purpose |
|-------|------|---------|
| `rate_policy_id` | uuid | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `threshold` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `condition_type` | USER-DEFINED | 🏷️ Classification/type |
| `positive_match` | boolean | 🔘 Feature flag/toggle |
| `header_name` | character varying | 📄 Data field |
| `interpret_header_name_as_wildcard` | boolean | 🔘 Feature flag/toggle |
| `interpret_values_case_sensitive` | boolean | 🔘 Feature flag/toggle |
| `interpret_values_as_wildcards` | boolean | 🔘 Feature flag/toggle |
| `shared_ip_handling` | USER-DEFINED | 🌐 IP/Network - check for overly broad ranges |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_url_prot_pol_hostname_paths_history`

📊 **11 rows** | 🕐 Last updated: 2025-12-28 08:35:38.097321

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `url_prot_pol_hostname_id` | uuid | 🔗 Foreign key reference |
| `path` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_contracts_history`

📊 **8 rows** | 🕐 Last updated: 2025-12-28 08:00:11.452127

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `integration_id` | uuid | 🔗 Integration reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `akamai_id` | character varying | 🔗 Foreign key reference |
| `contract_type_name` | USER-DEFINED | 🏷️ Classification/type |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `organization_name` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `akamai_raw_sec_config_url_prot_pols_history`

📊 **8 rows** | 🕐 Last updated: 2025-12-28 08:35:32.722123

| Field | Type | Purpose |
|-------|------|---------|
| `rate_threshold` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `shedding_threshold_hits_per_sec` | integer | ⚠️ **IMPORTANT** - Rate/threshold config - check adequacy |
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `config_version_id` | uuid | ⚙️ Configuration setting |
| `akamai_id` | integer | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `intelligent_load_shedding` | boolean | 🔘 Feature flag/toggle |
| `protection_type` | USER-DEFINED | 🏷️ Classification/type |
| `create_date` | timestamp with time zone | 📅 Timestamp |
| `created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `update_date` | timestamp with time zone | 📅 Timestamp |
| `updated_by` | character varying | 📄 Data field |
| `used` | boolean | 🔘 Feature flag/toggle |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_url_prot_pol_hostnames_history`

📊 **7 rows** | 🕐 Last updated: 2025-12-28 08:35:37.392116

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `url_prot_pol_id` | uuid | 🔗 Foreign key reference |
| `hostname` | character varying | 🏷️ Resource name/identifier |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

## Other (1 fresh tables)

### `entity_change_log`

📊 **5,727,162 rows** | 🕐 Last updated: 2025-12-28 08:15:55.629248

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `entity_name` | character varying | 📄 Data field |
| `entity_id` | character varying | 🔗 Foreign key reference |
| `asset_type` | character varying | 🏷️ Classification/type |
| `change_type` | character varying | 🏷️ Classification/type |
| `region` | character varying | 📄 Data field |
| `cf_id` | character varying | 🔗 Foreign key reference |
| `cloud_provider` | USER-DEFINED | 📄 Data field |
| `entity_state_before` | jsonb | 📦 Complex nested data |
| `entity_state_after` | jsonb | 📦 Complex nested data |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |

---

# ⚠️ STALE/VIEW TABLES (Collapsed)

<details>
<summary><strong>Click to expand 33 stale tables</strong></summary>

### `akamai_raw_edge_hostnames_history`

Rows: 44 | Last seen: 2025-12-17 08:00:21.493351+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `domain_prefix` | character varying | 📄 Data field |
| `domain_suffix` | character varying | 📄 Data field |
| `edge_hostname_domain` | character varying | 📄 Data field |
| `akamai_id` | character varying | 🔗 Foreign key reference |
| `ip_version_behavior` | USER-DEFINED | 🌐 IP/Network - check for overly broad ranges |
| `secure` | boolean | 🔘 Feature flag/toggle |
| `status` | USER-DEFINED | 📊 Resource state tracking |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_include_rule_behaviors_history`

Rows: 6 | Last seen: 2025-12-17 08:00:30.527497+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `include_id` | uuid | 🔗 Foreign key reference |
| `include_version` | integer | 🔢 Numeric value |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `name` | character varying | 🏷️ Resource name/identifier |
| `options` | json | ⚙️ Configuration setting |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_include_rule_criteria_history`

Rows: 3 | Last seen: 2025-11-23 08:00:11.774526+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `include_id` | uuid | 🔗 Foreign key reference |
| `include_version` | integer | 🔢 Numeric value |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `name` | character varying | 🏷️ Resource name/identifier |
| `options` | json | ⚙️ Configuration setting |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_include_rule_variables_history`

Rows: 1 | Last seen: 2025-11-23 08:00:10.512294+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `include_id` | uuid | 🔗 Foreign key reference |
| `include_version` | integer | 🔢 Numeric value |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `name` | character varying | 🏷️ Resource name/identifier |
| `value` | character varying | 📄 Data field |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `hidden` | boolean | 🔘 Feature flag/toggle |
| `sensitive` | boolean | 🔘 Feature flag/toggle |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_include_rules_history`

Rows: 9 | Last seen: 2025-12-17 08:00:28.354325+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `include_id` | uuid | 🔗 Foreign key reference |
| `include_version` | integer | 🔢 Numeric value |
| `rule_format` | character varying | 📄 Data field |
| `is_secure` | boolean | 🔘 Feature flag/toggle |
| `comments` | character varying | 📝 Documentation/notes |
| `name` | character varying | 🏷️ Resource name/identifier |
| `root_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `parent_rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `criteria_locked` | boolean | 🔘 Feature flag/toggle |
| `criteria_match` | USER-DEFINED | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_includes_history`

Rows: 3 | Last seen: 2025-12-17 08:00:25.169145+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `akamai_asset_id` | character varying | 🔗 Foreign key reference |
| `akamai_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | USER-DEFINED | 🏷️ Classification/type |
| `latest_version` | integer | 🔢 Numeric value |
| `production_version` | integer | 🔢 Numeric value |
| `staging_version` | integer | 🏷️ Resource tagging |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_property_hostnames_history`

Rows: 42 | Last seen: 2025-12-17 08:00:39.944484+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `property_id` | uuid | 🔗 Foreign key reference |
| `property_version` | integer | 🔢 Numeric value |
| `edge_hostname_id` | uuid | 🔗 Foreign key reference |
| `etag` | character varying | 🏷️ Resource tagging |
| `cert_provisioning_type` | USER-DEFINED | 🔒 Certificate tracking |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_property_includes_history`

Rows: 1 | Last seen: 2025-11-23 08:00:09.771702+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `contract_id` | uuid | 🔗 Foreign key reference |
| `group_id` | uuid | 🔗 Foreign key reference |
| `property_id` | uuid | 🔗 Foreign key reference |
| `property_version` | integer | 🔢 Numeric value |
| `include_id` | uuid | 🔗 Foreign key reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_url_prot_pol_bypass_cond_vals_history`

Rows: 21 | Last seen: 2025-11-23 08:00:52.274172+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `bypass_condition_id` | uuid | ⚠️ **IMPORTANT** - Bypass/exclusion - potential security gap |
| `value` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_sec_config_url_prot_pol_bypass_conds_history`

Rows: 10 | Last seen: 2025-11-23 08:00:48.973087+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `url_prot_pol_id` | uuid | 🔗 Foreign key reference |
| `condition_type` | USER-DEFINED | 🏷️ Classification/type |
| `positive_match` | boolean | 🔘 Feature flag/toggle |
| `interpret_header_name_as_wildcards` | boolean | 🔘 Feature flag/toggle |
| `interpret_values_case_sensitive` | boolean | 🔘 Feature flag/toggle |
| `interpret_values_as_wildcards` | boolean | 🔘 Feature flag/toggle |
| `check_ips` | USER-DEFINED | 🌐 IP/Network - check for overly broad ranges |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `akamai_raw_security_policy_attack_groups_history`

Rows: 6100 | Last seen: 2025-12-20 10:16:30.097317+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `organization_name` | character varying | 📄 Data field |
| `integration_id` | uuid | 🔗 Integration reference |
| `security_policy_id` | uuid | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `action` | USER-DEFINED | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `alembic_version`

Rows: 1 | Last seen: None

| Field | Type | Purpose |
|-------|------|---------|
| `version_num` | character varying | 📄 Data field |

### `aws_waf_acl_rule_endpoint_metrics`

Rows: 312685 | Last seen: 2025-10-23 10:00:33.833466+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `organization_id` | uuid | 🏢 Organization linkage |
| `aws_account_id` | character varying | 👤 Account reference |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `organization_name` | character varying | 📄 Data field |
| `region` | USER-DEFINED | 📄 Data field |
| `waf_acl_id` | uuid | 🔗 Foreign key reference |
| `waf_acl_name` | character varying | 📄 Data field |
| `uri` | character varying | 📄 Data field |
| `http_method` | character varying | 📄 Data field |
| `host` | character varying | 📄 Data field |
| `rule_name` | character varying | 📄 Data field |
| `terminating_rule_group_id` | character varying | 📜 Rule reference - track rule coverage |
| `terminating_rule_in_group_id` | character varying | 📜 Rule reference - track rule coverage |
| `event_timestamp` | timestamp with time zone | 📅 Timestamp |
| `total_requests` | integer | 📊 Metric/count value |
| `total_allow` | integer | 📊 Metric/count value |
| `total_blocked` | integer | 📊 Metric/count value |
| `total_counted` | integer | 📊 Metric/count value |
| `total_captcha` | integer | 🛡️ Challenge mechanism config |
| `total_challenge` | integer | 🛡️ Challenge mechanism config |

### `aws_website_paths_history`

Rows: 318620 | Last seen: 2025-08-31 09:09:34.004863

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `path` | character varying | 📄 Data field |
| `website_id` | uuid | 🔗 Foreign key reference |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_websites_history`

Rows: 113 | Last seen: 2025-08-31 09:02:46.572988

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `aws_integration_id` | uuid | 🔗 Foreign key reference |
| `website_url` | ARRAY | 📄 Data field |
| `aws_waf_id` | uuid | 🔗 Foreign key reference |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `aws_websites_paths_metrics_history`

Rows: 322069 | Last seen: 2025-08-31 09:10:04.424776

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `website_id` | uuid | 🔗 Foreign key reference |
| `path_id` | uuid | 🔗 Foreign key reference |
| `action` | character varying | 🔴 **CRITICAL** - Enforcement mode (detection vs prevention) |
| `amount` | integer | 🔢 Numeric value |
| `metric_date` | timestamp without time zone | 📊 Metric/count value |
| `metric_period` | integer | 📊 Metric/count value |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |

### `azure_fd_origin_groups`

Rows: 368 | Last seen: 2025-11-12 22:01:46.803040+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `profile_name` | character varying | 📄 Data field |
| `lb_sample_size` | integer | 🔢 Numeric value |
| `lb_successful_samples_required` | integer | 🔢 Numeric value |
| `lb_additional_latency_in_milliseconds` | integer | 🔢 Numeric value |
| `hp_probe_path` | character varying | 📄 Data field |
| `hp_probe_request_type` | character varying | 🏷️ Classification/type |
| `hp_probe_protocol` | character varying | 🔒 Protocol - verify HTTPS enforcement |
| `hp_probe_interval_in_seconds` | integer | 🔢 Numeric value |
| `traffic_restoration_time_to_healed_or_new_endpoints_in_minutes` | integer | 🔢 Numeric value |
| `session_affinity_state` | character varying | 📄 Data field |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `deployment_status` | character varying | 📄 Data field |
| `system_data_created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `system_data_created_by_type` | USER-DEFINED | 📅 Creation tracking - detect age/staleness |
| `system_data_created_at` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `system_data_last_modified_by` | character varying | 📅 Change tracking - detect drift |
| `system_data_last_modified_by_type` | USER-DEFINED | 📅 Change tracking - detect drift |
| `system_data_last_modified_at` | timestamp with time zone | 📅 Change tracking - detect drift |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_origins`

Rows: 816 | Last seen: 2025-11-12 22:07:18.909868+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `origin_group_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `origin_group_name` | character varying | 📄 Data field |
| `azure_origin_id` | character varying | 🔗 Foreign key reference |
| `host_name` | character varying | 📄 Data field |
| `http_port` | integer | 🔌 Port config - verify restricted ports |
| `https_port` | integer | 🔌 Port config - verify restricted ports |
| `origin_host_header` | character varying | 📄 Data field |
| `priority` | integer | 🔢 Numeric value |
| `weight` | integer | 🔢 Numeric value |
| `enabled_state` | USER-DEFINED | 🔴 **CRITICAL** - Security feature toggle |
| `enforce_certificate_name_check` | boolean | 🔒 Certificate tracking |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `deployment_status` | USER-DEFINED | 📄 Data field |
| `private_link_id` | character varying | 🔗 Foreign key reference |
| `private_link_location` | character varying | 🔗 Resource linkage |
| `private_link_group_id` | character varying | 🔗 Foreign key reference |
| `private_link_request_message` | character varying | 🔗 Resource linkage |
| `private_link_status` | USER-DEFINED | 🔗 Resource linkage |
| `system_data_created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `system_data_created_by_type` | USER-DEFINED | 📅 Creation tracking - detect age/staleness |
| `system_data_created_at` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `system_data_last_modified_by` | character varying | 📅 Change tracking - detect drift |
| `system_data_last_modified_by_type` | USER-DEFINED | 📅 Change tracking - detect drift |
| `system_data_last_modified_at` | timestamp with time zone | 📅 Change tracking - detect drift |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_route_compression_types`

Rows: 7585 | Last seen: 2025-11-19 22:05:09.748768+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `route_id` | uuid | 🔗 Foreign key reference |
| `content_type` | character varying | 📄 Content/payload data |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_route_custom_domains`

Rows: 1031 | Last seen: 2025-11-25 22:06:01.936411+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `route_id` | uuid | 🔗 Foreign key reference |
| `custom_domain_id` | uuid | 🔗 Foreign key reference |
| `is_active` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_routes`

Rows: 421 | Last seen: 2025-11-25 22:05:59.222724+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `endpoint_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `endpoint_name` | character varying | 📄 Data field |
| `origin_group_id` | uuid | 🔗 Foreign key reference |
| `origin_path` | character varying | 📄 Data field |
| `forwarding_protocol` | USER-DEFINED | 🔒 Protocol - verify HTTPS enforcement |
| `link_to_default_domain` | USER-DEFINED | 🔗 Resource linkage |
| `https_redirect` | USER-DEFINED | 🔒 **IMPORTANT** - SSL/TLS config |
| `enabled_state` | USER-DEFINED | 🔴 **CRITICAL** - Security feature toggle |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `deployment_status` | USER-DEFINED | 📄 Data field |
| `supported_protocols` | json | 🔌 Port config - verify restricted ports |
| `patterns_to_match` | json | 🔍 Match pattern - verify coverage |
| `system_data_created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `system_data_created_by_type` | USER-DEFINED | 📅 Creation tracking - detect age/staleness |
| `system_data_created_at` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `system_data_last_modified_by` | character varying | 📅 Change tracking - detect drift |
| `system_data_last_modified_by_type` | USER-DEFINED | 📅 Change tracking - detect drift |
| `system_data_last_modified_at` | timestamp with time zone | 📅 Change tracking - detect drift |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_routes_rule_sets`

Rows: 979 | Last seen: 2025-11-25 22:06:04.437320+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `route_id` | uuid | 🔗 Foreign key reference |
| `rule_set_id` | uuid | 📜 Rule reference - track rule coverage |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_rules`

Rows: 1081 | Last seen: 2025-12-08 22:10:26.860950+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `ruleset_id` | uuid | 📜 Rule reference - track rule coverage |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `rule_set_name` | character varying | 📄 Data field |
| `order_num` | integer | 🔢 Numeric value |
| `match_processing_behavior` | USER-DEFINED | 📄 Data field |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `deployment_status` | USER-DEFINED | 📄 Data field |
| `system_data_created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `system_data_created_by_type` | USER-DEFINED | 📅 Creation tracking - detect age/staleness |
| `system_data_created_at` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `system_data_last_modified_by` | character varying | 📅 Change tracking - detect drift |
| `system_data_last_modified_by_type` | USER-DEFINED | 📅 Change tracking - detect drift |
| `system_data_last_modified_at` | timestamp with time zone | 📅 Change tracking - detect drift |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_rulesets`

Rows: 129 | Last seen: 2025-10-27 15:28:59.220884+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `profile_name` | character varying | 📄 Data field |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `deployment_status` | USER-DEFINED | 📄 Data field |
| `system_data_created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `system_data_created_by_type` | USER-DEFINED | 📅 Creation tracking - detect age/staleness |
| `system_data_created_at` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `system_data_last_modified_by` | character varying | 📅 Change tracking - detect drift |
| `system_data_last_modified_by_type` | USER-DEFINED | 📅 Change tracking - detect drift |
| `system_data_last_modified_at` | timestamp with time zone | 📅 Change tracking - detect drift |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_security_policies`

Rows: 17 | Last seen: 2025-11-16 16:38:57.453353+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `waf_policy_id` | uuid | 🔗 Foreign key reference |
| `azure_id` | character varying | 🔗 Foreign key reference |
| `name` | character varying | 🏷️ Resource name/identifier |
| `type` | character varying | 🏷️ Classification/type |
| `profile_name` | character varying | 📄 Data field |
| `provisioning_state` | USER-DEFINED | 📊 Resource state tracking |
| `deployment_status` | USER-DEFINED | 📄 Data field |
| `waf_policy_azure_id` | character varying | 🔗 Foreign key reference |
| `system_data_created_by` | character varying | 📅 Creation tracking - detect age/staleness |
| `system_data_created_by_type` | USER-DEFINED | 📅 Creation tracking - detect age/staleness |
| `system_data_created_at` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `system_data_last_modified_by` | character varying | 📅 Change tracking - detect drift |
| `system_data_last_modified_by_type` | USER-DEFINED | 📅 Change tracking - detect drift |
| `system_data_last_modified_at` | timestamp with time zone | 📅 Change tracking - detect drift |
| `raw_obj` | json | 📦 Raw API response - full data access |
| `raw_hash` | character varying | 📦 Raw API response - full data access |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `azure_fd_security_policy_domains`

Rows: 121 | Last seen: 2025-11-16 16:39:02.135895+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `sub_id` | uuid | 🔗 Foreign key reference |
| `organization_id` | uuid | 🏢 Organization linkage |
| `rg_id` | uuid | 🔗 Foreign key reference |
| `fd_id` | uuid | 🔗 Foreign key reference |
| `security_policy_id` | uuid | 🔗 Foreign key reference |
| `custom_domain_id` | uuid | 🔗 Foreign key reference |
| `domain_azure_id` | character varying | 🔗 Foreign key reference |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `cloudflare_raw_rulesets_rule_skip_ap_phases_history`

Rows: 170 | Last seen: 2025-12-18 08:12:26.673757+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `phase` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `cloudflare_raw_rulesets_rule_skip_ap_products_history`

Rows: 317 | Last seen: 2025-12-18 08:12:27.040964+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `rule_id` | uuid | 📜 Rule reference - track rule coverage |
| `product` | character varying | 📄 Data field |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |

### `organization_akamai_integration_history`

Rows: 3 | Last seen: 2025-11-24 15:28:35.459541+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `secrets_manager_name` | character varying | 📄 Data field |
| `expires_on` | timestamp with time zone | 📅 Timestamp |
| `is_active` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `use_proxy_auth` | boolean | 🔘 Feature flag/toggle |
| `proxy_path_prefix` | character varying | 📄 Data field |
| `is_running_in_staging` | boolean | 🏷️ Resource tagging |

### `organization_aws_integration_history`

Rows: 58 | Last seen: 2025-12-14 11:27:01.924313

| Field | Type | Purpose |
|-------|------|---------|
| `organization_id` | uuid | 🏢 Organization linkage |
| `arn` | character varying | 📄 Data field |
| `aws_profile_name` | character varying | 📄 Data field |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `is_active` | boolean | 🔘 Feature flag/toggle |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `aws_account_id` | character varying | 👤 Account reference |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `is_log_analysis` | boolean | 📝 Logging configuration |
| `is_running_in_staging` | boolean | 🏷️ Resource tagging |

### `organization_azure_integration_history`

Rows: 10 | Last seen: 2025-11-16 09:34:46.749555+00:00

| Field | Type | Purpose |
|-------|------|---------|
| `id` | uuid | 🔑 Primary identifier |
| `organization_id` | uuid | 🏢 Organization linkage |
| `profile_name` | character varying | 📄 Data field |
| `is_active` | boolean | 🔘 Feature flag/toggle |
| `creation_date` | timestamp with time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp with time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `is_running_in_staging` | boolean | 🏷️ Resource tagging |

### `organization_cloudflare_integration_history`

Rows: 8 | Last seen: 2025-12-24 14:17:03.535835

| Field | Type | Purpose |
|-------|------|---------|
| `organization_id` | uuid | 🏢 Organization linkage |
| `api_token_name` | character varying | 📄 Data field |
| `description` | character varying | 🌐 IP/Network - check for overly broad ranges |
| `is_active` | boolean | 🔘 Feature flag/toggle |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `is_running_in_staging` | boolean | 🏷️ Resource tagging |

### `organization_history`

Rows: 19 | Last seen: 2025-12-22 07:50:09.305967

| Field | Type | Purpose |
|-------|------|---------|
| `org_display_name` | character varying | 📄 Data field |
| `org_name` | character varying | 📄 Data field |
| `id` | uuid | 🔑 Primary identifier |
| `creation_date` | timestamp without time zone | 📅 Creation tracking - detect age/staleness |
| `modification_date` | timestamp without time zone | 📅 Change tracking - detect drift |
| `is_deleted` | boolean | 🔘 Feature flag/toggle |
| `is_running_in_staging` | boolean | 🏷️ Resource tagging |

</details>

# ❌ EMPTY TABLES (Collapsed)

<details>
<summary><strong>Click to expand 41 empty tables</strong></summary>

These tables have schema defined but no data:

- `akamai_raw_custom_behaviors_history`
- `akamai_raw_custom_overrides_history`
- `akamai_raw_sec_config_http_header_log_cookies_history`
- `akamai_raw_sec_config_http_header_log_custom_headers_history`
- `akamai_raw_sec_config_http_header_log_standard_headers_history`
- `aws_raw_cloudfront_distribution_cache_behavior_history`
- `aws_raw_prefix_list_associations_history`
- `aws_raw_waf_acl_rule_group_statements_history`
- `aws_waf_acl_endpoints`
- `azure_app_gateway_listener_custom_errors`
- `azure_app_gateway_rewrite_rule_actions`
- `azure_app_gateway_rewrite_rule_conditions`
- `azure_app_gateway_rewrite_rule_sets`
- `azure_app_gateway_rewrite_rules`
- `azure_app_gateway_waf_managed_rule_exception_managed_rule_sets`
- `azure_app_gateway_waf_managed_rule_exception_values`
- `azure_app_gateway_waf_managed_rule_exceptions`
- `azure_app_gateway_waf_managed_rule_set_computed_disabled_rules`
- `azure_app_gateway_waf_policy_scrubbing_rules`
- `azure_app_gw_waf_mng_rule_exc_mng_ruleset_rg_rules`
- `azure_fd_identities`
- `azure_fd_log_scrubbing_rules`
- `azure_fd_user_assigned_identities`
- `azure_fd_waf_scrubbing_rules`
- `azure_front_door_custom_domains`
- `azure_front_door_endpoint_tags`
- `azure_front_door_endpoints`
- `azure_front_door_extended_properties`
- `azure_front_door_log_scrubbing_rules`
- `azure_front_door_metrics`
- `azure_front_door_origin_groups`
- `azure_front_door_origins`
- `azure_front_door_route_compression_types`
- `azure_front_door_routes`
- `azure_front_door_rulesets`
- `azure_front_door_security_policies`
- `azure_front_door_security_policy_domains`
- `azure_front_door_tags`
- `azure_front_door_user_assigned_identities`
- `azure_front_doors`
- `cloudflare_logs_storage_history`

</details>