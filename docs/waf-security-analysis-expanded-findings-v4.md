# WAF/CDN Security Analysis Framework v4.0
## Comprehensive AI-Agent Security Analysis Knowledge Base

> **PURPOSE**: This document serves as a comprehensive prompt/knowledge base for AI agents to perform autonomous security analysis of WAF/CDN configurations and traffic patterns across Cloudflare, Akamai, and AWS WAF environments.

> **EXECUTION MODE**: AI agents should systematically execute ALL checks in this document, replacing `{ORGANIZATION_ID}`, `{CUSTOMER}`, `{YEAR}`, `{MONTH}`, `{DAY}`, `{HOUR}` placeholders with actual values.

---

# MASTER SECURITY CHECK INDEX

## PostgreSQL Configuration Checks (150+ Checks)

| ID | Vendor | Category | Severity | Check Name | Table(s) |
|----|--------|----------|----------|------------|----------|
| CF-ZONE-001 | Cloudflare | Zone Security | CRITICAL | Zones Without WAF Protection | cloudflare_raw_zones_history, cloudflare_raw_rulesets_instance_history |
| CF-ZONE-002 | Cloudflare | Zone Security | HIGH | Zones on Free/Pro Plans | cloudflare_raw_zones_history |
| CF-ZONE-003 | Cloudflare | Zone Security | HIGH | Unproxied DNS Records | cloudflare_raw_dns_records_history |
| CF-ZONE-004 | Cloudflare | Zone Security | CRITICAL | Origin IP Exposure | cloudflare_raw_dns_records_history |
| CF-ZONE-005 | Cloudflare | Zone Security | HIGH | Inactive Zones with Active DNS | cloudflare_raw_zones_history |
| CF-ZONE-006 | Cloudflare | Zone Security | MEDIUM | Zone Development Mode Enabled | cloudflare_raw_zones_history |
| CF-RULE-001 | Cloudflare | Rule Config | CRITICAL | SKIP Rules Without IP Restriction | cloudflare_raw_rulesets_rules_history |
| CF-RULE-002 | Cloudflare | Rule Config | HIGH | Disabled Managed Rulesets | cloudflare_raw_rulesets_rules_history |
| CF-RULE-003 | Cloudflare | Rule Config | HIGH | Log-Only WAF Rules | cloudflare_raw_rulesets_rules_history |
| CF-RULE-004 | Cloudflare | Rule Config | MEDIUM | Rules Without Logging | cloudflare_raw_rulesets_rules_history |
| CF-RULE-005 | Cloudflare | Rule Config | HIGH | Overly Broad Allow Rules | cloudflare_raw_rulesets_rules_history |
| CF-RULE-006 | Cloudflare | Rule Config | CRITICAL | Rules Skipping WAF Phases | cloudflare_raw_rulesets_rule_skip_ap_phases_history |
| CF-RULE-007 | Cloudflare | Rule Config | HIGH | Rules Skipping Multiple Products | cloudflare_raw_rulesets_rule_skip_ap_products_history |
| CF-RULE-008 | Cloudflare | Rule Config | HIGH | Challenge Rules Without Timeout | cloudflare_raw_rulesets_rules_history |
| CF-RULE-009 | Cloudflare | Rule Config | MEDIUM | Duplicate Rule Expressions (excl. managed phase) | cloudflare_raw_rulesets_rules_history |
| CF-RULE-009-EXT | Cloudflare | Rule Config | MEDIUM | Same Expression with Different Thresholds/Actions | cloudflare_raw_rulesets_rules_history |
| CF-RULE-010 | Cloudflare | Rule Config | HIGH | Managed Rules Override to Allow | cloudflare_raw_rulesets_rules_history |
| CF-RULE-011 | Cloudflare | Rule Config | CRITICAL | Block Rules with Broad Scope | cloudflare_raw_rulesets_rules_history |
| CF-RULE-012 | Cloudflare | Rule Config | HIGH | Challenge Rules Without Timeout | cloudflare_raw_rulesets_rules_history |
| CF-RULE-013 | Cloudflare | Rule Config | HIGH | Missing OWASP Core Ruleset (excl. Free tier) | cloudflare_raw_rulesets_instance_history |
| CF-RATE-001 | Cloudflare | Rate Limiting | HIGH | No Rate Limiting on APIs | cloudflare_raw_rulesets_rules_history |
| CF-RATE-002 | Cloudflare | Rate Limiting | MEDIUM | High Rate Limit Thresholds | cloudflare_raw_rulesets_rule_rate_limits_history |
| CF-RATE-003 | Cloudflare | Rate Limiting | HIGH | Rate Limit Without Mitigation | cloudflare_raw_rulesets_rule_rate_limits_history |
| CF-RATE-004 | Cloudflare | Rate Limiting | MEDIUM | Rate Limit Short Duration | cloudflare_raw_rulesets_rule_rate_limits_history |
| CF-BOT-001 | Cloudflare | Bot Management | CRITICAL | No Bot Management Config | cloudflare_raw_bot_management_history |
| CF-BOT-002 | Cloudflare | Bot Management | HIGH | Bot Fight Mode Disabled | cloudflare_raw_bot_management_history |
| CF-BOT-003 | Cloudflare | Bot Management | HIGH | Automated Traffic Allowed | cloudflare_raw_bot_management_history |
| CF-BOT-004 | Cloudflare | Bot Management | MEDIUM | AI Bot Protection Disabled | cloudflare_raw_bot_management_history |
| CF-BOT-005 | Cloudflare | Bot Management | HIGH | Static Resource Protection Off | cloudflare_raw_bot_management_history |
| CF-BOT-006 | Cloudflare | Bot Management | MEDIUM | JS Detection Disabled | cloudflare_raw_bot_management_history |
| CF-LIST-001 | Cloudflare | IP Lists | MEDIUM | Stale IP Lists | cloudflare_raw_lists_history, cloudflare_raw_list_items_history |
| CF-LIST-002 | Cloudflare | IP Lists | HIGH | Empty Security Lists | cloudflare_raw_lists_history |
| CF-LIST-003 | Cloudflare | IP Lists | MEDIUM | Large IP Lists (Performance) | cloudflare_raw_list_items_history |
| CF-DNS-001 | Cloudflare | DNS Security | HIGH | CNAME to External Origin | cloudflare_raw_dns_records_history |
| CF-DNS-002 | Cloudflare | DNS Security | MEDIUM | Wildcard DNS Records | cloudflare_raw_dns_records_history |
| CF-DNS-003 | Cloudflare | DNS Security | HIGH | MX Records Not Proxied | cloudflare_raw_dns_records_history |
| AK-POLICY-001 | Akamai | Security Policy | CRITICAL | Policies in Monitor Mode | akamai_raw_security_policies_history |
| AK-POLICY-002 | Akamai | Security Policy | CRITICAL | Attack Groups Not Deny | akamai_raw_security_policy_attack_groups_history |
| AK-POLICY-003 | Akamai | Security Policy | HIGH | Slow POST Disabled | akamai_raw_security_policies_history |
| AK-POLICY-004 | Akamai | Security Policy | HIGH | API Request Constraints Off | akamai_raw_security_policies_history |
| AK-POLICY-005 | Akamai | Security Policy | MEDIUM | Pragma Header Disabled | akamai_raw_security_policies_history |
| AK-RATE-001 | Akamai | Rate Controls | HIGH | Rate Policies Alert Only | akamai_raw_security_policy_rate_policy_actions_history |
| AK-RATE-002 | Akamai | Rate Controls | MEDIUM | High Rate Thresholds | akamai_raw_sec_config_rate_policies_history |
| AK-RATE-003 | Akamai | Rate Controls | HIGH | No Rate Policies Defined | akamai_raw_sec_config_rate_policies_history |
| AK-BOT-001 | Akamai | Bot Manager | CRITICAL | Bot Categories Unprotected | akamai_raw_bot_category_actions_history |
| AK-BOT-002 | Akamai | Bot Manager | HIGH | Bot Detections Not Enforced | akamai_raw_bot_detection_actions_history |
| AK-BOT-003 | Akamai | Bot Manager | HIGH | Headless Browser Allowed | akamai_raw_bot_detection_actions_history |
| AK-CUSTOM-001 | Akamai | Custom Rules | HIGH | Custom Rules Alert Only | akamai_raw_sec_config_custom_rules_history |
| AK-CUSTOM-002 | Akamai | Custom Rules | MEDIUM | Custom Rules Without Conditions | akamai_raw_sec_config_custom_rule_conditions_history |
| AK-PROP-001 | Akamai | Property Config | HIGH | Properties Without WAF | akamai_raw_properties_history |
| AK-PROP-002 | Akamai | Property Config | HIGH | Origin Protocol HTTP | akamai_raw_property_rule_behaviors_history |
| AK-PROP-003 | Akamai | Property Config | MEDIUM | Caching on Sensitive Paths | akamai_raw_property_rules_history |
| AWS-ACL-001 | AWS WAF | Web ACL | CRITICAL | ACLs Without Resources | aws_raw_waf_acl_history, aws_raw_waf_acl_associated_resources_history |
| AWS-ACL-002 | AWS WAF | Web ACL | CRITICAL | ACLs Without Logging | aws_raw_waf_acl_logging_configurations_history |
| AWS-ACL-003 | AWS WAF | Web ACL | HIGH | High WCU Usage | aws_raw_waf_acl_history |
| AWS-ACL-004 | AWS WAF | Web ACL | HIGH | Default Action ALLOW | aws_raw_waf_acl_history |
| AWS-ACL-005 | AWS WAF | Web ACL | MEDIUM | CloudWatch Metrics Off | aws_raw_waf_acl_history |
| AWS-ACL-006 | AWS WAF | Web ACL | MEDIUM | Sample Requests Disabled | aws_raw_waf_acl_history |
| AWS-ACL-007 | AWS WAF | Web ACL | LOW | No Description | aws_raw_waf_acl_history |
| AWS-RULE-001 | AWS WAF | Rules | HIGH | Rules in Count Mode | aws_raw_waf_acl_rules_history |
| AWS-RULE-002 | AWS WAF | Rules | HIGH | Rules Without Labels | aws_raw_waf_acl_rule_labels_history |
| AWS-RULE-003 | AWS WAF | Rules | MEDIUM | Low Priority Rules | aws_raw_waf_acl_rules_history |
| AWS-RULE-004 | AWS WAF | Rules | HIGH | Rate Rules High Threshold | aws_raw_waf_acl_rules_history |
| AWS-MRG-001 | AWS WAF | Managed Rules | CRITICAL | No AWS Managed Rules | aws_raw_waf_acl_rule_group_statements_history |
| AWS-MRG-002 | AWS WAF | Managed Rules | HIGH | Core Rule Set Missing | aws_raw_waf_acl_rule_group_statements_history |
| AWS-MRG-003 | AWS WAF | Managed Rules | HIGH | Known Bad Inputs Missing | aws_raw_waf_acl_rule_group_statements_history |
| AWS-MRG-004 | AWS WAF | Managed Rules | HIGH | SQL Injection Rules Missing | aws_raw_waf_acl_rule_group_statements_history |
| AWS-MRG-005 | AWS WAF | Managed Rules | MEDIUM | Bot Control Missing | aws_raw_waf_acl_rule_group_statements_history |
| AWS-MRG-006 | AWS WAF | Managed Rules | HIGH | Rules Override to Count | aws_raw_acl_managed_rule_group_rule_override_history |
| AWS-CF-001 | AWS WAF | CloudFront | CRITICAL | CF Without WAF | aws_raw_cloudfront_distribution_history |
| AWS-CF-002 | AWS WAF | CloudFront | HIGH | Origin HTTP Protocol | aws_raw_cloudfront_distribution_origin_history |
| AWS-CF-003 | AWS WAF | CloudFront | HIGH | No Custom Error Pages | aws_raw_cloudfront_distribution_history |
| AWS-CF-004 | AWS WAF | CloudFront | MEDIUM | Geo Restrictions Missing | aws_raw_cloudfront_distribution_history |
| AWS-LOG-001 | AWS WAF | Logging | HIGH | Logging Filtered | aws_raw_waf_acl_logging_configurations_filters_history |
| AWS-LOG-002 | AWS WAF | Logging | MEDIUM | Fields Redacted | aws_raw_waf_acl_logging_configurations_redacted_fields_history |

## Trino Traffic Analysis Checks (100+ Checks)

| ID | Vendor | Category | Severity | Check Name | Log Fields |
|----|--------|----------|----------|------------|------------|
| CF-LOG-ATK-001 | Cloudflare | Attack Detection | CRITICAL | High Attack Score Not Blocked | wafattackscore, securityaction |
| CF-LOG-ATK-002 | Cloudflare | Attack Detection | CRITICAL | SQLi Score Not Blocked | wafsqliattackscore, securityaction |
| CF-LOG-ATK-003 | Cloudflare | Attack Detection | CRITICAL | XSS Score Not Blocked | wafxssattackscore, securityaction |
| CF-LOG-ATK-004 | Cloudflare | Attack Detection | CRITICAL | RCE Score Not Blocked | wafrceattackscore, securityaction |
| CF-LOG-ATK-005 | Cloudflare | Attack Detection | HIGH | Multiple Attack Types | wafattackscore, wafsqliattackscore, wafxssattackscore |
| CF-LOG-BOT-001 | Cloudflare | Bot Traffic | HIGH | Low Bot Score Allowed | botscore, securityaction |
| CF-LOG-BOT-002 | Cloudflare | Bot Traffic | HIGH | Verified Bot Spoofing | verifiedbotcategory, clientrequestuseragent |
| CF-LOG-BOT-003 | Cloudflare | Bot Traffic | MEDIUM | AI Crawler Detection | botdetectiontags, clientrequestuseragent |
| CF-LOG-BOT-004 | Cloudflare | Bot Traffic | HIGH | Headless Browser Traffic | bottags, botscore |
| CF-LOG-BOT-005 | Cloudflare | Bot Traffic | MEDIUM | Bot Tag Analysis | bottags, botdetectiontags |
| CF-LOG-ABU-001 | Cloudflare | Abuse Patterns | HIGH | Credential Stuffing | clientrequesturi, clientip, clientrequestmethod |
| CF-LOG-ABU-002 | Cloudflare | Abuse Patterns | HIGH | API Enumeration | clientrequesturi, edgeresponsestatus |
| CF-LOG-ABU-003 | Cloudflare | Abuse Patterns | HIGH | Path Traversal | clientrequesturi |
| CF-LOG-ABU-004 | Cloudflare | Abuse Patterns | CRITICAL | Command Injection | clientrequesturi |
| CF-LOG-ABU-005 | Cloudflare | Abuse Patterns | HIGH | SQL Injection Patterns | clientrequesturi |
| CF-LOG-ABU-006 | Cloudflare | Abuse Patterns | HIGH | XSS Patterns | clientrequesturi |
| CF-LOG-ABU-007 | Cloudflare | Abuse Patterns | MEDIUM | Directory Bruteforce | clientrequesturi, edgeresponsestatus |
| CF-LOG-ABU-008 | Cloudflare | Abuse Patterns | HIGH | Admin Path Probing | clientrequesturi |
| CF-LOG-ABU-009 | Cloudflare | Abuse Patterns | HIGH | Scanner User Agents | clientrequestuseragent |
| CF-LOG-ABU-010 | Cloudflare | Abuse Patterns | MEDIUM | Empty/Missing UA | clientrequestuseragent |
| CF-LOG-SEC-001 | Cloudflare | Security Events | HIGH | Blocked Requests Volume | securityaction |
| CF-LOG-SEC-002 | Cloudflare | Security Events | MEDIUM | Security Rules Triggered | securityruleid, securityruledescription |
| CF-LOG-SEC-003 | Cloudflare | Security Events | HIGH | Leaked Credentials | leakedcredentialcheckresult |
| CF-LOG-SEC-004 | Cloudflare | Security Events | MEDIUM | Challenge Success Rate | securityaction |
| CF-LOG-SEC-005 | Cloudflare | Security Events | HIGH | Fraud Detection | fraudattack, frauddetectionids |
| CF-LOG-ANO-001 | Cloudflare | Anomalies | HIGH | Unusual HTTP Methods | clientrequestmethod |
| CF-LOG-ANO-002 | Cloudflare | Anomalies | HIGH | Large Response Sizes | edgeresponsebytes |
| CF-LOG-ANO-003 | Cloudflare | Anomalies | MEDIUM | Origin 5xx Errors | originresponsestatus |
| CF-LOG-ANO-004 | Cloudflare | Anomalies | HIGH | TLS Downgrade | clientsslprotocol |
| CF-LOG-ANO-005 | Cloudflare | Anomalies | MEDIUM | Weak Cipher Usage | clientsslcipher |
| CF-LOG-ANO-006 | Cloudflare | Anomalies | HIGH | Protocol Anomalies | clientrequestprotocol |
| CF-LOG-ANO-007 | Cloudflare | Anomalies | MEDIUM | High Error Rates | edgeresponsestatus |
| CF-LOG-ANO-008 | Cloudflare | Anomalies | HIGH | Slow Origin Response | originresponsedurationms |
| CF-LOG-CAC-001 | Cloudflare | Cache Security | HIGH | Cache Poisoning Indicators | clientrequesturi, cachecachestatus |
| CF-LOG-CAC-002 | Cloudflare | Cache Security | MEDIUM | Cache Status Distribution | cachecachestatus |
| CF-LOG-CAC-003 | Cloudflare | Cache Security | HIGH | Sensitive Data Cached | cachecachestatus, clientrequesturi |
| CF-LOG-GEO-001 | Cloudflare | Geographic | MEDIUM | Traffic by Country | clientcountry |
| CF-LOG-GEO-002 | Cloudflare | Geographic | HIGH | Attack Traffic by Country | clientcountry, wafattackscore |
| CF-LOG-GEO-003 | Cloudflare | Geographic | MEDIUM | Unusual Countries | clientcountry |
| CF-LOG-JA-001 | Cloudflare | Fingerprinting | HIGH | Suspicious JA3/JA4 | ja3hash, ja4 |
| CF-LOG-JA-002 | Cloudflare | Fingerprinting | MEDIUM | JA4 Signal Analysis | ja4signals |
| CF-LOG-JA-003 | Cloudflare | Fingerprinting | HIGH | Known Malware JA3 | ja3hash |
| CF-LOG-WRK-001 | Cloudflare | Workers | MEDIUM | Worker Errors | workerstatus |
| CF-LOG-WRK-002 | Cloudflare | Workers | HIGH | Worker CPU Time | workercputime |
| CF-LOG-MTL-001 | Cloudflare | mTLS | HIGH | mTLS Failures | clientmtlsauthstatus |
| CF-LOG-MTL-002 | Cloudflare | mTLS | MEDIUM | mTLS Certificate Issues | clientmtlsauthcertfingerprint |
| AWS-LOG-ATK-001 | AWS WAF | Attack Detection | HIGH | Block Analysis | action, terminatingruleid |
| AWS-LOG-ATK-002 | AWS WAF | Attack Detection | HIGH | Top Attacking IPs | httprequest.clientip, action |
| AWS-LOG-ATK-003 | AWS WAF | Attack Detection | CRITICAL | Managed Rule Triggers | terminatingruleid, terminatingruletype |
| AWS-LOG-ATK-004 | AWS WAF | Attack Detection | HIGH | Count-Only Triggers | action |
| AWS-LOG-ATK-005 | AWS WAF | Attack Detection | HIGH | Rule Group Analysis | rulegrouplist |
| AWS-LOG-ABU-001 | AWS WAF | Abuse Patterns | HIGH | Credential Stuffing | httprequest.uri, httprequest.clientip |
| AWS-LOG-ABU-002 | AWS WAF | Abuse Patterns | HIGH | Rate Violations | httprequest.clientip |
| AWS-LOG-ABU-003 | AWS WAF | Abuse Patterns | CRITICAL | SQLi Patterns | httprequest.uri, httprequest.args |
| AWS-LOG-ABU-004 | AWS WAF | Abuse Patterns | HIGH | XSS Patterns | httprequest.uri |
| AWS-LOG-ABU-005 | AWS WAF | Abuse Patterns | HIGH | Path Traversal | httprequest.uri |
| AWS-LOG-SEC-001 | AWS WAF | Security Events | HIGH | Label Analysis | labels |
| AWS-LOG-SEC-002 | AWS WAF | Security Events | MEDIUM | CAPTCHA Analysis | captcharesponse |
| AWS-LOG-SEC-003 | AWS WAF | Security Events | HIGH | Oversize Requests | requestbodysize, oversizefields |
| AWS-LOG-SEC-004 | AWS WAF | Security Events | HIGH | Challenge Analysis | challengeresponse |
| AWS-LOG-ANO-001 | AWS WAF | Anomalies | HIGH | Unusual HTTP Methods | httprequest.httpmethod |
| AWS-LOG-ANO-002 | AWS WAF | Anomalies | MEDIUM | User Agent Analysis | httprequest.headers |
| AWS-LOG-ANO-003 | AWS WAF | Anomalies | HIGH | Geographic Analysis | httprequest.country |
| AWS-LOG-ANO-004 | AWS WAF | Anomalies | MEDIUM | Request Size Analysis | requestbodysize |
| AWS-LOG-FP-001 | AWS WAF | Fingerprinting | HIGH | JA3 Fingerprint Analysis | ja3fingerprint |
| AWS-LOG-FP-002 | AWS WAF | Fingerprinting | HIGH | JA4 Fingerprint Analysis | ja4fingerprint |

---

# OFFICIAL VENDOR DOCUMENTATION & SECURITY VALUE REFERENCE

> **PURPOSE**: This section provides official documentation links from each vendor and detailed explanations of why each security check matters for customer protection.

---

## 📚 CLOUDFLARE OFFICIAL DOCUMENTATION REFERENCES

### Zone Security & WAF Configuration

| Topic | Official Documentation URL |
|-------|---------------------------|
| **WAF Overview** | https://developers.cloudflare.com/waf/ |
| **Managed Rulesets** | https://developers.cloudflare.com/waf/managed-rules/ |
| **OWASP Core Ruleset** | https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/ |
| **Custom Rules** | https://developers.cloudflare.com/waf/custom-rules/ |
| **Rate Limiting** | https://developers.cloudflare.com/waf/rate-limiting-rules/ |
| **Skip Action** | https://developers.cloudflare.com/waf/custom-rules/skip/ |
| **Bot Management** | https://developers.cloudflare.com/bots/ |
| **Bot Fight Mode** | https://developers.cloudflare.com/bots/get-started/free/ |
| **Super Bot Fight Mode** | https://developers.cloudflare.com/bots/get-started/pro/ |
| **DNS Proxy Status** | https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/ |
| **IP Lists** | https://developers.cloudflare.com/waf/tools/lists/custom-lists/ |
| **Ruleset Engine** | https://developers.cloudflare.com/ruleset-engine/ |
| **Phases** | https://developers.cloudflare.com/ruleset-engine/reference/phases-list/ |
| **WAF Attack Score** | https://developers.cloudflare.com/waf/about/waf-attack-score/ |
| **Bot Score** | https://developers.cloudflare.com/bots/concepts/bot-score/ |
| **Leaked Credentials Check** | https://developers.cloudflare.com/waf/managed-rules/reference/exposed-credentials-check/ |
| **HTTP Request Fields** | https://developers.cloudflare.com/ruleset-engine/rules-language/fields/ |
| **Cloudflare Logs** | https://developers.cloudflare.com/logs/ |
| **Logpush Fields** | https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/ |

### Cloudflare Security Best Practices

| Resource | URL |
|----------|-----|
| **WAF Best Practices** | https://developers.cloudflare.com/waf/reference/best-practices/ |
| **Origin Protection** | https://developers.cloudflare.com/fundamentals/basic-tasks/protect-your-origin-server/ |
| **SSL/TLS Recommendations** | https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/ |
| **DDoS Protection** | https://developers.cloudflare.com/ddos-protection/ |
| **Security Level** | https://developers.cloudflare.com/waf/tools/security-level/ |

---

## 📚 AKAMAI OFFICIAL DOCUMENTATION REFERENCES

### App & API Protector (AAP) / Kona Site Defender (KSD)

| Topic | Official Documentation URL |
|-------|---------------------------|
| **App & API Protector** | https://techdocs.akamai.com/app-api-protector/docs |
| **Security Policies** | https://techdocs.akamai.com/app-api-protector/docs/security-policies |
| **Attack Groups** | https://techdocs.akamai.com/app-api-protector/docs/attack-groups |
| **Web Attack Tool Signatures** | https://techdocs.akamai.com/app-api-protector/docs/attack-tool-signatures |
| **Rate Controls** | https://techdocs.akamai.com/app-api-protector/docs/rate-controls |
| **Slow POST Protection** | https://techdocs.akamai.com/app-api-protector/docs/slow-post |
| **API Request Constraints** | https://techdocs.akamai.com/app-api-protector/docs/api-request-constraints |
| **Custom Rules** | https://techdocs.akamai.com/app-api-protector/docs/custom-rules |
| **Penalty Box** | https://techdocs.akamai.com/app-api-protector/docs/penalty-box |

### Bot Manager

| Topic | Official Documentation URL |
|-------|---------------------------|
| **Bot Manager Overview** | https://techdocs.akamai.com/bot-manager/docs |
| **Bot Categories** | https://techdocs.akamai.com/bot-manager/docs/bot-categories |
| **Bot Detection Methods** | https://techdocs.akamai.com/bot-manager/docs/detection-methods |
| **Transactional Endpoints** | https://techdocs.akamai.com/bot-manager/docs/transactional-endpoints |
| **Bot Analytics** | https://techdocs.akamai.com/bot-manager/docs/bot-analytics |

### Property Configuration

| Topic | Official Documentation URL |
|-------|---------------------------|
| **Property Manager** | https://techdocs.akamai.com/property-mgr/docs |
| **Origin Settings** | https://techdocs.akamai.com/property-mgr/docs/origin-server |
| **Caching Behaviors** | https://techdocs.akamai.com/property-mgr/docs/caching |

---

## 📚 AWS WAF OFFICIAL DOCUMENTATION REFERENCES

### Core WAF Documentation

| Topic | Official Documentation URL |
|-------|---------------------------|
| **AWS WAF Overview** | https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html |
| **Web ACLs** | https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html |
| **Rules and Rule Groups** | https://docs.aws.amazon.com/waf/latest/developerguide/waf-rules.html |
| **Managed Rule Groups** | https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups.html |
| **AWS Managed Rules List** | https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html |
| **Core Rule Set (CRS)** | https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html |
| **Known Bad Inputs** | https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html#aws-managed-rule-groups-baseline-kbi |
| **SQL Injection Rules** | https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html#aws-managed-rule-groups-use-case-sql-db |
| **Bot Control** | https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html |
| **Rate-Based Rules** | https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html |
| **IP Sets** | https://docs.aws.amazon.com/waf/latest/developerguide/waf-ip-set.html |
| **Rule Actions** | https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-action.html |
| **WCU Capacity** | https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-oversize-exception.html |

### Logging & Monitoring

| Topic | Official Documentation URL |
|-------|---------------------------|
| **WAF Logging** | https://docs.aws.amazon.com/waf/latest/developerguide/logging.html |
| **Log Fields** | https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html |
| **CloudWatch Metrics** | https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html |
| **Sample Requests** | https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html |

### CloudFront Integration

| Topic | Official Documentation URL |
|-------|---------------------------|
| **CloudFront & WAF** | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html |
| **CloudFront Security** | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/SecurityAndPrivateContent.html |
| **Origin Protocol Policy** | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesOriginProtocolPolicy |
| **Geo Restrictions** | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html |

### AWS Security Best Practices

| Resource | URL |
|----------|-----|
| **WAF Best Practices** | https://docs.aws.amazon.com/waf/latest/developerguide/waf-best-practices.html |
| **Security Pillar - Well-Architected** | https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html |
| **AWS Security Hub** | https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html |

---

# DETAILED SECURITY CHECK VALUE EXPLANATIONS

> **PURPOSE**: This section explains WHY each check is severe and what the customer security impact is.

---

## 🔶 CLOUDFLARE - PostgreSQL Check Security Value

### CF-ZONE Checks (Zone Security)

#### CF-ZONE-001: Zones Without WAF Protection
- **Official Docs**: https://developers.cloudflare.com/waf/managed-rules/
- **Security Value**: **CRITICAL** - A production zone without WAF rulesets deployed is completely vulnerable to OWASP Top 10 attacks including SQL injection, XSS, and RCE. Every HTTP request reaches the origin unfiltered.
- **Customer Impact**: Direct exposure to automated attacks, web scrapers, credential stuffing, and vulnerability exploitation. Attackers can freely probe for weaknesses.
- **Real-World Risk**: In 2023-2024, unprotected endpoints saw 10x higher attack volumes. Cloudflare blocks 158+ billion cyber threats daily - zones without WAF receive them all.

#### CF-ZONE-002: Zones on Free/Pro Plans
- **Official Docs**: https://developers.cloudflare.com/waf/reference/plan-limits/
- **Security Value**: **HIGH** - Free and Pro plans have significantly limited WAF capabilities. Free plans only get 5 custom WAF rules; Pro plans lack advanced managed rulesets and Bot Management.
- **Customer Impact**: Reduced protection against sophisticated attacks. Missing OWASP Core Ruleset customization, no exposed credentials detection, limited rate limiting.
- **Real-World Risk**: Organizations running production workloads on Free/Pro plans cannot implement defense-in-depth strategies required by compliance frameworks (PCI-DSS, SOC2).

#### CF-ZONE-003: Unproxied DNS Records
- **Official Docs**: https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/
- **Security Value**: **HIGH** - Unproxied (grey-cloud) DNS records bypass ALL Cloudflare security: WAF, DDoS protection, Bot Management, Rate Limiting. Traffic goes directly to origin.
- **Customer Impact**: Complete security bypass. Attackers who discover these records can attack the origin directly, bypassing millions of dollars of security infrastructure.
- **Real-World Risk**: Origin IP discovery via unproxied records is a documented attack technique. Once found, attackers add IPs to hosts files to permanently bypass CDN security.

#### CF-ZONE-004: Origin IP Exposure
- **Official Docs**: https://developers.cloudflare.com/fundamentals/basic-tasks/protect-your-origin-server/
- **Security Value**: **CRITICAL** - Exposed origin IPs in DNS records (even proxied ones visible via historical DNS) allow direct origin attacks.
- **Customer Impact**: Attackers can directly DDoS the origin, bypassing Cloudflare's DDoS mitigation. They can exploit vulnerabilities without WAF interference.
- **Real-World Risk**: Services like SecurityTrails and DNS history databases expose historical A records. Once an origin IP leaks, it's compromised forever unless changed.

#### CF-ZONE-005: Inactive Zones with Active DNS
- **Official Docs**: https://developers.cloudflare.com/fundamentals/get-started/concepts/how-cloudflare-works/
- **Security Value**: **HIGH** - Inactive zones with DNS records may be serving traffic without proper security configuration, or represent abandoned infrastructure.
- **Customer Impact**: Potential shadow IT, abandoned applications with unpatched vulnerabilities, or misconfiguration causing traffic to bypass security.
- **Real-World Risk**: Abandoned zones are prime targets for subdomain takeover attacks and become entry points into corporate networks.

### CF-RULE Checks (Rule Configuration)

#### CF-RULE-001: SKIP Rules Without IP Restriction
- **Official Docs**: https://developers.cloudflare.com/waf/custom-rules/skip/
- **Security Value**: **CRITICAL** - SKIP rules that aren't restricted to trusted IPs allow ANYONE to bypass WAF protection entirely. This is the #1 misconfiguration.
- **Customer Impact**: A single overly permissive SKIP rule can negate your entire WAF investment. Attackers who match the rule's expression bypass all security.
- **Real-World Risk**: We've seen SKIP rules matching User-Agent headers that attackers easily spoof. One misconfigured SKIP rule led to a full compromise within hours.

#### CF-RULE-002: Disabled Managed Rulesets
- **Official Docs**: https://developers.cloudflare.com/waf/managed-rules/deploy-zone-dashboard/
- **Security Value**: **HIGH** - Disabled managed ruleset rules create gaps in protection against known CVEs and attack patterns that Cloudflare's threat intel has identified.
- **Customer Impact**: Missing protection against actively exploited vulnerabilities. Cloudflare updates managed rules daily based on threat intel - disabled rules miss these updates.
- **Real-World Risk**: Log4Shell (CVE-2021-44228) rules were pushed within hours. Zones with disabled managed rules remained vulnerable.

#### CF-RULE-003: Log-Only WAF Rules
- **Official Docs**: https://developers.cloudflare.com/waf/custom-rules/create-dashboard/#rule-action
- **Security Value**: **HIGH** - Rules in "Log" action provide visibility but NO protection. Attacks are recorded but reach the origin.
- **Customer Impact**: False sense of security. Security teams see attacks in logs but attacks succeed. Useful for tuning but dangerous in production.
- **Real-World Risk**: Organizations running "log mode" for extended periods accumulate successful attack evidence in logs without blocking them.

#### CF-RULE-006: Rules Skipping WAF Phases
- **Official Docs**: https://developers.cloudflare.com/ruleset-engine/reference/phases-list/
- **Security Value**: **CRITICAL** - Skipping entire WAF phases (like `http_request_firewall_managed`) disables all managed rules for matching traffic.
- **Customer Impact**: Complete managed ruleset bypass. All OWASP protections, Cloudflare's threat intel rules, and emerging threat rules are disabled.
- **Real-World Risk**: Phase skips are sometimes added for "performance" or "compatibility" but create critical security holes. One phase skip can disable 1000+ security rules.

#### CF-RULE-007: Rules Skipping Multiple Products
- **Official Docs**: https://developers.cloudflare.com/waf/custom-rules/skip/options/
- **Security Value**: **HIGH** - Rules that skip multiple security products (WAF, Rate Limiting, Bot Management) create compound vulnerabilities.
- **Customer Impact**: Traffic matching these rules bypasses multiple layers of defense simultaneously. Attackers get a "golden path" through security.
- **Real-World Risk**: Combined product skips often exist from troubleshooting sessions that were never removed. They're forgotten backdoors.

### CF-RATE Checks (Rate Limiting)

#### CF-RATE-001: No Rate Limiting on APIs
- **Official Docs**: https://developers.cloudflare.com/waf/rate-limiting-rules/
- **Security Value**: **HIGH** - API endpoints without rate limiting are vulnerable to brute force, credential stuffing, enumeration, and resource exhaustion.
- **Customer Impact**: Attackers can make unlimited requests to authentication endpoints, exhaust backend resources, or enumerate valid usernames/IDs.
- **Real-World Risk**: Credential stuffing attacks average 1M+ attempts per incident. Without rate limiting, attackers can try entire breached credential databases.

#### CF-RATE-002: High Rate Limit Thresholds
- **Official Docs**: https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/
- **Security Value**: **MEDIUM** - Rate limits above 5000-10000 requests per period may not effectively prevent abuse while still impacting legitimate traffic.
- **Customer Impact**: Ineffective rate limits provide false security. Attackers stay under threshold while still conducting meaningful attacks.
- **Real-World Risk**: A 10,000 req/min limit still allows 600,000 attempts per hour - enough for significant enumeration or brute force.

#### CF-RATE-003: Rate Limit with Log-Only Action
- **Official Docs**: https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/#action
- **Security Value**: **HIGH** - Rate limits that only log don't actually limit rates. Abuse is recorded but not prevented.
- **Customer Impact**: Backend systems still receive abusive traffic volumes. Rate limit logs show violations but origin suffers impact.
- **Real-World Risk**: Log-only rate limits are often set during rollout and forgotten. They provide zero protection.

### CF-BOT Checks (Bot Management)

#### CF-BOT-001: No Bot Management Config
- **Official Docs**: https://developers.cloudflare.com/bots/
- **Security Value**: **CRITICAL** - Without bot management, automated traffic (scrapers, credential stuffers, inventory hoarders) is indistinguishable from humans.
- **Customer Impact**: Bots consume 40-50% of internet traffic. Without management, you're exposed to scraping, price manipulation, account takeover, and fraud.
- **Real-World Risk**: E-commerce sites without bot management report 10-30% of traffic being malicious bots affecting inventory, pricing, and customer experience.

#### CF-BOT-002: Bot Fight Mode Disabled
- **Official Docs**: https://developers.cloudflare.com/bots/get-started/free/
- **Security Value**: **HIGH** - Bot Fight Mode is Cloudflare's basic bot mitigation. Disabled means no automated bot challenges.
- **Customer Impact**: Definite bots (score 1-10) reach your origin unchallenged. Scraping and automation attacks proceed unimpeded.
- **Real-World Risk**: Simple bots flood sites daily. Bot Fight Mode stops the majority with zero configuration.

#### CF-BOT-003: Automated Traffic Allowed
- **Official Docs**: https://developers.cloudflare.com/bots/get-started/pro/#super-bot-fight-mode-features
- **Security Value**: **HIGH** - When `sbfm_definitely_automated` is set to "allow", confirmed bot traffic reaches origin.
- **Customer Impact**: Traffic Cloudflare has high confidence is automated (score 1-10) passes through. This includes known bad bots, scrapers, and attack tools.
- **Real-World Risk**: Definite bots include vulnerability scanners, credential stuffers, and content scrapers that should always be blocked.

---

## 🔷 AKAMAI - PostgreSQL Check Security Value

### AK-POLICY Checks (Security Policy)

#### AK-POLICY-002: Attack Groups Not in Deny Mode
- **Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/attack-groups
- **Security Value**: **CRITICAL** - Attack groups in "alert" or "none" mode detect attacks but don't block them. SQL injection, XSS, RCE attacks succeed.
- **Customer Impact**: Your WAF sees attacks and records them, but every attack reaches your application. Zero protection despite WAF deployment.
- **Real-World Risk**: Alert-only mode is meant for tuning (days/weeks), not production. Organizations forget to switch to deny, leaving permanent gaps.

#### AK-POLICY-003: Slow POST Disabled
- **Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/slow-post
- **Security Value**: **HIGH** - Slowloris/Slow POST attacks exhaust server connections by sending data extremely slowly, causing denial of service.
- **Customer Impact**: Without slow POST protection, attackers can exhaust your origin's connection pool with minimal bandwidth, causing outages.
- **Real-World Risk**: Slow POST attacks require minimal attacker resources but can take down servers. A single attacker with slow connections can cause significant impact.

#### AK-POLICY-004: API Request Constraints Off
- **Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/api-request-constraints
- **Security Value**: **HIGH** - API constraints protect against malformed requests, oversized payloads, and protocol abuse targeting APIs.
- **Customer Impact**: APIs are primary attack targets. Without constraints, attackers can send malformed JSON, oversized requests, or exploit parser vulnerabilities.
- **Real-World Risk**: API-specific attacks increased 300%+ in recent years. Unconstrained APIs are low-hanging fruit for attackers.

### AK-RATE Checks (Rate Controls)

#### AK-RATE-001: Rate Policies in Alert Mode
- **Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/rate-controls
- **Security Value**: **HIGH** - Alert-only rate policies log violations but don't enforce limits. Abuse continues unmitigated.
- **Customer Impact**: High-volume attacks, credential stuffing, and scraping proceed at full speed while you watch in logs.
- **Real-World Risk**: Rate controls in alert mode during "tuning" often stay that way for months or years.

#### AK-RATE-003: No Rate Policies Defined
- **Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/rate-controls
- **Security Value**: **HIGH** - Security configurations without rate policies have no abuse prevention for volumetric attacks.
- **Customer Impact**: No protection against brute force, credential stuffing, enumeration, or resource exhaustion attacks.
- **Real-World Risk**: Every production application needs rate limiting. None is a significant gap.

### AK-BOT Checks (Bot Manager)

#### AK-BOT-001: Bot Categories Without Protection
- **Official Docs**: https://techdocs.akamai.com/bot-manager/docs/bot-categories
- **Security Value**: **CRITICAL** - Unprotected bot categories allow known malicious bot types to access your application freely.
- **Customer Impact**: Web scrapers, credential stuffers, and automated attack tools operate unrestricted. Content theft, account takeover, and fraud increase.
- **Real-World Risk**: Bot categories like "Credential Stuffers" and "Web Scrapers" should always be blocked. Monitor-only is insufficient.

#### AK-BOT-002: Bot Detections Not Enforced
- **Official Docs**: https://techdocs.akamai.com/bot-manager/docs/detection-methods
- **Security Value**: **HIGH** - Bot detections (headless browsers, automation frameworks) in monitor mode see bots but don't stop them.
- **Customer Impact**: Advanced bots using Selenium, Puppeteer, or headless Chrome are detected but allowed through.
- **Real-World Risk**: Sophisticated bot operators specifically target sites with detection-but-no-action. They know they're seen but not stopped.

---

## 🔸 AWS WAF - PostgreSQL Check Security Value

### AWS-ACL Checks (Web ACL)

#### AWS-ACL-001: ACLs Without Resources
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html
- **Security Value**: **CRITICAL** - Web ACLs not associated with any resources (ALB, CloudFront, API Gateway) provide zero protection.
- **Customer Impact**: You're paying for WAF rules that protect nothing. Resources you think are protected are exposed.
- **Real-World Risk**: ACLs get disassociated during migrations, testing, or mistakes. Regular audits are essential.

#### AWS-ACL-002: ACLs Without Logging
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/logging.html
- **Security Value**: **CRITICAL** - Without logging, you have no visibility into attacks, rule effectiveness, or security events.
- **Customer Impact**: Can't tune rules (no data), can't investigate incidents (no evidence), can't prove compliance (no audit trail).
- **Real-World Risk**: Many compliance frameworks (PCI-DSS, SOC2) require WAF logging. No logs = compliance failure.

#### AWS-ACL-003: High WCU Usage
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/limits.html
- **Security Value**: **HIGH** - Web Capacity Units (WCU) near limits (5000 for CloudFront, 1500 for regional) prevent adding new rules.
- **Customer Impact**: Can't respond to new threats by adding rules. Forced to remove existing protection to add new.
- **Real-World Risk**: During zero-day events, you may need to quickly add rules. High WCU prevents this.

#### AWS-ACL-004: Default Action ALLOW
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html#web-acl-default-action
- **Security Value**: **HIGH** - Default ALLOW means any request not explicitly blocked passes through. Implicit allow is permissive.
- **Customer Impact**: New attack patterns not covered by rules succeed. You must anticipate all attacks in advance.
- **Real-World Risk**: Defense-in-depth recommends default-deny where feasible. Default-allow requires perfect rules.

### AWS-RULE Checks (Rules)

#### AWS-RULE-001: Rules in Count Mode
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-action.html
- **Security Value**: **HIGH** - Count mode logs matches but doesn't block. Attacks detected but not prevented.
- **Customer Impact**: Rules show activity in metrics but provide no protection. False sense of security.
- **Real-World Risk**: Count mode is for testing (1-2 weeks). Production rules in count mode for months are forgotten misconfigurations.

### AWS-MRG Checks (Managed Rules)

#### AWS-MRG-001: No AWS Managed Rules
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html
- **Security Value**: **CRITICAL** - AWS Managed Rules provide baseline protection against common attacks updated by AWS security teams.
- **Customer Impact**: No protection against OWASP Top 10, known bad inputs, or emerging threats. Must build all rules from scratch.
- **Real-World Risk**: AWS Managed Rules are updated for new CVEs within hours/days. Without them, you're always behind attackers.

#### AWS-MRG-002: Core Rule Set (CRS) Missing
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
- **Security Value**: **HIGH** - The Common Rule Set provides baseline protection against OWASP Top 10 including SQLi, XSS, and path traversal.
- **Customer Impact**: Missing fundamental protections that should be standard on all web applications.
- **Real-World Risk**: CRS catches the most common attacks. Without it, your first layer of defense is missing.

#### AWS-MRG-003: Known Bad Inputs Missing
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html#aws-managed-rule-groups-baseline-kbi
- **Security Value**: **HIGH** - Known Bad Inputs rules detect request patterns associated with exploitation of vulnerabilities.
- **Customer Impact**: Missing detection of Log4j/Log4Shell patterns, Java deserialization attacks, and other known exploit signatures.
- **Real-World Risk**: Log4Shell rules in Known Bad Inputs blocked millions of attacks. Missing this rule group = exposed.

#### AWS-MRG-006: Rules Override to Count
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-group-override.html
- **Security Value**: **HIGH** - Overriding managed rules to Count instead of Block defeats their purpose.
- **Customer Impact**: Managed rules detect attacks but don't block due to overrides. Protection is undermined.
- **Real-World Risk**: Overrides added during false positive investigation often remain permanently, creating gaps.

### AWS-CF Checks (CloudFront)

#### AWS-CF-001: CloudFront Without WAF
- **Official Docs**: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html
- **Security Value**: **CRITICAL** - CloudFront distributions without WAF association are unprotected entry points.
- **Customer Impact**: All traffic to this distribution bypasses WAF. Attacks reach origin unchallenged.
- **Real-World Risk**: Each unprotected distribution is a separate attack surface. Attackers look for these gaps.

#### AWS-CF-002: Origin HTTP Protocol
- **Official Docs**: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesOriginProtocolPolicy
- **Security Value**: **HIGH** - HTTP-only origin protocol allows man-in-the-middle attacks between CloudFront and origin.
- **Customer Impact**: Even with HTTPS to CloudFront, the CloudFront-to-origin leg is unencrypted. Attackers can intercept/modify.
- **Real-World Risk**: Cloud provider internal networks aren't necessarily secure. HTTPS to origin should be standard.

---

## 🔶 CLOUDFLARE - Trino Log Check Security Value

### CF-LOG-ATK Checks (Attack Detection)

#### CF-LOG-ATK-001: High Attack Score Not Blocked
- **Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/
- **Security Value**: **CRITICAL** - Cloudflare's ML model assigns attack scores (0-100). Scores 60+ indicate high-confidence attacks. Unblocked high scores = active compromise.
- **Customer Impact**: Cloudflare's AI identified attacks with high confidence, but they reached your origin. Active exploitation may be occurring.
- **Real-World Risk**: Attack scores are generated by ML models trained on billions of requests. High scores that aren't blocked represent significant gaps.

#### CF-LOG-ATK-002: SQLi Score Not Blocked
- **Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/#attack-score-fields
- **Security Value**: **CRITICAL** - SQL injection attacks with high scores reaching origin can lead to database compromise, data exfiltration.
- **Customer Impact**: SQLi is consistently #1-3 in OWASP Top 10. Unblocked SQLi can dump entire databases.
- **Real-World Risk**: SQLi remains the most common attack vector. A single successful injection can compromise everything.

#### CF-LOG-ATK-003: XSS Score Not Blocked
- **Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/#attack-score-fields
- **Security Value**: **CRITICAL** - XSS attacks with high scores reaching origin can steal sessions, credentials, and enable further attacks.
- **Customer Impact**: XSS enables account takeover, credential theft, malware distribution, and reputation damage.
- **Real-World Risk**: XSS affects users directly. Customer accounts get compromised, leading to fraud and trust issues.

#### CF-LOG-ATK-004: RCE Score Not Blocked
- **Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/#attack-score-fields
- **Security Value**: **CRITICAL** - Remote Code Execution is the most severe attack type. Successful RCE = full server compromise.
- **Customer Impact**: Attackers gain shell access, can install backdoors, pivot to internal networks, and exfiltrate data.
- **Real-World Risk**: RCE is the goal of most sophisticated attacks. A single successful RCE can compromise your entire infrastructure.

### CF-LOG-BOT Checks (Bot Traffic)

#### CF-LOG-BOT-001: Low Bot Score Allowed
- **Official Docs**: https://developers.cloudflare.com/bots/concepts/bot-score/
- **Security Value**: **HIGH** - Bot scores 1-30 indicate high confidence of automation. Allowing this traffic enables scraping, credential stuffing, fraud.
- **Customer Impact**: Confirmed automated traffic accessing your application. May be scraping content, testing credentials, or probing for vulnerabilities.
- **Real-World Risk**: Low bot scores correlate strongly with malicious intent. Scores 1-10 are "definite bots" that should rarely be allowed.

#### CF-LOG-BOT-002: Verified Bot Spoofing
- **Official Docs**: https://developers.cloudflare.com/bots/concepts/cloudflare-bot-management/#verified-bots
- **Security Value**: **HIGH** - Traffic claiming to be Googlebot/Bingbot but not verified is likely malicious hiding behind trusted names.
- **Customer Impact**: Attackers impersonate search engine bots to bypass allow-lists. Their traffic may be scraping or attacking.
- **Real-World Risk**: Bot spoofing is a common technique. Cloudflare's verified bot detection catches fakes that would otherwise bypass rules.

### CF-LOG-ABU Checks (Abuse Patterns)

#### CF-LOG-ABU-001: Credential Stuffing
- **Official Docs**: https://developers.cloudflare.com/waf/managed-rules/reference/exposed-credentials-check/
- **Security Value**: **HIGH** - High-volume POST requests to login endpoints indicate credential stuffing attacks using breached databases.
- **Customer Impact**: Account takeover at scale. Customers with reused passwords get compromised. Fraud, data theft, reputation damage.
- **Real-World Risk**: Credential stuffing is automated and relentless. Billions of breached credentials are tested against your login.

#### CF-LOG-ABU-004: Command Injection
- **Official Docs**: https://developers.cloudflare.com/waf/managed-rules/#owasp-core-ruleset
- **Security Value**: **CRITICAL** - Command injection patterns (|, ;, $()) in URIs attempt to execute system commands on your server.
- **Customer Impact**: Successful command injection = server compromise. Attackers can run any command as your application user.
- **Real-World Risk**: Command injection leads directly to RCE. A single vulnerable parameter can compromise your entire system.

#### CF-LOG-ABU-008: Admin Path Probing
- **Official Docs**: https://developers.cloudflare.com/waf/custom-rules/
- **Security Value**: **HIGH** - Requests to /admin, /wp-admin, /phpmyadmin indicate reconnaissance for administrative interfaces.
- **Customer Impact**: Attackers mapping your attack surface, looking for unprotected admin panels or default credentials.
- **Real-World Risk**: Admin panel discovery leads to brute force, default credential testing, or exploitation of admin-only vulnerabilities.

---

## 🔸 AWS WAF - Trino Log Check Security Value

### AWS-LOG-ATK Checks (Attack Detection)

#### AWS-LOG-ATK-001: Block Analysis
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
- **Security Value**: **HIGH** - Understanding what's being blocked helps tune rules and identify attack campaigns.
- **Customer Impact**: Visibility into active threats targeting your application. Essential for threat intelligence.
- **Real-World Risk**: Blocked request analysis reveals attacker TTPs, targeted endpoints, and potential gaps.

#### AWS-LOG-ATK-003: Managed Rule Triggers
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html
- **Security Value**: **CRITICAL** - When AWS managed rules fire, they've detected known attack patterns. High volumes indicate active campaigns.
- **Customer Impact**: Managed rules catching attacks proves their value and shows what threats target you.
- **Real-World Risk**: Managed rule triggers are validated attack detections. Analyze them to understand your threat landscape.

#### AWS-LOG-ATK-004: Count-Only Triggers
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-action.html
- **Security Value**: **HIGH** - Rules in COUNT mode that trigger frequently are detecting attacks but not blocking them.
- **Customer Impact**: Known attacks are reaching your application. COUNT mode provides visibility but no protection.
- **Real-World Risk**: High COUNT volumes mean you should probably switch to BLOCK. Long-term COUNT = long-term exposure.

### AWS-LOG-ABU Checks (Abuse Patterns)

#### AWS-LOG-ABU-003: SQLi Patterns
- **Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html#aws-managed-rule-groups-use-case-sql-db
- **Security Value**: **CRITICAL** - SQL injection patterns in requests (UNION SELECT, 1=1, etc.) indicate database attack attempts.
- **Customer Impact**: Active attempts to extract, modify, or delete database contents. Potential data breach.
- **Real-World Risk**: SQLi remains the most damaging web attack. Successful injection = database compromise.

---

# SCHEMA REFERENCE

## PostgreSQL Tables - CLOUDFLARE

### Core Tables
```
cloudflare_raw_zones_history
├── id (uuid)
├── organization_id (uuid)
├── name (varchar) - zone domain name
├── status (varchar) - active, pending, etc.
├── plan_name (varchar) - Free, Pro, Business, Enterprise
├── meta (json) - zone metadata
├── is_deleted (boolean)
└── modification_date (timestamp)

cloudflare_raw_rulesets_history
├── id (uuid)
├── name (varchar)
├── phase (varchar) - http_request_firewall_managed, etc.
├── kind (varchar) - managed, zone, etc.
└── is_deleted (boolean)

cloudflare_raw_rulesets_instance_history
├── id (uuid)
├── zone_id (uuid)
├── ruleset_id (uuid)
└── is_deleted (boolean)

cloudflare_raw_rulesets_rules_history
├── id (uuid)
├── ruleset_id (uuid)
├── cf_id (varchar)
├── description (text)
├── expression (text) - rule expression
├── enabled (boolean)
├── action (enum) - block, challenge, skip, etc.
├── action_parameters (json)
├── ratelimit_parameters (json)
├── logging_enabled (boolean)
└── is_deleted (boolean)

cloudflare_raw_bot_management_history
├── id (uuid)
├── zone_id (uuid)
├── fight_mode (boolean)
├── sbfm_definitely_automated (enum)
├── sbfm_likely_automated (enum)
├── sbfm_verified_bots (enum)
├── sbfm_static_resource_protection (boolean)
├── ai_bots_protection (enum)
├── enable_js (boolean)
└── is_deleted (boolean)

cloudflare_raw_dns_records_history
├── id (uuid)
├── zone_id (uuid)
├── name (varchar)
├── type (varchar) - A, AAAA, CNAME, etc.
├── content (varchar)
├── proxied (boolean)
└── is_deleted (boolean)

cloudflare_raw_lists_history
├── id (uuid)
├── organization_id (uuid)
├── name (varchar)
├── kind (varchar) - ip, redirect, etc.
└── is_deleted (boolean)

cloudflare_raw_list_items_history
├── id (uuid)
├── list_id (uuid)
├── ip (varchar)
├── modification_date (timestamp)
└── is_deleted (boolean)
```

## PostgreSQL Tables - AKAMAI

### Core Tables
```
akamai_raw_security_configurations_history
├── id (uuid)
├── organization_id (uuid)
├── name (varchar)
└── is_deleted (boolean)

akamai_raw_security_configuration_versions_history
├── id (uuid)
├── config_id (uuid)
└── is_deleted (boolean)

akamai_raw_security_policies_history
├── id (uuid)
├── config_version_id (uuid)
├── name (varchar)
├── apply_slow_post_controls (boolean)
├── apply_api_constraints (boolean)
└── is_deleted (boolean)

akamai_raw_security_policy_attack_groups_history
├── id (uuid)
├── security_policy_id (uuid)
├── name (varchar) - SQL, XSS, CMD, etc.
├── action (enum) - deny, alert, none
└── is_deleted (boolean)

akamai_raw_sec_config_rate_policies_history
├── id (uuid)
├── config_id (uuid)
├── name (varchar)
├── average_threshold (integer)
├── burst_threshold (integer)
└── is_deleted (boolean)

akamai_raw_security_policy_rate_policy_actions_history
├── id (uuid)
├── rate_policy_id (uuid)
├── ipv4_action (enum)
├── ipv6_action (enum)
└── is_deleted (boolean)

akamai_raw_bot_categories_history
├── id (uuid)
├── organization_id (uuid)
├── category_name (varchar)
└── is_deleted (boolean)

akamai_raw_bot_category_actions_history
├── id (uuid)
├── category_id (uuid)
├── action (enum)
└── is_deleted (boolean)

akamai_raw_bot_detections_history
├── id (uuid)
├── organization_id (uuid)
├── detection_name (varchar)
└── is_deleted (boolean)

akamai_raw_bot_detection_actions_history
├── id (uuid)
├── detection_id (uuid)
├── action (enum)
└── is_deleted (boolean)

akamai_raw_properties_history
├── id (uuid)
├── organization_id (uuid)
├── name (varchar)
└── is_deleted (boolean)

akamai_raw_property_hostnames_history
├── id (uuid)
├── property_id (uuid)
├── cert_provisioning_type (varchar)
└── is_deleted (boolean)
```

## PostgreSQL Tables - AWS WAF

### Core Tables
```
aws_raw_waf_acl_history
├── id (uuid)
├── organization_id (uuid)
├── name (varchar)
├── arn (varchar)
├── capacity (integer) - WCU used
├── region (enum)
├── default_action (enum)
├── cloudwatch_metrics_enabled (boolean)
├── sample_request_enabled (boolean)
├── description (varchar)
└── is_deleted (boolean)

aws_raw_waf_acl_rules_history
├── id (uuid)
├── acl_id (uuid)
├── name (varchar)
├── priority (integer)
├── action (varchar)
└── is_deleted (boolean)

aws_raw_waf_acl_rule_group_statements_history
├── id (uuid)
├── acl_id (uuid)
├── name (varchar)
├── vendor_name (varchar)
└── is_deleted (boolean)

aws_raw_waf_acl_associated_resources_history
├── id (uuid)
├── waf_acl_id (uuid)
├── arn (varchar)
├── resource_type (varchar)
└── is_deleted (boolean)

aws_raw_waf_acl_logging_configurations_history
├── id (uuid)
├── waf_acl_id (uuid)
├── log_destination_config (varchar)
└── is_deleted (boolean)

aws_raw_cloudfront_distribution_history
├── id (uuid)
├── organization_id (uuid)
├── domain_name (varchar)
├── arn (varchar)
├── enabled (boolean)
├── status (varchar)
└── is_deleted (boolean)

aws_raw_cloudfront_distribution_origin_history
├── id (uuid)
├── distribution_id (uuid)
├── domain_name (varchar)
├── origin_protocol_policy (varchar)
└── is_deleted (boolean)
```

## Trino Tables - CLOUDFLARE LOGS

### Table: aws_waf_logs.waf_logs_db.{customer}_waf_logs

```
Partition Columns:
├── year (integer)
├── month (integer)
├── day (integer)
└── hour (integer)

Security Fields:
├── securityaction (varchar) - block, challenge, allow, etc.
├── securityactions (array<varchar>)
├── securityruleid (varchar)
├── securityruledescription (varchar)
├── securityruleids (array<varchar>)
├── securitysources (array<varchar>)
├── wafattackscore (integer) - 0-100, higher = more likely attack
├── wafsqliattackscore (integer)
├── wafxssattackscore (integer)
├── wafrceattackscore (integer)
├── leakedcredentialcheckresult (varchar)
├── fraudattack (varchar)
├── frauddetectionids (array<integer>)
├── frauddetectiontags (array<varchar>)

Bot Fields:
├── botscore (integer) - 0-100, lower = more likely bot
├── botscoresrc (varchar)
├── bottags (array<varchar>)
├── botdetectionids (array<integer>)
├── botdetectiontags (array<varchar>)
├── verifiedbotcategory (varchar)
├── jsdetectionpassed (varchar)

Request Fields:
├── clientip (varchar)
├── clientcountry (varchar)
├── clientcity (varchar)
├── clientasn (integer)
├── clientrequesthost (varchar)
├── clientrequesturi (varchar)
├── clientrequestpath (varchar)
├── clientrequestmethod (varchar)
├── clientrequestuseragent (varchar)
├── clientrequestprotocol (varchar)
├── clientrequestscheme (varchar)
├── clientrequestreferer (varchar)
├── clientrequestbytes (bigint)

Response Fields:
├── edgeresponsestatus (integer)
├── edgeresponsebytes (bigint)
├── edgeresponsecontenttype (varchar)
├── originresponsestatus (integer)
├── originresponsedurationms (integer)

TLS/SSL Fields:
├── clientsslprotocol (varchar)
├── clientsslcipher (varchar)
├── clientmtlsauthstatus (varchar)
├── clientmtlsauthcertfingerprint (varchar)

Fingerprinting:
├── ja3hash (varchar)
├── ja4 (varchar)
├── ja4signals (struct)

Cache Fields:
├── cachecachestatus (varchar)
├── cacheresponsebytes (bigint)

Worker Fields:
├── workerscriptname (varchar)
├── workerstatus (varchar)
├── workercputime (bigint)

Other:
├── rayid (varchar)
├── zonename (varchar)
├── edgestarttimestamp (varchar)
├── requestheaders (map<varchar,varchar>)
├── responseheaders (map<varchar,varchar>)
├── cookies (map<varchar,varchar>)
```

## Trino Tables - AWS WAF LOGS

### Table: aws_waf_logs.waf_logs_db.{customer}_waf_logs

```
Partition Columns:
├── accountid (varchar)
├── region (varchar)
├── acl (varchar)
├── year (integer)
├── month (integer)
├── day (integer)
├── hour (integer)
└── minute (integer)

Core Fields:
├── timestamp (bigint) - Unix timestamp in milliseconds
├── action (varchar) - ALLOW, BLOCK, COUNT
├── terminatingruleid (varchar)
├── terminatingruletype (varchar)
├── terminatingrulematchdetails (array<struct>)
├── webaclid (varchar)

Request (nested struct):
├── httprequest.host (varchar)
├── httprequest.clientip (varchar)
├── httprequest.country (varchar)
├── httprequest.uri (varchar)
├── httprequest.args (varchar)
├── httprequest.httpmethod (varchar)
├── httprequest.httpversion (varchar)
├── httprequest.headers (array<struct<name,value>>)
├── httprequest.requestid (varchar)

Rule Groups:
├── rulegrouplist (array<struct>) - Complex nested structure
│   ├── rulegroupid
│   ├── terminatingrule
│   ├── nonterminatingmatchingrules
│   └── excludedrules

Labels:
├── labels (array<struct<name>>)

CAPTCHA/Challenge:
├── captcharesponse (struct)
│   ├── responsecode
│   ├── solvetimestamp
│   └── failurereason
├── challengeresponse (struct)
│   ├── responsecode
│   ├── solvetimestamp
│   └── failurereason

Fingerprinting:
├── ja3fingerprint (varchar)
├── ja4fingerprint (varchar)

Size/Oversize:
├── requestbodysize (integer)
├── requestbodysizeinspectedbywaf (integer)
├── oversizefields (varchar)
```

---

# PART 1: POSTGRESQL CONFIGURATION ANALYSIS

---

# 🔶 CLOUDFLARE - PostgreSQL Configuration Analysis

## CF-ZONE: Zone Security Checks

### CF-ZONE-001 [CRITICAL] Zones Without ANY WAF Protection

> **📚 Official Docs**: https://developers.cloudflare.com/waf/managed-rules/
> 
> **🛡️ Security Value**: Production zones without WAF rulesets are completely exposed to OWASP Top 10 attacks (SQLi, XSS, RCE). Every HTTP request reaches the origin unfiltered. Cloudflare blocks 158+ billion threats daily - zones without WAF receive them all.
> 
> **💼 Customer Impact**: Direct exposure to automated attacks, credential stuffing, vulnerability exploitation. Compliance failures (PCI-DSS, SOC2 require WAF).

```sql
SELECT o.org_display_name, z.name as zone_name, z.status, z.plan_name,
    'CRITICAL: Zone has no WAF rulesets deployed' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
WHERE z.is_deleted = false AND z.status = 'active'
AND NOT EXISTS (SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri WHERE ri.zone_id = z.id AND ri.is_deleted = false)
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%', '%stg%', '%uat%', '%sandbox%', '%demo%', '%poc%', '%local%'])
ORDER BY o.org_display_name, z.name;
```

### CF-ZONE-002 [HIGH] Zones on Free/Pro Plans

> **📚 Official Docs**: https://developers.cloudflare.com/waf/reference/plan-limits/
> 
> **🛡️ Security Value**: Free/Pro plans have significantly limited WAF capabilities. Free = 5 custom rules only, no Bot Management. Pro = limited managed rulesets, no exposed credentials detection.
> 
> **💼 Customer Impact**: Reduced protection against sophisticated attacks. Cannot implement defense-in-depth required by compliance frameworks.

```sql
SELECT o.org_display_name, z.name as zone_name, z.plan_name,
    CASE WHEN z.plan_name ILIKE '%free%' THEN 'CRITICAL: Free plan'
         WHEN z.plan_name ILIKE '%pro%' THEN 'HIGH: Pro plan - limited managed rules'
         ELSE 'Review' END as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
WHERE z.is_deleted = false AND z.status = 'active'
AND z.plan_name ILIKE ANY(ARRAY['%free%', '%pro%'])
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

### CF-ZONE-003 [HIGH] Unproxied DNS Records (Bypasses Security)

> **📚 Official Docs**: https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/
> 
> **🛡️ Security Value**: Unproxied (grey-cloud) DNS records bypass ALL Cloudflare security: WAF, DDoS protection, Bot Management, Rate Limiting. Traffic goes directly to origin IP.
> 
> **💼 Customer Impact**: Complete security bypass. Attackers discovering these records can attack origin directly, bypassing your entire security investment.

```sql
SELECT o.org_display_name, z.name as zone_name, d.name as dns_record, d.type, d.content,
    'HIGH: DNS record not proxied - bypasses all CF security' as finding
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
JOIN organization o ON z.organization_id = o.id
WHERE d.is_deleted = false AND z.is_deleted = false
AND d.proxied = false AND d.type IN ('A', 'AAAA', 'CNAME')
AND d.name NOT LIKE ANY(ARRAY['mail%', 'smtp%', 'mx%', '_dmarc%', '_domainkey%', 'autodiscover%'])
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

### CF-ZONE-004 [CRITICAL] Origin IP Exposure (Public IPs in DNS)

> **📚 Official Docs**: https://developers.cloudflare.com/fundamentals/basic-tasks/protect-your-origin-server/
> 
> **🛡️ Security Value**: Exposed origin IPs allow direct attacks bypassing CDN. Services like SecurityTrails expose historical DNS. Once an origin IP leaks, it's compromised forever unless changed.
> 
> **💼 Customer Impact**: Attackers can DDoS origin directly, exploit vulnerabilities without WAF interference, or establish persistent backdoors.

```sql
SELECT o.org_display_name, z.name as zone_name, d.name as dns_record, d.content as origin_ip,
    'CRITICAL: Public origin IP exposed - direct access bypasses WAF' as finding
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
JOIN organization o ON z.organization_id = o.id
WHERE d.is_deleted = false AND z.is_deleted = false
AND d.proxied = true AND d.type IN ('A', 'AAAA')
AND d.content ~ '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
AND d.content NOT LIKE '10.%' AND d.content NOT LIKE '172.16.%' AND d.content NOT LIKE '172.17.%'
AND d.content NOT LIKE '172.18.%' AND d.content NOT LIKE '172.19.%' AND d.content NOT LIKE '172.2%'
AND d.content NOT LIKE '172.30.%' AND d.content NOT LIKE '172.31.%' AND d.content NOT LIKE '192.168.%'
AND d.content NOT LIKE '100.64.%';
```

### CF-ZONE-005 [HIGH] Inactive Zones with Active DNS Records

> **📚 Official Docs**: https://developers.cloudflare.com/fundamentals/get-started/concepts/how-cloudflare-works/
> 
> **🛡️ Security Value**: Inactive zones with DNS records may serve traffic without security, represent abandoned infrastructure, or be vulnerable to subdomain takeover.
> 
> **💼 Customer Impact**: Shadow IT, abandoned apps with unpatched vulnerabilities, or potential subdomain takeover attacks affecting brand reputation.

```sql
SELECT o.org_display_name, z.name as zone_name, z.status, COUNT(d.id) as dns_record_count,
    'HIGH: Inactive zone still has DNS records' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
LEFT JOIN cloudflare_raw_dns_records_history d ON z.id = d.zone_id AND d.is_deleted = false
WHERE z.is_deleted = false AND z.status != 'active'
GROUP BY o.org_display_name, z.name, z.status
HAVING COUNT(d.id) > 0;
```

### CF-ZONE-006 [MEDIUM] Zone Count per Organization (Sprawl Detection)

> **📚 Official Docs**: https://developers.cloudflare.com/fundamentals/account-and-billing/account-setup/
> 
> **🛡️ Security Value**: Large zone counts indicate potential governance issues. More zones = larger attack surface and more potential for misconfigurations.
> 
> **💼 Customer Impact**: Difficulty maintaining consistent security policies across many zones. Increased likelihood of forgotten or misconfigured zones.

```sql
SELECT o.org_display_name, COUNT(z.id) as zone_count,
    SUM(CASE WHEN z.status = 'active' THEN 1 ELSE 0 END) as active_zones,
    CASE WHEN COUNT(z.id) > 100 THEN 'HIGH: Large zone count - review governance'
         WHEN COUNT(z.id) > 50 THEN 'MEDIUM: Moderate zone count'
         ELSE 'OK' END as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
WHERE z.is_deleted = false
GROUP BY o.org_display_name
ORDER BY zone_count DESC;
```

---

## CF-RULE: Rule Configuration Checks

### CF-RULE-001 [CRITICAL] SKIP Rules Without IP/Geo Restriction

> **📚 Official Docs**: https://developers.cloudflare.com/waf/custom-rules/skip/
> 
> **🛡️ Security Value**: SKIP rules without IP restriction allow ANYONE to bypass WAF entirely. This is the #1 WAF misconfiguration. A single overly permissive SKIP rule can negate your entire WAF investment.
> 
> **💼 Customer Impact**: Attackers matching the rule expression bypass ALL security. We've seen SKIP rules matching User-Agent that attackers easily spoof, leading to full compromise within hours.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description, r.expression, r.action::text,
    'CRITICAL: SKIP rule without IP/geo restriction - potential full WAF bypass' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true AND r.action::text ILIKE '%skip%'
AND r.expression NOT ILIKE '%ip.src%' AND r.expression NOT ILIKE '%ip.geoip%' AND r.expression NOT ILIKE '%cf.threat_score%';
```

### CF-RULE-002 [HIGH] Disabled Managed Ruleset Rules

> **📚 Official Docs**: https://developers.cloudflare.com/waf/managed-rules/deploy-zone-dashboard/
> 
> **🛡️ Security Value**: Disabled managed rules create gaps against known CVEs and attack patterns. Cloudflare updates managed rules daily - disabled rules miss these threat intel updates.
> 
> **💼 Customer Impact**: Missing protection against actively exploited vulnerabilities. Log4Shell rules were pushed within hours - zones with disabled managed rules remained vulnerable.

```sql
SELECT o.org_display_name, z.name as zone_name, rs.name as ruleset_name, r.description,
    'HIGH: Managed ruleset rule is disabled' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = false
AND rs.name ILIKE ANY(ARRAY['%managed%', '%owasp%', '%cloudflare%']);
```

### CF-RULE-003 [HIGH] Log-Only Actions on WAF Rules

> **📚 Official Docs**: https://developers.cloudflare.com/waf/custom-rules/create-dashboard/#rule-action
> 
> **🛡️ Security Value**: Rules in "Log" action provide visibility but NO protection. Attacks are recorded but reach the origin. Useful for tuning (days/weeks) but dangerous long-term.
> 
> **💼 Customer Impact**: False sense of security. Security teams see attacks in logs but attacks succeed. Organizations running log mode for months accumulate successful attack evidence.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description, r.action::text,
    'HIGH: Rule in log-only mode - attacks not blocked' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true
AND r.action::text ILIKE ANY(ARRAY['%log%', '%simulate%', '%monitor%'])
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

### CF-RULE-004 [MEDIUM] Rules Without Logging Enabled

> **📚 Official Docs**: https://developers.cloudflare.com/waf/analytics/
> 
> **🛡️ Security Value**: Rules without logging provide protection but no audit trail. Can't tune rules without data, can't investigate incidents without evidence.
> 
> **💼 Customer Impact**: Compliance frameworks require security logging. No visibility into rule effectiveness or attack patterns targeting your application.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description, r.action::text,
    'MEDIUM: Rule has logging disabled - no audit trail' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true
AND (r.logging_enabled = false OR r.logging_enabled IS NULL)
AND r.action::text NOT ILIKE '%allow%';
```

### CF-RULE-005 [HIGH] Overly Broad Allow Rules

> **📚 Official Docs**: https://developers.cloudflare.com/waf/custom-rules/create-dashboard/
> 
> **🛡️ Security Value**: Allow rules with broad expressions (true, short expressions) can inadvertently bypass security for large amounts of traffic including attacks.
> 
> **💼 Customer Impact**: Attackers craft requests to match broad allow rules. A rule allowing "all /api/ traffic" lets attackers bypass WAF on your most sensitive endpoints.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description, r.expression,
    'HIGH: Allow rule with broad matching - potential bypass' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true AND r.action::text ILIKE '%allow%'
AND (r.expression = 'true' OR r.expression ILIKE '%http.request.uri.path contains%' OR LENGTH(r.expression) < 30);
```

### CF-RULE-006 [CRITICAL] Rules Skipping WAF Phases

> **📚 Official Docs**: https://developers.cloudflare.com/ruleset-engine/reference/phases-list/
> 
> **🛡️ Security Value**: Skipping entire WAF phases (like http_request_firewall_managed) disables ALL managed rules for matching traffic. One phase skip can disable 1000+ security rules.
> 
> **💼 Customer Impact**: Complete managed ruleset bypass. All OWASP protections, Cloudflare's threat intel, and emerging threat rules are disabled. Critical security hole.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description, r.expression, sap.phase as skipped_phase,
    'CRITICAL: Rule skips WAF phase - disables protection' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
JOIN cloudflare_raw_rulesets_rule_skip_ap_phases_history sap ON r.id = sap.rule_id AND sap.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true;
```

### CF-RULE-007 [HIGH] Rules Skipping Multiple Security Products

> **📚 Official Docs**: https://developers.cloudflare.com/waf/custom-rules/skip/options/
> 
> **🛡️ Security Value**: Rules skipping multiple products (WAF + Rate Limiting + Bot Management) create compound vulnerabilities. Attackers get a "golden path" through all security layers.
> 
> **💼 Customer Impact**: Traffic matching these rules bypasses multiple defense layers simultaneously. Often forgotten backdoors from troubleshooting sessions.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description, r.expression,
    COUNT(DISTINCT spr.product) as products_skipped, array_agg(DISTINCT spr.product::text) as skipped_products,
    'HIGH: Rule skips multiple security products' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
JOIN cloudflare_raw_rulesets_rule_skip_ap_products_history spr ON r.id = spr.rule_id AND spr.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true
GROUP BY o.org_display_name, z.name, r.description, r.expression
HAVING COUNT(DISTINCT spr.product) > 1;
```

### CF-RULE-008 [HIGH] Rules Skipping Specific Rulesets

> **📚 Official Docs**: https://developers.cloudflare.com/waf/custom-rules/skip/options/#skip-specific-rules
> 
> **🛡️ Security Value**: Skipping specific rulesets creates targeted protection gaps. May be intentional for false positive reduction but creates blind spots.
> 
> **💼 Customer Impact**: Certain attack types won't be detected for matching traffic. Important to document and review regularly.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description, r.expression, 
    array_agg(DISTINCT sar.ruleset_id::text) as skipped_rulesets,
    'HIGH: Rule skips specific rulesets' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
JOIN cloudflare_raw_rulesets_rule_skip_ap_rules_history sar ON r.id = sar.rule_id AND sar.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true
GROUP BY o.org_display_name, z.name, r.description, r.expression;
```

### CF-RULE-009 [MEDIUM] Duplicate Rule Expressions

> **📚 Official Docs**: https://developers.cloudflare.com/waf/custom-rules/
> 
> **🛡️ Security Value**: Duplicate expressions indicate rule sprawl or copy-paste errors. May cause unexpected behavior or performance impact.
> 
> **💼 Customer Impact**: Operational complexity, harder to maintain, potential for conflicting actions on same traffic.

```sql
SELECT o.org_display_name, z.name as zone_name, r.expression, COUNT(*) as duplicate_count,
    'MEDIUM: Duplicate rule expressions found' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true
GROUP BY o.org_display_name, z.name, r.expression
HAVING COUNT(*) > 1;
```

### CF-RULE-010 [HIGH] Execute Actions with Overrides

> **📚 Official Docs**: https://developers.cloudflare.com/waf/managed-rules/waf-exceptions/define-dashboard/
> 
> **🛡️ Security Value**: Execute actions with overrides can weaken managed rules by disabling specific rules or changing actions. Creates protection gaps.
> 
> **💼 Customer Impact**: Managed rule effectiveness reduced. Overrides added during false positive investigation often remain permanently.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description,
    eap.overrides::text as execute_overrides,
    'HIGH: Execute action with rule overrides - review for security' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
JOIN cloudflare_raw_rulesets_rule_execute_action_parameters_history eap ON r.id = eap.rule_id AND eap.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true
AND eap.overrides IS NOT NULL;
```

### CF-RULE-011 [MEDIUM] Rules with Custom Block Response

> **📚 Official Docs**: https://developers.cloudflare.com/waf/custom-rules/create-dashboard/#configure-a-custom-response-for-blocked-requests
> 
> **🛡️ Security Value**: Custom block responses may leak information about WAF configuration, internal systems, or provide attack feedback to adversaries.
> 
> **💼 Customer Impact**: Information disclosure risk. Custom responses should not reveal WAF vendor, rule IDs, or internal error details.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description, 
    bap.status_code, LEFT(bap.content::text, 100) as block_content,
    'MEDIUM: Review custom block response for information disclosure' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
JOIN cloudflare_raw_rulesets_rule_block_action_parameters_history bap ON r.id = bap.rule_id AND bap.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true;
```

---

## CF-RATE: Rate Limiting Checks

### CF-RATE-001 [HIGH] No Rate Limiting on API Endpoints

> **📚 Official Docs**: https://developers.cloudflare.com/waf/rate-limiting-rules/
> 
> **🛡️ Security Value**: API endpoints without rate limiting are vulnerable to brute force, credential stuffing, enumeration, and resource exhaustion. APIs are primary attack targets.
> 
> **💼 Customer Impact**: Attackers can make unlimited requests to auth endpoints, exhaust backend resources, or enumerate valid usernames. Credential stuffing averages 1M+ attempts per incident.

```sql
SELECT o.org_display_name, z.name as zone_name,
    'HIGH: API zone without rate limiting rules' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
WHERE z.is_deleted = false AND z.status = 'active'
AND z.name ~* '(api\.|^api-|apis\.|\.api\.)'
AND NOT EXISTS (
    SELECT 1 FROM cloudflare_raw_rulesets_instance_history ri
    JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id
    JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id
    WHERE ri.zone_id = z.id AND ri.is_deleted = false AND rs.is_deleted = false AND r.is_deleted = false
    AND r.ratelimit_parameters IS NOT NULL
);
```

### CF-RATE-002 [MEDIUM] High Rate Limit Thresholds

> **📚 Official Docs**: https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/
> 
> **🛡️ Security Value**: Rate limits above 5000-10000 requests/period may not effectively prevent abuse. A 10,000 req/min limit allows 600,000 attempts per hour - enough for significant attacks.
> 
> **💼 Customer Impact**: Ineffective rate limits provide false security. Attackers stay under threshold while still conducting meaningful credential stuffing or enumeration.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description,
    rl.requests_per_period, rl.period,
    CASE WHEN rl.requests_per_period > 10000 THEN 'HIGH: Very high rate limit'
         WHEN rl.requests_per_period > 5000 THEN 'MEDIUM: High rate limit'
         ELSE 'Review' END as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
JOIN cloudflare_raw_rulesets_rule_rate_limits_history rl ON r.id = rl.rule_id AND rl.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true
AND rl.requests_per_period > 5000;
```

### CF-RATE-003 [HIGH] Rate Limit with Log-Only Action

> **📚 Official Docs**: https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/#action
> 
> **🛡️ Security Value**: Rate limits that only log don't actually limit rates. Abuse is recorded but not prevented. Backend systems still receive full abusive traffic volumes.
> 
> **💼 Customer Impact**: Log-only rate limits are often set during rollout and forgotten. They show violations in logs but provide zero protection.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description, r.action::text,
    rl.requests_per_period, rl.period,
    'HIGH: Rate limit triggers log only - no mitigation' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
JOIN cloudflare_raw_rulesets_rule_rate_limits_history rl ON r.id = rl.rule_id AND rl.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true
AND r.action::text ILIKE '%log%';
```

### CF-RATE-004 [MEDIUM] Rate Limit with Short Period

> **📚 Official Docs**: https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/#period
> 
> **🛡️ Security Value**: Very short rate limit periods (under 10 seconds) may cause false positives for legitimate burst traffic while being ineffective against distributed attacks.
> 
> **💼 Customer Impact**: Legitimate users may be blocked during normal navigation. Attackers distribute across time to evade short windows.

```sql
SELECT o.org_display_name, z.name as zone_name, r.description,
    rl.requests_per_period, rl.period,
    'MEDIUM: Very short rate limit period - may cause false positives' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_rulesets_instance_history ri ON z.id = ri.zone_id AND ri.is_deleted = false
JOIN cloudflare_raw_rulesets_history rs ON ri.ruleset_id = rs.id AND rs.is_deleted = false
JOIN cloudflare_raw_rulesets_rules_history r ON rs.id = r.ruleset_id AND r.is_deleted = false
JOIN cloudflare_raw_rulesets_rule_rate_limits_history rl ON r.id = rl.rule_id AND rl.is_deleted = false
WHERE z.is_deleted = false AND r.enabled = true
AND rl.period < 10;
```

---

## CF-BOT: Bot Management Checks

### CF-BOT-001 [CRITICAL] No Bot Management Configuration

> **📚 Official Docs**: https://developers.cloudflare.com/bots/
> 
> **🛡️ Security Value**: Without bot management, automated traffic (40-50% of internet) is indistinguishable from humans. Scrapers, credential stuffers, inventory hoarders operate freely.
> 
> **💼 Customer Impact**: E-commerce sites without bot management report 10-30% malicious bot traffic affecting inventory, pricing, and customer experience. Account takeover at scale.

```sql
SELECT o.org_display_name, z.name as zone_name, z.plan_name,
    'CRITICAL: No bot management configured' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
LEFT JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.is_deleted = false AND z.status = 'active'
AND bm.id IS NULL
AND z.name NOT LIKE ANY(ARRAY['%dev%', '%test%', '%staging%']);
```

### CF-BOT-002 [HIGH] Bot Fight Mode Disabled

> **📚 Official Docs**: https://developers.cloudflare.com/bots/get-started/free/
> 
> **🛡️ Security Value**: Bot Fight Mode is Cloudflare's basic bot mitigation. Disabled means no automated challenges for definite bots (score 1-10). Simple bots flood sites daily.
> 
> **💼 Customer Impact**: Scrapers, simple automation, and known bad bots reach origin unchallenged. Bot Fight Mode stops the majority with zero configuration.

```sql
SELECT o.org_display_name, z.name as zone_name, bm.fight_mode,
    'HIGH: Bot Fight Mode is disabled' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.is_deleted = false AND z.status = 'active'
AND bm.fight_mode = false;
```

### CF-BOT-003 [HIGH] Automated Traffic Allowed

> **📚 Official Docs**: https://developers.cloudflare.com/bots/get-started/pro/#super-bot-fight-mode-features
> 
> **🛡️ Security Value**: When sbfm_definitely_automated is "allow", confirmed bot traffic (score 1-10) reaches origin. This includes known bad bots, scrapers, and attack tools.
> 
> **💼 Customer Impact**: Traffic Cloudflare has HIGH confidence is automated passes through. Definite bots include vulnerability scanners and credential stuffers that should always be blocked.

```sql
SELECT o.org_display_name, z.name as zone_name,
    bm.sbfm_definitely_automated::text, bm.sbfm_likely_automated::text,
    'HIGH: Automated traffic is being allowed through' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.is_deleted = false AND z.status = 'active'
AND (bm.sbfm_definitely_automated::text IN ('allow', 'none') 
     OR bm.sbfm_likely_automated::text IN ('allow', 'none'));
```

### CF-BOT-004 [MEDIUM] AI Bot Protection Disabled

> **📚 Official Docs**: https://developers.cloudflare.com/bots/reference/bot-management-variables/#ai-bots
> 
> **🛡️ Security Value**: AI bots (ChatGPT, Claude crawlers) can scrape content at scale for training data. AI protection lets you control how AI systems access your content.
> 
> **💼 Customer Impact**: Content may be used for AI training without consent. Emerging regulatory requirements (EU AI Act) may require control over AI crawlers.

```sql
SELECT o.org_display_name, z.name as zone_name, bm.ai_bots_protection::text,
    'MEDIUM: AI bot protection not enabled' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.is_deleted = false AND z.status = 'active'
AND (bm.ai_bots_protection IS NULL OR bm.ai_bots_protection::text IN ('allow', 'disabled'));
```

### CF-BOT-005 [HIGH] Static Resource Protection Disabled

> **📚 Official Docs**: https://developers.cloudflare.com/bots/get-started/pro/#static-resource-protection
> 
> **🛡️ Security Value**: Static resources (JS, CSS, images) can be scraped to clone sites for phishing. Static resource protection extends bot checks to these assets.
> 
> **💼 Customer Impact**: Phishing sites clone your branding by downloading static assets. Price scraping bots target product images and data.

```sql
SELECT o.org_display_name, z.name as zone_name, bm.sbfm_static_resource_protection,
    'HIGH: Static resource protection disabled' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.is_deleted = false AND bm.sbfm_static_resource_protection = false;
```

### CF-BOT-006 [MEDIUM] JavaScript Detection Disabled

> **📚 Official Docs**: https://developers.cloudflare.com/bots/reference/javascript-detections/
> 
> **🛡️ Security Value**: JavaScript detection validates that visitors can execute JavaScript, filtering out simple bots. Disabled reduces bot detection accuracy significantly.
> 
> **💼 Customer Impact**: Simple bots that can't execute JS still get low bot scores. JS detection is a key signal for distinguishing bots from browsers.

```sql
SELECT o.org_display_name, z.name as zone_name, bm.enable_js,
    'MEDIUM: JavaScript detection disabled - reduced bot detection' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.is_deleted = false AND bm.enable_js = false;
```

### CF-BOT-007 [MEDIUM] Session Score Suppressed

> **📚 Official Docs**: https://developers.cloudflare.com/bots/concepts/bot-score/#session-score
> 
> **🛡️ Security Value**: Session scores track behavior across requests for better bot detection. Suppression reduces detection of sophisticated bots that behave normally initially.
> 
> **💼 Customer Impact**: Bots that "warm up" with normal behavior before attacking may evade detection when session scoring is disabled.

```sql
SELECT o.org_display_name, z.name as zone_name, bm.suppress_session_score,
    'MEDIUM: Session score suppressed - reduced bot detection accuracy' as finding
FROM cloudflare_raw_zones_history z
JOIN organization o ON z.organization_id = o.id
JOIN cloudflare_raw_bot_management_history bm ON z.id = bm.zone_id AND bm.is_deleted = false
WHERE z.is_deleted = false AND bm.suppress_session_score = true;
```

---

## CF-LIST: IP List Management Checks

### CF-LIST-001 [MEDIUM] Stale IP Lists (Not Updated)

> **📚 Official Docs**: https://developers.cloudflare.com/waf/tools/lists/custom-lists/
> 
> **🛡️ Security Value**: IP lists not updated in 90+ days may contain outdated entries. Threat actor IPs change frequently; stale blocklists miss current threats.
> 
> **💼 Customer Impact**: Blocklists become less effective over time. Allowlists may include IPs that have changed ownership and are now malicious.

```sql
SELECT o.org_display_name, l.name as list_name, l.kind as list_type,
    COUNT(li.id) as item_count, MAX(li.modification_date) as last_update,
    CASE WHEN MAX(li.modification_date) < NOW() - INTERVAL '180 days' THEN 'HIGH: List not updated in 180+ days'
         WHEN MAX(li.modification_date) < NOW() - INTERVAL '90 days' THEN 'MEDIUM: List not updated in 90+ days'
         ELSE 'OK' END as finding
FROM cloudflare_raw_lists_history l
JOIN organization o ON l.organization_id = o.id
LEFT JOIN cloudflare_raw_list_items_history li ON l.id = li.list_id AND li.is_deleted = false
WHERE l.is_deleted = false
GROUP BY o.org_display_name, l.name, l.kind
HAVING MAX(li.modification_date) < NOW() - INTERVAL '90 days';
```

### CF-LIST-002 [HIGH] Empty Security Lists

> **📚 Official Docs**: https://developers.cloudflare.com/waf/tools/lists/custom-lists/
> 
> **🛡️ Security Value**: Empty lists referenced in rules provide no protection. Rules referencing empty lists appear to work but have no effect.
> 
> **💼 Customer Impact**: False sense of security. A "blocklist" rule with an empty list blocks nothing. Rules should be disabled if lists are intentionally empty.

```sql
SELECT o.org_display_name, l.name as list_name, l.kind as list_type,
    'HIGH: Security list is empty - provides no protection' as finding
FROM cloudflare_raw_lists_history l
JOIN organization o ON l.organization_id = o.id
WHERE l.is_deleted = false
AND NOT EXISTS (SELECT 1 FROM cloudflare_raw_list_items_history li WHERE li.list_id = l.id AND li.is_deleted = false);
```

### CF-LIST-003 [MEDIUM] Large IP Lists (Performance Impact)

> **📚 Official Docs**: https://developers.cloudflare.com/waf/tools/lists/custom-lists/#number-of-lists
> 
> **🛡️ Security Value**: Very large IP lists (10,000+) may impact rule evaluation performance. Lists should be optimized using CIDR aggregation where possible.
> 
> **💼 Customer Impact**: Potential latency impact from large list lookups. Consider using Cloudflare's managed IP lists for common threat intel.

```sql
SELECT o.org_display_name, l.name as list_name, l.kind as list_type, COUNT(li.id) as item_count,
    CASE WHEN COUNT(li.id) > 10000 THEN 'HIGH: Very large list - potential performance impact'
         WHEN COUNT(li.id) > 5000 THEN 'MEDIUM: Large list'
         ELSE 'OK' END as finding
FROM cloudflare_raw_lists_history l
JOIN organization o ON l.organization_id = o.id
JOIN cloudflare_raw_list_items_history li ON l.id = li.list_id AND li.is_deleted = false
WHERE l.is_deleted = false
GROUP BY o.org_display_name, l.name, l.kind
HAVING COUNT(li.id) > 5000;
```

---

## CF-DNS: DNS Security Checks

### CF-DNS-001 [HIGH] CNAME to External/Unknown Origin

> **📚 Official Docs**: https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/
> 
> **🛡️ Security Value**: CNAMEs to external origins route traffic outside your control. The external origin may have different security posture or be compromised.
> 
> **💼 Customer Impact**: Supply chain risk. External origin issues become your issues. Subdomain takeover possible if external service is deprovisioned.

```sql
SELECT o.org_display_name, z.name as zone_name, d.name as dns_record, d.type, d.content,
    'HIGH: CNAME points to external origin - verify trust' as finding
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
JOIN organization o ON z.organization_id = o.id
WHERE d.is_deleted = false AND z.is_deleted = false
AND d.type = 'CNAME'
AND d.content NOT LIKE '%cloudflare%'
AND d.content NOT LIKE '%amazonaws.com'
AND d.content NOT LIKE '%azurewebsites.net'
AND d.content NOT LIKE '%googleapis.com';
```

### CF-DNS-002 [MEDIUM] Wildcard DNS Records

> **📚 Official Docs**: https://developers.cloudflare.com/dns/manage-dns-records/reference/wildcard-dns-records/
> 
> **🛡️ Security Value**: Wildcard records route ANY subdomain to your origin. May expose unintended subdomains or internal systems.
> 
> **💼 Customer Impact**: Attackers can access arbitrary subdomains. SSL certificate validation may be bypassed. Increased attack surface.

```sql
SELECT o.org_display_name, z.name as zone_name, d.name as dns_record, d.type, d.content, d.proxied,
    'MEDIUM: Wildcard DNS record - may expose unexpected subdomains' as finding
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
JOIN organization o ON z.organization_id = o.id
WHERE d.is_deleted = false AND z.is_deleted = false
AND d.name LIKE '*%';
```

### CF-DNS-003 [HIGH] Multiple A Records (Load Balancing Review)

> **📚 Official Docs**: https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/
> 
> **🛡️ Security Value**: Multiple A records indicate DNS-based load balancing. Should verify all IPs are protected and consistently configured.
> 
> **💼 Customer Impact**: If one origin IP is compromised or misconfigured, round-robin DNS sends some traffic there. All origins must maintain equal security.

```sql
SELECT o.org_display_name, z.name as zone_name, d.name as dns_record, COUNT(*) as record_count,
    'HIGH: Multiple A records - verify load balancing is intentional' as finding
FROM cloudflare_raw_dns_records_history d
JOIN cloudflare_raw_zones_history z ON d.zone_id = z.id
JOIN organization o ON z.organization_id = o.id
WHERE d.is_deleted = false AND z.is_deleted = false AND d.type = 'A'
GROUP BY o.org_display_name, z.name, d.name
HAVING COUNT(*) > 1;
```


---

# 🔷 AKAMAI - PostgreSQL Configuration Analysis

## AK-POLICY: Security Policy Checks

### AK-POLICY-001 [CRITICAL] Security Configurations Overview

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/security-policies
> 
> **🛡️ Security Value**: Provides visibility into security configuration landscape. Essential for understanding coverage and identifying gaps.
> 
> **💼 Customer Impact**: Foundation for security posture assessment. Identifies how many policies protect your applications.

```sql
SELECT o.org_display_name, sc.name as security_config_name,
    COUNT(DISTINCT sp.id) as policy_count,
    'INFO: Security configuration summary' as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
LEFT JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
LEFT JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
WHERE sc.is_deleted = false
GROUP BY o.org_display_name, sc.name;
```

### AK-POLICY-002 [CRITICAL] Attack Groups NOT in Deny Mode

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/attack-groups
> 
> **🛡️ Security Value**: Attack groups in "alert" or "none" mode detect but DON'T block SQLi, XSS, RCE attacks. Your WAF sees attacks but they all succeed.
> 
> **💼 Customer Impact**: Zero protection despite WAF deployment. Alert mode is for tuning (days/weeks) not production. Organizations forget to switch to deny, leaving permanent gaps.

```sql
SELECT o.org_display_name, sc.name as security_config_name, sp.name as security_policy_name,
    ag.name as attack_group_name, ag.action::text as current_action,
    CASE WHEN ag.action::text = 'none' THEN 'CRITICAL: Attack group disabled'
         WHEN ag.action::text = 'alert' THEN 'HIGH: Attack group in alert-only mode'
         ELSE 'Review' END as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_policy_attack_groups_history ag ON sp.id = ag.security_policy_id AND ag.is_deleted = false
WHERE sc.is_deleted = false AND ag.action::text IN ('none', 'alert')
ORDER BY CASE WHEN ag.action::text = 'none' THEN 1 ELSE 2 END;
```

### AK-POLICY-003 [HIGH] Slow POST Protection Disabled

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/slow-post
> 
> **🛡️ Security Value**: Slowloris/Slow POST attacks exhaust server connections by sending data extremely slowly, causing denial of service with minimal bandwidth.
> 
> **💼 Customer Impact**: Attackers can exhaust your origin's connection pool with minimal resources, causing outages. A single attacker with slow connections can take down servers.

```sql
SELECT o.org_display_name, sc.name as security_config_name, sp.name as security_policy_name,
    sp.apply_slow_post_controls,
    'HIGH: Slow POST protection disabled - vulnerable to Slowloris attacks' as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
WHERE sc.is_deleted = false AND sp.apply_slow_post_controls = false;
```

### AK-POLICY-004 [HIGH] API Request Constraints Disabled

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/api-request-constraints
> 
> **🛡️ Security Value**: API constraints protect against malformed requests, oversized payloads, and protocol abuse. APIs are primary attack targets with 300%+ attack increase.
> 
> **💼 Customer Impact**: Without constraints, attackers send malformed JSON, oversized requests, or exploit parser vulnerabilities targeting your API layer.

```sql
SELECT o.org_display_name, sc.name as security_config_name, sp.name as security_policy_name,
    sp.apply_api_constraints,
    'HIGH: API request constraints disabled' as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
WHERE sc.is_deleted = false AND sp.apply_api_constraints = false;
```

### AK-POLICY-005 [HIGH] All Attack Groups Analysis

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/attack-groups
> 
> **🛡️ Security Value**: Comprehensive view of attack group configuration. Identifies which attack types (SQLi, XSS, CMD, LFI) are in deny vs alert mode.
> 
> **💼 Customer Impact**: Shows protection gaps at a glance. Any attack group not in deny mode represents a category of attacks that will succeed.

```sql
SELECT o.org_display_name, sc.name as security_config_name, sp.name as security_policy_name,
    COUNT(CASE WHEN ag.action::text = 'deny' THEN 1 END) as deny_count,
    COUNT(CASE WHEN ag.action::text = 'alert' THEN 1 END) as alert_count,
    COUNT(CASE WHEN ag.action::text = 'none' THEN 1 END) as disabled_count,
    COUNT(*) as total_groups,
    CASE WHEN COUNT(CASE WHEN ag.action::text IN ('none', 'alert') THEN 1 END) > 0 
         THEN 'HIGH: Some attack groups not blocking' ELSE 'OK' END as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_security_configuration_versions_history scv ON sc.id = scv.config_id AND scv.is_deleted = false
JOIN akamai_raw_security_policies_history sp ON scv.id = sp.config_version_id AND sp.is_deleted = false
JOIN akamai_raw_security_policy_attack_groups_history ag ON sp.id = ag.security_policy_id AND ag.is_deleted = false
WHERE sc.is_deleted = false
GROUP BY o.org_display_name, sc.name, sp.name;
```

---

## AK-RATE: Rate Control Checks

### AK-RATE-001 [HIGH] Rate Policies in Alert Mode

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/rate-controls
> 
> **🛡️ Security Value**: Alert-only rate policies log violations but don't enforce limits. High-volume attacks proceed at full speed while you watch in logs.
> 
> **💼 Customer Impact**: Rate controls in alert mode during "tuning" often stay that way for months or years. No protection against credential stuffing or abuse.

```sql
SELECT o.org_display_name, sc.name as security_config_name, rp.name as rate_policy_name,
    rpa.ipv4_action::text as action,
    'HIGH: Rate policy in alert mode only - not blocking abuse' as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_sec_config_rate_policies_history rp ON sc.id = rp.config_id AND rp.is_deleted = false
JOIN akamai_raw_security_policy_rate_policy_actions_history rpa ON rp.id = rpa.rate_policy_id AND rpa.is_deleted = false
WHERE sc.is_deleted = false AND rpa.ipv4_action::text = 'alert';
```

### AK-RATE-002 [MEDIUM] Excessively High Rate Thresholds

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/rate-controls
> 
> **🛡️ Security Value**: Rate thresholds above 5000-10000 may not effectively prevent abuse. Attackers stay under threshold while still conducting meaningful attacks.
> 
> **💼 Customer Impact**: Ineffective rate limits provide false security. Thresholds should be based on legitimate application traffic patterns.

```sql
SELECT o.org_display_name, sc.name as security_config_name, rp.name as rate_policy_name,
    rp.average_threshold, rp.burst_threshold,
    CASE WHEN rp.average_threshold > 10000 THEN 'HIGH: Extremely high rate threshold'
         WHEN rp.average_threshold > 5000 THEN 'MEDIUM: High rate threshold'
         ELSE 'Review' END as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_sec_config_rate_policies_history rp ON sc.id = rp.config_id AND rp.is_deleted = false
WHERE sc.is_deleted = false AND rp.average_threshold > 5000
ORDER BY rp.average_threshold DESC;
```

### AK-RATE-003 [HIGH] No Rate Policies Defined

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/rate-controls
> 
> **🛡️ Security Value**: Security configurations without rate policies have zero abuse prevention for volumetric attacks. Every production application needs rate limiting.
> 
> **💼 Customer Impact**: No protection against brute force, credential stuffing, enumeration, or resource exhaustion. Attackers have unlimited attempts.

```sql
SELECT o.org_display_name, sc.name as security_config_name,
    'HIGH: Security config has no rate policies defined' as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
WHERE sc.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM akamai_raw_sec_config_rate_policies_history rp
    WHERE rp.config_id = sc.id AND rp.is_deleted = false
);
```

### AK-RATE-004 [MEDIUM] Rate Policy Path Coverage

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/rate-controls
> 
> **🛡️ Security Value**: Rate policies should cover critical paths (login, API, checkout). Limited path coverage leaves sensitive endpoints unprotected.
> 
> **💼 Customer Impact**: Attackers target unprotected paths. Critical endpoints like authentication should have specific rate policies.

```sql
SELECT o.org_display_name, sc.name as security_config_name, rp.name as rate_policy_name,
    COUNT(rpp.id) as path_count,
    'INFO: Rate policy path coverage' as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_sec_config_rate_policies_history rp ON sc.id = rp.config_id AND rp.is_deleted = false
LEFT JOIN akamai_raw_sec_config_rate_policy_paths_history rpp ON rp.id = rpp.rate_policy_id AND rpp.is_deleted = false
WHERE sc.is_deleted = false
GROUP BY o.org_display_name, sc.name, rp.name;
```

---

## AK-BOT: Bot Manager Checks

### AK-BOT-001 [CRITICAL] Bot Categories Without Protection

> **📚 Official Docs**: https://techdocs.akamai.com/bot-manager/docs/bot-categories
> 
> **🛡️ Security Value**: Unprotected bot categories allow known malicious bot types to access your application. Bot categories like "Credential Stuffers" should always be blocked.
> 
> **💼 Customer Impact**: Web scrapers, credential stuffers, and automated attack tools operate unrestricted. Content theft, account takeover, and fraud increase.

```sql
SELECT o.org_display_name, bc.category_name, bca.action::text,
    CASE WHEN bca.id IS NULL THEN 'CRITICAL: Bot category has no action configured'
         WHEN bca.action::text IN ('none', 'monitor') THEN 'HIGH: Bot category not blocking'
         ELSE 'OK' END as finding
FROM akamai_raw_bot_categories_history bc
JOIN organization o ON bc.organization_id = o.id
LEFT JOIN akamai_raw_bot_category_actions_history bca ON bc.id = bca.category_id AND bca.is_deleted = false
WHERE bc.is_deleted = false
AND (bca.id IS NULL OR bca.action::text IN ('none', 'monitor'));
```

### AK-BOT-002 [HIGH] Bot Detections Not Enforced

> **📚 Official Docs**: https://techdocs.akamai.com/bot-manager/docs/detection-methods
> 
> **🛡️ Security Value**: Bot detections (headless browsers, automation frameworks) in monitor mode see bots but don't stop them. Detection without action is pointless.
> 
> **💼 Customer Impact**: Advanced bots using Selenium, Puppeteer, or headless Chrome are detected but allowed. Sophisticated operators know they're seen but not stopped.

```sql
SELECT o.org_display_name, bd.detection_name, bda.action::text,
    CASE WHEN bda.id IS NULL THEN 'CRITICAL: Bot detection has no action'
         WHEN bda.action::text IN ('none', 'monitor', 'alert') THEN 'HIGH: Bot detection not enforced'
         ELSE 'OK' END as finding
FROM akamai_raw_bot_detections_history bd
JOIN organization o ON bd.organization_id = o.id
LEFT JOIN akamai_raw_bot_detection_actions_history bda ON bd.id = bda.detection_id AND bda.is_deleted = false
WHERE bd.is_deleted = false
AND (bda.id IS NULL OR bda.action::text IN ('none', 'monitor', 'alert'));
```

### AK-BOT-003 [HIGH] Known Bot List Coverage

> **📚 Official Docs**: https://techdocs.akamai.com/bot-manager/docs/bot-definitions
> 
> **🛡️ Security Value**: Visibility into known bot definitions. More definitions = better coverage. Akamai maintains extensive bot signature database.
> 
> **💼 Customer Impact**: Understanding your bot detection coverage helps identify gaps. Low bot definition counts may indicate incomplete configuration.

```sql
SELECT o.org_display_name, COUNT(b.id) as known_bots,
    'INFO: Known bot definitions count' as finding
FROM akamai_raw_bots_history b
JOIN organization o ON b.organization_id = o.id
WHERE b.is_deleted = false
GROUP BY o.org_display_name;
```

---

## AK-CUSTOM: Custom Rule Checks

### AK-CUSTOM-001 [HIGH] Custom Rules in Alert Mode

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/custom-rules
> 
> **🛡️ Security Value**: Custom rules represent organization-specific protections. Alert mode means these tailored defenses don't actually protect.
> 
> **💼 Customer Impact**: Custom rules are often created for specific vulnerabilities or business logic attacks. Alert mode defeats their purpose.

```sql
SELECT o.org_display_name, sc.name as security_config_name, cr.name as custom_rule_name,
    'HIGH: Custom rule in alert mode only - not blocking' as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_sec_config_custom_rules_history cr ON sc.id = cr.config_id AND cr.is_deleted = false
WHERE sc.is_deleted = false;
```

### AK-CUSTOM-002 [MEDIUM] Custom Rules Without Conditions

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/custom-rules
> 
> **🛡️ Security Value**: Custom rules with no or single conditions may be overly broad, causing false positives or ineffective protection.
> 
> **💼 Customer Impact**: Rules without conditions may block/allow too much traffic. Rules should be specific to intended use cases.

```sql
SELECT o.org_display_name, sc.name as security_config_name, cr.name as custom_rule_name,
    COUNT(crc.id) as condition_count,
    CASE WHEN COUNT(crc.id) = 0 THEN 'HIGH: Custom rule has no conditions'
         WHEN COUNT(crc.id) = 1 THEN 'MEDIUM: Custom rule has single condition'
         ELSE 'OK' END as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_sec_config_custom_rules_history cr ON sc.id = cr.config_id AND cr.is_deleted = false
LEFT JOIN akamai_raw_sec_config_custom_rule_conditions_history crc ON cr.id = crc.custom_rule_id AND crc.is_deleted = false
WHERE sc.is_deleted = false
GROUP BY o.org_display_name, sc.name, cr.name
HAVING COUNT(crc.id) < 2;
```

---

## AK-PROP: Property Configuration Checks

### AK-PROP-001 [HIGH] Properties Count per Organization

> **📚 Official Docs**: https://techdocs.akamai.com/property-mgr/docs
> 
> **🛡️ Security Value**: Visibility into property landscape. More properties = larger attack surface. Helps identify governance and coverage gaps.
> 
> **💼 Customer Impact**: Understanding property count helps ensure all web assets are consistently protected. Shadow properties may lack security.

```sql
SELECT o.org_display_name, COUNT(p.id) as property_count,
    'INFO: Properties per organization' as finding
FROM akamai_raw_properties_history p
JOIN organization o ON p.organization_id = o.id
WHERE p.is_deleted = false
GROUP BY o.org_display_name;
```

### AK-PROP-002 [HIGH] Property Hostnames Analysis

> **📚 Official Docs**: https://techdocs.akamai.com/property-mgr/docs/hostnames
> 
> **🛡️ Security Value**: Each hostname is an attack surface. Properties with many hostnames need consistent security across all.
> 
> **💼 Customer Impact**: Missing hostnames from security policies create protection gaps. All hostnames should have WAF coverage.

```sql
SELECT o.org_display_name, p.name as property_name, COUNT(ph.id) as hostname_count,
    'INFO: Property hostname count' as finding
FROM akamai_raw_properties_history p
JOIN organization o ON p.organization_id = o.id
LEFT JOIN akamai_raw_property_hostnames_history ph ON p.id = ph.property_id AND ph.is_deleted = false
WHERE p.is_deleted = false
GROUP BY o.org_display_name, p.name;
```

### AK-PROP-003 [MEDIUM] Property Rule Behaviors Analysis

> **📚 Official Docs**: https://techdocs.akamai.com/property-mgr/docs/behavior-reference
> 
> **🛡️ Security Value**: Property behaviors control caching, origin communication, and security features. Misconfigured behaviors can introduce vulnerabilities.
> 
> **💼 Customer Impact**: Behaviors like caching on sensitive paths, HTTP-only origins, or disabled security features create risks.

```sql
SELECT o.org_display_name, p.name as property_name, 
    prb.behavior_name, COUNT(*) as behavior_count,
    'INFO: Property behavior usage' as finding
FROM akamai_raw_properties_history p
JOIN organization o ON p.organization_id = o.id
JOIN akamai_raw_property_rules_history pr ON p.id = pr.property_id AND pr.is_deleted = false
JOIN akamai_raw_property_rule_behaviors_history prb ON pr.id = prb.property_rule_id AND prb.is_deleted = false
WHERE p.is_deleted = false
GROUP BY o.org_display_name, p.name, prb.behavior_name
ORDER BY behavior_count DESC;
```

---

## AK-URL: URL Protection Checks

### AK-URL-001 [HIGH] URL Protection Policies

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/url-protection
> 
> **🛡️ Security Value**: URL protection policies defend against directory traversal, file inclusion, and URL-based attacks. Essential for path-based security.
> 
> **💼 Customer Impact**: Visibility into URL protection coverage. Missing policies leave path-based attacks undetected.

```sql
SELECT o.org_display_name, sc.name as security_config_name,
    upp.name as url_protection_policy,
    'INFO: URL protection policy defined' as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_sec_config_url_prot_pols_history upp ON sc.id = upp.config_id AND upp.is_deleted = false
WHERE sc.is_deleted = false;
```

### AK-URL-002 [MEDIUM] URL Protection Bypass Conditions

> **📚 Official Docs**: https://techdocs.akamai.com/app-api-protector/docs/url-protection
> 
> **🛡️ Security Value**: Bypass conditions in URL protection create intentional security gaps. Should be reviewed regularly and minimized.
> 
> **💼 Customer Impact**: Bypass conditions may have been added for troubleshooting and forgotten. Each bypass is a potential attack vector.

```sql
SELECT o.org_display_name, sc.name as security_config_name, upp.name as url_protection_policy,
    COUNT(upbc.id) as bypass_condition_count,
    'MEDIUM: URL protection has bypass conditions - review for security' as finding
FROM akamai_raw_security_configurations_history sc
JOIN organization o ON sc.organization_id = o.id
JOIN akamai_raw_sec_config_url_prot_pols_history upp ON sc.id = upp.config_id AND upp.is_deleted = false
JOIN akamai_raw_sec_config_url_prot_pol_bypass_conds_history upbc ON upp.id = upbc.url_prot_pol_id AND upbc.is_deleted = false
WHERE sc.is_deleted = false
GROUP BY o.org_display_name, sc.name, upp.name;
```


---

# 🔸 AWS WAF - PostgreSQL Configuration Analysis

## AWS-ACL: Web ACL Checks

### AWS-ACL-001 [CRITICAL] Web ACLs Without Associated Resources

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html
> 
> **🛡️ Security Value**: Web ACLs not associated with resources (ALB, CloudFront, API Gateway) provide zero protection. You're paying for rules that protect nothing.
> 
> **💼 Customer Impact**: Resources you think are protected are exposed. ACLs get disassociated during migrations, testing, or mistakes. Regular audits are essential.

```sql
SELECT o.org_display_name, acl.name as acl_name, acl.region::text, acl.capacity,
    'CRITICAL: Web ACL has no associated resources - provides no protection' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_associated_resources_history ar
    WHERE ar.waf_acl_id = acl.id AND ar.is_deleted = false
);
```

### AWS-ACL-002 [CRITICAL] Web ACLs Without Logging

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/logging.html
> 
> **🛡️ Security Value**: Without logging, you have zero visibility into attacks, rule effectiveness, or security events. Can't tune, investigate, or prove compliance.
> 
> **💼 Customer Impact**: Compliance frameworks (PCI-DSS, SOC2, HIPAA) require WAF logging. No logs = compliance failure + blind to attacks.

```sql
SELECT o.org_display_name, acl.name as acl_name, acl.region::text,
    'CRITICAL: Web ACL has no logging configured - no visibility' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_logging_configurations_history lc
    WHERE lc.waf_acl_id = acl.id AND lc.is_deleted = false
);
```

### AWS-ACL-003 [HIGH] High WCU Usage (Capacity Warning)

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/limits.html
> 
> **🛡️ Security Value**: WCU near limits (5000 CloudFront, 1500 regional) prevents adding new rules. During zero-days, you may need to quickly add rules but can't.
> 
> **💼 Customer Impact**: Can't respond to new threats. Forced to remove existing protection to add new. Operational agility severely limited.

```sql
SELECT o.org_display_name, acl.name as acl_name, acl.capacity as wcu_used,
    5000 - acl.capacity as wcu_remaining,
    ROUND((acl.capacity::numeric / 5000) * 100, 1) as capacity_percent,
    CASE WHEN acl.capacity > 4500 THEN 'CRITICAL: Over 90% WCU capacity'
         WHEN acl.capacity > 4000 THEN 'HIGH: Over 80% WCU capacity'
         WHEN acl.capacity > 2500 THEN 'MEDIUM: Over 50% WCU capacity'
         ELSE 'OK' END as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false AND acl.capacity > 2500
ORDER BY acl.capacity DESC;
```

### AWS-ACL-004 [HIGH] Default Action Set to ALLOW

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html#web-acl-default-action
> 
> **🛡️ Security Value**: Default ALLOW means any request not explicitly blocked passes through. You must anticipate ALL attacks in advance. New attack patterns succeed.
> 
> **💼 Customer Impact**: Permissive security posture. Defense-in-depth recommends default-deny where feasible. Default-allow requires perfect, comprehensive rules.

```sql
SELECT o.org_display_name, acl.name as acl_name, acl.default_action::text,
    'HIGH: Default action is ALLOW - unmatched requests pass through' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false AND acl.default_action::text ILIKE '%allow%';
```

### AWS-ACL-005 [MEDIUM] CloudWatch Metrics Disabled

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html
> 
> **🛡️ Security Value**: CloudWatch metrics enable alerting on attack volume, rule triggers, and anomalies. Disabled = no real-time visibility or alerting.
> 
> **💼 Customer Impact**: Can't set up CloudWatch alarms for attacks. No dashboards showing WAF activity. Limited operational visibility.

```sql
SELECT o.org_display_name, acl.name as acl_name, acl.cloudwatch_metrics_enabled,
    'MEDIUM: CloudWatch metrics disabled - limited observability' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false AND acl.cloudwatch_metrics_enabled = false;
```

### AWS-ACL-006 [MEDIUM] Sample Requests Disabled

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-testing.html
> 
> **🛡️ Security Value**: Sample requests help tune rules by showing actual request data that triggered rules. Disabled = harder to identify false positives.
> 
> **💼 Customer Impact**: Difficult to tune rules without seeing actual requests. May lead to over-blocking legitimate traffic or missing attacks.

```sql
SELECT o.org_display_name, acl.name as acl_name, acl.sample_request_enabled,
    'MEDIUM: Sample requests disabled - difficult to tune rules' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false AND acl.sample_request_enabled = false;
```

### AWS-ACL-007 [LOW] ACLs Without Description

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl.html
> 
> **🛡️ Security Value**: Documentation best practice. Descriptions help teams understand ACL purpose, ownership, and intended protection scope.
> 
> **💼 Customer Impact**: Operational complexity when troubleshooting. Harder for teams to understand what each ACL protects and why.

```sql
SELECT o.org_display_name, acl.name as acl_name, acl.description,
    'LOW: ACL has no description - poor documentation' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false 
AND (acl.description IS NULL OR acl.description = '');
```

### AWS-ACL-008 [MEDIUM] ACL Regional Distribution

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works.html
> 
> **🛡️ Security Value**: Understanding regional ACL distribution helps ensure global coverage. Regional ACLs only protect resources in that region.
> 
> **💼 Customer Impact**: Resources in regions without ACLs are unprotected. CloudFront requires GLOBAL scope ACLs; regional ALBs need regional ACLs.

```sql
SELECT o.org_display_name, acl.region::text, COUNT(*) as acl_count,
    'INFO: ACL regional distribution' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false
GROUP BY o.org_display_name, acl.region::text
ORDER BY acl_count DESC;
```

### AWS-ACL-009 [HIGH] ACLs Managed by Firewall Manager

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/fms-chapter.html
> 
> **🛡️ Security Value**: Firewall Manager provides centralized policy management. Managed ACLs should follow organizational standards.
> 
> **💼 Customer Impact**: Centrally managed ACLs ensure consistent security policies across accounts. Identify which ACLs are vs aren't under central management.

```sql
SELECT o.org_display_name, acl.name as acl_name, acl.managed_by_firewall_manager,
    'INFO: ACL managed by Firewall Manager' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false AND acl.managed_by_firewall_manager = true;
```

---

## AWS-RULE: Rule Configuration Checks

### AWS-RULE-001 [HIGH] Rules in Count Mode

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-action.html
> 
> **🛡️ Security Value**: Count mode logs matches but doesn't block. Attacks detected but not prevented. Count is for testing (1-2 weeks), not production.
> 
> **💼 Customer Impact**: Rules show activity in metrics but provide NO protection. False sense of security. Production rules in count for months are forgotten misconfigs.

```sql
SELECT o.org_display_name, acl.name as acl_name, r.name as rule_name, r.action, r.priority,
    'HIGH: Rule in Count mode - not blocking attacks' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.acl_id AND r.is_deleted = false
WHERE acl.is_deleted = false AND r.action ILIKE '%count%';
```

### AWS-RULE-002 [HIGH] Rule Priority Analysis

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-priority.html
> 
> **🛡️ Security Value**: Rule priority determines evaluation order. Lower numbers = evaluated first. Blocking rules should come before allow rules.
> 
> **💼 Customer Impact**: Misconfigured priorities can cause security bypasses or false positives. Allow rules evaluated before blocks can create gaps.

```sql
SELECT o.org_display_name, acl.name as acl_name, 
    COUNT(*) as total_rules,
    MIN(r.priority) as min_priority,
    MAX(r.priority) as max_priority,
    'INFO: Rule priority spread' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.acl_id AND r.is_deleted = false
WHERE acl.is_deleted = false
GROUP BY o.org_display_name, acl.name;
```

### AWS-RULE-003 [MEDIUM] Rules Without Labels

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-labels.html
> 
> **🛡️ Security Value**: Labels enable cross-rule logic, improved logging, and rule chaining. Without labels, advanced WAF patterns aren't possible.
> 
> **💼 Customer Impact**: Can't implement sophisticated rule logic like "if rule A matches AND rule B matches, then block". Limited analysis capabilities.

```sql
SELECT o.org_display_name, acl.name as acl_name, r.name as rule_name,
    'MEDIUM: Rule not using labels for tracking' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.acl_id AND r.is_deleted = false
WHERE acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rule_labels_history rl
    WHERE rl.rule_id = r.id AND rl.is_deleted = false
);
```

### AWS-RULE-004 [MEDIUM] Rules with Multiple Text Transforms

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields.html#waf-rule-statement-transformation
> 
> **🛡️ Security Value**: Text transforms normalize input for better detection (URL decode, lowercase). Multiple transforms improve evasion prevention.
> 
> **💼 Customer Impact**: Rules without proper transforms can be evaded with encoding tricks. Attackers use URL encoding, double encoding, etc.

```sql
SELECT o.org_display_name, acl.name as acl_name, r.name as rule_name,
    COUNT(tt.id) as transform_count,
    'INFO: Rule text transform count' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
JOIN aws_raw_waf_acl_rules_history r ON acl.id = r.acl_id AND r.is_deleted = false
LEFT JOIN aws_raw_waf_acl_rule_statement_text_transform_history tt ON r.id = tt.rule_id AND tt.is_deleted = false
WHERE acl.is_deleted = false
GROUP BY o.org_display_name, acl.name, r.name;
```

---

## AWS-MRG: Managed Rule Group Checks

### AWS-MRG-001 [CRITICAL] No AWS Managed Rules Configured

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html
> 
> **🛡️ Security Value**: AWS Managed Rules provide baseline protection updated by AWS security teams. Without them, no protection against OWASP Top 10 or emerging threats.
> 
> **💼 Customer Impact**: Must build ALL rules from scratch. AWS updates managed rules for new CVEs within hours/days - without them, you're always behind attackers.

```sql
SELECT o.org_display_name, acl.name as acl_name,
    'CRITICAL: No AWS managed rule groups configured' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rule_group_statements_history rgs
    WHERE rgs.acl_id = acl.id AND rgs.is_deleted = false AND rgs.vendor_name ILIKE '%aws%'
);
```

### AWS-MRG-002 [HIGH] Core Rule Set (CRS) Missing

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
> 
> **🛡️ Security Value**: AWSManagedRulesCommonRuleSet provides baseline OWASP Top 10 protection including SQLi, XSS, path traversal. Essential foundation.
> 
> **💼 Customer Impact**: Missing fundamental protections that should be standard. CRS is the first line of defense every web app needs.

```sql
SELECT o.org_display_name, acl.name as acl_name,
    'HIGH: AWS Core Rule Set (AWSManagedRulesCommonRuleSet) not configured' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rule_group_statements_history rgs
    WHERE rgs.acl_id = acl.id AND rgs.is_deleted = false AND rgs.name ILIKE '%commonruleset%'
);
```

### AWS-MRG-003 [HIGH] Known Bad Inputs Missing

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html#aws-managed-rule-groups-baseline-kbi
> 
> **🛡️ Security Value**: Detects request patterns associated with vulnerability exploitation: Log4Shell, Java deserialization, other known exploit signatures.
> 
> **💼 Customer Impact**: Log4Shell (CVE-2021-44228) rules in Known Bad Inputs blocked millions of attacks. Missing = exposed to known exploits.

```sql
SELECT o.org_display_name, acl.name as acl_name,
    'HIGH: AWS Known Bad Inputs rule set not configured' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rule_group_statements_history rgs
    WHERE rgs.acl_id = acl.id AND rgs.is_deleted = false AND rgs.name ILIKE '%knownbadinputs%'
);
```

### AWS-MRG-004 [HIGH] SQL Injection Rules Missing

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html#aws-managed-rule-groups-use-case-sql-db
> 
> **🛡️ Security Value**: AWSManagedRulesSQLiRuleSet provides enhanced SQL injection detection. SQLi remains #1-3 in OWASP Top 10 consistently.
> 
> **💼 Customer Impact**: SQLi can dump entire databases, modify data, or enable further attacks. A single successful injection can compromise everything.

```sql
SELECT o.org_display_name, acl.name as acl_name,
    'HIGH: AWS SQL Database rule set not configured' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rule_group_statements_history rgs
    WHERE rgs.acl_id = acl.id AND rgs.is_deleted = false AND rgs.name ILIKE '%sqli%'
);
```

### AWS-MRG-005 [MEDIUM] Bot Control Missing

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html
> 
> **🛡️ Security Value**: AWS Bot Control identifies and manages automated traffic. Without it, 40%+ of internet traffic (bots) is unanalyzed.
> 
> **💼 Customer Impact**: Scrapers, credential stuffers, inventory hoarders operate undetected. Note: Bot Control has additional cost implications.

```sql
SELECT o.org_display_name, acl.name as acl_name,
    'MEDIUM: AWS Bot Control rule set not configured' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
WHERE acl.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_rule_group_statements_history rgs
    WHERE rgs.acl_id = acl.id AND rgs.is_deleted = false AND rgs.name ILIKE '%botcontrol%'
);
```

### AWS-MRG-006 [HIGH] Managed Rule Group Rules Override to Count

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-group-override.html
> 
> **🛡️ Security Value**: Overriding managed rules to Count defeats their purpose. Rules detect attacks but don't block due to overrides. Protection undermined.
> 
> **💼 Customer Impact**: Overrides added during false positive investigation often remain permanently. Each override is a security gap.

```sql
SELECT o.org_display_name, acl.name as acl_name, 
    mro.rule_id, mro.action_to_use,
    'HIGH: Managed rule override to Count' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
JOIN aws_raw_acl_managed_rule_group_rule_override_history mro ON acl.id = mro.acl_id AND mro.is_deleted = false
WHERE acl.is_deleted = false
AND mro.action_to_use ILIKE '%count%';
```

### AWS-MRG-007 [MEDIUM] All Managed Rule Groups Summary

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
> 
> **🛡️ Security Value**: Comprehensive view of managed rule group configuration. Shows which AWS rule groups are deployed and from which vendors.
> 
> **💼 Customer Impact**: Essential for understanding your managed protection coverage. Identifies gaps in rule group deployment.

```sql
SELECT o.org_display_name, acl.name as acl_name, rgs.vendor_name, rgs.name as rule_group_name,
    'INFO: Managed rule group configured' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
JOIN aws_raw_waf_acl_rule_group_statements_history rgs ON acl.id = rgs.acl_id AND rgs.is_deleted = false
WHERE acl.is_deleted = false
ORDER BY o.org_display_name, acl.name;
```

---

## AWS-CF: CloudFront Integration Checks

### AWS-CF-001 [CRITICAL] CloudFront Distributions Without WAF

> **📚 Official Docs**: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html
> 
> **🛡️ Security Value**: CloudFront distributions without WAF are unprotected entry points. All traffic reaches origin unchallenged. Each unprotected distribution is attack surface.
> 
> **💼 Customer Impact**: Attackers target unprotected distributions. Modern attack tools enumerate all CloudFront distributions and test for protection gaps.

```sql
SELECT o.org_display_name, cf.domain_name, cf.enabled, cf.status,
    'CRITICAL: CloudFront distribution has no WAF association' as finding
FROM aws_raw_cloudfront_distribution_history cf
JOIN organization o ON cf.organization_id = o.id
WHERE cf.is_deleted = false AND cf.enabled = true
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_associated_resources_history ar
    WHERE ar.arn ILIKE '%' || cf.id::text || '%' AND ar.is_deleted = false
);
```

### AWS-CF-002 [HIGH] Origin with HTTP Protocol

> **📚 Official Docs**: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesOriginProtocolPolicy
> 
> **🛡️ Security Value**: HTTP-only or match-viewer origin protocol allows MITM attacks between CloudFront and origin. Even with HTTPS to CloudFront, backend is exposed.
> 
> **💼 Customer Impact**: Attackers can intercept/modify CloudFront-to-origin traffic. Cloud provider networks aren't necessarily secure. HTTPS to origin should be standard.

```sql
SELECT o.org_display_name, cf.domain_name, co.domain_name as origin_domain, co.origin_protocol_policy,
    'HIGH: Origin using HTTP or match-viewer protocol - potential MITM' as finding
FROM aws_raw_cloudfront_distribution_history cf
JOIN organization o ON cf.organization_id = o.id
JOIN aws_raw_cloudfront_distribution_origin_history co ON cf.id = co.distribution_id AND co.is_deleted = false
WHERE cf.is_deleted = false
AND co.origin_protocol_policy IN ('http-only', 'match-viewer');
```

### AWS-CF-003 [MEDIUM] CloudFront Distribution Summary

> **📚 Official Docs**: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html
> 
> **🛡️ Security Value**: Distribution inventory helps ensure all CloudFront assets are consistently protected and configured.
> 
> **💼 Customer Impact**: Visibility into CloudFront landscape. Multiple origins/aliases increase complexity and potential for misconfiguration.

```sql
SELECT o.org_display_name, cf.domain_name, cf.enabled, cf.status,
    COUNT(DISTINCT co.id) as origin_count,
    COUNT(DISTINCT ca.id) as alias_count,
    'INFO: CloudFront distribution overview' as finding
FROM aws_raw_cloudfront_distribution_history cf
JOIN organization o ON cf.organization_id = o.id
LEFT JOIN aws_raw_cloudfront_distribution_origin_history co ON cf.id = co.distribution_id AND co.is_deleted = false
LEFT JOIN aws_raw_cloudfront_distribution_alias_history ca ON cf.id = ca.distribution_id AND ca.is_deleted = false
WHERE cf.is_deleted = false
GROUP BY o.org_display_name, cf.domain_name, cf.enabled, cf.status;
```

### AWS-CF-004 [HIGH] CloudFront Cache Behaviors

> **📚 Official Docs**: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html#DownloadDistValuesCacheBehavior
> 
> **🛡️ Security Value**: Cache behaviors with allow-all viewer protocol permit HTTP connections. Sensitive data may be transmitted unencrypted.
> 
> **💼 Customer Impact**: Users connecting over HTTP have credentials and data exposed. Should enforce HTTPS-only for sensitive applications.

```sql
SELECT o.org_display_name, cf.domain_name, cb.path_pattern, cb.viewer_protocol_policy,
    CASE WHEN cb.viewer_protocol_policy = 'allow-all' 
         THEN 'HIGH: Cache behavior allows HTTP' ELSE 'OK' END as finding
FROM aws_raw_cloudfront_distribution_history cf
JOIN organization o ON cf.organization_id = o.id
JOIN aws_raw_cloudfront_distribution_cache_behavior_history cb ON cf.id = cb.distribution_id AND cb.is_deleted = false
WHERE cf.is_deleted = false;
```

---

## AWS-LOG: Logging Configuration Checks

### AWS-LOG-001 [HIGH] Logging with Filters (Limited Visibility)

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/logging.html#logging-filter
> 
> **🛡️ Security Value**: Log filters reduce logged events but may hide important attacks. Only ALLOW requests logged = no visibility into blocked attacks.
> 
> **💼 Customer Impact**: Filtered logs provide incomplete picture. During incidents, you may not have the data needed for investigation.

```sql
SELECT o.org_display_name, acl.name as acl_name, COUNT(f.id) as filter_count,
    'HIGH: Logging has filters - some events may not be logged' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
JOIN aws_raw_waf_acl_logging_configurations_history lc ON acl.id = lc.waf_acl_id AND lc.is_deleted = false
JOIN aws_raw_waf_acl_logging_configurations_filters_history f ON lc.id = f.logging_config_id AND f.is_deleted = false
WHERE acl.is_deleted = false
GROUP BY o.org_display_name, acl.name
HAVING COUNT(f.id) > 0;
```

### AWS-LOG-002 [MEDIUM] Logging with Redacted Fields

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/logging.html#logging-redaction
> 
> **🛡️ Security Value**: Redacted fields remove potentially sensitive data but also remove forensic evidence. Balance privacy with investigation needs.
> 
> **💼 Customer Impact**: During incidents, redacted fields may hide attack payloads needed to understand the attack. May limit forensic capability.

```sql
SELECT o.org_display_name, acl.name as acl_name, COUNT(rf.id) as redacted_field_count,
    'MEDIUM: Logging has redacted fields - limited forensics capability' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
JOIN aws_raw_waf_acl_logging_configurations_history lc ON acl.id = lc.waf_acl_id AND lc.is_deleted = false
JOIN aws_raw_waf_acl_logging_configurations_redacted_fields_history rf ON lc.id = rf.logging_config_id AND rf.is_deleted = false
WHERE acl.is_deleted = false
GROUP BY o.org_display_name, acl.name
HAVING COUNT(rf.id) > 0;
```

---

## AWS-ASSOC: Resource Association Checks

### AWS-ASSOC-001 [HIGH] Associated Resource Types

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-aws-resource.html
> 
> **🛡️ Security Value**: Understanding which resource types are protected (ALB, CloudFront, API Gateway, AppSync) helps identify coverage gaps.
> 
> **💼 Customer Impact**: Different resource types have different security requirements. Ensure all web-facing resources are protected appropriately.

```sql
SELECT o.org_display_name, acl.name as acl_name, ar.resource_type, COUNT(*) as resource_count,
    'INFO: Resources associated with ACL by type' as finding
FROM aws_raw_waf_acl_history acl
JOIN organization o ON acl.organization_id = o.id
JOIN aws_raw_waf_acl_associated_resources_history ar ON acl.id = ar.waf_acl_id AND ar.is_deleted = false
WHERE acl.is_deleted = false
GROUP BY o.org_display_name, acl.name, ar.resource_type;
```

### AWS-ASSOC-002 [HIGH] Load Balancers Without WAF

> **📚 Official Docs**: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancer-web-application-firewalls.html
> 
> **🛡️ Security Value**: Internet-facing ALBs without WAF are direct attack targets. All traffic reaches your application unfiltered.
> 
> **💼 Customer Impact**: Load balancers are primary entry points. Unprotected ALBs expose your entire application stack to attacks.

```sql
SELECT o.org_display_name, lb.name as load_balancer_name, lb.type, lb.scheme,
    'CRITICAL: Load balancer has no WAF association' as finding
FROM aws_raw_load_balancers_history lb
JOIN organization o ON lb.organization_id = o.id
WHERE lb.is_deleted = false
AND NOT EXISTS (
    SELECT 1 FROM aws_raw_waf_acl_associated_resources_history ar
    WHERE ar.arn ILIKE '%' || lb.id::text || '%' AND ar.is_deleted = false
);
```


---

# PART 2: TRINO TRAFFIC/LOG ANALYSIS

---

# 🔶 CLOUDFLARE - Trino Traffic Analysis

> **TABLE**: `aws_waf_logs.waf_logs_db.{customer}_waf_logs` (e.g., `quillbot_waf_logs_huskeys_copy`)
> **PARTITIONS**: `year`, `month`, `day`, `hour`

## CF-LOG-ATK: Attack Score Analysis

### CF-LOG-ATK-001 [CRITICAL] High Attack Score NOT Blocked

> **📚 Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/
> 
> **🛡️ Security Value**: Cloudflare's ML model assigns attack scores (0-100). Scores 60+ indicate high-confidence attacks. Unblocked high scores = active exploitation reaching your origin.
> 
> **💼 Customer Impact**: Cloudflare's AI identified attacks with high confidence, but they reached origin. Active exploitation may be occurring RIGHT NOW.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, wafattackscore, securityaction, edgeresponsestatus, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND wafattackscore IS NOT NULL AND wafattackscore >= 60
AND (securityaction IS NULL OR securityaction NOT IN ('block', 'challenge', 'managed_challenge', 'jschallenge'))
GROUP BY 1, 2, 3, 4, 5, 6 ORDER BY wafattackscore DESC, count DESC LIMIT 100;
```

### CF-LOG-ATK-002 [CRITICAL] SQLi Attack Score NOT Blocked

> **📚 Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/#attack-score-fields
> 
> **🛡️ Security Value**: SQL injection attacks with high scores reaching origin can lead to database compromise, data exfiltration, or complete data loss.
> 
> **💼 Customer Impact**: SQLi is consistently #1-3 in OWASP Top 10. A single successful injection can dump entire databases, modify records, or destroy data.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, wafsqliattackscore, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND wafsqliattackscore IS NOT NULL AND wafsqliattackscore >= 70
AND (securityaction IS NULL OR securityaction NOT IN ('block', 'challenge'))
GROUP BY 1, 2, 3, 4, 5 ORDER BY wafsqliattackscore DESC, count DESC LIMIT 100;
```

### CF-LOG-ATK-003 [CRITICAL] XSS Attack Score NOT Blocked

> **📚 Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/#attack-score-fields
> 
> **🛡️ Security Value**: XSS attacks with high scores reaching origin can steal sessions, credentials, enable account takeover, and damage reputation.
> 
> **💼 Customer Impact**: XSS affects users directly. Customer accounts get compromised, leading to fraud, data theft, and trust issues. Regulatory implications (GDPR).

```sql
SELECT clientrequesthost, clientrequesturi, clientip, wafxssattackscore, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND wafxssattackscore IS NOT NULL AND wafxssattackscore >= 70
AND (securityaction IS NULL OR securityaction NOT IN ('block', 'challenge'))
GROUP BY 1, 2, 3, 4, 5 ORDER BY wafxssattackscore DESC, count DESC LIMIT 100;
```

### CF-LOG-ATK-004 [CRITICAL] RCE Attack Score NOT Blocked

> **📚 Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/#attack-score-fields
> 
> **🛡️ Security Value**: Remote Code Execution is the most severe attack type. Successful RCE = full server compromise, backdoors, lateral movement possible.
> 
> **💼 Customer Impact**: A single successful RCE can compromise your entire infrastructure. Attackers gain shell access, install persistence, exfiltrate data.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, wafrceattackscore, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND wafrceattackscore IS NOT NULL AND wafrceattackscore >= 70
AND (securityaction IS NULL OR securityaction NOT IN ('block', 'challenge'))
GROUP BY 1, 2, 3, 4, 5 ORDER BY wafrceattackscore DESC, count DESC LIMIT 100;
```

### CF-LOG-ATK-005 [HIGH] Combined High Attack Scores

> **📚 Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/
> 
> **🛡️ Security Value**: Multiple elevated attack scores on same request indicates sophisticated multi-vector attack attempting SQLi, XSS, and RCE simultaneously.
> 
> **💼 Customer Impact**: Attackers often try multiple techniques. Combined scores identify sophisticated threats that may evade single-vector detection.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, 
    wafattackscore, wafsqliattackscore, wafxssattackscore, wafrceattackscore, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (wafattackscore >= 50 OR wafsqliattackscore >= 50 OR wafxssattackscore >= 50 OR wafrceattackscore >= 50)
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8 ORDER BY wafattackscore DESC NULLS LAST LIMIT 100;
```

### CF-LOG-ATK-006 [HIGH] Attack Score Distribution

> **📚 Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/
> 
> **🛡️ Security Value**: Understanding attack score distribution helps tune WAF sensitivity. High volumes at each threshold indicate attack patterns.
> 
> **💼 Customer Impact**: Provides visibility into overall threat landscape. Helps justify security investments and tune blocking thresholds.

```sql
SELECT clientrequesthost,
    COUNT(CASE WHEN wafattackscore >= 90 THEN 1 END) as critical_90_plus,
    COUNT(CASE WHEN wafattackscore >= 70 AND wafattackscore < 90 THEN 1 END) as high_70_89,
    COUNT(CASE WHEN wafattackscore >= 50 AND wafattackscore < 70 THEN 1 END) as medium_50_69,
    COUNT(CASE WHEN wafattackscore < 50 THEN 1 END) as low_under_50
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND wafattackscore IS NOT NULL
GROUP BY 1 ORDER BY critical_90_plus DESC;
```

---

## CF-LOG-BOT: Bot Traffic Analysis

### CF-LOG-BOT-001 [HIGH] Low Bot Score Traffic Allowed

> **📚 Official Docs**: https://developers.cloudflare.com/bots/concepts/bot-score/
> 
> **🛡️ Security Value**: Bot scores 1-30 indicate high confidence of automation. Allowing this traffic enables scraping, credential stuffing, and fraud.
> 
> **💼 Customer Impact**: Confirmed automated traffic accessing your application. Scores 1-10 are "definite bots" that should rarely be allowed through.

```sql
SELECT clientrequesthost, botscore, botscoresrc, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND botscore IS NOT NULL AND botscore <= 30
AND botscoresrc != 'verified_bot'
AND (securityaction IS NULL OR securityaction = 'allow')
GROUP BY 1, 2, 3, 4 HAVING COUNT(*) > 100 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-BOT-002 [HIGH] Verified Bot Spoofing

> **📚 Official Docs**: https://developers.cloudflare.com/bots/concepts/cloudflare-bot-management/#verified-bots
> 
> **🛡️ Security Value**: Traffic claiming to be Googlebot/Bingbot but not verified is malicious hiding behind trusted names. Attackers impersonate search engines to bypass allow-lists.
> 
> **💼 Customer Impact**: Spoofed bots may be scraping, attacking, or conducting reconnaissance. Your Googlebot allow rules are being exploited.

```sql
SELECT clientrequesthost, clientrequestuseragent, clientip, botscore, verifiedbotcategory, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(clientrequestuseragent) LIKE '%googlebot%' OR LOWER(clientrequestuseragent) LIKE '%bingbot%')
AND (verifiedbotcategory IS NULL OR verifiedbotcategory = '')
GROUP BY 1, 2, 3, 4, 5 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-BOT-003 [MEDIUM] AI Crawler Traffic

> **📚 Official Docs**: https://developers.cloudflare.com/bots/reference/bot-management-variables/#ai-bots
> 
> **🛡️ Security Value**: AI crawlers (GPTBot, ClaudeBot) scrape content for model training. Organizations may want to control AI access to proprietary content.
> 
> **💼 Customer Impact**: Content may be used for AI training without consent. Emerging regulations (EU AI Act) may require transparency and control.

```sql
SELECT clientrequesthost, clientrequestuseragent, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(clientrequestuseragent) LIKE '%chatgpt%' OR LOWER(clientrequestuseragent) LIKE '%gpt%'
     OR LOWER(clientrequestuseragent) LIKE '%openai%' OR LOWER(clientrequestuseragent) LIKE '%claude%'
     OR LOWER(clientrequestuseragent) LIKE '%anthropic%' OR LOWER(clientrequestuseragent) LIKE '%bard%')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-BOT-004 [HIGH] Headless Browser Detection

> **📚 Official Docs**: https://developers.cloudflare.com/bots/concepts/bot-score/
> 
> **🛡️ Security Value**: Headless browsers (Puppeteer, Playwright, Selenium) indicate sophisticated automation. Often used for scraping, account takeover, or fraud.
> 
> **💼 Customer Impact**: Advanced bots can bypass simple protections. Headless browser traffic often indicates organized attacks or commercial scraping.

```sql
SELECT clientrequesthost, botscore, clientrequestuseragent, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(clientrequestuseragent) LIKE '%headless%' OR LOWER(clientrequestuseragent) LIKE '%phantom%'
     OR LOWER(clientrequestuseragent) LIKE '%selenium%' OR LOWER(clientrequestuseragent) LIKE '%puppeteer%')
GROUP BY 1, 2, 3, 4 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-BOT-005 [MEDIUM] Bot Score Distribution

> **📚 Official Docs**: https://developers.cloudflare.com/bots/concepts/bot-score/
> 
> **🛡️ Security Value**: Bot score distribution shows the composition of your traffic: definite bots, likely bots, uncertain, likely human. Helps tune bot management.
> 
> **💼 Customer Impact**: Understanding bot traffic ratios helps justify bot management investment and tune challenge thresholds appropriately.

```sql
SELECT clientrequesthost,
    COUNT(CASE WHEN botscore <= 10 THEN 1 END) as definitely_bot_1_10,
    COUNT(CASE WHEN botscore > 10 AND botscore <= 30 THEN 1 END) as likely_bot_11_30,
    COUNT(CASE WHEN botscore > 30 AND botscore <= 70 THEN 1 END) as uncertain_31_70,
    COUNT(CASE WHEN botscore > 70 THEN 1 END) as likely_human_71_plus
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND botscore IS NOT NULL
GROUP BY 1 ORDER BY definitely_bot_1_10 DESC;
```

### CF-LOG-BOT-006 [HIGH] Verified Bots Analysis

> **📚 Official Docs**: https://developers.cloudflare.com/bots/concepts/cloudflare-bot-management/#verified-bots
> 
> **🛡️ Security Value**: Shows which verified bots (Google, Bing, etc.) are accessing your site. Helps maintain allow-lists and identify unexpected bot activity.
> 
> **💼 Customer Impact**: Verified bot analysis ensures search engines can crawl while identifying any unauthorized bot categories accessing your content.

```sql
SELECT clientrequesthost, verifiedbotcategory, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND verifiedbotcategory IS NOT NULL AND verifiedbotcategory != ''
GROUP BY 1, 2 ORDER BY count DESC LIMIT 50;
```

---

## CF-LOG-ABU: Abuse Pattern Detection

### CF-LOG-ABU-001 [HIGH] Credential Stuffing Detection

> **📚 Official Docs**: https://developers.cloudflare.com/waf/managed-rules/reference/exposed-credentials-check/
> 
> **🛡️ Security Value**: High-volume POST requests to login endpoints from single IPs indicate credential stuffing attacks using breached databases. Attackers systematically test stolen username/password combinations.
> 
> **💼 Customer Impact**: Account takeover at scale. Customers with reused passwords get compromised. Leads to fraud, data theft, and severe reputation damage. Breached accounts often used for further attacks.

```sql
SELECT clientrequesthost, clientip, COUNT(DISTINCT clientrequesturi) as unique_paths, COUNT(*) as total_requests
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND clientrequestmethod = 'POST'
AND (clientrequesturi LIKE '%login%' OR clientrequesturi LIKE '%signin%' OR clientrequesturi LIKE '%auth%')
GROUP BY 1, 2 HAVING COUNT(*) > 50 ORDER BY total_requests DESC LIMIT 50;
```

### CF-LOG-ABU-002 [HIGH] API Enumeration

> **📚 Official Docs**: https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/
> 
> **🛡️ Security Value**: IPs accessing many unique API endpoints with high 404/403 rates indicate reconnaissance and enumeration attacks. Attackers map API surface to find undocumented or vulnerable endpoints.
> 
> **💼 Customer Impact**: Exposes API attack surface. Attackers discover shadow APIs, deprecated endpoints, or admin functions. Precursor to targeted exploitation of discovered weaknesses.

```sql
SELECT clientrequesthost, clientip, COUNT(DISTINCT clientrequesturi) as unique_endpoints, COUNT(*) as total_requests,
    SUM(CASE WHEN edgeresponsestatus = 404 THEN 1 ELSE 0 END) as not_found,
    SUM(CASE WHEN edgeresponsestatus = 403 THEN 1 ELSE 0 END) as forbidden
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND clientrequesturi LIKE '/api/%'
GROUP BY 1, 2 HAVING COUNT(DISTINCT clientrequesturi) > 20 ORDER BY unique_endpoints DESC LIMIT 50;
```

### CF-LOG-ABU-003 [HIGH] Path Traversal Attempts

> **📚 Official Docs**: https://owasp.org/www-community/attacks/Path_Traversal
> 
> **🛡️ Security Value**: Path traversal patterns (../, ..\, /etc/passwd, /proc/self) attempt to escape web root and access sensitive system files. Successful exploitation leads to information disclosure or code execution.
> 
> **💼 Customer Impact**: Exposure of sensitive configuration files, source code, credentials, or system information. Can lead to complete server compromise if combined with other vulnerabilities.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, securityaction, edgeresponsestatus, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (clientrequesturi LIKE '%../%' OR clientrequesturi LIKE '%..\\%' OR clientrequesturi LIKE '%/etc/passwd%'
     OR clientrequesturi LIKE '%/etc/shadow%' OR clientrequesturi LIKE '%/proc/self%')
GROUP BY 1, 2, 3, 4, 5 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ABU-004 [CRITICAL] Command Injection Patterns

> **📚 Official Docs**: https://owasp.org/www-community/attacks/Command_Injection
> 
> **🛡️ Security Value**: Command injection patterns (pipes, semicolons, shell commands) reaching origin can enable arbitrary command execution on servers.
> 
> **💼 Customer Impact**: Successful command injection = full server compromise. Attackers can execute any system command, exfiltrate data, establish persistence.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (clientrequesturi LIKE '%|%' OR clientrequesturi LIKE '%;%' OR clientrequesturi LIKE '%$(%'
     OR LOWER(clientrequesturi) LIKE '%/bin/sh%' OR LOWER(clientrequesturi) LIKE '%cmd.exe%')
GROUP BY 1, 2, 3, 4 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ABU-005 [HIGH] SQL Injection Patterns

> **📚 Official Docs**: https://owasp.org/www-community/attacks/SQL_Injection
> 
> **🛡️ Security Value**: SQL injection patterns (UNION SELECT, 1=1, OR statements) in URIs indicate active database attack attempts. Pattern matching complements ML-based WAF attack scores for comprehensive detection.
> 
> **💼 Customer Impact**: Successful SQLi can dump entire databases, modify/delete data, bypass authentication, or enable lateral movement. Consistently ranked #1-3 in OWASP Top 10.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, securityaction, wafsqliattackscore, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(clientrequesturi) LIKE '%select%from%' OR LOWER(clientrequesturi) LIKE '%union%select%'
     OR LOWER(clientrequesturi) LIKE '%1=1%' OR LOWER(clientrequesturi) LIKE '%or%1%=%')
GROUP BY 1, 2, 3, 4, 5 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ABU-006 [HIGH] XSS Patterns in URI

> **📚 Official Docs**: https://owasp.org/www-community/attacks/xss/
> 
> **🛡️ Security Value**: XSS patterns (<script>, javascript:, onerror, onload) in URIs indicate cross-site scripting attempts. Successful XSS enables session hijacking, credential theft, and malware distribution.
> 
> **💼 Customer Impact**: User sessions compromised, credentials stolen, defacement, malware injection. Affects end-users directly, causing trust damage and potential regulatory issues (GDPR user data breach).

```sql
SELECT clientrequesthost, clientrequesturi, clientip, securityaction, wafxssattackscore, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(clientrequesturi) LIKE '%<script%' OR LOWER(clientrequesturi) LIKE '%javascript:%'
     OR LOWER(clientrequesturi) LIKE '%onerror%' OR LOWER(clientrequesturi) LIKE '%onload%')
GROUP BY 1, 2, 3, 4, 5 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ABU-007 [MEDIUM] Directory Bruteforce

> **📚 Official Docs**: https://owasp.org/www-community/attacks/Brute_force_attack
> 
> **🛡️ Security Value**: IPs generating high 404 volumes indicate directory/file bruteforce using wordlists. Attackers use tools like DirBuster, Gobuster, or ffuf to discover hidden content.
> 
> **💼 Customer Impact**: Discovery of backup files, admin panels, development endpoints, or configuration files. Found paths become targets for further exploitation.

```sql
SELECT clientrequesthost, clientip, COUNT(*) as total_404s
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND edgeresponsestatus = 404
GROUP BY 1, 2 HAVING COUNT(*) > 100 ORDER BY total_404s DESC LIMIT 50;
```

### CF-LOG-ABU-008 [HIGH] Admin Path Probing

> **📚 Official Docs**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
> 
> **🛡️ Security Value**: Requests to /admin, /wp-admin, /phpmyadmin, /manager indicate targeted reconnaissance for administrative interfaces. Attackers probe for unprotected or default-credential admin panels.
> 
> **💼 Customer Impact**: Admin panel discovery leads to brute force attacks, default credential testing, or exploitation of admin-specific vulnerabilities. Successful access = full application compromise.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, edgeresponsestatus, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(clientrequesturi) LIKE '%/admin%' OR LOWER(clientrequesturi) LIKE '%/wp-admin%'
     OR LOWER(clientrequesturi) LIKE '%/phpmyadmin%' OR LOWER(clientrequesturi) LIKE '%/manager%')
GROUP BY 1, 2, 3, 4 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ABU-009 [HIGH] Scanner/Tool User Agents

> **📚 Official Docs**: https://developers.cloudflare.com/bots/reference/bot-management-variables/
> 
> **🛡️ Security Value**: User agents containing sqlmap, nikto, nmap, burp, dirbuster, gobuster, ffuf indicate automated security scanning or attack tools. These are deliberate attack attempts.
> 
> **💼 Customer Impact**: Active attack in progress. Scanner tools systematically probe for vulnerabilities. While some may be legitimate penetration testing, unauthorized scanners indicate malicious reconnaissance.

```sql
SELECT clientrequesthost, clientrequestuseragent, clientip, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(clientrequestuseragent) LIKE '%sqlmap%' OR LOWER(clientrequestuseragent) LIKE '%nikto%'
     OR LOWER(clientrequestuseragent) LIKE '%nmap%' OR LOWER(clientrequestuseragent) LIKE '%masscan%'
     OR LOWER(clientrequestuseragent) LIKE '%burp%' OR LOWER(clientrequestuseragent) LIKE '%dirbuster%'
     OR LOWER(clientrequestuseragent) LIKE '%gobuster%' OR LOWER(clientrequestuseragent) LIKE '%ffuf%')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ABU-010 [MEDIUM] Empty/Missing User Agent

> **📚 Official Docs**: https://developers.cloudflare.com/ruleset-engine/rules-language/fields/#http-request-user-agent
> 
> **🛡️ Security Value**: Empty or missing User-Agent headers often indicate automated scripts, bots, or attack tools. Legitimate browsers always send User-Agent. May also indicate IoT devices or malformed clients.
> 
> **💼 Customer Impact**: Potential bot traffic or attack tools. While some legitimate API clients may omit UA, high volumes warrant investigation. Consider requiring UA on sensitive endpoints.

```sql
SELECT clientrequesthost, clientip, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (clientrequestuseragent IS NULL OR clientrequestuseragent = '' OR clientrequestuseragent = '-')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ABU-011 [HIGH] Sensitive File Access Attempts

> **📚 Official Docs**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/
> 
> **🛡️ Security Value**: Requests for .env, .git, wp-config.php, config.php, .sql, backup files indicate attempts to access sensitive configuration or data files that may contain credentials or secrets.
> 
> **💼 Customer Impact**: Exposure of database credentials, API keys, encryption secrets, or application source code. Leaked credentials enable full system compromise. Git exposure reveals entire codebase.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, edgeresponsestatus, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(clientrequesturi) LIKE '%.env%' OR LOWER(clientrequesturi) LIKE '%.git%'
     OR LOWER(clientrequesturi) LIKE '%wp-config%' OR LOWER(clientrequesturi) LIKE '%config.php%'
     OR LOWER(clientrequesturi) LIKE '%.sql%' OR LOWER(clientrequesturi) LIKE '%backup%')
GROUP BY 1, 2, 3, 4 ORDER BY count DESC LIMIT 50;
```

---

## CF-LOG-SEC: Security Event Analysis

### CF-LOG-SEC-001 [HIGH] Blocked Requests Summary

> **📚 Official Docs**: https://developers.cloudflare.com/waf/analytics/
> 
> **🛡️ Security Value**: Aggregate view of blocked requests reveals attack volume, targeted zones, and security effectiveness. High block volumes indicate active threats; low volumes may indicate gaps in protection.
> 
> **💼 Customer Impact**: Demonstrates WAF value by showing prevented attacks. Essential for executive reporting, ROI justification, and identifying zones under heaviest attack pressure.

```sql
SELECT clientrequesthost, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND securityaction IN ('block', 'challenge', 'managed_challenge', 'jschallenge')
GROUP BY 1, 2 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-SEC-002 [MEDIUM] Security Rules Triggered

> **📚 Official Docs**: https://developers.cloudflare.com/waf/analytics/paid-plans/#activity-log
> 
> **🛡️ Security Value**: Identifies which security rules are firing most frequently. Reveals attack patterns, rule effectiveness, and potential false positives. Essential for rule tuning and optimization.
> 
> **💼 Customer Impact**: Understand what threats target your application most. High-frequency rules may need tuning; unused rules may indicate coverage gaps. Enables data-driven security decisions.

```sql
SELECT clientrequesthost, securityruleid, securityruledescription, securityaction, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND securityruleid IS NOT NULL
GROUP BY 1, 2, 3, 4 ORDER BY count DESC LIMIT 100;
```

### CF-LOG-SEC-003 [HIGH] Leaked Credential Detections

> **📚 Official Docs**: https://developers.cloudflare.com/waf/managed-rules/reference/exposed-credentials-check/
> 
> **🛡️ Security Value**: Cloudflare checks credentials against known breach databases. Detections indicate users attempting to log in with compromised credentials - either legitimate users with reused passwords or attackers.
> 
> **💼 Customer Impact**: Users logging in with exposed credentials are at high risk. May indicate credential stuffing attacks or compromised user accounts. Trigger password reset flows for affected users.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, leakedcredentialcheckresult, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND leakedcredentialcheckresult IS NOT NULL AND leakedcredentialcheckresult != ''
GROUP BY 1, 2, 3, 4 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-SEC-004 [HIGH] Fraud Detection Triggers

> **📚 Official Docs**: https://developers.cloudflare.com/waf/about/fraud-detection/
> 
> **🛡️ Security Value**: Cloudflare Fraud Detection identifies account takeover attempts, fake account creation, and payment fraud. Triggers indicate sophisticated attacks beyond simple web exploits.
> 
> **💼 Customer Impact**: Direct financial impact from fraud. Account takeovers lead to unauthorized purchases, data theft, and abuse of customer accounts. Early detection prevents fraud losses.

```sql
SELECT clientrequesthost, fraudattack, clientip, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND fraudattack IS NOT NULL AND fraudattack != ''
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-SEC-005 [MEDIUM] Security Action Distribution

> **📚 Official Docs**: https://developers.cloudflare.com/waf/custom-rules/create-dashboard/#rule-action
> 
> **🛡️ Security Value**: Distribution of security actions (block, challenge, log, allow) per zone shows security posture. High allow rates may indicate gaps; high block rates may indicate attack campaigns or false positives.
> 
> **💼 Customer Impact**: Benchmark security effectiveness. Compare zones to identify inconsistent protection. Track changes over time to detect degradation or improvement in security posture.

```sql
SELECT clientrequesthost, securityaction, COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (PARTITION BY clientrequesthost), 2) as percentage
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2 ORDER BY clientrequesthost, count DESC;
```

---

## CF-LOG-ANO: Traffic Anomaly Detection

### CF-LOG-ANO-001 [HIGH] Unusual HTTP Methods

> **📚 Official Docs**: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
> 
> **🛡️ Security Value**: HTTP methods like TRACE, CONNECT, PROPFIND indicate either specialized legitimate usage or attack attempts. TRACE enables XST attacks; unusual methods may bypass WAF rules targeting GET/POST.
> 
> **💼 Customer Impact**: Potential WAF bypass or exploitation of method-specific vulnerabilities. TRACE method can expose cookies; WebDAV methods may enable unauthorized file operations.

```sql
SELECT clientrequesthost, clientrequestmethod, clientip, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND clientrequestmethod NOT IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ANO-002 [HIGH] Large Response Sizes

> **📚 Official Docs**: https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/#edgeresponsebytes
> 
> **🛡️ Security Value**: Abnormally large responses (>10MB) may indicate data exfiltration, SQL injection dumping data, or unintended exposure of large datasets. Could also signal web scraping bulk downloads.
> 
> **💼 Customer Impact**: Potential data breach in progress. Large responses to unexpected endpoints warrant immediate investigation. May indicate successful exploitation leading to mass data extraction.

```sql
SELECT clientrequesthost, clientrequesturi, clientip, edgeresponsebytes, edgeresponsestatus
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND edgeresponsebytes > 10000000
ORDER BY edgeresponsebytes DESC LIMIT 50;
```

### CF-LOG-ANO-003 [MEDIUM] Origin 5xx Errors

> **📚 Official Docs**: https://developers.cloudflare.com/support/troubleshooting/cloudflare-errors/troubleshooting-cloudflare-5xx-errors/
> 
> **🛡️ Security Value**: High 5xx error rates may indicate successful DoS attacks, application-level exploits causing crashes, or resource exhaustion. Patterns per URI reveal targeted attack endpoints.
> 
> **💼 Customer Impact**: Service degradation or outage. 5xx errors indicate origin server issues that affect user experience. May indicate attacks overwhelming application resources or exploiting crash bugs.

```sql
SELECT clientrequesthost, originresponsestatus, clientrequesturi, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND originresponsestatus >= 500
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ANO-004 [HIGH] TLS Downgrade (Old Protocols)

> **📚 Official Docs**: https://developers.cloudflare.com/ssl/reference/protocols-and-ciphers/
> 
> **🛡️ Security Value**: TLSv1.0, TLSv1.1, and SSLv3 have known vulnerabilities (POODLE, BEAST, etc.). Traffic using these protocols indicates either legacy clients or downgrade attacks attempting to exploit protocol weaknesses.
> 
> **💼 Customer Impact**: Increased risk of man-in-the-middle attacks, credential interception, or session hijacking. Compliance violations (PCI-DSS requires TLS 1.2+). Identify legacy clients for planned deprecation.

```sql
SELECT clientrequesthost, clientsslprotocol, clientip, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND clientsslprotocol IN ('TLSv1', 'TLSv1.1', 'SSLv3')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ANO-005 [MEDIUM] Weak Cipher Usage

> **📚 Official Docs**: https://developers.cloudflare.com/ssl/reference/protocols-and-ciphers/#cipher-suites
> 
> **🛡️ Security Value**: Weak ciphers (RC4, DES, MD5-based) are cryptographically broken or weakened. Traffic using these ciphers is vulnerable to decryption. May indicate legacy systems or cipher downgrade attacks.
> 
> **💼 Customer Impact**: Encrypted traffic may be decryptable by sophisticated attackers. Compliance violations for standards requiring strong cryptography. Plan cipher restriction to improve security.

```sql
SELECT clientrequesthost, clientsslcipher, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (clientsslcipher LIKE '%RC4%' OR clientsslcipher LIKE '%DES%' OR clientsslcipher LIKE '%MD5%')
GROUP BY 1, 2 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-ANO-006 [HIGH] Slow Origin Response

> **📚 Official Docs**: https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/#originresponsedurationms
> 
> **🛡️ Security Value**: Consistently slow origin responses (>5s) may indicate ReDoS attacks, application-layer DoS, resource exhaustion, or complex queries being exploited. Targeted slow requests can exhaust server resources.
> 
> **💼 Customer Impact**: User experience degradation, potential service outage, increased infrastructure costs. Attackers use slow endpoints for resource exhaustion attacks with minimal bandwidth.

```sql
SELECT clientrequesthost, clientrequesturi, AVG(originresponsedurationms) as avg_response_ms, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND originresponsedurationms > 5000
GROUP BY 1, 2 ORDER BY avg_response_ms DESC LIMIT 50;
```

### CF-LOG-ANO-007 [MEDIUM] Response Status Distribution

> **📚 Official Docs**: https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/#edgeresponsestatus
> 
> **🛡️ Security Value**: Status code distribution reveals application health and attack patterns. High 4xx rates indicate enumeration; high 5xx rates indicate availability issues; unusual patterns warrant investigation.
> 
> **💼 Customer Impact**: Baseline for normal traffic patterns. Sudden distribution changes indicate attacks or application issues. Essential for anomaly detection and operational monitoring.

```sql
SELECT clientrequesthost, edgeresponsestatus, COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (PARTITION BY clientrequesthost), 2) as percentage
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2 ORDER BY clientrequesthost, count DESC;
```

---

## CF-LOG-GEO: Geographic Analysis

### CF-LOG-GEO-001 [MEDIUM] Traffic by Country

> **📚 Official Docs**: https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/#clientcountry
> 
> **🛡️ Security Value**: Geographic traffic distribution establishes baseline for normal operations. Traffic from unexpected countries may indicate VPN/proxy evasion, attack infrastructure, or unauthorized access.
> 
> **💼 Customer Impact**: Identify geographic expansion opportunities, detect unusual access patterns, and support geo-blocking decisions. Essential baseline for geographic anomaly detection.

```sql
SELECT clientrequesthost, clientcountry, COUNT(*) as count, COUNT(DISTINCT clientip) as unique_ips
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2 ORDER BY count DESC LIMIT 100;
```

### CF-LOG-GEO-002 [HIGH] Attack Traffic by Country

> **📚 Official Docs**: https://developers.cloudflare.com/waf/about/waf-attack-score/
> 
> **🛡️ Security Value**: Correlating attack scores with geography identifies countries with disproportionate attack traffic. Supports geo-blocking decisions and identifies attack infrastructure geographic clusters.
> 
> **💼 Customer Impact**: Data-driven geo-blocking decisions. If 90% of attacks come from countries with 1% of legitimate traffic, geo-blocking ROI is clear. Identify attack campaigns by geography.

```sql
SELECT clientrequesthost, clientcountry, COUNT(*) as total_requests,
    SUM(CASE WHEN wafattackscore >= 60 THEN 1 ELSE 0 END) as high_attack_score,
    SUM(CASE WHEN securityaction IN ('block', 'challenge') THEN 1 ELSE 0 END) as blocked
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2 HAVING SUM(CASE WHEN wafattackscore >= 60 THEN 1 ELSE 0 END) > 10
ORDER BY high_attack_score DESC LIMIT 50;
```

### CF-LOG-GEO-003 [MEDIUM] City-Level Analysis

> **📚 Official Docs**: https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/#clientcity
> 
> **🛡️ Security Value**: City-level granularity reveals hosting provider concentrations (data centers) and potential botnet geographic distribution. Single cities with unusually high traffic may indicate proxy farms.
> 
> **💼 Customer Impact**: Finer-grained geographic analysis for fraud detection. Identify hosting provider abuse, proxy/VPN services, and localized attack infrastructure.

```sql
SELECT clientrequesthost, clientcountry, clientcity, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 100;
```

---

## CF-LOG-FP: Fingerprint Analysis

### CF-LOG-FP-001 [HIGH] JA3/JA4 Fingerprint Analysis

> **📚 Official Docs**: https://developers.cloudflare.com/bots/concepts/ja3-ja4-fingerprint/
> 
> **🛡️ Security Value**: TLS fingerprints uniquely identify client software. Same JA3/JA4 across many IPs indicates automated tools. Low bot scores + common fingerprint = botnet infrastructure.
> 
> **💼 Customer Impact**: Identify bot networks using same tools across distributed infrastructure. Block entire bot campaigns by fingerprint rather than IP. More resilient than IP-based blocking.

```sql
SELECT clientrequesthost, ja3hash, ja4, COUNT(DISTINCT clientip) as unique_ips, COUNT(*) as count, AVG(botscore) as avg_bot_score
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND ja3hash IS NOT NULL
GROUP BY 1, 2, 3 HAVING AVG(botscore) < 30
ORDER BY count DESC LIMIT 50;
```

### CF-LOG-FP-002 [HIGH] High Volume JA3 Fingerprints

> **📚 Official Docs**: https://developers.cloudflare.com/bots/concepts/ja3-ja4-fingerprint/
> 
> **🛡️ Security Value**: Fingerprints generating disproportionate traffic from multiple IPs indicate coordinated automation. Enables blocking bot campaigns by TLS fingerprint regardless of IP rotation.
> 
> **💼 Customer Impact**: Block sophisticated bots that rotate IPs but maintain consistent TLS fingerprint. More effective than IP blocking for distributed bot attacks.

```sql
SELECT clientrequesthost, ja3hash, COUNT(DISTINCT clientip) as unique_ips, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND ja3hash IS NOT NULL
GROUP BY 1, 2 ORDER BY count DESC LIMIT 50;
```

---

## CF-LOG-CACHE: Cache Security

### CF-LOG-CACHE-001 [HIGH] Cache Status Distribution

> **📚 Official Docs**: https://developers.cloudflare.com/cache/concepts/default-cache-behavior/
> 
> **🛡️ Security Value**: Cache status distribution reveals CDN effectiveness and potential cache bypass attacks. High MISS rates on static content may indicate cache-busting attacks or misconfigurations.
> 
> **💼 Customer Impact**: Origin server load and cost optimization. Cache BYPASS or MISS on cacheable content increases origin load and latency. Identify cache misconfigurations costing performance.

```sql
SELECT clientrequesthost, cachecachestatus, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2 ORDER BY count DESC;
```

### CF-LOG-CACHE-002 [HIGH] Cache Poisoning Indicators

> **📚 Official Docs**: https://portswigger.net/web-security/web-cache-poisoning
> 
> **🛡️ Security Value**: Requests with cache poisoning headers (X-Forwarded-Host, X-Host) attempt to poison CDN cache with malicious content. Successful cache poisoning serves malware to all users.
> 
> **💼 Customer Impact**: Cache poisoning can turn your CDN into malware distribution network. All users receive poisoned cached response. Major security incident with widespread user impact.

```sql
SELECT clientrequesthost, clientrequesturi, cachecachestatus, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(clientrequesturi) LIKE '%x-forwarded%' OR LOWER(clientrequesturi) LIKE '%x-host%')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

---

## CF-LOG-MTL: mTLS Analysis

### CF-LOG-MTL-001 [HIGH] mTLS Failures

> **📚 Official Docs**: https://developers.cloudflare.com/api-shield/security/mtls/
> 
> **🛡️ Security Value**: mTLS failures indicate either misconfigured clients, expired certificates, or unauthorized access attempts. For APIs requiring client certificates, failures may indicate attack probing.
> 
> **💼 Customer Impact**: Unauthorized API access attempts or legitimate client configuration issues. mTLS failures from known client IPs indicate certificate renewal needed; unknown IPs indicate attacks.

```sql
SELECT clientrequesthost, clientmtlsauthstatus, clientip, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND clientmtlsauthstatus IS NOT NULL AND clientmtlsauthstatus NOT IN ('', 'ok', 'success')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

---

## CF-LOG-WRK: Worker Analysis

### CF-LOG-WRK-001 [MEDIUM] Worker Error Analysis

> **📚 Official Docs**: https://developers.cloudflare.com/workers/observability/
> 
> **🛡️ Security Value**: Worker errors may indicate edge security logic failures, application bugs exploitable by attackers, or resource exhaustion attacks targeting Worker compute limits.
> 
> **💼 Customer Impact**: Edge security logic not executing properly. If Workers handle authentication or authorization, errors may create security bypasses. Monitor for targeted error-inducing attacks.

```sql
SELECT clientrequesthost, workerscriptname, workerstatus, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND workerscriptname IS NOT NULL AND workerstatus NOT IN ('', 'ok')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### CF-LOG-WRK-002 [HIGH] High Worker CPU Time

> **📚 Official Docs**: https://developers.cloudflare.com/workers/platform/limits/
> 
> **🛡️ Security Value**: Abnormally high Worker CPU time indicates either legitimate complex processing or ReDoS attacks targeting Worker regex patterns. Attackers can craft inputs that exhaust Worker compute.
> 
> **💼 Customer Impact**: Worker CPU abuse leads to increased costs, request timeouts, and potential service degradation. Investigate high-CPU requests for malicious payloads exploiting Worker code.

```sql
SELECT clientrequesthost, workerscriptname, AVG(workercputime) as avg_cpu_time, MAX(workercputime) as max_cpu_time
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND workercputime > 10000000
GROUP BY 1, 2 ORDER BY avg_cpu_time DESC LIMIT 50;
```


---

# 🔸 AWS WAF - Trino Traffic Analysis

> **TABLE**: `aws_waf_logs.waf_logs_db.{customer}_waf_logs` (e.g., `moovit_waf_logs`)
> **PARTITIONS**: `accountid`, `region`, `acl`, `year`, `month`, `day`, `hour`, `minute`
> **NOTE**: The `httprequest` field is a nested struct - access fields via `httprequest.fieldname`

## AWS-LOG-ATK: Attack Analysis

### AWS-LOG-ATK-001 [HIGH] Blocked Requests Analysis

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
> 
> **🛡️ Security Value**: Understanding what's being blocked helps tune rules, identify attack campaigns, and validate WAF effectiveness. Blocked request analysis reveals attacker TTPs and targeted endpoints.
> 
> **💼 Customer Impact**: Visibility into active threats targeting your application. Essential for threat intelligence, incident response, and demonstrating security value to stakeholders.

```sql
SELECT httprequest.host, httprequest.uri, action, terminatingruleid, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND action = 'BLOCK'
GROUP BY 1, 2, 3, 4 ORDER BY count DESC LIMIT 100;
```

### AWS-LOG-ATK-002 [HIGH] Top Attacking IPs

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-ipset-match.html
> 
> **🛡️ Security Value**: Identifying top attacking IPs enables targeted blocking and reveals attack infrastructure. High-volume attackers warrant IP set blocking; distributed attacks indicate botnets.
> 
> **💼 Customer Impact**: Actionable threat intelligence for IP blocking decisions. Identify persistent attackers for blocklisting. Geographic correlation reveals attack origin regions.

```sql
SELECT httprequest.clientip, httprequest.country, COUNT(*) as total_requests,
    SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
    COUNT(DISTINCT httprequest.uri) as unique_paths
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2 HAVING SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) > 10
ORDER BY blocked DESC LIMIT 50;
```

### AWS-LOG-ATK-003 [CRITICAL] Managed Rule Triggers

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html
> 
> **🛡️ Security Value**: When AWS managed rules fire, they've detected known attack patterns. High volumes indicate active campaigns. Identifies which managed rule groups provide most value.
> 
> **💼 Customer Impact**: Validates managed rule investment. High trigger counts justify rule costs. Low counts may indicate coverage gaps or need for additional rule groups.

```sql
SELECT httprequest.host, terminatingruleid, terminatingruletype, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND terminatingruleid IS NOT NULL
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 100;
```

### AWS-LOG-ATK-004 [HIGH] Count-Only Rule Triggers

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-action.html
> 
> **🛡️ Security Value**: Rules in COUNT mode detect but don't block. High COUNT volumes mean attacks are reaching your application. Identifies rules that should be switched to BLOCK.
> 
> **💼 Customer Impact**: Known attacks reaching application. COUNT mode provides visibility but zero protection. Long-term COUNT indicates forgotten misconfigurations or excessive caution.

```sql
SELECT httprequest.host, httprequest.uri, terminatingruleid, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND action = 'COUNT'
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 100;
```

### AWS-LOG-ATK-005 [HIGH] Action Distribution

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-action.html
> 
> **🛡️ Security Value**: Distribution of ALLOW/BLOCK/COUNT reveals security posture. High ALLOW rates may indicate gaps; high BLOCK rates indicate active threats or potential false positives.
> 
> **💼 Customer Impact**: Security posture benchmark. Track changes over time to detect policy drift. Compare across ACLs to identify inconsistent protection levels.

```sql
SELECT httprequest.host, action, COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2 ORDER BY count DESC;
```

---

## AWS-LOG-ABU: Abuse Pattern Detection

### AWS-LOG-ABU-001 [HIGH] Credential Stuffing Detection

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html
> 
> **🛡️ Security Value**: High-volume POST requests to authentication endpoints indicate credential stuffing. Attackers test stolen credentials systematically. Time window analysis reveals attack intensity.
> 
> **💼 Customer Impact**: Account takeover at scale. Compromised accounts enable fraud, data theft, and abuse. Early detection enables protective measures like MFA enforcement or account lockouts.

```sql
SELECT httprequest.clientip, httprequest.host, COUNT(*) as login_attempts,
    from_unixtime(MIN(timestamp)/1000) as first_attempt, from_unixtime(MAX(timestamp)/1000) as last_attempt
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND httprequest.httpmethod = 'POST'
AND (httprequest.uri LIKE '%login%' OR httprequest.uri LIKE '%signin%' OR httprequest.uri LIKE '%auth%')
GROUP BY 1, 2 HAVING COUNT(*) > 50 ORDER BY login_attempts DESC LIMIT 50;
```

### AWS-LOG-ABU-002 [HIGH] Rate Violation Analysis

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html
> 
> **🛡️ Security Value**: IPs with abnormally high request rates indicate abuse, scraping, or DoS attempts. Identifies candidates for rate limiting and reveals effectiveness of existing rate rules.
> 
> **💼 Customer Impact**: Resource exhaustion, increased costs, and degraded performance for legitimate users. Rate abusers consume disproportionate resources. Block or rate-limit identified abusers.

```sql
SELECT httprequest.clientip, httprequest.country, COUNT(*) as request_count,
    COUNT(DISTINCT httprequest.uri) as unique_paths
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY} AND hour = {HOUR}
GROUP BY 1, 2 HAVING COUNT(*) > 1000 ORDER BY request_count DESC LIMIT 50;
```

### AWS-LOG-ABU-003 [CRITICAL] SQL Injection Patterns

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html#aws-managed-rule-groups-use-case-sql-db
> 
> **🛡️ Security Value**: SQL injection patterns (UNION SELECT, OR 1=1) in URIs or arguments indicate database attack attempts. Pattern matching complements managed rules for comprehensive SQLi detection.
> 
> **💼 Customer Impact**: Database compromise risk. Successful SQLi leads to data exfiltration, data destruction, or privilege escalation. A single successful injection can dump entire databases.

```sql
SELECT httprequest.clientip, httprequest.uri, httprequest.args, action, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(httprequest.uri) LIKE '%select%from%' OR LOWER(httprequest.uri) LIKE '%union%select%'
     OR LOWER(httprequest.args) LIKE '%select%from%')
GROUP BY 1, 2, 3, 4 ORDER BY count DESC LIMIT 50;
```

### AWS-LOG-ABU-004 [HIGH] Path Traversal Attempts

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html
> 
> **🛡️ Security Value**: Path traversal patterns (../, ..\) attempt to escape web root and access sensitive files. Successful exploitation leads to configuration exposure or source code leak.
> 
> **💼 Customer Impact**: Exposure of server files including configuration, credentials, and source code. May reveal infrastructure details enabling further attacks.

```sql
SELECT httprequest.clientip, httprequest.uri, action, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (httprequest.uri LIKE '%../%' OR httprequest.uri LIKE '%..\\%')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### AWS-LOG-ABU-005 [HIGH] Admin Path Probing

> **📚 Official Docs**: https://owasp.org/www-project-web-security-testing-guide/
> 
> **🛡️ Security Value**: Requests to /admin, /manager paths indicate reconnaissance for administrative interfaces. Attackers probe for unprotected admin panels or default credentials.
> 
> **💼 Customer Impact**: Admin panel discovery leads to brute force, credential testing, or exploitation. Successful admin access = complete application compromise.

```sql
SELECT httprequest.clientip, httprequest.uri, action, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (LOWER(httprequest.uri) LIKE '%/admin%' OR LOWER(httprequest.uri) LIKE '%/manager%')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

---

## AWS-LOG-SEC: Security Event Analysis

### AWS-LOG-SEC-001 [HIGH] Label Analysis

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-labels.html
> 
> **🛡️ Security Value**: AWS WAF labels provide granular visibility into why requests matched rules. Labels enable cross-rule logic and detailed attack classification beyond simple rule names.
> 
> **💼 Customer Impact**: Understand attack types at granular level. Labels like "awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF" specify exact attack detected. Essential for targeted remediation.

```sql
SELECT httprequest.host, l.name as label_name, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
CROSS JOIN UNNEST(labels) AS t(l)
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2 ORDER BY count DESC LIMIT 100;
```

### AWS-LOG-SEC-002 [MEDIUM] CAPTCHA Response Analysis

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge.html
> 
> **🛡️ Security Value**: CAPTCHA response analysis reveals bot versus human traffic patterns. High failure rates indicate automated attacks; successful completions suggest legitimate users or advanced bots.
> 
> **💼 Customer Impact**: Validate CAPTCHA effectiveness. If bots consistently fail CAPTCHA, it's working. If they pass, consider stronger bot protection. Monitor for false positive impact on users.

```sql
SELECT httprequest.host, captcharesponse.responsecode, captcharesponse.failurereason, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND captcharesponse IS NOT NULL
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### AWS-LOG-SEC-003 [HIGH] Challenge Response Analysis

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge.html#waf-challenge
> 
> **🛡️ Security Value**: Challenge responses (silent JavaScript validation) distinguish browsers from simple bots. Failure patterns reveal automation tools that can't execute JavaScript challenges.
> 
> **💼 Customer Impact**: Less intrusive than CAPTCHA while blocking simple automation. High failure rates validate challenge effectiveness. Monitor for legitimate browser compatibility issues.

```sql
SELECT httprequest.host, challengeresponse.responsecode, challengeresponse.failurereason, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND challengeresponse IS NOT NULL
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### AWS-LOG-SEC-004 [HIGH] Oversize Request Analysis

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html
> 
> **🛡️ Security Value**: Oversized requests may indicate buffer overflow attempts, DoS attacks, or payload smuggling. Large requests bypass default WAF inspection limits, creating blind spots.
> 
> **💼 Customer Impact**: Potential WAF evasion through payload size manipulation. Attackers craft oversized requests to hide malicious content beyond WAF inspection range. Monitor for exploitation attempts.

```sql
SELECT httprequest.host, httprequest.uri, requestbodysize, requestbodysizeinspectedbywaf, oversizefields, action, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND (oversizefields IS NOT NULL OR requestbodysize > requestbodysizeinspectedbywaf)
GROUP BY 1, 2, 3, 4, 5, 6 ORDER BY count DESC LIMIT 50;
```

---

## AWS-LOG-ANO: Anomaly Detection

### AWS-LOG-ANO-001 [HIGH] Unusual HTTP Methods

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-byte-match.html
> 
> **🛡️ Security Value**: HTTP methods like TRACE, CONNECT, PROPFIND may indicate attack attempts or specialized exploitation. Most applications only need GET/POST/PUT/DELETE.
> 
> **💼 Customer Impact**: Potential WAF bypass or method-specific vulnerabilities. TRACE enables XST attacks; unusual methods may exploit unhandled code paths. Block unnecessary methods.

```sql
SELECT httprequest.host, httprequest.httpmethod, httprequest.clientip, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND httprequest.httpmethod NOT IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD')
GROUP BY 1, 2, 3 ORDER BY count DESC LIMIT 50;
```

### AWS-LOG-ANO-002 [MEDIUM] User Agent Analysis

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html
> 
> **🛡️ Security Value**: User agent distribution reveals traffic composition. Scanner tools, outdated browsers, or unusual UAs indicate potential threats. High IP diversity per UA may indicate botnets.
> 
> **💼 Customer Impact**: Identify attack tools (sqlmap, nikto), outdated/vulnerable browsers, and suspicious automation. Baseline normal UA distribution to detect anomalies.

```sql
SELECT httprequest.host, 
    element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value AS user_agent,
    COUNT(*) as count, COUNT(DISTINCT httprequest.clientip) as unique_ips
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2 ORDER BY count DESC LIMIT 100;
```

### AWS-LOG-ANO-003 [HIGH] Geographic Distribution

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-geo-match.html
> 
> **🛡️ Security Value**: Geographic traffic distribution correlated with block rates reveals attack origin countries. Disproportionate blocks from specific countries may warrant geo-blocking.
> 
> **💼 Customer Impact**: Data-driven geo-blocking decisions. Identify countries with high attack-to-legitimate ratio. Support compliance requirements for geographic access restrictions.

```sql
SELECT httprequest.host, httprequest.country, COUNT(*) as count,
    SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked,
    COUNT(DISTINCT httprequest.clientip) as unique_ips
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
GROUP BY 1, 2 ORDER BY count DESC LIMIT 100;
```

### AWS-LOG-ANO-004 [MEDIUM] Request Body Size Distribution

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html
> 
> **🛡️ Security Value**: Request body size distribution establishes baseline. Abnormally large requests may indicate DoS attempts, data exfiltration uploads, or payload smuggling attacks.
> 
> **💼 Customer Impact**: Detect file upload abuse, oversized payload attacks, and resource exhaustion. Size limits protect against buffer overflows and excessive processing.

```sql
SELECT httprequest.host, 
    CASE WHEN requestbodysize < 1000 THEN 'small_under_1k'
         WHEN requestbodysize < 10000 THEN 'medium_1k_10k'
         WHEN requestbodysize < 100000 THEN 'large_10k_100k'
         ELSE 'xlarge_over_100k' END as size_bucket,
    COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND requestbodysize IS NOT NULL
GROUP BY 1, 2 ORDER BY count DESC;
```

---

## AWS-LOG-FP: Fingerprint Analysis

### AWS-LOG-FP-001 [HIGH] JA3 Fingerprint Analysis

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields.html#waf-rule-statement-ja3-fingerprint
> 
> **🛡️ Security Value**: JA3 TLS fingerprints uniquely identify client software. Same JA3 across many IPs indicates automated tools or botnets. More persistent identifier than IP address.
> 
> **💼 Customer Impact**: Block bot campaigns by TLS fingerprint regardless of IP rotation. Identify and block attack infrastructure using consistent tooling. Superior to IP-only blocking.

```sql
SELECT httprequest.host, ja3fingerprint, COUNT(DISTINCT httprequest.clientip) as unique_ips, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND ja3fingerprint IS NOT NULL
GROUP BY 1, 2 ORDER BY count DESC LIMIT 50;
```

### AWS-LOG-FP-002 [HIGH] JA4 Fingerprint Analysis

> **📚 Official Docs**: https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-fields.html#waf-rule-statement-ja4-fingerprint
> 
> **🛡️ Security Value**: JA4 is the next-generation TLS fingerprint with improved detection capabilities. Captures additional TLS extension data for more precise client identification than JA3.
> 
> **💼 Customer Impact**: More accurate bot detection than JA3. JA4 captures QUIC/HTTP3 signatures and provides better discrimination between similar clients. Future-proof fingerprinting.

```sql
SELECT httprequest.host, ja4fingerprint, COUNT(DISTINCT httprequest.clientip) as unique_ips, COUNT(*) as count
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND ja4fingerprint IS NOT NULL
GROUP BY 1, 2 ORDER BY count DESC LIMIT 50;
```

---

# PART 3: AI AGENT EXECUTION INSTRUCTIONS

---

## Execution Protocol for AI Agents

### Step 1: Identify Target
1. Determine the organization to analyze
2. Get organization_id from PostgreSQL: `SELECT id, org_display_name FROM organization WHERE org_display_name ILIKE '%{NAME}%'`
3. Note the organization_id for use in queries

### Step 2: PostgreSQL Configuration Analysis
Execute ALL PostgreSQL queries in order:
1. Replace `{ORGANIZATION_ID}` with actual organization UUID
2. Execute each query
3. Record findings with severity level
4. Note any CRITICAL or HIGH findings for immediate attention

### Step 3: Trino Log Analysis
1. Identify available log tables for the customer
2. Determine appropriate time range (recommend last 7 days)
3. Set partition values: `year`, `month`, `day`, `hour`
4. For AWS WAF: Also set `accountid`, `region`, `acl`
5. Execute each query systematically
6. Record findings with counts and severity

### Step 4: Cross-Reference Findings
1. Correlate PostgreSQL config issues with Trino traffic patterns
2. Example: If CF-RULE-001 finds SKIP rules, check CF-LOG-ATK for bypassed attacks
3. Prioritize findings that appear in both configuration AND traffic

### Step 5: Generate Report
1. Group findings by vendor (Cloudflare, Akamai, AWS)
2. Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
3. Include evidence (query results)
4. Provide remediation recommendations

---

## Query Placeholders Reference

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `{ORGANIZATION_ID}` | PostgreSQL org UUID | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| `{CUSTOMER}` | Trino table customer name | `quillbot`, `moovit` |
| `{ACCOUNT_ID}` | AWS Account ID | `254431071183` |
| `{REGION}` | AWS Region | `cloudfront`, `us-east-1` |
| `{ACL_NAME}` | AWS WAF ACL name | `moovitapp-com` |
| `{YEAR}` | Year partition | `2025` |
| `{MONTH}` | Month partition | `12` |
| `{DAY}` | Day partition | `21` |
| `{HOUR}` | Hour partition | `6` |

---

## Severity Definitions

| Severity | Description | Action Required |
|----------|-------------|-----------------|
| **CRITICAL** | Immediate security risk, active bypass possible | Fix within 24 hours |
| **HIGH** | Significant security gap, attack surface exposed | Fix within 1 week |
| **MEDIUM** | Suboptimal configuration, moderate risk | Fix within 1 month |
| **LOW** | Best practice deviation, minimal risk | Fix when convenient |
| **INFO** | Informational, no action needed | Document only |

---

**Document Version:** 4.0
**Total Checks:** 150+ PostgreSQL + 100+ Trino = 250+ Security Checks
**Last Updated:** January 2026


---

# PART 4: CONFIGURATION-TO-LOG CORRELATION ANALYSIS

> **PURPOSE**: When a misconfiguration is detected in PostgreSQL, this section tells the AI agent exactly what to look for in the traffic logs to confirm exploitation or risk exposure.

---

## Correlation Matrix: Config Finding → Log Investigation

### CLOUDFLARE Correlations

| Config Finding | Log Investigation | Query Pattern |
|----------------|-------------------|---------------|
| CF-RULE-001 (SKIP without IP) | Look for high attack scores that weren't blocked on affected zones | CF-CORR-001 |
| CF-RULE-003 (Log-only rules) | Check if attacks are being logged but not blocked | CF-CORR-002 |
| CF-BOT-001 (No bot management) | Analyze bot score distribution - are low scores getting through? | CF-CORR-003 |
| CF-BOT-003 (Automated allowed) | Find definite bots (score <10) that reached origin | CF-CORR-004 |
| CF-RATE-001 (No rate limiting on API) | Look for high-volume single IPs on API endpoints | CF-CORR-005 |
| CF-ZONE-003 (Unproxied records) | N/A - traffic bypasses CF entirely, check origin logs | N/A |
| CF-RULE-006 (Skipping phases) | Compare attack scores vs security actions on affected zones | CF-CORR-006 |
| CF-DNS-001 (External CNAME) | Check for unusual response patterns from external origins | CF-CORR-007 |

### AKAMAI Correlations

| Config Finding | Log Investigation | Query Pattern |
|----------------|-------------------|---------------|
| AK-POLICY-002 (Attack groups not deny) | Look for attack patterns that triggered alerts but weren't blocked | AK-CORR-001 |
| AK-POLICY-003 (Slow POST disabled) | Check for slow/large POST requests to sensitive endpoints | AK-CORR-002 |
| AK-RATE-001 (Rate alert only) | Find IPs exceeding thresholds that weren't rate-limited | AK-CORR-003 |
| AK-BOT-001 (Bot categories unprotected) | Analyze known bot signatures that reached origin | AK-CORR-004 |

### AWS WAF Correlations

| Config Finding | Log Investigation | Query Pattern |
|----------------|-------------------|---------------|
| AWS-RULE-001 (Rules in count mode) | Find requests that triggered COUNT rules - what would have been blocked? | AWS-CORR-001 |
| AWS-MRG-001 (No managed rules) | Look for attack patterns that should have been caught | AWS-CORR-002 |
| AWS-MRG-006 (Override to count) | Analyze what managed rules are being bypassed | AWS-CORR-003 |
| AWS-ACL-004 (Default ALLOW) | Check requests reaching default action - are they malicious? | AWS-CORR-004 |

---

## CF-CORR: Cloudflare Correlation Queries

### CF-CORR-001 [CRITICAL] Validate SKIP Rule Exploitation
**Context**: When CF-RULE-001 finds SKIP rules without IP restriction, run this to see if attacks are bypassing WAF.
```sql
-- Find high attack score requests that weren't blocked on zones with SKIP rules
-- Replace {ZONE_NAMES} with comma-separated zone names from CF-RULE-001 findings
WITH zone_traffic AS (
    SELECT 
        clientrequesthost,
        clientrequesturi,
        clientip,
        clientcountry,
        wafattackscore,
        wafsqliattackscore,
        wafxssattackscore,
        securityaction,
        edgeresponsestatus,
        edgestarttimestamp
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND clientrequesthost IN ({ZONE_NAMES})
),
attack_analysis AS (
    SELECT 
        clientrequesthost,
        clientip,
        COUNT(*) as total_requests,
        COUNT(CASE WHEN wafattackscore >= 60 THEN 1 END) as high_attack_requests,
        COUNT(CASE WHEN wafattackscore >= 60 AND securityaction NOT IN ('block', 'challenge') THEN 1 END) as unblocked_attacks,
        AVG(CASE WHEN wafattackscore >= 60 THEN wafattackscore END) as avg_attack_score,
        COUNT(DISTINCT clientrequesturi) as unique_paths_attacked
    FROM zone_traffic
    GROUP BY 1, 2
)
SELECT 
    clientrequesthost,
    clientip,
    total_requests,
    high_attack_requests,
    unblocked_attacks,
    ROUND(unblocked_attacks * 100.0 / NULLIF(high_attack_requests, 0), 1) as bypass_rate_pct,
    avg_attack_score,
    unique_paths_attacked,
    'CRITICAL: SKIP rule may be bypassing WAF - ' || unblocked_attacks || ' unblocked attacks' as finding
FROM attack_analysis
WHERE high_attack_requests > 0 AND unblocked_attacks > 0
ORDER BY unblocked_attacks DESC
LIMIT 50;
```

### CF-CORR-002 [HIGH] Validate Log-Only Rule Impact
**Context**: When CF-RULE-003 finds log-only rules, run this to quantify attack volume being logged but not blocked.
```sql
-- Analyze attacks that are being logged but not blocked
WITH security_events AS (
    SELECT 
        clientrequesthost,
        securityruleid,
        securityruledescription,
        securityaction,
        wafattackscore,
        clientip,
        clientrequesturi,
        COUNT(*) as event_count
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND securityruleid IS NOT NULL
    GROUP BY 1, 2, 3, 4, 5, 6, 7
)
SELECT 
    clientrequesthost,
    securityruleid,
    securityruledescription,
    securityaction,
    COUNT(DISTINCT clientip) as unique_attackers,
    SUM(event_count) as total_events,
    AVG(wafattackscore) as avg_attack_score,
    CASE 
        WHEN securityaction IN ('log', 'simulate', 'monitor') THEN 'WARNING: Rule is log-only'
        WHEN securityaction IS NULL THEN 'WARNING: No action taken'
        ELSE 'OK: Action applied'
    END as status
FROM security_events
GROUP BY 1, 2, 3, 4
HAVING securityaction IN ('log', 'simulate', 'monitor', NULL)
ORDER BY total_events DESC
LIMIT 50;
```

### CF-CORR-003 [HIGH] Validate Bot Management Gap
**Context**: When CF-BOT-001 finds zones without bot management, analyze actual bot traffic.
```sql
-- Analyze bot traffic on zones without bot management
WITH bot_traffic AS (
    SELECT 
        clientrequesthost,
        botscore,
        botscoresrc,
        verifiedbotcategory,
        clientip,
        clientrequestuseragent,
        securityaction,
        edgeresponsestatus
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND botscore IS NOT NULL
)
SELECT 
    clientrequesthost,
    -- Bot classification
    COUNT(CASE WHEN botscore <= 10 THEN 1 END) as definite_bots,
    COUNT(CASE WHEN botscore > 10 AND botscore <= 30 THEN 1 END) as likely_bots,
    COUNT(CASE WHEN botscore > 30 AND botscore <= 70 THEN 1 END) as uncertain,
    COUNT(CASE WHEN botscore > 70 THEN 1 END) as likely_human,
    -- Unblocked bot traffic
    COUNT(CASE WHEN botscore <= 30 AND (securityaction IS NULL OR securityaction = 'allow') THEN 1 END) as unblocked_bots,
    -- Unique bot IPs
    COUNT(DISTINCT CASE WHEN botscore <= 30 THEN clientip END) as unique_bot_ips,
    -- Risk assessment
    ROUND(COUNT(CASE WHEN botscore <= 30 AND (securityaction IS NULL OR securityaction = 'allow') THEN 1 END) * 100.0 / 
          NULLIF(COUNT(CASE WHEN botscore <= 30 THEN 1 END), 0), 1) as bot_bypass_rate_pct
FROM bot_traffic
GROUP BY 1
HAVING COUNT(CASE WHEN botscore <= 30 THEN 1 END) > 100
ORDER BY unblocked_bots DESC;
```

### CF-CORR-004 [CRITICAL] Validate Automated Traffic Bypass
**Context**: When CF-BOT-003 finds automated traffic allowed, quantify the exposure.
```sql
-- Find definite automation reaching origin
SELECT 
    clientrequesthost,
    clientip,
    botscore,
    botscoresrc,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientrequesturi) as unique_paths,
    COUNT(CASE WHEN edgeresponsestatus BETWEEN 200 AND 299 THEN 1 END) as successful_requests,
    -- Sample of paths accessed
    ARRAY_AGG(DISTINCT clientrequesturi ORDER BY clientrequesturi LIMIT 5) as sample_paths,
    'CRITICAL: Definite automation (score ' || botscore || ') reaching origin' as finding
FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
AND botscore <= 10
AND botscoresrc != 'verified_bot'
AND (securityaction IS NULL OR securityaction = 'allow')
GROUP BY 1, 2, 3, 4
HAVING COUNT(*) > 50
ORDER BY request_count DESC
LIMIT 50;
```

### CF-CORR-005 [HIGH] Validate Rate Limiting Gap on APIs
**Context**: When CF-RATE-001 finds APIs without rate limiting, check for abuse.
```sql
-- Find high-volume IPs on API endpoints that should have been rate-limited
WITH api_traffic AS (
    SELECT 
        clientrequesthost,
        clientip,
        clientrequesturi,
        clientrequestmethod,
        edgeresponsestatus,
        -- Time bucketing for rate analysis
        date_trunc('minute', from_iso8601_timestamp(edgestarttimestamp)) as minute_bucket
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND clientrequesturi LIKE '/api/%'
),
rate_analysis AS (
    SELECT 
        clientrequesthost,
        clientip,
        minute_bucket,
        COUNT(*) as requests_per_minute,
        COUNT(DISTINCT clientrequesturi) as unique_endpoints,
        COUNT(CASE WHEN edgeresponsestatus = 429 THEN 1 END) as rate_limited
    FROM api_traffic
    GROUP BY 1, 2, 3
)
SELECT 
    clientrequesthost,
    clientip,
    COUNT(DISTINCT minute_bucket) as active_minutes,
    MAX(requests_per_minute) as peak_rpm,
    AVG(requests_per_minute) as avg_rpm,
    SUM(rate_limited) as times_rate_limited,
    CASE 
        WHEN MAX(requests_per_minute) > 1000 AND SUM(rate_limited) = 0 THEN 'CRITICAL: No rate limiting despite >1000 RPM'
        WHEN MAX(requests_per_minute) > 500 AND SUM(rate_limited) = 0 THEN 'HIGH: No rate limiting despite >500 RPM'
        WHEN MAX(requests_per_minute) > 100 AND SUM(rate_limited) = 0 THEN 'MEDIUM: Consider rate limiting'
        ELSE 'OK'
    END as finding
FROM rate_analysis
GROUP BY 1, 2
HAVING MAX(requests_per_minute) > 100 AND SUM(rate_limited) = 0
ORDER BY MAX(requests_per_minute) DESC
LIMIT 50;
```

### CF-CORR-006 [CRITICAL] Validate WAF Phase Skip Impact
**Context**: When CF-RULE-006 finds rules skipping WAF phases, verify if attacks are bypassing.
```sql
-- Compare attack detection vs actual blocking on zones with phase skips
WITH zone_security AS (
    SELECT 
        clientrequesthost,
        -- Attack detection
        wafattackscore,
        wafsqliattackscore,
        wafxssattackscore,
        wafrceattackscore,
        -- Security response
        securityaction,
        securityruleid,
        -- Request context
        clientip,
        clientrequesturi,
        clientrequestmethod
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND clientrequesthost IN ({ZONE_NAMES_WITH_PHASE_SKIPS})
)
SELECT 
    clientrequesthost,
    -- Attack volume
    COUNT(CASE WHEN wafattackscore >= 60 THEN 1 END) as high_attack_score_count,
    COUNT(CASE WHEN wafsqliattackscore >= 60 THEN 1 END) as sqli_detected,
    COUNT(CASE WHEN wafxssattackscore >= 60 THEN 1 END) as xss_detected,
    COUNT(CASE WHEN wafrceattackscore >= 60 THEN 1 END) as rce_detected,
    -- Blocking effectiveness
    COUNT(CASE WHEN wafattackscore >= 60 AND securityaction IN ('block', 'challenge') THEN 1 END) as attacks_blocked,
    COUNT(CASE WHEN wafattackscore >= 60 AND (securityaction IS NULL OR securityaction NOT IN ('block', 'challenge')) THEN 1 END) as attacks_bypassed,
    -- Bypass rate
    ROUND(COUNT(CASE WHEN wafattackscore >= 60 AND (securityaction IS NULL OR securityaction NOT IN ('block', 'challenge')) THEN 1 END) * 100.0 /
          NULLIF(COUNT(CASE WHEN wafattackscore >= 60 THEN 1 END), 0), 1) as bypass_rate_pct,
    -- Verdict
    CASE 
        WHEN COUNT(CASE WHEN wafattackscore >= 60 AND (securityaction IS NULL OR securityaction NOT IN ('block', 'challenge')) THEN 1 END) > 100 
        THEN 'CRITICAL: Phase skip causing significant attack bypass'
        WHEN COUNT(CASE WHEN wafattackscore >= 60 AND (securityaction IS NULL OR securityaction NOT IN ('block', 'challenge')) THEN 1 END) > 10
        THEN 'HIGH: Phase skip may be causing attack bypass'
        ELSE 'OK'
    END as finding
FROM zone_security
GROUP BY 1
ORDER BY attacks_bypassed DESC;
```

---

## AWS-CORR: AWS WAF Correlation Queries

### AWS-CORR-001 [HIGH] Validate Count Mode Rule Impact
**Context**: When AWS-RULE-001 finds rules in count mode, analyze what's being counted but not blocked.
```sql
-- Analyze requests that triggered COUNT rules
WITH count_events AS (
    SELECT 
        httprequest.host,
        httprequest.uri,
        httprequest.clientip,
        httprequest.country,
        httprequest.httpmethod,
        terminatingruleid,
        action,
        timestamp
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
    AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND action = 'COUNT'
)
SELECT 
    httprequest.host,
    terminatingruleid,
    COUNT(*) as count_events,
    COUNT(DISTINCT httprequest.clientip) as unique_ips,
    COUNT(DISTINCT httprequest.uri) as unique_paths,
    -- Sample URIs
    ARRAY_AGG(DISTINCT httprequest.uri ORDER BY httprequest.uri LIMIT 5) as sample_uris,
    -- Geographic distribution
    ARRAY_AGG(DISTINCT httprequest.country ORDER BY httprequest.country LIMIT 10) as countries,
    'HIGH: Rule ' || terminatingruleid || ' in COUNT mode - ' || COUNT(*) || ' events would have been blocked' as finding
FROM count_events
GROUP BY 1, 2
ORDER BY count_events DESC
LIMIT 50;
```

### AWS-CORR-002 [CRITICAL] Validate Missing Managed Rules Impact
**Context**: When AWS-MRG-001 finds no managed rules, look for attack patterns that should have been caught.
```sql
-- Find attack patterns that AWS managed rules would have caught
WITH potential_attacks AS (
    SELECT 
        httprequest.host,
        httprequest.uri,
        httprequest.clientip,
        httprequest.httpmethod,
        action,
        -- Pattern matching for common attacks
        CASE 
            WHEN LOWER(httprequest.uri) LIKE '%select%from%' OR LOWER(httprequest.uri) LIKE '%union%select%' THEN 'SQLi'
            WHEN LOWER(httprequest.uri) LIKE '%<script%' OR LOWER(httprequest.uri) LIKE '%javascript:%' THEN 'XSS'
            WHEN httprequest.uri LIKE '%../%' OR httprequest.uri LIKE '%/etc/passwd%' THEN 'Path Traversal'
            WHEN LOWER(httprequest.uri) LIKE '%cmd.exe%' OR LOWER(httprequest.uri) LIKE '%/bin/sh%' THEN 'RCE'
            WHEN LOWER(httprequest.uri) LIKE '%.env%' OR LOWER(httprequest.uri) LIKE '%wp-config%' THEN 'Sensitive File'
            ELSE NULL
        END as attack_type
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
    AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
)
SELECT 
    httprequest.host,
    attack_type,
    COUNT(*) as attack_count,
    COUNT(DISTINCT httprequest.clientip) as unique_attackers,
    COUNT(CASE WHEN action = 'ALLOW' THEN 1 END) as allowed_through,
    ROUND(COUNT(CASE WHEN action = 'ALLOW' THEN 1 END) * 100.0 / COUNT(*), 1) as allow_rate_pct,
    'CRITICAL: ' || attack_type || ' pattern allowed through - managed rules would block' as finding
FROM potential_attacks
WHERE attack_type IS NOT NULL
GROUP BY 1, 2
HAVING COUNT(CASE WHEN action = 'ALLOW' THEN 1 END) > 0
ORDER BY allowed_through DESC
LIMIT 50;
```

### AWS-CORR-003 [HIGH] Validate Managed Rule Override Impact
**Context**: When AWS-MRG-006 finds overrides to count, analyze what's being bypassed.
```sql
-- Find requests that matched overridden managed rules
WITH rule_matches AS (
    SELECT 
        httprequest.host,
        httprequest.uri,
        httprequest.clientip,
        terminatingruleid,
        terminatingruletype,
        action,
        -- Extract rule group info
        rulegrouplist
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
    AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND action = 'COUNT'
    AND terminatingruletype = 'MANAGED_RULE_GROUP'
)
SELECT 
    httprequest.host,
    terminatingruleid,
    COUNT(*) as count_events,
    COUNT(DISTINCT httprequest.clientip) as unique_ips,
    ARRAY_AGG(DISTINCT httprequest.uri ORDER BY httprequest.uri LIMIT 5) as sample_uris,
    'HIGH: Managed rule ' || terminatingruleid || ' overridden to COUNT - attacks not blocked' as finding
FROM rule_matches
GROUP BY 1, 2
ORDER BY count_events DESC
LIMIT 50;
```

---

# PART 5: CONTEXT-AWARE TRINO QUERIES

> **PURPOSE**: These queries analyze traffic patterns with temporal, behavioral, and endpoint context to identify sophisticated attacks and anomalies.

---

## CF-CTX: Cloudflare Context-Aware Analysis

### CF-CTX-001 [CRITICAL] Temporal Attack Correlation
**Purpose**: Find attack patterns happening around the same time on the same host.
```sql
-- Analyze attack patterns with temporal context (5-minute windows)
WITH timestamped_attacks AS (
    SELECT 
        clientrequesthost,
        clientip,
        clientrequesturi,
        wafattackscore,
        securityaction,
        date_trunc('minute', from_iso8601_timestamp(edgestarttimestamp)) as minute_ts,
        -- Create 5-minute windows
        date_trunc('minute', from_iso8601_timestamp(edgestarttimestamp)) - 
            (EXTRACT(MINUTE FROM from_iso8601_timestamp(edgestarttimestamp)) % 5) * INTERVAL '1' MINUTE as window_5min
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND clientrequesthost = '{TARGET_HOST}'
    AND wafattackscore >= 50
),
window_analysis AS (
    SELECT 
        clientrequesthost,
        window_5min,
        COUNT(*) as attacks_in_window,
        COUNT(DISTINCT clientip) as unique_attackers,
        COUNT(DISTINCT clientrequesturi) as unique_paths,
        AVG(wafattackscore) as avg_attack_score,
        COUNT(CASE WHEN securityaction IN ('block', 'challenge') THEN 1 END) as blocked,
        COUNT(CASE WHEN securityaction IS NULL OR securityaction NOT IN ('block', 'challenge') THEN 1 END) as bypassed,
        ARRAY_AGG(DISTINCT clientip ORDER BY clientip LIMIT 10) as attacker_ips
    FROM timestamped_attacks
    GROUP BY 1, 2
)
SELECT 
    clientrequesthost,
    window_5min as attack_window,
    attacks_in_window,
    unique_attackers,
    unique_paths,
    ROUND(avg_attack_score, 1) as avg_score,
    blocked,
    bypassed,
    attacker_ips,
    CASE 
        WHEN attacks_in_window > 100 AND unique_attackers > 10 THEN 'CRITICAL: Coordinated attack - multiple IPs, same window'
        WHEN attacks_in_window > 50 AND unique_attackers = 1 THEN 'HIGH: Single attacker burst - possible scanner'
        WHEN attacks_in_window > 20 THEN 'MEDIUM: Elevated attack activity'
        ELSE 'LOW'
    END as severity
FROM window_analysis
WHERE attacks_in_window > 10
ORDER BY attacks_in_window DESC
LIMIT 50;
```

### CF-CTX-002 [HIGH] Endpoint Attack Pattern Analysis
**Purpose**: Analyze attack patterns per endpoint with surrounding context.
```sql
-- Analyze attack patterns by endpoint with behavioral context
WITH endpoint_traffic AS (
    SELECT 
        clientrequesthost,
        clientrequesturi,
        clientrequestpath,
        clientip,
        clientcountry,
        clientrequestmethod,
        wafattackscore,
        botscore,
        securityaction,
        edgeresponsestatus,
        edgeresponsebytes
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND clientrequesthost = '{TARGET_HOST}'
),
endpoint_analysis AS (
    SELECT 
        clientrequesthost,
        clientrequestpath,
        -- Volume metrics
        COUNT(*) as total_requests,
        COUNT(DISTINCT clientip) as unique_ips,
        -- Attack metrics
        COUNT(CASE WHEN wafattackscore >= 50 THEN 1 END) as attack_requests,
        AVG(wafattackscore) as avg_attack_score,
        -- Bot metrics
        AVG(botscore) as avg_bot_score,
        COUNT(CASE WHEN botscore <= 30 THEN 1 END) as bot_requests,
        -- Response analysis
        COUNT(CASE WHEN edgeresponsestatus BETWEEN 200 AND 299 THEN 1 END) as success_2xx,
        COUNT(CASE WHEN edgeresponsestatus BETWEEN 400 AND 499 THEN 1 END) as client_error_4xx,
        COUNT(CASE WHEN edgeresponsestatus >= 500 THEN 1 END) as server_error_5xx,
        -- Security actions
        COUNT(CASE WHEN securityaction IN ('block', 'challenge') THEN 1 END) as blocked,
        -- Geographic spread
        COUNT(DISTINCT clientcountry) as country_count,
        -- Method distribution
        COUNT(CASE WHEN clientrequestmethod = 'POST' THEN 1 END) as post_requests
    FROM endpoint_traffic
    GROUP BY 1, 2
)
SELECT 
    clientrequesthost,
    clientrequestpath,
    total_requests,
    unique_ips,
    attack_requests,
    ROUND(attack_requests * 100.0 / total_requests, 1) as attack_pct,
    ROUND(avg_attack_score, 1) as avg_attack_score,
    bot_requests,
    ROUND(avg_bot_score, 1) as avg_bot_score,
    blocked,
    country_count,
    CASE 
        WHEN attack_requests > 100 AND blocked < attack_requests * 0.5 THEN 'CRITICAL: High attack volume, low blocking'
        WHEN bot_requests > total_requests * 0.5 THEN 'HIGH: Majority bot traffic'
        WHEN unique_ips > 100 AND attack_requests > 50 THEN 'HIGH: Distributed attack pattern'
        WHEN attack_requests > 10 THEN 'MEDIUM: Attack activity detected'
        ELSE 'LOW'
    END as severity
FROM endpoint_analysis
WHERE attack_requests > 0 OR bot_requests > total_requests * 0.3
ORDER BY attack_requests DESC, bot_requests DESC
LIMIT 100;
```

### CF-CTX-003 [CRITICAL] IP Behavior Analysis with Context
**Purpose**: Analyze IP behavior patterns across multiple dimensions.
```sql
-- Comprehensive IP behavior analysis
WITH ip_behavior AS (
    SELECT 
        clientrequesthost,
        clientip,
        clientcountry,
        -- Request patterns
        COUNT(*) as total_requests,
        COUNT(DISTINCT clientrequesturi) as unique_paths,
        COUNT(DISTINCT date_trunc('minute', from_iso8601_timestamp(edgestarttimestamp))) as active_minutes,
        -- Attack indicators
        AVG(wafattackscore) as avg_attack_score,
        MAX(wafattackscore) as max_attack_score,
        COUNT(CASE WHEN wafattackscore >= 60 THEN 1 END) as high_attack_requests,
        -- Bot indicators
        AVG(botscore) as avg_bot_score,
        MIN(botscore) as min_bot_score,
        -- Security actions taken
        COUNT(CASE WHEN securityaction IN ('block', 'challenge') THEN 1 END) as times_blocked,
        -- Response patterns
        COUNT(CASE WHEN edgeresponsestatus = 403 THEN 1 END) as forbidden_count,
        COUNT(CASE WHEN edgeresponsestatus = 404 THEN 1 END) as not_found_count,
        COUNT(CASE WHEN edgeresponsestatus BETWEEN 200 AND 299 THEN 1 END) as success_count,
        -- Method patterns
        COUNT(CASE WHEN clientrequestmethod = 'POST' THEN 1 END) as post_count,
        -- Request rate
        COUNT(*) * 1.0 / NULLIF(COUNT(DISTINCT date_trunc('minute', from_iso8601_timestamp(edgestarttimestamp))), 0) as avg_rpm
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND clientrequesthost = '{TARGET_HOST}'
    GROUP BY 1, 2, 3
)
SELECT 
    clientrequesthost,
    clientip,
    clientcountry,
    total_requests,
    unique_paths,
    active_minutes,
    ROUND(avg_rpm, 1) as avg_requests_per_minute,
    ROUND(avg_attack_score, 1) as avg_attack_score,
    high_attack_requests,
    ROUND(avg_bot_score, 1) as avg_bot_score,
    times_blocked,
    forbidden_count,
    not_found_count,
    -- Threat classification
    CASE 
        WHEN high_attack_requests > 50 AND times_blocked < high_attack_requests * 0.5 THEN 'CRITICAL: Active attacker evading blocks'
        WHEN avg_bot_score < 20 AND total_requests > 100 THEN 'HIGH: Confirmed automation'
        WHEN not_found_count > total_requests * 0.5 THEN 'HIGH: Scanner/enum behavior'
        WHEN avg_rpm > 100 THEN 'HIGH: Rate abuse'
        WHEN high_attack_requests > 10 THEN 'MEDIUM: Attack attempts detected'
        WHEN unique_paths > 50 AND active_minutes < 5 THEN 'MEDIUM: Rapid path enumeration'
        ELSE 'LOW'
    END as threat_level,
    -- Recommended action
    CASE 
        WHEN high_attack_requests > 50 OR (avg_bot_score < 20 AND total_requests > 1000) THEN 'BLOCK: Add to blocklist'
        WHEN avg_rpm > 100 OR unique_paths > 100 THEN 'RATE_LIMIT: Apply rate limiting'
        WHEN avg_bot_score < 30 THEN 'CHALLENGE: Apply bot challenge'
        ELSE 'MONITOR'
    END as recommended_action
FROM ip_behavior
WHERE total_requests > 10
ORDER BY high_attack_requests DESC, total_requests DESC
LIMIT 100;
```

### CF-CTX-004 [HIGH] Cross-Endpoint Attack Correlation
**Purpose**: Find attackers targeting multiple endpoints in coordinated fashion.
```sql
-- Find IPs attacking multiple endpoints
WITH attacker_endpoints AS (
    SELECT 
        clientrequesthost,
        clientip,
        clientrequestpath,
        COUNT(*) as requests_to_endpoint,
        AVG(wafattackscore) as avg_attack_score,
        COUNT(CASE WHEN securityaction IN ('block', 'challenge') THEN 1 END) as blocked
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
    AND clientrequesthost = '{TARGET_HOST}'
    AND wafattackscore >= 40
    GROUP BY 1, 2, 3
),
ip_summary AS (
    SELECT 
        clientrequesthost,
        clientip,
        COUNT(DISTINCT clientrequestpath) as endpoints_attacked,
        SUM(requests_to_endpoint) as total_attack_requests,
        AVG(avg_attack_score) as overall_avg_score,
        SUM(blocked) as total_blocked,
        ARRAY_AGG(clientrequestpath ORDER BY requests_to_endpoint DESC LIMIT 10) as top_endpoints
    FROM attacker_endpoints
    GROUP BY 1, 2
)
SELECT 
    clientrequesthost,
    clientip,
    endpoints_attacked,
    total_attack_requests,
    ROUND(overall_avg_score, 1) as avg_attack_score,
    total_blocked,
    total_attack_requests - total_blocked as unblocked_attacks,
    top_endpoints,
    CASE 
        WHEN endpoints_attacked > 10 AND total_attack_requests > 100 THEN 'CRITICAL: Wide-scope coordinated attack'
        WHEN endpoints_attacked > 5 THEN 'HIGH: Multi-endpoint attack'
        WHEN total_attack_requests > 50 THEN 'HIGH: Focused endpoint attack'
        ELSE 'MEDIUM'
    END as severity
FROM ip_summary
WHERE endpoints_attacked > 2
ORDER BY endpoints_attacked DESC, total_attack_requests DESC
LIMIT 50;
```

### CF-CTX-005 [HIGH] Security Action Effectiveness by Host
**Purpose**: Analyze how effective security actions are per host.
```sql
-- Security action effectiveness analysis
WITH host_security AS (
    SELECT 
        clientrequesthost,
        -- Total volume
        COUNT(*) as total_requests,
        -- Attack detection
        COUNT(CASE WHEN wafattackscore >= 60 THEN 1 END) as high_risk_detected,
        COUNT(CASE WHEN wafsqliattackscore >= 60 THEN 1 END) as sqli_detected,
        COUNT(CASE WHEN wafxssattackscore >= 60 THEN 1 END) as xss_detected,
        -- Security actions
        COUNT(CASE WHEN securityaction = 'block' THEN 1 END) as blocked,
        COUNT(CASE WHEN securityaction IN ('challenge', 'managed_challenge', 'jschallenge') THEN 1 END) as challenged,
        COUNT(CASE WHEN securityaction = 'allow' OR securityaction IS NULL THEN 1 END) as allowed,
        -- Bot handling
        COUNT(CASE WHEN botscore <= 30 THEN 1 END) as bot_traffic,
        COUNT(CASE WHEN botscore <= 30 AND (securityaction IS NULL OR securityaction = 'allow') THEN 1 END) as bots_allowed,
        -- Unique threats
        COUNT(DISTINCT CASE WHEN wafattackscore >= 60 THEN clientip END) as unique_attackers
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE year = {YEAR} AND month = {MONTH} AND day = {DAY}
    GROUP BY 1
)
SELECT 
    clientrequesthost,
    total_requests,
    -- Attack detection summary
    high_risk_detected,
    sqli_detected,
    xss_detected,
    unique_attackers,
    -- Action breakdown
    blocked,
    challenged,
    allowed,
    -- Effectiveness metrics
    ROUND(blocked * 100.0 / NULLIF(high_risk_detected, 0), 1) as attack_block_rate_pct,
    ROUND(bots_allowed * 100.0 / NULLIF(bot_traffic, 0), 1) as bot_bypass_rate_pct,
    -- Risk assessment
    CASE 
        WHEN high_risk_detected > 100 AND blocked < high_risk_detected * 0.5 THEN 'CRITICAL: Poor attack blocking'
        WHEN bot_traffic > total_requests * 0.3 AND bots_allowed > bot_traffic * 0.5 THEN 'HIGH: Bot protection gaps'
        WHEN high_risk_detected > 50 THEN 'MEDIUM: Active attacks detected'
        ELSE 'OK'
    END as risk_level
FROM host_security
ORDER BY high_risk_detected DESC
LIMIT 50;
```

---

## AWS-CTX: AWS WAF Context-Aware Analysis

### AWS-CTX-001 [CRITICAL] Temporal Pattern Analysis
**Purpose**: Analyze attack patterns with time correlation for AWS WAF.
```sql
-- Temporal attack analysis with 5-minute windows
WITH timestamped_events AS (
    SELECT 
        httprequest.host,
        httprequest.clientip,
        httprequest.uri,
        action,
        terminatingruleid,
        from_unixtime(timestamp/1000) as event_time,
        date_trunc('minute', from_unixtime(timestamp/1000)) - 
            (EXTRACT(MINUTE FROM from_unixtime(timestamp/1000)) % 5) * INTERVAL '1' MINUTE as window_5min
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
    AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
),
window_analysis AS (
    SELECT 
        httprequest.host,
        window_5min,
        COUNT(*) as total_requests,
        COUNT(CASE WHEN action = 'BLOCK' THEN 1 END) as blocked,
        COUNT(CASE WHEN action = 'COUNT' THEN 1 END) as counted,
        COUNT(CASE WHEN action = 'ALLOW' THEN 1 END) as allowed,
        COUNT(DISTINCT httprequest.clientip) as unique_ips,
        COUNT(DISTINCT httprequest.uri) as unique_paths,
        COUNT(DISTINCT terminatingruleid) as rules_triggered
    FROM timestamped_events
    GROUP BY 1, 2
)
SELECT 
    httprequest.host,
    window_5min,
    total_requests,
    blocked,
    counted,
    allowed,
    unique_ips,
    unique_paths,
    rules_triggered,
    CASE 
        WHEN blocked > 100 AND unique_ips > 10 THEN 'CRITICAL: Coordinated attack detected'
        WHEN blocked > 50 AND unique_ips = 1 THEN 'HIGH: Single source attack burst'
        WHEN counted > blocked THEN 'WARNING: More events counted than blocked'
        WHEN blocked > 20 THEN 'MEDIUM: Elevated attack activity'
        ELSE 'NORMAL'
    END as status
FROM window_analysis
WHERE blocked > 10 OR counted > 50
ORDER BY blocked DESC, window_5min
LIMIT 100;
```

### AWS-CTX-002 [HIGH] IP Reputation Analysis
**Purpose**: Build IP behavior profiles across multiple dimensions.
```sql
-- IP behavior profiling
WITH ip_profile AS (
    SELECT 
        httprequest.clientip,
        httprequest.country,
        httprequest.host,
        -- Volume
        COUNT(*) as total_requests,
        COUNT(DISTINCT httprequest.uri) as unique_paths,
        COUNT(DISTINCT httprequest.host) as hosts_accessed,
        -- Actions
        COUNT(CASE WHEN action = 'BLOCK' THEN 1 END) as blocked,
        COUNT(CASE WHEN action = 'COUNT' THEN 1 END) as counted,
        COUNT(CASE WHEN action = 'ALLOW' THEN 1 END) as allowed,
        -- Time spread
        COUNT(DISTINCT date_trunc('hour', from_unixtime(timestamp/1000))) as active_hours,
        -- Methods
        COUNT(CASE WHEN httprequest.httpmethod = 'POST' THEN 1 END) as post_requests,
        COUNT(CASE WHEN httprequest.httpmethod NOT IN ('GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD') THEN 1 END) as unusual_methods,
        -- Rules triggered
        COUNT(DISTINCT terminatingruleid) as distinct_rules_triggered
    FROM aws_waf_logs.waf_logs_db.{CUSTOMER}_waf_logs
    WHERE accountid = '{ACCOUNT_ID}' AND region = '{REGION}' AND acl = '{ACL_NAME}'
    AND year = {YEAR} AND month = {MONTH} AND day = {DAY}
    GROUP BY 1, 2, 3
)
SELECT 
    httprequest.clientip,
    httprequest.country,
    httprequest.host,
    total_requests,
    unique_paths,
    blocked,
    counted,
    allowed,
    active_hours,
    distinct_rules_triggered,
    -- Risk scoring
    CASE 
        WHEN blocked > 100 OR distinct_rules_triggered > 5 THEN 'CRITICAL'
        WHEN blocked > 50 OR (counted > 100 AND allowed > counted) THEN 'HIGH'
        WHEN blocked > 10 OR unusual_methods > 0 THEN 'MEDIUM'
        WHEN counted > 10 THEN 'LOW'
        ELSE 'BENIGN'
    END as risk_level,
    -- Behavior type
    CASE 
        WHEN unique_paths > 50 AND active_hours < 2 THEN 'SCANNER'
        WHEN post_requests > total_requests * 0.8 AND unique_paths < 5 THEN 'CREDENTIAL_STUFFER'
        WHEN blocked > total_requests * 0.5 THEN 'ATTACKER'
        WHEN distinct_rules_triggered > 3 THEN 'MULTI_VECTOR_ATTACKER'
        ELSE 'UNKNOWN'
    END as behavior_type
FROM ip_profile
WHERE blocked > 0 OR counted > 10
ORDER BY blocked DESC, counted DESC
LIMIT 100;
```


---

# PART 6: SECURITY CHECK VALIDATION & PRIORITIZATION

> **PURPOSE**: Team review of each security check for customer value, severity accuracy, and practical applicability.

---

## Review Legend

| Rating | Meaning |
|--------|---------|
| ✅ **VALIDATED** | High-value check, proven detection, keep as-is |
| ⚠️ **TUNE** | Valid concept, needs threshold/logic adjustment |
| 🔄 **CONTEXT-DEPENDENT** | Value depends on customer environment |
| ❌ **DEPRIORITIZE** | Low value or high false positive rate |
| 🆕 **NEW** | Newly added, needs production validation |

---

## CLOUDFLARE PostgreSQL Checks Review

### Zone Security (CF-ZONE)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| CF-ZONE-001 | CRITICAL | ✅ **HIGH** | ✅ VALIDATED | Production zones without WAF = major gap. Exclude dev/test properly. |
| CF-ZONE-002 | HIGH | 🔄 CONTEXT | ⚠️ TUNE | Free/Pro plans may be intentional for low-value properties. Add traffic volume context. |
| CF-ZONE-003 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Unproxied A/AAAA records are common blind spots. Real attack vector. |
| CF-ZONE-004 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | Public origin IP exposure = direct WAF bypass. High-value finding. |
| CF-ZONE-005 | HIGH | ⚠️ MEDIUM | 🔄 CONTEXT | Inactive zones with DNS may be planned migrations. Add age context. |
| CF-ZONE-006 | MEDIUM | ⚠️ LOW | ❌ DEPRIORITIZE | Zone count alone isn't security risk. More of governance metric. |

### Rule Configuration (CF-RULE)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| CF-RULE-001 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | SKIP without IP restriction = full WAF bypass. Top finding. **LINK TO CF-CORR-001** |
| CF-RULE-002 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Disabled managed rules weaken protection. Worth flagging. |
| CF-RULE-003 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Log-only on production = visibility without protection. **LINK TO CF-CORR-002** |
| CF-RULE-004 | MEDIUM | ⚠️ MEDIUM | ⚠️ TUNE | Some rules intentionally don't log (e.g., allow rules). Add action context. |
| CF-RULE-005 | HIGH | ✅ **HIGH** | ⚠️ TUNE | Overly broad is subjective. Expression length isn't always indicator. |
| CF-RULE-006 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | Phase skipping disables entire WAF layers. Critical finding. **LINK TO CF-CORR-006** |
| CF-RULE-007 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Multiple product skips compound risk. Worth flagging. |
| CF-RULE-008 | HIGH | ⚠️ HIGH | 🔄 CONTEXT | Ruleset skipping may be intentional for FP reduction. Add description context. |
| CF-RULE-009 | MEDIUM | ⚠️ LOW | ❌ DEPRIORITIZE | Duplicate expressions may be intentional (different actions). Low value. |
| CF-RULE-010 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Execute overrides can weaken managed rules. Worth review. |
| CF-RULE-011 | MEDIUM | ⚠️ LOW | 🔄 CONTEXT | Custom block pages are common. Only flag if containing sensitive info. |

### Rate Limiting (CF-RATE)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| CF-RATE-001 | HIGH | ✅ **HIGH** | ✅ VALIDATED | APIs without rate limiting = abuse vector. **LINK TO CF-CORR-005** |
| CF-RATE-002 | MEDIUM | ⚠️ MEDIUM | ⚠️ TUNE | "High" threshold is relative. Add endpoint context (login vs static). |
| CF-RATE-003 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Log-only rate limiting provides no protection. |
| CF-RATE-004 | MEDIUM | ⚠️ LOW | ❌ DEPRIORITIZE | Short periods may be intentional for burst protection. Context needed. |

### Bot Management (CF-BOT)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| CF-BOT-001 | CRITICAL | ✅ **CRITICAL** | ⚠️ TUNE | No bot management is serious, but requires Enterprise. Check plan eligibility. **LINK TO CF-CORR-003** |
| CF-BOT-002 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Bot Fight Mode disabled on eligible zones = gap. |
| CF-BOT-003 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Automated traffic allowed through = scraping/abuse risk. **LINK TO CF-CORR-004** |
| CF-BOT-004 | MEDIUM | ⚠️ MEDIUM | 🆕 NEW | AI bot protection is new feature. May not be available on all plans. |
| CF-BOT-005 | HIGH | ⚠️ MEDIUM | 🔄 CONTEXT | Static resource protection may cause CDN issues. Context dependent. |
| CF-BOT-006 | MEDIUM | ⚠️ MEDIUM | ✅ VALIDATED | JS detection improves bot detection accuracy. Worth flagging if disabled. |
| CF-BOT-007 | MEDIUM | ⚠️ LOW | ❌ DEPRIORITIZE | Session score suppression is edge case. Low customer value. |

### IP Lists (CF-LIST)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| CF-LIST-001 | MEDIUM | ⚠️ MEDIUM | ⚠️ TUNE | 90-day threshold may be too aggressive. Make configurable. |
| CF-LIST-002 | HIGH | ⚠️ MEDIUM | 🔄 CONTEXT | Empty lists may be placeholders. Only flag if referenced in active rules. |
| CF-LIST-003 | MEDIUM | ⚠️ LOW | ❌ DEPRIORITIZE | Large lists are often legitimate (threat intel feeds). Low value. |

### DNS Security (CF-DNS)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| CF-DNS-001 | HIGH | ⚠️ MEDIUM | ⚠️ TUNE | External CNAMEs are often legitimate (CDNs, SaaS). Add known-good list. |
| CF-DNS-002 | MEDIUM | ⚠️ MEDIUM | 🔄 CONTEXT | Wildcards are common. Only flag if combined with sensitive content. |
| CF-DNS-003 | HIGH | ⚠️ LOW | ❌ DEPRIORITIZE | Multiple A records for LB are standard. Very low value. |

---

## AKAMAI PostgreSQL Checks Review

### Security Policy (AK-POLICY)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| AK-POLICY-001 | INFO | ⚠️ LOW | ❌ DEPRIORITIZE | Just a summary. No security value on its own. |
| AK-POLICY-002 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | Attack groups not in deny = attacks pass through. Top Akamai finding. |
| AK-POLICY-003 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Slow POST attacks (Slowloris) are real threat. Valid check. |
| AK-POLICY-004 | HIGH | ✅ **HIGH** | 🔄 CONTEXT | API constraints depend on application architecture. |
| AK-POLICY-005 | HIGH | ⚠️ MEDIUM | ⚠️ TUNE | Attack group analysis is valuable. Severity depends on which groups. |

### Rate Controls (AK-RATE)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| AK-RATE-001 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Alert-only rate policies = no actual protection. |
| AK-RATE-002 | MEDIUM | ⚠️ MEDIUM | ⚠️ TUNE | Threshold appropriateness depends on application. |
| AK-RATE-003 | HIGH | ✅ **HIGH** | ✅ VALIDATED | No rate policies = no abuse protection. |
| AK-RATE-004 | INFO | ⚠️ LOW | ❌ DEPRIORITIZE | Path coverage is informational. Low security value. |

### Bot Manager (AK-BOT)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| AK-BOT-001 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | Unprotected bot categories = scraping/abuse. |
| AK-BOT-002 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Detection without enforcement = visibility without protection. |
| AK-BOT-003 | INFO | ⚠️ LOW | ❌ DEPRIORITIZE | Bot count is informational. No security value. |

---

## AWS WAF PostgreSQL Checks Review

### Web ACL (AWS-ACL)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| AWS-ACL-001 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | ACL without resources = wasted config, no protection. |
| AWS-ACL-002 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | No logging = no visibility. Critical for compliance. |
| AWS-ACL-003 | HIGH | ✅ **HIGH** | ✅ VALIDATED | High WCU = approaching limits. May block new rules. |
| AWS-ACL-004 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Default ALLOW is permissive stance. Worth flagging. |
| AWS-ACL-005 | MEDIUM | ⚠️ MEDIUM | ✅ VALIDATED | CloudWatch metrics useful for alerting. |
| AWS-ACL-006 | MEDIUM | ⚠️ MEDIUM | ✅ VALIDATED | Sample requests help rule tuning. |
| AWS-ACL-007 | LOW | ⚠️ LOW | ❌ DEPRIORITIZE | Missing description is just documentation issue. |
| AWS-ACL-008 | INFO | ⚠️ LOW | ❌ DEPRIORITIZE | Regional distribution is informational. |
| AWS-ACL-009 | INFO | ⚠️ LOW | ❌ DEPRIORITIZE | Firewall Manager info is just metadata. |

### Rules (AWS-RULE)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| AWS-RULE-001 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Count mode = monitoring without protection. **LINK TO AWS-CORR-001** |
| AWS-RULE-002 | INFO | ⚠️ LOW | ❌ DEPRIORITIZE | Priority spread is informational. |
| AWS-RULE-003 | MEDIUM | ⚠️ LOW | ❌ DEPRIORITIZE | Labels are nice-to-have, not security critical. |
| AWS-RULE-004 | INFO | ⚠️ LOW | ❌ DEPRIORITIZE | Text transform count is informational. |

### Managed Rule Groups (AWS-MRG)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| AWS-MRG-001 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | No managed rules = minimal protection. **LINK TO AWS-CORR-002** |
| AWS-MRG-002 | HIGH | ✅ **HIGH** | ✅ VALIDATED | CRS is baseline protection. Should be present. |
| AWS-MRG-003 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Known Bad Inputs catches common attacks. |
| AWS-MRG-004 | HIGH | ⚠️ HIGH | 🔄 CONTEXT | SQLi rules only needed if SQL backend exists. |
| AWS-MRG-005 | MEDIUM | ⚠️ MEDIUM | 🔄 CONTEXT | Bot control has cost implications. Context dependent. |
| AWS-MRG-006 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Overrides to count bypass protection. **LINK TO AWS-CORR-003** |
| AWS-MRG-007 | INFO | ⚠️ LOW | ❌ DEPRIORITIZE | Summary is informational. |

### CloudFront (AWS-CF)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| AWS-CF-001 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | CloudFront without WAF = unprotected distribution. |
| AWS-CF-002 | HIGH | ✅ **HIGH** | ✅ VALIDATED | HTTP origin = MITM risk. Valid security finding. |
| AWS-CF-003 | MEDIUM | ⚠️ LOW | ❌ DEPRIORITIZE | Distribution summary is informational. |
| AWS-CF-004 | HIGH | ⚠️ MEDIUM | ⚠️ TUNE | allow-all viewer protocol may be intentional for HTTP support. |

---

## TRINO Log Analysis Checks Review

### Attack Detection (CF-LOG-ATK, AWS-LOG-ATK)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| CF-LOG-ATK-001 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | High attack score unblocked = active exploitation. Top log finding. |
| CF-LOG-ATK-002 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | SQLi detected but unblocked = database at risk. |
| CF-LOG-ATK-003 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | XSS detected but unblocked = user sessions at risk. |
| CF-LOG-ATK-004 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | RCE detected but unblocked = server compromise risk. |
| CF-LOG-ATK-005 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Combined scores provide attack context. |
| CF-LOG-ATK-006 | HIGH | ⚠️ MEDIUM | ✅ VALIDATED | Score distribution helps understand attack landscape. |

### Bot Traffic (CF-LOG-BOT)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| CF-LOG-BOT-001 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Low bot score + allowed = scraping/abuse active. |
| CF-LOG-BOT-002 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Bot spoofing is real attack technique. |
| CF-LOG-BOT-003 | MEDIUM | ✅ **MEDIUM** | 🆕 NEW | AI crawlers are emerging concern. Validate patterns. |
| CF-LOG-BOT-004 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Headless browsers = automation. Valid detection. |
| CF-LOG-BOT-005 | MEDIUM | ⚠️ MEDIUM | ✅ VALIDATED | Score distribution provides context. |
| CF-LOG-BOT-006 | HIGH | ⚠️ MEDIUM | ✅ VALIDATED | Verified bot analysis helps whitelist management. |

### Abuse Patterns (CF-LOG-ABU)

| Check ID | Severity | Customer Value | Review | Notes |
|----------|----------|----------------|--------|-------|
| CF-LOG-ABU-001 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Credential stuffing is top attack. Threshold tunable. |
| CF-LOG-ABU-002 | HIGH | ✅ **HIGH** | ✅ VALIDATED | API enumeration indicates recon activity. |
| CF-LOG-ABU-003 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Path traversal = file system access attempt. |
| CF-LOG-ABU-004 | CRITICAL | ✅ **CRITICAL** | ✅ VALIDATED | Command injection = RCE attempt. Critical. |
| CF-LOG-ABU-005 | HIGH | ✅ **HIGH** | ✅ VALIDATED | SQLi patterns complement score-based detection. |
| CF-LOG-ABU-006 | HIGH | ✅ **HIGH** | ✅ VALIDATED | XSS patterns complement score-based detection. |
| CF-LOG-ABU-007 | MEDIUM | ⚠️ MEDIUM | ✅ VALIDATED | Directory bruteforce indicates scanning. |
| CF-LOG-ABU-008 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Admin path probing = privilege escalation attempt. |
| CF-LOG-ABU-009 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Scanner UAs = automated attack tools. |
| CF-LOG-ABU-010 | MEDIUM | ⚠️ MEDIUM | ⚠️ TUNE | Empty UA may have false positives (IoT, APIs). |
| CF-LOG-ABU-011 | HIGH | ✅ **HIGH** | ✅ VALIDATED | Sensitive file access = config/secrets exposure. |

---

## Summary: Top 20 Highest-Value Checks

Based on team review, these are the most valuable checks for customer security:

| Rank | Check ID | Vendor | Severity | Value Rating |
|------|----------|--------|----------|--------------|
| 1 | CF-RULE-001 | Cloudflare | CRITICAL | ✅ **CRITICAL** - SKIP rule bypass |
| 2 | CF-RULE-006 | Cloudflare | CRITICAL | ✅ **CRITICAL** - Phase skip bypass |
| 3 | CF-ZONE-004 | Cloudflare | CRITICAL | ✅ **CRITICAL** - Origin IP exposure |
| 4 | AK-POLICY-002 | Akamai | CRITICAL | ✅ **CRITICAL** - Attack groups not blocking |
| 5 | AWS-MRG-001 | AWS WAF | CRITICAL | ✅ **CRITICAL** - No managed rules |
| 6 | AWS-ACL-002 | AWS WAF | CRITICAL | ✅ **CRITICAL** - No logging |
| 7 | CF-LOG-ATK-001 | Cloudflare | CRITICAL | ✅ **CRITICAL** - High attack score unblocked |
| 8 | CF-LOG-ABU-004 | Cloudflare | CRITICAL | ✅ **CRITICAL** - Command injection |
| 9 | CF-ZONE-001 | Cloudflare | CRITICAL | ✅ **CRITICAL** - No WAF protection |
| 10 | AWS-CF-001 | AWS WAF | CRITICAL | ✅ **CRITICAL** - CloudFront without WAF |
| 11 | CF-RULE-003 | Cloudflare | HIGH | ✅ **HIGH** - Log-only rules |
| 12 | CF-BOT-003 | Cloudflare | HIGH | ✅ **HIGH** - Automated traffic allowed |
| 13 | CF-RATE-001 | Cloudflare | HIGH | ✅ **HIGH** - No API rate limiting |
| 14 | AWS-RULE-001 | AWS WAF | HIGH | ✅ **HIGH** - Rules in count mode |
| 15 | AK-POLICY-003 | Akamai | HIGH | ✅ **HIGH** - Slow POST disabled |
| 16 | CF-LOG-ABU-001 | Cloudflare | HIGH | ✅ **HIGH** - Credential stuffing |
| 17 | CF-LOG-BOT-001 | Cloudflare | HIGH | ✅ **HIGH** - Bot bypass |
| 18 | CF-ZONE-003 | Cloudflare | HIGH | ✅ **HIGH** - Unproxied records |
| 19 | AWS-MRG-006 | AWS WAF | HIGH | ✅ **HIGH** - Managed rule override |
| 20 | CF-LOG-ABU-008 | Cloudflare | HIGH | ✅ **HIGH** - Admin path probing |

---

## Checks Recommended for Removal/Deprioritization

These checks have low security value or high false positive rates:

| Check ID | Reason |
|----------|--------|
| CF-ZONE-006 | Zone count is governance, not security |
| CF-RULE-009 | Duplicate expressions may be intentional |
| CF-RULE-011 | Custom block pages are common |
| CF-LIST-003 | Large lists are often legitimate |
| CF-DNS-003 | Multiple A records are standard LB |
| AK-POLICY-001 | Just informational |
| AK-RATE-004 | Path coverage is informational |
| AK-BOT-003 | Bot count is informational |
| AWS-ACL-007 | Missing description is documentation issue |
| AWS-ACL-008 | Regional distribution is informational |
| AWS-ACL-009 | Firewall Manager info is metadata |
| AWS-RULE-002 | Priority spread is informational |
| AWS-RULE-003 | Labels are nice-to-have |
| AWS-RULE-004 | Text transform count is informational |
| AWS-MRG-007 | Summary is informational |
| AWS-CF-003 | Distribution summary is informational |

---

**Document Version:** 4.1
**Last Updated:** January 2026
**Reviewed By:** Security Team (Winston, Mary, Murat, Amelia)


---

# PART 7: TABLE USAGE ANALYSIS & IMPLEMENTATION COVERAGE

> **PURPOSE**: This section maps the PostgreSQL tables used in the existing recipes codebase (`huskeys-web-apps/packages/api/findings-engine/src/recipes`) against the full schema documentation. It identifies high-value tables NOT yet utilized for security checks.

---

## Tables Currently Used by Production Recipes

### Cloudflare Tables (13 tables in use)

| Table | Usage Count | Recipe(s) |
|-------|-------------|-----------|
| `CloudflareZoneTable` | 11 | missing-managed-rulesets, skip-rules-with-broad-ip-list, cf-zones-paused, missing-rate-limit, non-proxied-dns, empty-custom-lists |
| `CloudflareAccountTable` | 7 | missing-managed-rulesets, skip-rules-with-broad-ip-list, cf-zones-paused, empty-custom-lists |
| `CloudflareWafRulesRegularTable` | 5 | cf-zones-paused, skip-rules-with-broad-ip-list |
| `CloudflareRulesetInstanceRegularTable` | 5 | cf-zones-paused |
| `CloudflareWafRulesTable` | 4 | missing-managed-rulesets |
| `CloudflareRulesetInstanceTable` | 4 | missing-managed-rulesets |
| `CloudflareRawZoneMetricsTable` | 3 | cf-zones-paused, missing-rate-limit |
| `CloudflareListTable` | 2 | skip-rules-with-broad-ip-list, empty-custom-lists |
| `CloudflareDnsRecordsTable` | 2 | non-proxied-dns, proxied-dns-pointing-to-cloudfront |
| `CloudflareListItemTable` | 1 | skip-rules-with-broad-ip-list |
| `CloudflareRuleRateLimitsTable` | 1 | rate-limits-insufficient-timeout |
| `CloudflareRuleExecuteActionParametersTable` | 1 | missing-managed-rulesets |
| `CloudflareRawRuleMetricsTable` | 1 | metric-based-rule-spike-detection |

### AWS Tables (17 tables in use)

| Table | Usage Count | Recipe(s) |
|-------|-------------|-----------|
| `WafAclTable` | 16 | internet-facing-alb-without-waf, cloudfront-waf-bypass, missing-essential-aws-managed-rules, acls-without-rate-limit, managed-rule-group-override, waf-acls-100-percent-blocking |
| `WafAclRuleTable` | 9 | waf-rule-in-count-long-time, waf-rule-name-mismatch |
| `WafAclAssociatedResourceTable` | 7 | internet-facing-alb-without-waf, cloudfront-waf-bypass |
| `CloudFrontDistributionTable` | 7 | cloudfront-waf-bypass, disabled-cloudfront-distributions |
| `LoadBalancerTable` | 5 | internet-facing-alb-without-waf, cloudfront-waf-bypass, alb-unconditional-forward-rule |
| `SecurityGroupsTable` | 3 | internet-facing-alb-without-waf, cloudfront-waf-bypass |
| `SecurityGroupInboundsTable` | 3 | internet-facing-alb-without-waf, cloudfront-waf-bypass |
| `LoadBalancerSecurityGroupsTable` | 3 | internet-facing-alb-without-waf |
| `WafIpSetTable` | 2 | empty-ip-set, unreferenced-ip-set |
| `WafManagedRuleGroupTable` | 1 | missing-essential-aws-managed-rules |
| `CloudFrontOriginTable` | 1 | cloudfront-waf-bypass |
| `CloudFrontMetricsTable` | 1 | metric-based-rule-spike-detection |

### Akamai Tables (10 tables in use)

| Table | Usage Count | Recipe(s) |
|-------|-------------|-----------|
| `AkamaiRawSecurityConfigurationTable` | 7 | properties-without-waf, hostnames-attack-groups-alert, hostnames-no-slow-post |
| `AkamaiRawSecurityConfigurationVersionTable` | 6 | hostnames-attack-groups-alert |
| `AkamaiRawSecurityConfigurationMatchTargetTable` | 6 | sec-config-prod-hostname-no-waf |
| `AkamaiRawSecurityConfigMatchTargetHostnameTable` | 6 | sec-config-prod-hostname-no-waf |
| `AkamaiRawSecurityPolicyTable` | 4 | hostnames-no-slow-post, hostnames-no-rapid-rules |
| `AkamaiRawSecurityPolicyAttackGroupsTable` | 2 | hostnames-attack-groups-disabled |
| `AkamaiPropertyTable` | 1 | properties-without-waf |
| `AkamaiPropertyHostnameTable` | 1 | properties-without-waf |
| `AkamaiGroupTable` | 1 | properties-without-waf |
| `AkamaiContractTable` | 1 | properties-without-waf |

### Azure Tables (14 tables in use)

| Table | Usage Count | Recipe(s) |
|-------|-------------|-----------|
| `AzureResourceGroupsTable` | 7 | az-waf-no-custom-rules, frontdoor-waf-with-all-custom-rules-allow |
| `AzureWafPoliciesTable` | 3 | az-waf-no-custom-rules |
| `AzureAppGatewayTable` | 3 | app-gateway-without-waf-policy, app-gateway-waf-detection-mode |
| `AzureAppGatewayRoutingRulesTable` | 3 | public-app-gateway-waf-incompatible-tier |
| `AzureAppGatewayHttpListenersTable` | 3 | az-waf-no-custom-rules |
| `AzureFrontDoorWafCustomRulesTable` | 2 | az-waf-no-custom-rules |
| `AzureFrontDoorSecurityPoliciesTable` | 2 | az-waf-no-custom-rules |
| `AzureFdWafMetricsTable` | 2 | az-waf-no-custom-rules |
| `AzureAppGatewayWafPoliciesTable` | 2 | az-waf-no-custom-rules |
| `AzureAppGatewayWafCustomRulesTable` | 2 | az-waf-no-custom-rules |
| `AzureAppGatewayWafPolicyMetricsTable` | 1 | az-waf-no-custom-rules |
| `AzureFdWafManagedRuleSetsTable` | 1 | az-waf-outdated-managed-rulesets |

---

## 🆕 HIGH-VALUE UNUSED TABLES - Priority for New Security Checks

These tables contain rich security-relevant data but are NOT yet used in any production recipes:

### Cloudflare - Unused High-Value Tables

| Table | Rows | Security Value | Recommended Checks |
|-------|------|----------------|-------------------|
| **`cloudflare_raw_bot_management_history`** | 340 | 🔴 **CRITICAL** | Bot fight mode, AI protection, automated traffic config |
| **`cloudflare_raw_rulesets_rule_skip_ap_rules_history`** | 83 | 🔴 **CRITICAL** | Skip rules that bypass security - major gap |
| **`cloudflare_raw_rulesets_rule_rate_limits_history`** | 64 | ⚠️ HIGH | Rate limit configs - threshold analysis |
| **`cloudflare_raw_rulesets_rule_skip_ap_phases_history`** | ~50 | 🔴 **CRITICAL** | Rules skipping WAF phases |
| **`cloudflare_raw_rulesets_rule_skip_ap_products_history`** | ~40 | ⚠️ HIGH | Rules skipping security products |
| `cloudflare_raw_rulesets_rule_block_action_parameters_history` | 44 | MEDIUM | Block action configuration |

### AWS - Unused High-Value Tables

| Table | Rows | Security Value | Recommended Checks |
|-------|------|----------------|-------------------|
| **`aws_raw_cloudwatch_waf_metrics_history`** | 5,078,961 | 🔴 **CRITICAL** | Rule trigger volume, anomaly detection |
| **`aws_raw_cloudwatch_cloudfront_metrics_history`** | 1,036,633 | ⚠️ HIGH | Traffic patterns, error rates |
| **`aws_raw_route53_resource_records_values_history`** | 494,209 | ⚠️ HIGH | DNS misconfigurations |
| **`aws_raw_route53_hosted_resource_records_history`** | 184,114 | ⚠️ HIGH | DNS security checks |
| **`aws_raw_waf_acl_rule_statements_history`** | 64,326 | 🔴 **CRITICAL** | Rule statement analysis, excluded rules |
| **`aws_raw_waf_acl_rule_statement_text_transform_history`** | 12,228 | MEDIUM | Text transformation coverage |
| **`aws_raw_waf_rule_statement_field_to_match_history`** | 11,607 | MEDIUM | Field matching coverage |
| **`aws_raw_waf_acl_logging_configurations_history`** | ~200 | 🔴 **CRITICAL** | Logging config validation |
| **`aws_raw_waf_acl_logging_configurations_filters_history`** | ~100 | ⚠️ HIGH | Log filtering risks |

### Akamai - Unused High-Value Tables

| Table | Rows | Security Value | Recommended Checks |
|-------|------|----------------|-------------------|
| **`akamai_raw_bot_categories_history`** | ~500 | 🔴 **CRITICAL** | Bot category configuration |
| **`akamai_raw_bot_category_actions_history`** | ~1000 | 🔴 **CRITICAL** | Bot actions - monitor vs deny |
| **`akamai_raw_bot_detections_history`** | ~200 | ⚠️ HIGH | Bot detection settings |
| **`akamai_raw_bot_detection_actions_history`** | ~300 | ⚠️ HIGH | Detection action configuration |
| **`akamai_raw_sec_config_rate_policies_history`** | ~100 | ⚠️ HIGH | Rate policy configuration |
| **`akamai_raw_security_policy_rate_policy_actions_history`** | ~150 | ⚠️ HIGH | Rate policy actions |
| **`akamai_raw_sec_config_custom_rules_history`** | ~200 | MEDIUM | Custom rule analysis |
| **`akamai_raw_sec_config_custom_rule_conditions_history`** | ~300 | MEDIUM | Custom rule conditions |

### Azure - Unused High-Value Tables

| Table | Rows | Security Value | Recommended Checks |
|-------|------|----------------|-------------------|
| **`azure_front_door_waf_managed_rule_sets_history`** | ~100 | 🔴 **CRITICAL** | Managed ruleset configuration |
| **`azure_front_door_waf_managed_rule_set_overrides_history`** | ~50 | 🔴 **CRITICAL** | Override analysis |
| **`azure_front_door_endpoints_history`** | ~200 | ⚠️ HIGH | Endpoint security |
| **`azure_front_door_routes_history`** | ~150 | ⚠️ HIGH | Route configuration |
| **`azure_app_gateway_backend_pools_history`** | ~100 | MEDIUM | Backend pool analysis |

---

## Implementation Coverage: Checks vs Production Recipes

### Legend
- ✅ **IMPLEMENTED** - Check exists in production recipe code
- 🔄 **PARTIAL** - Similar check exists but different scope
- ❌ **NOT IMPLEMENTED** - Check only in this document

### Cloudflare Checks

| Check ID | Status | Recipe/Notes |
|----------|--------|--------------|
| CF-ZONE-001 | ✅ | `missing-managed-rulesets` |
| CF-ZONE-003 | ✅ | `non-proxied-dns-record-pointing-to-unprotected-web-assets` |
| CF-RULE-001 | ✅ | `skip-rules-with-broad-ip-list` |
| CF-RULE-002 | 🔄 | `missing-managed-rulesets` (partial) |
| CF-RULE-003 | ❌ | Not implemented - LOG-ONLY RULES |
| CF-RULE-010 | ✅ | `override-managed-rule-group-action` |
| CF-RATE-001 | ✅ | `missing-rate-limit` |
| CF-RATE-004 | ✅ | `rate-limits-insufficient-timeout` |
| CF-BOT-001 | ❌ | Not implemented - BOT MANAGEMENT (HIGH VALUE) |
| CF-BOT-002 | ❌ | Not implemented - BOT FIGHT MODE |
| CF-LIST-001 | 🔄 | `empty-custom-lists` (checks empty, not stale) |
| CF-LIST-002 | ✅ | `empty-custom-lists` |
| CF-DNS-001 | ✅ | `proxied-dns-record-pointing-to-aws-cloudfront` |

### AWS Checks

| Check ID | Status | Recipe/Notes |
|----------|--------|--------------|
| AWS-ACL-001 | 🔄 | `shadow-assets-non-associated-acls` |
| AWS-ACL-002 | ❌ | Not implemented - LOGGING CONFIG (HIGH VALUE) |
| AWS-ACL-004 | ❌ | Not implemented - DEFAULT ACTION ALLOW |
| AWS-RULE-001 | ✅ | `waf-rule-in-count-long-time` |
| AWS-MRG-001 | ✅ | `missing-essential-aws-managed-rules` |
| AWS-MRG-006 | ✅ | `managed-rule-group-rule-override-to-allow` |
| AWS-CF-001 | 🔄 | `cloudfront-waf-bypass-via-alb-origin` |
| AWS-ALB-001 | ✅ | `internet-facing-alb-without-waf` |
| AWS-RATE-001 | ✅ | `acls-without-rate-limit-rules` |

### Akamai Checks

| Check ID | Status | Recipe/Notes |
|----------|--------|--------------|
| AK-POLICY-002 | ✅ | `hostnames-attack-groups-alert`, `hostnames-attack-groups-disabled` |
| AK-POLICY-003 | ✅ | `hostnames-no-slow-post` |
| AK-BOT-001 | ❌ | Not implemented - BOT CATEGORIES (HIGH VALUE) |
| AK-BOT-002 | ❌ | Not implemented - BOT DETECTION ACTIONS |
| AK-PROP-001 | ✅ | `properties-without-waf` |
| AK-RATE-001 | ❌ | Not implemented - RATE POLICIES |
| AK-CUSTOM-001 | ❌ | Not implemented - CUSTOM RULES |

### Azure Checks

| Check ID | Status | Recipe/Notes |
|----------|--------|--------------|
| AZ-WAF-001 | ✅ | `az-waf-no-custom-rules` |
| AZ-WAF-002 | 🔄 | `frontdoor-waf-with-all-custom-rules-allow` |
| AZ-FD-001 | ❌ | Not implemented - FRONT DOOR WITHOUT WAF |
| AZ-FD-002 | ❌ | Not implemented - ENDPOINT SECURITY |
| AZ-AGW-001 | ✅ | `app-gateway-without-waf-policy` |
| AZ-AGW-002 | ✅ | `app-gateway-waf-detection-mode` |
| AZ-MRG-001 | ✅ | `az-waf-outdated-managed-rulesets` |

---

## Recommended New Recipes (High Priority)

Based on the unused high-value tables, these are the **TOP 10 NEW CHECKS** to implement:

### 1. Cloudflare Bot Management Configuration
**Tables**: `cloudflare_raw_bot_management_history`
**Check**: Zones without bot fight mode enabled, AI protection disabled, or automated traffic allowed
**Severity**: CRITICAL

### 2. Cloudflare WAF Phase/Product Skip Rules
**Tables**: `cloudflare_raw_rulesets_rule_skip_ap_phases_history`, `cloudflare_raw_rulesets_rule_skip_ap_products_history`
**Check**: Rules that skip entire WAF phases or security products
**Severity**: CRITICAL

### 3. AWS WAF Logging Configuration Gaps
**Tables**: `aws_raw_waf_acl_logging_configurations_history`
**Check**: ACLs without logging, filtered logging, or redacted fields
**Severity**: CRITICAL

### 4. AWS CloudWatch WAF Metrics Anomaly
**Tables**: `aws_raw_cloudwatch_waf_metrics_history`
**Check**: Rules with zero hits (unused), rules with 100% block rate (false positives), sudden spikes
**Severity**: HIGH

### 5. Akamai Bot Category Actions
**Tables**: `akamai_raw_bot_categories_history`, `akamai_raw_bot_category_actions_history`
**Check**: Bot categories set to monitor/alert instead of deny/challenge
**Severity**: CRITICAL

### 6. Akamai Rate Policy Configuration
**Tables**: `akamai_raw_sec_config_rate_policies_history`, `akamai_raw_security_policy_rate_policy_actions_history`
**Check**: Rate policies in alert-only mode, high thresholds
**Severity**: HIGH

### 7. AWS Route53 DNS Security
**Tables**: `aws_raw_route53_hosted_resource_records_history`, `aws_raw_route53_resource_records_values_history`
**Check**: Dangling DNS, records pointing to non-protected origins
**Severity**: HIGH

### 8. Azure Front Door Managed Ruleset Overrides
**Tables**: `azure_front_door_waf_managed_rule_sets_history`, `azure_front_door_waf_managed_rule_set_overrides_history`
**Check**: Managed rules disabled or overridden to allow
**Severity**: CRITICAL

### 9. Cloudflare Log-Only Rules Analysis
**Tables**: `cloudflare_raw_rulesets_rules_history` (action = 'log')
**Check**: Rules in log-only mode with high trigger volume (should be blocking)
**Severity**: HIGH

### 10. AWS WAF Rule Statement Analysis
**Tables**: `aws_raw_waf_acl_rule_statements_history`
**Check**: Rules with excluded_rules (security gaps), overly permissive IP ranges
**Severity**: CRITICAL

---
