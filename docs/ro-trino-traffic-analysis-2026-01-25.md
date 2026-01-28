# RO Customer - Comprehensive WAF Security Analysis

**Date:** January 25, 2026  
**Customer:** RO (Ro Health / Roman Health)  
**Data Source:** Trino (`huskeys_customers_logs.waf_logs_db.ro_waf_logs_rcloned`)  
**Analysis Period:** January 25, 2026 (1.78M events)  
**Environment:** Development/Staging (`rotests.com`)

---

## Executive Summary

This deep-dive analysis identified **10 critical and high severity security findings** including active vulnerability scanning, path traversal attacks bypassing WAF, exposed CI/CD infrastructure, and healthcare data endpoints accessible without proper WAF evaluation.

---

## Finding 1: CRITICAL - Jenkins CI/CD Infrastructure Exposed

### Summary
Jenkins CI/CD server at `ci.rotests.com` is accessible without WAF protection, exposing build jobs, execution details, and potentially sensitive configuration.

### Evidence

**Primary Target:** `ci.rotests.com`

| Path | Source IP | Country | Status | Count |
|------|-----------|---------|--------|-------|
| `/job/Prepare%20feature%20environment/wfapi/runs` | 2a09:bac0:1000:472::39b:1a | Poland | 200 | **5,336** |
| `/job/Prepare%20feature%20environment/wfapi/runs` | 2a09:bac0:1000:472::39b:1a | Poland | 504 | 2,669 |
| `/job/Prepare%20feature%20environment/buildHistory/ajax` | 2a09:bac0:1000:472::39b:1a | Poland | 200 | 38 |
| `/job/AT/job/at-daily/buildHistory/ajax` | 45.90.2.231 | Poland | 403 | 11 |
| `/job/Prepare%20feature%20environment/1990/execution/node/151/wfapi/describe` | 2a09:bac0:1000:472::39b:1a | Poland | 200 | 8 |
| `/job/Update%20frontend%20of%20environment/buildHistory/ajax` | 2a09:bac0:1000:472::420:61 | Poland | 200 | 2 |
| `/job/Prepare%20feature%20environment/parambuild/configSubmit` | 2a09:bac0:1000:472::39b:1a | Poland | 302 | 2 |
| `/adjuncts/96573c8f/org/jenkinsci/plugins/scriptsecurity/scripts/ScriptApproval/FormValidationPageDecorator/validate.js` | 2a09:bac0:1000:46e::499:34 | USA | 200 | 2 |

**Exposed Jenkins Plugins/Features:**
- ScriptApproval/FormValidationPageDecorator
- Build parameter submission
- Workflow API (wfapi)
- Build history
- Artifact listing

**Other CI/CD Paths Probed:**

| Path | Target Host | Source IP | Country | Action | Status |
|------|-------------|-----------|---------|--------|--------|
| `/auto-deploy/` | pha-tomato.rotests.com | 185.55.240.233 | France | NULL | 302 |
| `/data-pipeline/` | spermkit-mango.rotests.com | 185.55.240.233 | France | NULL | 302 |
| `/pipelinex/` | rotests.com | 192.166.82.68 | USA | NULL | 404 |
| `/buildhub/` | my-whiskey.rotests.com:8080 | 77.90.13.135 | Germany | block | 403 |
| `/jenkins-api/` | start-blueberry.rotests.com | 46.224.199.2 | Germany | block | 403 |

### Impact
- Build configurations potentially exposed
- Deployment credentials at risk
- Infrastructure enumeration possible
- CI/CD pipeline manipulation risk

---

## Finding 2: CRITICAL - Luxembourg Scanner Bypassing WAF (96.5%)

### Summary
IP `45.12.139.54` from Luxembourg (ASN 209847) performed extensive reconnaissance with only 3.5% of requests blocked.

### Statistics
| Metric | Value |
|--------|-------|
| **Total Requests** | 3,630 |
| **Blocked** | 126 (3.5%) |
| **Allowed** | 3,504 (96.5%) |
| **Unique Paths Scanned** | 3,612 |

### Sample Unblocked Paths

**Target Host:** `try-hellorory-beta.rotests.com`

| Path | Status | Attack Type |
|------|--------|-------------|
| `/fckeditor/editor/filemanager/connectors/aspx/connector.aspx` | 301 | FCKEditor RCE |
| `/fckeditor/editor/filemanager/connectors/aspx/upload.aspx` | 301 | File Upload |
| `/fckeditor/editor/filemanager/connectors/php/connector.php` | 301 | FCKEditor RCE |
| `/fckeditor/editor/filemanager/upload/php/upload.php` | 301 | File Upload |
| `/file_upload.php` | 301 | File Upload |
| `/file_upload.aspx` | 301 | File Upload |
| `/fileadmin/user_upload` | 301 | TYPO3 Upload |
| `/filemanager/upload.php` | 301 | File Manager |
| `/files.zip` | 301 | Data Exfil |
| `/files.tar.gz` | 301 | Data Exfil |
| `/firebase-debug.log` | 301 | Log Exposure |
| `/firebird_schema.sql` | 301 | DB Schema |

**User-Agent:** `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`

### FortiGate VPN Exploit (CVE-2018-13379)

| URI | Target | Status |
|-----|--------|--------|
| `/remote/fgt_lang?lang=/../../../../////////////////////////bin/sslvpnd` | try-hellorory-beta.rotests.com | 301 |
| `/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` | try-hellorory-beta.rotests.com | 301 |

---

## Finding 3: CRITICAL - Path Traversal Attacks Bypassing WAF

### Summary
50+ path traversal/LFI attacks reached backend servers without being blocked.

### Detailed Attack Evidence

| # | Target Host | Source IP | Country | Status | Attack URI |
|---|-------------|-----------|---------|--------|------------|
| 1 | care-strawberry.rotests.com | 34.238.250.162 | US | 302 | `/..././/..././/..././/..././/..././/..././/..././/..././etc/./passwd` |
| 2 | notebook-api-peach.rotests.com | 35.175.153.123 | US | 302 | `/..%5c..%5c..%5c..%5c..%5c/windows/win.ini` |
| 3 | spermkit-phy-apple.rotests.com | 3.95.225.132 | US | 302 | `/////////////////////..././/..././/..././/..././etc/./passwd` |
| 4 | pgbadger-staging.rotests.com | 18.234.141.77 | US | 403 | `////////////////////c:/windows/nydjv/../win.ini` |
| 5 | notebook-api-zulu.rotests.com | 18.234.141.77 | US | 302 | `/////////////////////windows/rohzd/../win.ini` |
| 6 | webhooks-api-banana.rotests.com | 34.238.250.162 | US | 404 | `//%2e%2e%2e/%2e/%2e%2e%2e/%2e/%2e%2e%2e/%2e/etc/passwd` |
| 7 | api-spermkit-staging.rotests.com | 3.89.124.169 | US | 302 | `////////////////////\..%5c..%5c..%5c..%5c..%5c\windows\win.ini` |
| 8 | webhooks-api-tango.rotests.com | 35.175.153.123 | US | 404 | `////////////////////c:/windows/win.ini` |
| 9 | ro-co.rotests.com | 54.226.67.61 | US | 302 | `/..%252f/..%252f/..%252f/..%252f/..%252f/etc/passwd` |
| 10 | spermlab-peach.rotests.com | 54.157.52.94 | US | 302 | `////////////////////\..\..\..\..\..\..\windows\cavhl\..\win.ini` |
| 11 | hellorory-staging.rotests.com | 34.238.250.162 | US | 301 | `/////////////////////windows/win.ini` |
| 12 | fulfillment-spermkit-staging.rotests.com | 44.212.57.79 | US | 302 | `/..././..././..././..././etc/passwd` |
| 13 | spermkit-apricot.rotests.com | 44.202.155.13 | US | 302 | `/////////////////////..%5c..%5c..%5c..%5c..%5c/windows/win.ini` |
| 14 | internal-staging.rotests.com | 18.234.141.77 | US | 302 | `////////////////////c%3a/windows/win.ini` |
| 15 | ci-artifacts.rotests.com | 54.234.137.247 | US | 403 | `////////////////////c:/windows/bevth/../win.ini` |

### Attacking IP Analysis
All attacking IPs are from AWS (us-east-1 region):
- 34.238.250.162, 35.175.153.123, 3.95.225.132, 18.234.141.77
- 44.201.228.86, 3.89.124.169, 54.157.52.94, 44.203.147.147

**User-Agent:** All using `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`

---

## Finding 4: CRITICAL - Malicious Requests (Attack Score 1) Allowed

### Summary
40+ requests with WAF attack score of 1 (highest maliciousness) bypassed protection.

### Detailed Evidence

| # | Target Host | Source IP | Attack Score | SQLi Score | URI (truncated) |
|---|-------------|-----------|--------------|------------|-----------------|
| 1 | ro-co.rotests.com | 54.226.67.61 | 1 | 98 | `/////\../\../\../\../\windows/\uanrl/\../\win.ini` |
| 2 | spermkit-pf.rotests.com | 44.201.228.86 | 1 | 98 | `/////\../\../\../\../\windows/\ubypa/\../\win.ini` |
| 3 | iframe-ro-co.rotests.com | 3.87.219.205 | 1 | 98 | `/..%252f/..%252f/..%252f/etc/passwd` |
| 4 | spermkit-phy-whiskey.rotests.com | 44.202.145.238 | 1 | 98 | `/%2f...%2f.%2f%2f...%2f.%2f%2f...%2f.%2f/etc/passwd` |
| 5 | spermkit-lemon.rotests.com | 13.222.54.71 | 1 | 98 | `/////..././/..././/..././/..././etc/./passwd` |
| 6 | my-vanilla.rotests.com | 34.238.250.162 | 1 | 98 | `/////%2e%2e%2e/%2e//%2e%2e%2e/%2e//etc/passwd` |
| 7 | spermkit-watermelon.rotests.com | 3.92.225.113 | 1 | 98 | `/%2f..%252f%2f..%252f%2fetc%2fpasswd` |
| 8 | fulfillment-spermkit-staging.rotests.com | 44.212.57.79 | 1 | 98 | `////\\..\\..\\..\\..\\windows\\xcgpx\\..\\win.ini` |
| 9 | ro-co-beta.rotests.com | 13.222.54.71 | 1 | 98 | `/%2f..%252f%2f..%252f%2f..%252f/etc/passwd` |
| 10 | phy-cherry.rotests.com | 3.93.146.221 | 1 | 98 | `/%2f..%252f%2f..%252f/etc/passwd` |

**Total Malicious Requests Allowed:** 40+ with attack score = 1

---

## Finding 5: HIGH - Nuclei Vulnerability Scanner Allowed

### Summary
Nuclei scanner from Moldova (178.175.128.41) performed vulnerability scanning without being blocked.

### Evidence

| Target Host | Source IP | Country | Action | Status | URI |
|-------------|-----------|---------|--------|--------|-----|
| spermkit-phy-cookie.rotests.com | 178.175.128.41 | Moldova | **NULL** | 301 | `/?gqlyp=gxlas` |
| spermkit-phy-cookie.rotests.com | 178.175.128.41 | Moldova | **NULL** | 301 | `/?gqlyp=gxlas` |
| spermkit-phy-cookie.rotests.com | 178.175.128.41 | Moldova | **NULL** | 301 | `/?gqlyp=gxlas` |
| spermkit-phy-cookie.rotests.com | 178.175.128.41 | Moldova | **NULL** | 301 | `/?gqlyp=gxlas` |
| spermkit-phy-cookie.rotests.com | 178.175.128.41 | Moldova | **NULL** | 301 | `/?gqlyp=gxlas` |

**User-Agent:** `Nuclei - Open-source project (github.com/projectdiscovery/nuclei)`

**Total Nuclei Requests:** 5 (all unblocked)

---

## Finding 6: HIGH - Definite Bot Traffic Bypassing (Score 0-1)

### Summary
3,084 requests with bot score 0-1 (definitively automated) bypassed WAF via SKIP rules.

### Evidence

| Target Host | Path | Source IP | Country | Bot Score | Action | User-Agent |
|-------------|------|-----------|---------|-----------|--------|------------|
| start-staging.rotests.com | `/` | 2600:1f16:23e:2312:8a11:ac6:ec7f:155 | US | 1 | skip | curl/8.5.0 |
| start-staging.rotests.com | `/data/roman_api/schemas/fdalgd/...` | 2600:1f16:23e:2312:8a11:ac6:ec7f:155 | US | 1 | skip | Mozilla/5.0 (X11; Linux x86_64) |
| start-staging.rotests.com | `/svc/ro-experiments/public/roexp.min.js` | 2600:1f16:23e:2312:8a11:ac6:4e55:c6c | US | 1 | skip | Mozilla/5.0 (X11; Linux x86_64) |
| start-staging.rotests.com | `/svc/provider-workflows/internal/batch-config` | 2600:1f16:23e:2305:ba54:ac6:c31f:191 | US | 1 | skip | Mozilla/5.0 (Windows NT 10.0) |
| ro-co.rotests.com | `/svc/ro-experiments/public/roexp.min.js` | 2600:1f16:23e:2304:9796:ac5:1dc8:121 | US | 1 | skip | Mozilla/5.0 (X11; Linux x86_64) |
| ro-co.rotests.com | `/rocostatic/fonts/Ro_Sans-Bold.woff` | 2600:1f16:23e:2304:9796:ac5:1dc8:121 | US | 1 | skip | Mozilla/5.0 (X11; Linux x86_64) |
| ro-co.rotests.com | `/rocostatic/fonts.css` | 2600:1f16:23e:2304:9796:ac5:1dc8:121 | US | 1 | skip | Mozilla/5.0 (X11; Linux x86_64) |

**Total Bot Traffic Allowed:** 3,084 requests

---

## Finding 7: HIGH - Patient/PHI Endpoints via SKIP Rules

### Summary
Healthcare data endpoints receiving traffic via SKIP rules without WAF attack validation.

### Evidence

| Path | Target Host | Source IP | Country | Status | Action |
|------|-------------|-----------|---------|--------|--------|
| `/svc/patients/start.public/exists` | start-staging.rotests.com | 2600:1f16:23e:2304:9796:ac5:79f1:d5d | US | 200 | skip |
| `/svc/patients/start.public/exists` | start-staging.rotests.com | 2600:1f16:23e:2305:ba54:ac6:67d8:3cf | US | 200 | skip |
| `/svc/clinical-encounters/cc/clinical-encounters/bulk-type` | cc-staging.rotests.com | 2600:1f16:23e:2305:ba54:ac6:67d8:3cf | US | 200 | skip |
| `/svc/patients/start.public/exists` | start-staging.rotests.com | 2600:1f16:23e:2312:8a11:ac6:ec7f:155 | US | 200 | skip |
| `/svc/patients/start.public/exists` | start-staging.rotests.com | 2600:1f16:23e:2312:8a11:ac6:7bff:78 | US | 200 | skip |

### PHI Endpoint Summary

| Endpoint | Action | Count |
|----------|--------|-------|
| `/svc/patients/cc/search` | skip | 695 |
| `/svc/patients/start.public/exists` | skip | 622 |
| `/svc/clinical-encounters/cc/clinical-encounters/bulk-type` | skip | 420 |
| `/api/pharmacy/user-permissions` | skip | 259 |
| `/svc/patients/pharmacy/search` | skip | 240 |
| `/api/my/patient-contracts` | skip | 177 |
| `/svc/id-verification/pharmacy/retrieve-verification` | skip | 163 |
| `/svc/dur/pharmacy/doccos` | skip | 112 |
| `/svc/clinical-flags/cc/treatment-request` | skip | 110 |

---

## Finding 8: HIGH - Geographic Anomaly - Latvia 0% Block Rate

### Summary
All traffic from Latvia (13,351 requests) bypassed WAF blocking entirely.

### Evidence

**Source IP:** `196.196.53.52` (Latvia)
**Target:** `api-gooseberry.rotests.com`

| Path | Status | Action | Sample Count |
|------|--------|--------|--------------|
| `/` | 302 | NULL | Multiple |
| `/` | 403 | managedChallenge | Multiple |

**Total Latvia Traffic:** 13,351 requests
**Block Rate:** 0%

### Country Block Rate Comparison

| Country | Total | Blocked | Block Rate |
|---------|-------|---------|------------|
| Finland (fi) | 37,190 | 37,174 | 100.0% |
| Singapore (sg) | 17,372 | 17,326 | 99.7% |
| UK (gb) | 8,170 | 8,147 | 99.7% |
| Germany (de) | 355,199 | 288,474 | 81.2% |
| France (fr) | 111,210 | 78,982 | 71.0% |
| **Luxembourg (lu)** | 3,630 | 126 | **3.5%** |
| **Moldova (md)** | 1,068 | 25 | **2.3%** |
| **Latvia (lv)** | 13,351 | 0 | **0.0%** |

---

## Finding 9: Security Rules Analysis

### Top Triggered Rules

| Rule Description | Action | Count |
|------------------|--------|-------|
| Block High Risk ASN Traffic | block | 540,813 |
| [SKIP] BYPASS K6 LOAD TEST | skip | 215,989 |
| [Block] Non-standard Ports | block | 126,759 |
| [SKIP] core-service IP bypass | skip | 52,912 |
| [Managed Challenge] 404 Rate Limit - Non US | challenge | 29,719 |
| [TEMP] Cache Bust Enumeration | challenge | 21,893 |
| High Traffic Fuzzer Block | block | 2,657 |

### Problem: SKIP Rules Too Permissive
The K6 load test and core-service IP bypass rules are skipping WAF evaluation for all traffic from whitelisted sources, including actual attacks.

---

## Finding 10: Attacks Properly Blocked (What's Working)

### Blocked Attack Types

| Attack Type | Blocked Count | Evidence |
|-------------|---------------|----------|
| Prototype Pollution | 15+ | `/?__proto__[...]=...` |
| .env Enumeration | 788+ | `/.env`, `/.env.production`, etc. |
| Template Injection (SSTI) | Multiple | `${9898*323}`, `${dirname}` |
| File Inclusion (WEB-INF) | 156 | Blocked by rule |
| Version Control Exposure | 159 | `/.git/config` attempts |
| PHP Code Injection | 4 | CVE-2017-9841 |
| XSS | 1+ | Script tag injection |

---

## Risk Matrix

| ID | Severity | Finding | Count | Impact |
|----|----------|---------|-------|--------|
| RO-001 | CRITICAL | Jenkins CI/CD exposed | 8,000+ | Infrastructure compromise |
| RO-002 | CRITICAL | Luxembourg scanner 96.5% bypass | 3,504 | Full recon capability |
| RO-003 | CRITICAL | Path traversal bypasses | 50+ | Potential file read |
| RO-004 | CRITICAL | Attack score 1 traffic allowed | 40+ | Active exploitation |
| RO-005 | HIGH | Nuclei scanner unblocked | 5 | Vulnerability discovery |
| RO-006 | HIGH | Bot traffic via SKIP | 3,084 | Automated abuse |
| RO-007 | HIGH | PHI endpoints via SKIP | 2,000+ | Data access risk |
| RO-008 | HIGH | Latvia 0% block rate | 13,351 | Blind spot |
| RO-009 | HIGH | FortiGate CVE probe allowed | 2 | Vuln scanning |
| RO-010 | MEDIUM | Empty UA allowed | 92,950 | Potential probing |

---

## Immediate Remediation

### 1. Block Active Scanners
```
# Block Luxembourg scanner
ip.src == 45.12.139.54

# Block Nuclei user-agent
http.user_agent contains "Nuclei"

# Block Moldova scanner IP
ip.src == 178.175.128.41
```

### 2. Fix SKIP Rules - Add Attack Validation
```
# Current (too permissive):
(ip.src in $K6_LOAD_TEST_IPS)

# Recommended (with attack validation):
(ip.src in $K6_LOAD_TEST_IPS) AND (cf.waf.score > 30 OR cf.waf.score IS NULL)
```

### 3. Block Jenkins Paths
```
(http.host eq "ci.rotests.com") AND NOT (ip.src in $INTERNAL_IPS)
```

### 4. Block Path Traversal Patterns
```
(http.request.uri.path contains "../") OR
(http.request.uri.path contains "..%2f") OR
(http.request.uri.path contains "etc/passwd") OR
(http.request.uri.path contains "win.ini")
```

### 5. Investigate Low Block Rate Countries
- Review why Latvia, Luxembourg, Moldova have near-zero block rates
- Consider geo-blocking for countries with no legitimate business need

---

## Appendix: Source IP Summary

### Top Attacking IPs (Path Traversal)

| IP | Country | Requests |
|----|---------|----------|
| 34.238.250.162 | US (AWS) | Multiple |
| 35.175.153.123 | US (AWS) | Multiple |
| 18.234.141.77 | US (AWS) | Multiple |
| 44.201.228.86 | US (AWS) | Multiple |
| 3.92.225.113 | US (AWS) | Multiple |
| 44.203.147.147 | US (AWS) | Multiple |
| 3.89.124.169 | US (AWS) | Multiple |
| 54.157.52.94 | US (AWS) | Multiple |

### Scanner IPs

| IP | Country | ASN | Activity |
|----|---------|-----|----------|
| 45.12.139.54 | Luxembourg | 209847 | Full site recon (3,612 paths) |
| 178.175.128.41 | Moldova | - | Nuclei scanning |
| 196.196.53.52 | Latvia | - | API probing |

---

**Report Generated:** 2026-01-25  
**Analysis Depth:** Comprehensive with full evidence  
**Data Source:** Trino (huskeys_customers_logs.waf_logs_db.ro_waf_logs_rcloned)
