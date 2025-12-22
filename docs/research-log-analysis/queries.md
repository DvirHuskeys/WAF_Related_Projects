# WAF Log Research Queries

**Complete catalog of queries for detecting abusive behaviors, anomalies, and security threats in Cloudflare WAF logs.**

---

## Table of Contents

1. [Traffic Floods & Rate-Based Attacks](#traffic-floods--rate-based-attacks)
2. [WAF Bypass Detection](#waf-bypass-detection)
3. [Anomaly Detection](#anomaly-detection)
4. [Scraper & Bot Detection](#scraper--bot-detection)
5. [Attack Tool Signatures](#attack-tool-signatures)
6. [Geographic & Network Analysis](#geographic--network-analysis)
7. [Request Pattern Analysis](#request-pattern-analysis)
8. [Security Event Correlation](#security-event-correlation)

---

## Traffic Floods & Rate-Based Attacks

### Q1: High-Volume IP Addresses

**Purpose:** Identify IP addresses generating excessive request volumes, indicating potential DDoS or brute-force attacks.

**Impact:** High - Detects volumetric attacks and resource exhaustion attempts.

**Query:**
```sql
SELECT 
    clientip,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints,
    COUNT(DISTINCT clientrequestuseragent) as unique_user_agents
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
GROUP BY clientip
HAVING COUNT(*) > 1000
ORDER BY request_count DESC
LIMIT 100
```

**What it does:** Aggregates requests by source IP, filtering for IPs exceeding 1000 requests per hour. Includes unique endpoint and user-agent counts to identify automated patterns.

**Expected Results:** List of IPs with request counts, showing potential attack sources.

**Thresholds:** Adjust `HAVING COUNT(*) > 1000` based on baseline (typical: 500-2000 requests/hour per IP).

---

### Q2: Endpoint Request Floods

**Purpose:** Detect endpoints receiving unusually high traffic volumes, indicating targeted attacks or scraping.

**Impact:** High - Identifies targeted resource attacks and potential API abuse.

**Query:**
```sql
SELECT 
    clientrequesturi,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(DISTINCT clientrequestuseragent) as unique_user_agents,
    AVG(edgeresponsebytes) as avg_response_size
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
GROUP BY clientrequesturi
HAVING COUNT(*) > 500
ORDER BY request_count DESC
LIMIT 50
```

**What it does:** Identifies endpoints with high request volumes, showing potential targets for attacks or scraping.

**Expected Results:** Top endpoints by request volume with associated metrics.

---

### Q3: Request Rate Spikes by Time Window

**Purpose:** Detect sudden traffic spikes within short time windows, indicating burst attacks.

**Impact:** Medium - Identifies time-based attack patterns.

**Query:**
```sql
SELECT 
    year,
    month,
    day,
    hour,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
GROUP BY year, month, day, hour
ORDER BY request_count DESC
```

**What it does:** Aggregates traffic by hour to identify peak periods and potential attack windows.

**Expected Results:** Hourly request counts showing traffic distribution.

---

### Q4: Bandwidth Consumption Analysis

**Purpose:** Identify high-bandwidth consumers, detecting data exfiltration or large payload attacks.

**Impact:** Medium - Detects resource-intensive attacks.

**Query:**
```sql
SELECT 
    clientip,
    SUM(edgeresponsebytes) as total_bytes,
    COUNT(*) as request_count,
    AVG(edgeresponsebytes) as avg_bytes_per_request,
    MAX(edgeresponsebytes) as max_response_size
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
GROUP BY clientip
HAVING SUM(edgeresponsebytes) > 100000000
ORDER BY total_bytes DESC
LIMIT 50
```

**What it does:** Calculates total bandwidth consumption per IP, flagging high-volume data transfers.

**Expected Results:** IPs ranked by bandwidth consumption.

**Threshold:** 100MB+ per hour per IP (adjust based on baseline).

---

## WAF Bypass Detection

### Q5: Successful Requests After WAF Challenges

**Purpose:** Identify requests that successfully bypassed WAF challenges, indicating potential evasion.

**Impact:** Critical - Detects WAF bypass attempts.

**Query:**
```sql
SELECT 
    clientip,
    clientrequesturi,
    clientrequestmethod,
    wafaction,
    edgeresponsestatus,
    COUNT(*) as bypass_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND wafaction IN ('challenge', 'log')
  AND edgeresponsestatus = 200
GROUP BY clientip, clientrequesturi, clientrequestmethod, wafaction, edgeresponsestatus
HAVING COUNT(*) > 10
ORDER BY bypass_count DESC
```

**What it does:** Finds requests that triggered WAF challenges but still returned 200 OK, indicating potential bypass.

**Expected Results:** Patterns showing successful requests after WAF intervention.

---

### Q6: WAF Action Distribution Analysis

**Purpose:** Understand WAF effectiveness and identify patterns where actions differ from expected.

**Impact:** High - Measures WAF rule effectiveness.

**Query:**
```sql
SELECT 
    wafaction,
    COUNT(*) as action_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints,
    AVG(edgeresponsestatus) as avg_status_code
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND wafaction IS NOT NULL
GROUP BY wafaction
ORDER BY action_count DESC
```

**What it does:** Aggregates WAF actions to show distribution of block/challenge/log actions.

**Expected Results:** Breakdown of WAF actions with associated metrics.

---

### Q7: Repeated Bypass Attempts

**Purpose:** Detect IPs repeatedly attempting to bypass WAF rules with variations.

**Impact:** Critical - Identifies persistent attackers.

**Query:**
```sql
SELECT 
    clientip,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints_tested,
    COUNT(DISTINCT clientrequestuseragent) as user_agent_rotations,
    COUNT(*) as total_attempts,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count,
    COUNT(CASE WHEN edgeresponsestatus = 200 THEN 1 END) as successful_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 4 AND 6
GROUP BY clientip
HAVING COUNT(*) > 50 
   AND COUNT(DISTINCT clientrequesturi) > 5
ORDER BY total_attempts DESC
LIMIT 100
```

**What it does:** Identifies IPs testing multiple endpoints with various techniques, showing systematic bypass attempts.

**Expected Results:** IPs with high attempt counts across multiple endpoints.

---

### Q8: User-Agent Rotation Patterns

**Purpose:** Detect attackers rotating user-agents to evade detection.

**Impact:** Medium - Identifies sophisticated evasion techniques.

**Query:**
```sql
SELECT 
    clientip,
    COUNT(DISTINCT clientrequestuseragent) as unique_user_agents,
    COUNT(*) as total_requests,
    COLLECT_SET(clientrequestuseragent) as user_agent_list
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
GROUP BY clientip
HAVING COUNT(DISTINCT clientrequestuseragent) > 5
ORDER BY unique_user_agents DESC
LIMIT 50
```

**What it does:** Finds IPs using multiple user-agents, indicating automated tools or evasion attempts.

**Expected Results:** IPs with excessive user-agent diversity.

---

## Anomaly Detection

### Q9: Unusual HTTP Methods

**Purpose:** Detect non-standard HTTP methods that may indicate attack tools or misconfigurations.

**Impact:** Medium - Identifies unusual request patterns.

**Query:**
```sql
SELECT 
    clientrequestmethod,
    COUNT(*) as method_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND clientrequestmethod NOT IN ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH')
GROUP BY clientrequestmethod
ORDER BY method_count DESC
```

**What it does:** Identifies requests using non-standard HTTP methods (e.g., PROPFIND, CONNECT, TRACE).

**Expected Results:** List of unusual HTTP methods with usage counts.

---

### Q10: Status Code Anomalies

**Purpose:** Detect unusual status code distributions indicating errors, attacks, or misconfigurations.

**Impact:** Medium - Identifies application errors or attack patterns.

**Query:**
```sql
SELECT 
    edgeresponsestatus,
    COUNT(*) as status_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
GROUP BY edgeresponsestatus
ORDER BY status_count DESC
```

**What it does:** Shows distribution of HTTP status codes, highlighting anomalies (high 4xx/5xx rates).

**Expected Results:** Status code breakdown with percentages.

---

### Q11: Geographic Anomalies

**Purpose:** Detect traffic from unexpected geographic locations.

**Impact:** Low-Medium - Identifies potential geographic-based attacks or account compromise.

**Query:**
```sql
SELECT 
    clientcountry,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints,
    AVG(edgeresponsestatus) as avg_status_code
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
GROUP BY clientcountry
ORDER BY request_count DESC
LIMIT 50
```

**What it does:** Aggregates traffic by country, identifying unusual geographic patterns.

**Expected Results:** Top countries by request volume.

---

### Q12: Request Size Anomalies

**Purpose:** Detect unusually large or small request payloads indicating attacks or malformed requests.

**Impact:** Medium - Identifies payload-based attacks.

**Query:**
```sql
SELECT 
    clientip,
    clientrequestmethod,
    clientrequesturi,
    clientrequestbytes,
    edgeresponsestatus,
    wafaction
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND (clientrequestbytes > 1000000 OR clientrequestbytes < 100)
ORDER BY clientrequestbytes DESC
LIMIT 100
```

**What it does:** Finds requests with abnormally large (>1MB) or small (<100B) payloads.

**Expected Results:** Requests with unusual payload sizes.

---

## Scraper & Bot Detection

### Q13: Bot Score Analysis

**Purpose:** Analyze Cloudflare bot scores to identify automated traffic.

**Impact:** High - Detects bot traffic and automated scraping.

**Query:**
```sql
SELECT 
    CASE 
        WHEN botscore < 1 THEN 'Definitely Bot'
        WHEN botscore < 30 THEN 'Likely Bot'
        WHEN botscore < 70 THEN 'Uncertain'
        ELSE 'Likely Human'
    END as bot_category,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientip) as unique_ips,
    AVG(botscore) as avg_bot_score
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND botscore IS NOT NULL
GROUP BY bot_category
ORDER BY request_count DESC
```

**What it does:** Categorizes traffic by bot score ranges to identify automated vs human traffic.

**Expected Results:** Distribution of traffic across bot score categories.

---

### Q14: Known Bot User-Agents

**Purpose:** Identify requests from known bot/crawler user-agents.

**Impact:** Medium - Detects legitimate and malicious bots.

**Query:**
```sql
SELECT 
    clientrequestuseragent,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND (
    LOWER(clientrequestuseragent) LIKE '%bot%'
    OR LOWER(clientrequestuseragent) LIKE '%crawler%'
    OR LOWER(clientrequestuseragent) LIKE '%spider%'
    OR LOWER(clientrequestuseragent) LIKE '%scraper%'
  )
GROUP BY clientrequestuseragent
ORDER BY request_count DESC
LIMIT 50
```

**What it does:** Identifies requests from user-agents containing bot-related keywords.

**Expected Results:** List of bot user-agents with request counts.

---

### Q15: Crawl Pattern Detection

**Purpose:** Detect systematic crawling patterns indicating scraping or reconnaissance.

**Impact:** High - Identifies automated data collection.

**Query:**
```sql
SELECT 
    clientip,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints_crawled,
    COUNT(*) as total_requests,
    MIN(timestamp) as first_request,
    MAX(timestamp) as last_request,
    COUNT(DISTINCT clientrequestuseragent) as user_agent_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
GROUP BY clientip
HAVING COUNT(DISTINCT clientrequesturi) > 20
ORDER BY unique_endpoints_crawled DESC
LIMIT 50
```

**What it does:** Identifies IPs accessing many different endpoints, indicating crawling behavior.

**Expected Results:** IPs with high endpoint diversity.

---

### Q16: Request Frequency Analysis

**Purpose:** Detect IPs making requests at suspiciously regular intervals (automated tools).

**Impact:** Medium - Identifies automated request patterns.

**Query:**
```sql
SELECT 
    clientip,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints,
    AVG(EXTRACT(EPOCH FROM (timestamp - LAG(timestamp) OVER (PARTITION BY clientip ORDER BY timestamp)))) as avg_seconds_between_requests
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
GROUP BY clientip
HAVING COUNT(*) > 100
ORDER BY request_count DESC
LIMIT 50
```

**What it does:** Calculates average time between requests per IP to identify automated patterns.

**Expected Results:** IPs with suspiciously regular request intervals.

---

## Attack Tool Signatures

### Q17: SQL Injection Pattern Detection

**Purpose:** Detect SQL injection attempts in request URIs and query parameters.

**Impact:** Critical - Identifies SQL injection attacks.

**Query:**
```sql
SELECT 
    clientip,
    clientrequesturi,
    clientrequestmethod,
    wafaction,
    edgeresponsestatus,
    COUNT(*) as attempt_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND (
    LOWER(clientrequesturi) LIKE '%union%select%'
    OR LOWER(clientrequesturi) LIKE '%or%1=1%'
    OR LOWER(clientrequesturi) LIKE '%drop%table%'
    OR LOWER(clientrequesturi) LIKE '%exec%(%'
    OR LOWER(clientrequesturi) LIKE '%;--%'
    OR LOWER(clientrequesturi) LIKE '%\'%or%\'%'
  )
GROUP BY clientip, clientrequesturi, clientrequestmethod, wafaction, edgeresponsestatus
ORDER BY attempt_count DESC
LIMIT 100
```

**What it does:** Searches for common SQL injection patterns in request URIs.

**Expected Results:** Requests containing SQL injection signatures.

---

### Q18: XSS Pattern Detection

**Purpose:** Detect cross-site scripting (XSS) attack attempts.

**Impact:** Critical - Identifies XSS attacks.

**Query:**
```sql
SELECT 
    clientip,
    clientrequesturi,
    clientrequestmethod,
    wafaction,
    edgeresponsestatus,
    COUNT(*) as attempt_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND (
    LOWER(clientrequesturi) LIKE '%<script%'
    OR LOWER(clientrequesturi) LIKE '%javascript:%'
    OR LOWER(clientrequesturi) LIKE '%onerror=%'
    OR LOWER(clientrequesturi) LIKE '%onclick=%'
    OR LOWER(clientrequesturi) LIKE '%alert(%'
    OR LOWER(clientrequesturi) LIKE '%eval(%'
  )
GROUP BY clientip, clientrequesturi, clientrequestmethod, wafaction, edgeresponsestatus
ORDER BY attempt_count DESC
LIMIT 100
```

**What it does:** Identifies requests containing XSS attack patterns.

**Expected Results:** Requests with XSS signatures.

---

### Q19: Path Traversal Detection

**Purpose:** Detect directory traversal attempts (../, ..\\, etc.).

**Impact:** High - Identifies path traversal attacks.

**Query:**
```sql
SELECT 
    clientip,
    clientrequesturi,
    clientrequestmethod,
    wafaction,
    edgeresponsestatus,
    COUNT(*) as attempt_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND (
    clientrequesturi LIKE '%../%'
    OR clientrequesturi LIKE '%..\\%'
    OR clientrequesturi LIKE '%....//%'
    OR clientrequesturi LIKE '%%2e%2e%2f%'
  )
GROUP BY clientip, clientrequesturi, clientrequestmethod, wafaction, edgeresponsestatus
ORDER BY attempt_count DESC
LIMIT 100
```

**What it does:** Finds requests attempting directory traversal.

**Expected Results:** Requests with path traversal patterns.

---

### Q20: Command Injection Detection

**Purpose:** Detect command injection attempts (system command execution).

**Impact:** Critical - Identifies command injection attacks.

**Query:**
```sql
SELECT 
    clientip,
    clientrequesturi,
    clientrequestmethod,
    wafaction,
    edgeresponsestatus,
    COUNT(*) as attempt_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND (
    LOWER(clientrequesturi) LIKE '%|%whoami%'
    OR LOWER(clientrequesturi) LIKE '%|%ls%'
    OR LOWER(clientrequesturi) LIKE '%|%cat%'
    OR LOWER(clientrequesturi) LIKE '%;%whoami%'
    OR LOWER(clientrequesturi) LIKE '%`%whoami%`%'
    OR LOWER(clientrequesturi) LIKE '%$(whoami)%'
  )
GROUP BY clientip, clientrequesturi, clientrequestmethod, wafaction, edgeresponsestatus
ORDER BY attempt_count DESC
LIMIT 100
```

**What it does:** Identifies command injection patterns using pipes, semicolons, backticks, or command substitution.

**Expected Results:** Requests with command injection signatures.

---

### Q21: Known Scanner Signatures

**Purpose:** Detect requests from known vulnerability scanners and attack tools.

**Impact:** Medium - Identifies reconnaissance and scanning tools.

**Query:**
```sql
SELECT 
    clientip,
    clientrequestuseragent,
    clientrequesturi,
    COUNT(*) as request_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND (
    LOWER(clientrequestuseragent) LIKE '%nikto%'
    OR LOWER(clientrequestuseragent) LIKE '%sqlmap%'
    OR LOWER(clientrequestuseragent) LIKE '%nmap%'
    OR LOWER(clientrequestuseragent) LIKE '%masscan%'
    OR LOWER(clientrequestuseragent) LIKE '%zap%'
    OR LOWER(clientrequestuseragent) LIKE '%burp%'
    OR LOWER(clientrequesturi) LIKE '%wp-admin%'
    OR LOWER(clientrequesturi) LIKE '%phpmyadmin%'
    OR LOWER(clientrequesturi) LIKE '%.env%'
  )
GROUP BY clientip, clientrequestuseragent, clientrequesturi
ORDER BY request_count DESC
LIMIT 100
```

**What it does:** Identifies requests from known security scanners or targeting common vulnerable endpoints.

**Expected Results:** Requests from scanning tools or targeting admin interfaces.

---

## Geographic & Network Analysis

### Q22: ASN-Based Attack Clusters

**Purpose:** Identify attacks originating from specific ASNs or network providers.

**Impact:** Medium - Identifies network-based attack patterns.

**Query:**
```sql
SELECT 
    clientasn,
    clientcountry,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND clientasn IS NOT NULL
GROUP BY clientasn, clientcountry
HAVING COUNT(*) > 100
ORDER BY blocked_count DESC, request_count DESC
LIMIT 50
```

**What it does:** Aggregates traffic by ASN to identify network-level attack sources.

**Expected Results:** ASNs ranked by blocked request counts.

---

### Q23: Cross-Country Attack Patterns

**Purpose:** Detect coordinated attacks from multiple countries.

**Impact:** Medium - Identifies distributed attack campaigns.

**Query:**
```sql
SELECT 
    clientcountry,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(*) as total_requests,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    AVG(botscore) as avg_bot_score
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 4 AND 6
  AND clientcountry IS NOT NULL
GROUP BY clientcountry
HAVING COUNT(*) > 500
ORDER BY blocked_count DESC
LIMIT 30
```

**What it does:** Analyzes attack patterns by country over multiple hours.

**Expected Results:** Countries ranked by blocked request volume.

---

## Request Pattern Analysis

### Q24: HTTP Method Distribution

**Purpose:** Understand normal HTTP method usage and detect anomalies.

**Impact:** Low-Medium - Baseline analysis for anomaly detection.

**Query:**
```sql
SELECT 
    clientrequestmethod,
    COUNT(*) as method_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
GROUP BY clientrequestmethod
ORDER BY method_count DESC
```

**What it does:** Shows distribution of HTTP methods in traffic.

**Expected Results:** HTTP method breakdown with percentages.

---

### Q25: Top Requested Endpoints

**Purpose:** Identify most frequently accessed endpoints for baseline establishment.

**Impact:** Low - Baseline analysis.

**Query:**
```sql
SELECT 
    clientrequesturi,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientip) as unique_ips,
    AVG(edgeresponsestatus) as avg_status_code,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
GROUP BY clientrequesturi
ORDER BY request_count DESC
LIMIT 50
```

**What it does:** Lists most popular endpoints with associated metrics.

**Expected Results:** Top endpoints by request volume.

---

## Security Event Correlation

### Q26: IP Reputation Scoring

**Purpose:** Create reputation scores for IPs based on multiple factors.

**Impact:** High - Enables automated threat scoring.

**Query:**
```sql
SELECT 
    clientip,
    COUNT(*) as total_requests,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints,
    COUNT(DISTINCT clientrequestuseragent) as user_agent_count,
    AVG(botscore) as avg_bot_score,
    ROUND(
        (COUNT(CASE WHEN wafaction = 'block' THEN 1 END) * 3.0 +
         COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) * 1.5 +
         (COUNT(DISTINCT clientrequestuseragent) - 1) * 0.5) / 
        NULLIF(COUNT(*), 0) * 100, 2
    ) as threat_score
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 4 AND 6
GROUP BY clientip
HAVING COUNT(*) > 10
ORDER BY threat_score DESC
LIMIT 100
```

**What it does:** Calculates threat scores for IPs based on blocked requests, challenges, and behavior patterns.

**Expected Results:** IPs ranked by calculated threat scores.

---

### Q27: Attack Campaign Detection

**Purpose:** Identify coordinated attacks across multiple IPs targeting similar endpoints.

**Impact:** Critical - Detects organized attack campaigns.

**Query:**
```sql
SELECT 
    clientrequesturi,
    COUNT(DISTINCT clientip) as attacking_ips,
    COUNT(*) as total_attempts,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(DISTINCT clientcountry) as unique_countries,
    MIN(timestamp) as first_attempt,
    MAX(timestamp) as last_attempt
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 4 AND 6
  AND wafaction IN ('block', 'challenge')
GROUP BY clientrequesturi
HAVING COUNT(DISTINCT clientip) > 5
ORDER BY attacking_ips DESC, total_attempts DESC
LIMIT 50
```

**What it does:** Identifies endpoints targeted by multiple IPs, indicating coordinated attacks.

**Expected Results:** Endpoints under coordinated attack.

---

### Q28: Time-Based Attack Windows

**Purpose:** Identify time periods with concentrated attack activity.

**Impact:** Medium - Helps understand attack timing patterns.

**Query:**
```sql
SELECT 
    hour,
    COUNT(*) as total_requests,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count,
    COUNT(DISTINCT clientip) as unique_ips,
    ROUND(COUNT(CASE WHEN wafaction = 'block' THEN 1 END) * 100.0 / COUNT(*), 2) as block_percentage
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
GROUP BY hour
ORDER BY blocked_count DESC
```

**What it does:** Analyzes attack intensity by hour to identify peak attack windows.

**Expected Results:** Hourly attack statistics showing peak periods.

---

## Query Usage Guidelines

### Time Window Selection
- **Single Hour:** Use for detailed analysis (`hour = 5`)
- **Multiple Hours:** Use for pattern detection (`hour BETWEEN 4 AND 6`)
- **Full Day:** Use for baseline establishment (`day = 21`)

### Threshold Adjustment
- Start with conservative thresholds
- Adjust based on baseline analysis
- Consider customer-specific patterns
- Document threshold rationale

### Performance Optimization
- Use appropriate LIMIT clauses
- Filter early with WHERE conditions
- Aggregate before joining
- Consider partitioning strategy

### Result Interpretation
- Compare against baselines
- Correlate multiple queries
- Consider false positives
- Document findings with evidence

---

## Next Steps

1. **Establish Baselines:** Run baseline queries (Q24, Q25) to understand normal traffic
2. **Detect Anomalies:** Execute anomaly queries (Q9-Q12) to identify deviations
3. **Investigate Threats:** Run threat-specific queries (Q17-Q21) for attack detection
4. **Correlate Findings:** Use correlation queries (Q26-Q28) to identify patterns
5. **Document Results:** Record findings with timestamps and evidence

---

**Last Updated:** 2025-12-21  
**Query Count:** 28  
**Categories:** 8

