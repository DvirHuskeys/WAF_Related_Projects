# Advanced WAF Log Analysis Queries

**Extended query catalog for deep-dive analysis and pattern detection.**

---

## Table of Contents

1. [Multi-Time Window Analysis](#multi-time-window-analysis)
2. [Cross-Customer Pattern Detection](#cross-customer-pattern-detection)
3. [Attack Chain Reconstruction](#attack-chain-reconstruction)
4. [Behavioral Profiling](#behavioral-profiling)
5. [Threat Intelligence Correlation](#threat-intelligence-correlation)

---

## Multi-Time Window Analysis

### Q29: Traffic Trend Analysis (Multi-Hour)

**Purpose:** Identify traffic trends across multiple hours to detect sustained attacks or gradual increases.

**Impact:** High - Detects time-based attack patterns.

**Query:**
```sql
SELECT 
    hour,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count,
    ROUND(COUNT(CASE WHEN wafaction = 'block' THEN 1 END) * 100.0 / COUNT(*), 2) as block_percentage
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 0 AND 23
GROUP BY hour
ORDER BY hour
```

**What it does:** Analyzes traffic patterns across all hours of a day to identify peak attack periods.

**Expected Results:** Hourly breakdown showing traffic volume and attack intensity.

---

### Q30: Day-over-Day Comparison

**Purpose:** Compare traffic patterns across multiple days to detect anomalies.

**Impact:** Medium - Identifies day-to-day variations.

**Query:**
```sql
SELECT 
    day,
    COUNT(*) as request_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    AVG(botscore) as avg_bot_score
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day BETWEEN 15 AND 21
GROUP BY day
ORDER BY day
```

**What it does:** Compares daily metrics to identify unusual days.

**Expected Results:** Daily metrics showing trends and anomalies.

---

## Cross-Customer Pattern Detection

### Q31: Common Attack Patterns Across Customers

**Purpose:** Identify attack patterns that appear across multiple customers, indicating widespread threats.

**Impact:** Critical - Detects coordinated or widespread attacks.

**Query:**
```sql
SELECT 
    clientrequesturi,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(*) as total_attempts,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(DISTINCT clientcountry) as unique_countries
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 0 AND 23
  AND wafaction IN ('block', 'challenge')
GROUP BY clientrequesturi
HAVING COUNT(DISTINCT clientip) > 10
ORDER BY unique_ips DESC, total_attempts DESC
LIMIT 50
```

**What it does:** Finds endpoints targeted by multiple IPs, indicating coordinated attacks.

**Expected Results:** Endpoints under coordinated attack with attacker counts.

---

### Q32: IP Reuse Across Time Windows

**Purpose:** Detect IPs that appear across multiple time windows, indicating persistent attackers.

**Impact:** High - Identifies persistent threat actors.

**Query:**
```sql
SELECT 
    clientip,
    COUNT(DISTINCT CONCAT(year, '-', month, '-', day, '-', hour)) as time_windows_active,
    COUNT(*) as total_requests,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    MIN(CONCAT(year, '-', month, '-', day, '-', hour)) as first_seen,
    MAX(CONCAT(year, '-', month, '-', day, '-', hour)) as last_seen
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day BETWEEN 15 AND 21
GROUP BY clientip
HAVING COUNT(DISTINCT CONCAT(year, '-', month, '-', day, '-', hour)) > 3
ORDER BY time_windows_active DESC, total_requests DESC
LIMIT 100
```

**What it does:** Identifies IPs active across multiple time windows, showing persistence.

**Expected Results:** IPs with persistent activity patterns.

---

## Attack Chain Reconstruction

### Q33: Attack Sequence Analysis

**Purpose:** Reconstruct attack sequences by analyzing request patterns from the same IP.

**Impact:** Critical - Understands attack methodology.

**Query:**
```sql
SELECT 
    clientip,
    clientrequesturi,
    clientrequestmethod,
    wafaction,
    edgeresponsestatus,
    timestamp,
    ROW_NUMBER() OVER (PARTITION BY clientip ORDER BY timestamp) as request_sequence
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  AND clientip IN (
    SELECT clientip 
    FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
    WHERE year = 2025 AND month = 12 AND day = 21 AND hour = 5
    GROUP BY clientip
    HAVING COUNT(*) > 20
  )
ORDER BY clientip, timestamp
LIMIT 500
```

**What it does:** Sequences requests from high-volume IPs to understand attack progression.

**Expected Results:** Chronological request sequences showing attack patterns.

---

### Q34: Endpoint Enumeration Detection

**Purpose:** Detect systematic endpoint enumeration attempts (scanning for vulnerabilities).

**Impact:** High - Identifies reconnaissance activities.

**Query:**
```sql
SELECT 
    clientip,
    COUNT(DISTINCT clientrequesturi) as endpoints_tested,
    COUNT(*) as total_requests,
    COUNT(CASE WHEN edgeresponsestatus = 404 THEN 1 END) as not_found_count,
    COUNT(CASE WHEN edgeresponsestatus = 200 THEN 1 END) as success_count,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 0 AND 23
GROUP BY clientip
HAVING COUNT(DISTINCT clientrequesturi) > 50
ORDER BY endpoints_tested DESC
LIMIT 50
```

**What it does:** Identifies IPs testing many different endpoints, indicating enumeration.

**Expected Results:** IPs with high endpoint diversity showing scanning behavior.

---

## Behavioral Profiling

### Q35: User-Agent Fingerprinting

**Purpose:** Profile attackers based on user-agent patterns and behaviors.

**Impact:** Medium - Helps identify attack tool signatures.

**Query:**
```sql
SELECT 
    clientrequestuseragent,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(*) as total_requests,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    AVG(botscore) as avg_bot_score,
    COUNT(DISTINCT clientcountry) as unique_countries
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 0 AND 23
  AND clientrequestuseragent IS NOT NULL
GROUP BY clientrequestuseragent
HAVING COUNT(*) > 10
ORDER BY blocked_count DESC, total_requests DESC
LIMIT 100
```

**What it does:** Profiles user-agents to identify attack tools and bot signatures.

**Expected Results:** User-agents ranked by malicious activity.

---

### Q36: Request Timing Pattern Analysis

**Purpose:** Detect automated request patterns based on timing intervals.

**Impact:** Medium - Identifies automated tools and bots.

**Query:**
```sql
WITH timed_requests AS (
    SELECT 
        clientip,
        timestamp,
        LAG(timestamp) OVER (PARTITION BY clientip ORDER BY timestamp) as prev_timestamp,
        EXTRACT(EPOCH FROM (timestamp - LAG(timestamp) OVER (PARTITION BY clientip ORDER BY timestamp))) as seconds_between
    FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
    WHERE year = 2025
      AND month = 12
      AND day = 21
      AND hour = 5
)
SELECT 
    clientip,
    COUNT(*) as request_count,
    AVG(seconds_between) as avg_seconds_between,
    STDDEV(seconds_between) as stddev_seconds_between,
    MIN(seconds_between) as min_interval,
    MAX(seconds_between) as max_interval
FROM timed_requests
WHERE seconds_between IS NOT NULL
GROUP BY clientip
HAVING COUNT(*) > 10
  AND STDDEV(seconds_between) < 5  -- Low variance indicates automation
ORDER BY request_count DESC
LIMIT 50
```

**What it does:** Analyzes request timing to detect automated patterns (low variance = bot).

**Expected Results:** IPs with suspiciously regular request intervals.

---

## Threat Intelligence Correlation

### Q37: Known Bad IP Detection

**Purpose:** Identify requests from IPs matching known threat intelligence indicators.

**Impact:** Critical - Detects known malicious actors.

**Query:**
```sql
-- Note: Requires external threat intel feed or known bad IP list
-- This is a template - replace with actual threat intel source

WITH known_bad_ips AS (
    -- Example: Replace with actual threat intel query or table
    SELECT '1.2.3.4' as bad_ip UNION ALL
    SELECT '5.6.7.8' as bad_ip
    -- In production, this would come from a threat intel feed
)
SELECT 
    l.clientip,
    COUNT(*) as request_count,
    COUNT(CASE WHEN l.wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(DISTINCT l.clientrequesturi) as unique_endpoints,
    MAX(l.timestamp) as last_seen
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy l
INNER JOIN known_bad_ips k ON l.clientip = k.bad_ip
WHERE l.year = 2025
  AND l.month = 12
  AND l.day = 21
GROUP BY l.clientip
ORDER BY request_count DESC
```

**What it does:** Correlates logs with known threat intelligence to identify confirmed bad actors.

**Expected Results:** Requests from known malicious IPs.

---

### Q38: ASN Reputation Analysis

**Purpose:** Analyze traffic patterns by ASN to identify malicious network providers.

**Impact:** Medium - Identifies network-level threats.

**Query:**
```sql
SELECT 
    clientasn,
    clientcountry,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(*) as total_requests,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count,
    ROUND(COUNT(CASE WHEN wafaction = 'block' THEN 1 END) * 100.0 / COUNT(*), 2) as block_rate,
    AVG(botscore) as avg_bot_score
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 0 AND 23
  AND clientasn IS NOT NULL
GROUP BY clientasn, clientcountry
HAVING COUNT(*) > 100
ORDER BY block_rate DESC, blocked_count DESC
LIMIT 50
```

**What it does:** Ranks ASNs by attack volume and block rate to identify malicious networks.

**Expected Results:** ASNs with high attack rates.

---

### Q39: Geographic Attack Heatmap

**Purpose:** Create geographic distribution of attacks for visualization.

**Impact:** Medium - Visual threat intelligence.

**Query:**
```sql
SELECT 
    clientcountry,
    COUNT(*) as total_requests,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(CASE WHEN wafaction = 'challenge' THEN 1 END) as challenged_count,
    COUNT(DISTINCT clientrequesturi) as unique_endpoints_targeted,
    AVG(botscore) as avg_bot_score,
    ROUND(COUNT(CASE WHEN wafaction = 'block' THEN 1 END) * 100.0 / COUNT(*), 2) as attack_rate
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 0 AND 23
  AND clientcountry IS NOT NULL
GROUP BY clientcountry
HAVING COUNT(*) > 50
ORDER BY attack_rate DESC, blocked_count DESC
LIMIT 100
```

**What it does:** Aggregates attacks by country for geographic threat analysis.

**Expected Results:** Countries ranked by attack volume and intensity.

---

### Q40: Attack Category Distribution

**Purpose:** Categorize attacks by type (injection, XSS, path traversal, etc.) for threat intelligence.

**Impact:** High - Provides attack taxonomy.

**Query:**
```sql
SELECT 
    CASE 
        WHEN LOWER(clientrequesturi) LIKE '%union%select%' OR LOWER(clientrequesturi) LIKE '%or%1=1%' THEN 'SQL Injection'
        WHEN LOWER(clientrequesturi) LIKE '%<script%' OR LOWER(clientrequesturi) LIKE '%javascript:%' THEN 'XSS'
        WHEN clientrequesturi LIKE '%../%' OR clientrequesturi LIKE '%..\\%' THEN 'Path Traversal'
        WHEN LOWER(clientrequesturi) LIKE '%|%whoami%' OR LOWER(clientrequesturi) LIKE '%;%whoami%' THEN 'Command Injection'
        WHEN LOWER(clientrequesturi) LIKE '%wp-admin%' OR LOWER(clientrequesturi) LIKE '%phpmyadmin%' THEN 'Admin Interface Scan'
        WHEN LOWER(clientrequesturi) LIKE '%.env%' OR LOWER(clientrequesturi) LIKE '%config%' THEN 'Config File Access'
        ELSE 'Other'
    END as attack_category,
    COUNT(*) as attack_count,
    COUNT(DISTINCT clientip) as unique_ips,
    COUNT(CASE WHEN wafaction = 'block' THEN 1 END) as blocked_count,
    COUNT(DISTINCT clientcountry) as unique_countries
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour BETWEEN 0 AND 23
  AND (
    LOWER(clientrequesturi) LIKE '%union%select%'
    OR LOWER(clientrequesturi) LIKE '%or%1=1%'
    OR LOWER(clientrequesturi) LIKE '%<script%'
    OR LOWER(clientrequesturi) LIKE '%javascript:%'
    OR clientrequesturi LIKE '%../%'
    OR LOWER(clientrequesturi) LIKE '%|%whoami%'
    OR LOWER(clientrequesturi) LIKE '%wp-admin%'
    OR LOWER(clientrequesturi) LIKE '%.env%'
  )
GROUP BY attack_category
ORDER BY attack_count DESC
```

**What it does:** Categorizes attacks by type for threat intelligence reporting.

**Expected Results:** Attack types with counts and distributions.

---

## Query Usage Notes

### Performance Optimization

- Use appropriate time windows (start with 1 hour, expand as needed)
- Add LIMIT clauses for exploratory queries
- Use aggregations before joins
- Consider partitioning strategy

### Data Availability

- These queries assume data exists in the specified time windows
- Adjust time parameters based on available data
- Some queries may return 0 rows if no attacks match patterns
- Use exploration scripts to find data-rich time windows

### Integration

- Results can be exported to CSV/Parquet for further analysis
- Use with visualization tools (Grafana, Tableau, etc.)
- Integrate with SIEM systems for alerting
- Feed into threat intelligence platforms

---

**Last Updated:** 2025-12-21  
**Query Count:** 12 additional advanced queries  
**Total Query Catalog:** 40 queries

