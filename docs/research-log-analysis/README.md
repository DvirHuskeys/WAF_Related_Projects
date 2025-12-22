# WAF Log Research Process

**Purpose:** Methodical approach for analyzing Cloudflare WAF logs to detect abusive behaviors, anomalies, and security threats across multiple customers.

**Last Updated:** 2025-12-21

---

## Overview

This research process provides a systematic framework for querying and analyzing Cloudflare WAF logs stored in Trino to identify:

- **Traffic Floods:** Rate-based attacks, DDoS patterns, resource exhaustion attempts
- **WAF Bypass Attempts:** Evasion techniques, rule testing, adaptive attacks
- **Anomalies:** Unusual patterns, deviations from baseline, suspicious behaviors
- **Scrapers & Bots:** Automated scraping, bot traffic, crawler abuse
- **Attack Tools:** Known attack signatures, exploit attempts, malicious payloads

## Data Source

- **Database:** `waf_logs_db.quillbot_waf_logs_huskeys_copy`
- **Partitioning:** Year/Month/Day/Hour (optimized for time-based queries)
- **Access:** Trino MCP (configured in `~/.cursor/mcp.json`)

## Query Template Pattern

All queries follow this base pattern:

```sql
SELECT [columns]
FROM waf_logs_db.quillbot_waf_logs_huskeys_copy 
WHERE year = 2025
  AND month = 12
  AND day = 21
  AND hour = 5
  [additional filters]
GROUP BY [grouping columns]
ORDER BY [sorting columns]
```

## Research Workflow

### Phase 1: Baseline Establishment
1. Run baseline queries to understand normal traffic patterns
2. Identify typical request volumes, methods, status codes
3. Document customer-specific baselines

### Phase 2: Anomaly Detection
1. Execute anomaly detection queries
2. Compare results against baselines
3. Flag deviations exceeding thresholds

### Phase 3: Threat Investigation
1. Run threat-specific queries (WAF bypass, attack tools)
2. Correlate findings across time windows
3. Identify attack patterns and sources

### Phase 4: Cross-Customer Analysis
1. Aggregate findings across multiple customers
2. Identify common attack patterns
3. Detect coordinated attacks

### Phase 5: Reporting & Documentation
1. Document findings with evidence
2. Create recommendations
3. Update query catalog with new patterns

## Query Categories

See [queries.md](./queries.md) for the complete catalog of queries organized by:

1. **Traffic Analysis** - Volume, rate, and distribution patterns
2. **Security Events** - WAF actions, blocked requests, challenges
3. **Behavioral Analysis** - User patterns, session analysis, bot detection
4. **Attack Detection** - Known attack signatures, exploit attempts
5. **Anomaly Detection** - Statistical outliers, unusual patterns

## Usage

### Prerequisites
- Trino MCP configured and accessible
- Access to `waf_logs_db.quillbot_waf_logs_huskeys_copy` table
- Understanding of Cloudflare log schema

### Running Queries

1. **Select appropriate query** from `queries.md`
2. **Customize time window** (year, month, day, hour)
3. **Adjust filters** as needed (customer, domain, IP ranges)
4. **Execute via Trino MCP**
5. **Analyze results** and document findings

### Best Practices

- Start with small time windows (1-2 hours) for initial testing
- Use appropriate aggregations to manage result set size
- Document query parameters and results
- Compare findings across multiple time windows
- Correlate with other data sources when available

## Contributing

When adding new queries:

1. Test query with sample data
2. Document purpose, impact, and expected results
3. Add to appropriate category in `queries.md`
4. Update this README if adding new categories
5. Include example results if helpful

## Tools & Scripts

See [TOOLS.md](./TOOLS.md) for complete toolkit documentation.

**Available Scripts:**
- `test_trino_queries.py` - Validate all queries
- `explore_trino_data.py` - Discover available data
- `discover_trino_schema.py` - Schema discovery
- `run_analysis_suite.py` - Comprehensive analysis

## Query Catalogs

1. **[queries.md](./queries.md)** - 28 core production queries
2. **[advanced-queries.md](./advanced-queries.md)** - 12 advanced analysis queries

**Total:** 40 queries ready for use

## Test Results

✅ **All 28 core queries validated** - See [TEST_RESULTS.md](./TEST_RESULTS.md)

## Related Documentation

- [Architecture Overview](../architecture.md)
- [Product Requirements](../prd.md)
- [Epic Breakdown](../epics.md)
- [Tools Documentation](./TOOLS.md)

