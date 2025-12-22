# Execution Workflow - WAF Log Analysis

**Complete step-by-step workflow for executing WAF log analysis.**

---

## Phase 1: Data Discovery

### Step 1.1: Verify Table Access

```bash
# Check table exists
python scripts/discover_trino_schema.py

# Verify access
python scripts/aggressive_data_search.py
```

**Expected:** Table structure and any available data

---

### Step 1.2: Find Data Windows

```bash
# Search for time windows with data
python scripts/find_data_windows.py

# Review results: docs/research-log-analysis/data-windows.json
```

**Expected:** List of time windows with request counts

**If no data found:**
- Check data ingestion pipeline
- Verify table name and schema
- Contact data team

---

## Phase 2: Baseline Establishment

### Step 2.1: Run Baseline Queries

**Queries:**
- Q24: HTTP Method Distribution
- Q25: Top Requested Endpoints  
- Q10: Status Code Distribution
- Q11: Geographic Distribution

**Command:**
```bash
python scripts/run_analysis_suite.py --year YYYY --month MM --day DD --hour HH
```

**Output:** Baseline metrics in `analysis-{timestamp}.json`

---

### Step 2.2: Document Baselines

**Create baseline document:**
- Normal request volumes
- Common HTTP methods
- Typical status codes
- Geographic distribution
- Peak hours

**File:** `docs/research-log-analysis/baselines.md`

---

## Phase 3: Threat Detection

### Step 3.1: Run Threat Detection Queries

**Queries:**
- Q17-Q21: Attack signatures
- Q1-Q4: Traffic floods
- Q5-Q8: WAF bypass
- Q13-Q16: Bot detection

**Command:**
```bash
python scripts/generate_findings_report.py --year YYYY --month MM --day DD --hour HH --customer Quillbot
```

**Output:** Findings report with threat data

---

### Step 3.2: Analyze Threats

**Review:**
- Top attacking IPs
- Attack types
- Targeted endpoints
- Geographic patterns

**Action Items:**
- Block persistent attackers
- Investigate attack patterns
- Update WAF rules
- Alert security team

---

## Phase 4: Anomaly Detection

### Step 4.1: Run Anomaly Queries

**Queries:**
- Q9: Unusual HTTP methods
- Q12: Request size anomalies
- Q26: IP reputation scoring
- Q27: Attack campaigns

**Process:**
```bash
# Run specific anomaly queries
# Compare to baselines
# Identify deviations
```

---

### Step 4.2: Investigate Anomalies

**Actions:**
- Review anomaly details
- Correlate with threats
- Determine risk level
- Take appropriate action

---

## Phase 5: Report Generation

### Step 5.1: Generate Comprehensive Report

```bash
python scripts/generate_findings_report.py --year YYYY --month MM --day DD --hour HH --customer Quillbot
```

**Output:** `quillbot-findings-{timestamp}.md`

---

### Step 5.2: Review and Action

**Review:**
- Executive summary
- Key findings
- Recommendations
- Action items

**Actions:**
- Share with stakeholders
- Implement recommendations
- Track follow-ups
- Schedule next analysis

---

## Phase 6: Continuous Monitoring

### Step 6.1: Set Up Daily Analysis

**Schedule:**
- Daily at 9 AM
- Analyze previous day
- Generate daily report
- Review findings

**Automation:**
```bash
# Cron job example
0 9 * * * cd /path/to/project && python scripts/generate_findings_report.py --year $(date +%Y) --month $(date +%m) --day $(date -d yesterday +%d) --hour 0 --customer Quillbot
```

---

### Step 6.2: Weekly Aggregation

**Process:**
- Aggregate daily reports
- Identify trends
- Update baselines
- Generate weekly summary

---

### Step 6.3: Monthly Review

**Process:**
- Comprehensive monthly analysis
- Threat landscape assessment
- Strategic recommendations
- Executive presentation

---

## Quick Reference

### Daily Workflow
```bash
# 1. Find data
python scripts/find_data_windows.py

# 2. Run analysis
python scripts/generate_findings_report.py --year YYYY --month MM --day DD --hour HH

# 3. Review report
cat docs/research-log-analysis/quillbot-findings-*.md
```

### Weekly Workflow
```bash
# Aggregate findings
# Generate weekly summary
# Update baselines
# Review trends
```

### Monthly Workflow
```bash
# Comprehensive analysis
# Threat assessment
# Strategic recommendations
# Executive report
```

---

## Troubleshooting Guide

### Issue: No Data Found

**Check:**
1. Table exists: `SHOW TABLES FROM waf_logs_db.default`
2. Data ingested: Check data pipeline
3. Time window: Try different dates
4. Permissions: Verify access

**Solution:**
- Contact data team
- Verify ingestion pipeline
- Check table structure

### Issue: Queries Slow

**Check:**
1. Time window size
2. Query complexity
3. Data volume

**Solution:**
- Reduce time window
- Add LIMIT clauses
- Optimize queries
- Check partitioning

### Issue: No Results

**Check:**
1. Thresholds too high
2. Filters too restrictive
3. No data for period

**Solution:**
- Lower HAVING thresholds
- Remove filters temporarily
- Try different time window

---

## Success Criteria

### Framework
- ✅ All queries validated
- ✅ All tools working
- ✅ Documentation complete

### Analysis (When Data Available)
- 📊 Baselines established
- 🎯 Threats detected
- 📈 Anomalies identified
- 📋 Reports generated

### Operations
- ⏱️ Fast query execution
- 📊 Comprehensive coverage
- 🎯 High detection rate
- 📈 Low false positives

---

**Status:** Ready for Execution  
**Last Updated:** 2025-12-22

