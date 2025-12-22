# Operations Guide - WAF Log Analysis

**Complete operational guide for running WAF log analysis in production.**

---

## 🚀 Quick Start

### Daily Operations

```bash
# 1. Find latest data window
python scripts/aggressive_data_search.py

# 2. Run analysis
python scripts/generate_findings_report.py --year YYYY --month MM --day DD --hour HH --customer Quillbot

# 3. Review findings
cat docs/research-log-analysis/quillbot-findings-*.md
```

---

## 📅 Scheduled Operations

### Daily Monitoring

**Schedule:** Every hour

```bash
# Monitor script
python scripts/monitor_waf_logs.py --interval 3600 --alert-threshold 1000
```

**Output:**
- Real-time alerts
- `alerts.log` - Alert log file
- `monitoring-results.json` - Monitoring data

### Daily Analysis

**Schedule:** Daily at 9 AM (analyze previous day)

```bash
# Get yesterday's date
YESTERDAY=$(date -d yesterday +%Y-%m-%d)
YEAR=$(date -d yesterday +%Y)
MONTH=$(date -d yesterday +%m)
DAY=$(date -d yesterday +%d)

# Run analysis
python scripts/generate_findings_report.py \
  --year $YEAR --month $MONTH --day $DAY --hour 0 \
  --customer Quillbot
```

### Weekly Summary

**Schedule:** Every Monday at 9 AM

```bash
# Aggregate weekly data
# Generate weekly summary report
# Review trends
```

### Monthly Review

**Schedule:** First Monday of month at 9 AM

```bash
# Comprehensive monthly analysis
# Threat landscape assessment
# Executive report generation
```

---

## 🔔 Alerting Configuration

### Alert Types

1. **High Volume IPs**
   - Threshold: 1000+ requests/hour
   - Severity: High
   - Action: Review and potentially block

2. **Attack Patterns**
   - Threshold: 5+ attack attempts
   - Severity: Critical
   - Action: Immediate investigation

3. **WAF Bypass**
   - Threshold: 10+ successful bypasses
   - Severity: Critical
   - Action: Review WAF rules

### Alert Channels

Configure in `monitor_waf_logs.py`:

- **Email:** SMTP integration
- **Slack:** Webhook integration
- **PagerDuty:** API integration
- **Log File:** `alerts.log`
- **Custom Webhook:** HTTP POST

---

## 📊 Dashboard Setup

### Generate Dashboard Data

```bash
python scripts/create_dashboard_data.py --year 2025 --month 12 --day 21
```

**Output:** `dashboard-{date}.json`

### Dashboard Integration

**Supported Formats:**
- JSON (default)
- CSV (for Excel/Sheets)
- Grafana (via JSON)

**Charts Available:**
- Hourly traffic distribution
- Top countries
- Attack types distribution
- WAF action distribution
- Summary metrics

### Visualization Tools

1. **Grafana**
   - Import JSON data
   - Create dashboards
   - Set up alerts

2. **Tableau/Power BI**
   - Import CSV data
   - Create visualizations
   - Build reports

3. **Custom Dashboard**
   - Use JSON API
   - Build custom UI
   - Real-time updates

---

## 🔧 Maintenance Tasks

### Weekly Tasks

1. **Review Alerts**
   ```bash
   tail -100 docs/research-log-analysis/alerts.log
   ```

2. **Check Query Performance**
   - Review execution times
   - Optimize slow queries
   - Update thresholds

3. **Update Baselines**
   - Review normal patterns
   - Adjust thresholds
   - Update documentation

### Monthly Tasks

1. **Query Optimization**
   - Review query performance
   - Optimize slow queries
   - Add indexes if needed

2. **Threshold Review**
   - Review alert thresholds
   - Adjust based on trends
   - Document changes

3. **Documentation Update**
   - Update findings
   - Document new patterns
   - Update workflows

---

## 🛠️ Troubleshooting

### Common Issues

#### Issue: No Data Found

**Symptoms:**
- Queries return 0 rows
- No time windows found

**Solutions:**
1. Verify table exists
2. Check data ingestion pipeline
3. Verify time window parameters
4. Check Trino connectivity

#### Issue: Slow Queries

**Symptoms:**
- Queries take > 10 seconds
- Timeouts occur

**Solutions:**
1. Reduce time window
2. Add LIMIT clauses
3. Optimize query filters
4. Check partitioning

#### Issue: High Alert Volume

**Symptoms:**
- Too many alerts
- Alert fatigue

**Solutions:**
1. Increase thresholds
2. Filter false positives
3. Adjust alert criteria
4. Review baselines

---

## 📈 Performance Optimization

### Query Optimization

1. **Use Appropriate Time Windows**
   - Start with 1 hour
   - Expand as needed
   - Avoid full table scans

2. **Add LIMIT Clauses**
   - Limit result sets
   - Top N queries
   - Pagination

3. **Optimize Filters**
   - Filter early
   - Use indexed columns
   - Avoid functions in WHERE

### Monitoring Optimization

1. **Batch Queries**
   - Combine related queries
   - Reduce round trips
   - Cache results

2. **Schedule Off-Peak**
   - Run during low traffic
   - Avoid peak hours
   - Distribute load

---

## 🔐 Security Considerations

### Access Control

1. **Trino Credentials**
   - Use read-only accounts
   - Rotate passwords regularly
   - Limit access

2. **Alert Data**
   - Secure alert logs
   - Encrypt sensitive data
   - Access controls

### Data Privacy

1. **IP Addresses**
   - Anonymize if needed
   - Secure storage
   - Access controls

2. **Request Data**
   - Filter sensitive data
   - Secure transmission
   - Retention policies

---

## 📋 Checklists

### Daily Checklist

- [ ] Run monitoring script
- [ ] Review alerts
- [ ] Check query performance
- [ ] Review findings reports
- [ ] Document incidents

### Weekly Checklist

- [ ] Generate weekly summary
- [ ] Review trends
- [ ] Update baselines
- [ ] Optimize queries
- [ ] Review thresholds

### Monthly Checklist

- [ ] Comprehensive analysis
- [ ] Threat assessment
- [ ] Performance review
- [ ] Documentation update
- [ ] Executive report

---

## 🎯 Success Metrics

### Operational Metrics

- **Query Execution Time:** < 1 second average
- **Alert Response Time:** < 5 minutes
- **Report Generation:** < 30 seconds
- **Uptime:** > 99.9%

### Analysis Metrics

- **Threat Detection Rate:** > 95%
- **False Positive Rate:** < 5%
- **Coverage:** All time windows analyzed
- **Accuracy:** Validated findings

---

## 📞 Support

### Escalation Path

1. **Level 1:** Operations Team
   - Query issues
   - Data access
   - Basic troubleshooting

2. **Level 2:** Engineering Team
   - Performance issues
   - Query optimization
   - Tool enhancements

3. **Level 3:** Security Team
   - Threat analysis
   - Incident response
   - Strategic decisions

---

**Last Updated:** 2025-12-22  
**Status:** Production Ready

