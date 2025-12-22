# Automation Guide - WAF Log Analysis

**Complete automation setup for continuous WAF log analysis.**

---

## 🤖 Automation Scripts

### 1. Daily Analysis Automation

**Script:** `scripts/automate_daily_analysis.sh`

**What it does:**
- Finds data windows
- Generates findings report
- Creates dashboard data
- Checks for threats
- Logs all activities

**Schedule:** Daily at 9 AM

**Cron Setup:**
```bash
# Edit crontab
crontab -e

# Add this line (adjust path)
0 9 * * * /path/to/project/scripts/automate_daily_analysis.sh
```

---

### 2. Continuous Monitoring

**Script:** `scripts/monitor_waf_logs.py`

**What it does:**
- Monitors WAF logs continuously
- Detects threats in real-time
- Generates alerts
- Logs monitoring data

**Schedule:** Continuous (runs as daemon)

**Setup:**
```bash
# Run as background process
nohup python3 scripts/monitor_waf_logs.py --interval 3600 > monitor.log 2>&1 &

# Or use systemd service (see below)
```

---

### 3. Dashboard Data Generation

**Script:** `scripts/create_dashboard_data.py`

**What it does:**
- Generates dashboard JSON data
- Creates visualization datasets
- Updates metrics

**Schedule:** Hourly or on-demand

---

## 🔧 Systemd Service Setup

### Monitor Service

Create `/etc/systemd/system/waf-monitor.service`:

```ini
[Unit]
Description=WAF Log Monitor
After=network.target

[Service]
Type=simple
User=waf-user
WorkingDirectory=/path/to/project
ExecStart=/usr/bin/python3 /path/to/project/scripts/monitor_waf_logs.py --interval 3600
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl enable waf-monitor
sudo systemctl start waf-monitor
sudo systemctl status waf-monitor
```

---

## 📅 Cron Jobs

### Daily Analysis

```bash
# Run daily analysis at 9 AM
0 9 * * * /path/to/project/scripts/automate_daily_analysis.sh
```

### Hourly Monitoring

```bash
# Run monitoring check every hour
0 * * * * /path/to/project/scripts/monitor_waf_logs.py --once --hour $(date +%H)
```

### Weekly Summary

```bash
# Generate weekly summary every Monday at 9 AM
0 9 * * 1 /path/to/project/scripts/generate_weekly_summary.sh
```

---

## 🔔 Alert Integration

### Email Alerts

**Configure in `monitor_waf_logs.py`:**

```python
import smtplib
from email.mime.text import MIMEText

def send_email_alert(alert, config):
    msg = MIMEText(alert['message'])
    msg['Subject'] = f"[WAF Alert] {alert['severity']}: {alert['type']}"
    msg['From'] = config['from_email']
    msg['To'] = config['to_email']
    
    server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
    server.send_message(msg)
    server.quit()
```

### Slack Integration

**Configure webhook:**

```python
import requests

def send_slack_alert(alert, webhook_url):
    payload = {
        "text": f"🚨 WAF Alert: {alert['message']}",
        "attachments": [{
            "color": "danger" if alert['severity'] == 'critical' else "warning",
            "fields": [
                {"title": "Type", "value": alert['type'], "short": True},
                {"title": "Severity", "value": alert['severity'], "short": True}
            ]
        }]
    }
    requests.post(webhook_url, json=payload)
```

### PagerDuty Integration

**Configure API:**

```python
import requests

def send_pagerduty_alert(alert, api_key):
    payload = {
        "routing_key": api_key,
        "event_action": "trigger",
        "payload": {
            "summary": alert['message'],
            "severity": alert['severity'],
            "source": "WAF Log Analysis"
        }
    }
    requests.post("https://events.pagerduty.com/v2/enqueue", json=payload)
```

---

## 📊 Dashboard Integration

### Grafana Setup

1. **Install Grafana**
2. **Add JSON Data Source**
3. **Import Dashboard JSON**
4. **Configure Auto-Refresh**

**Dashboard JSON Location:**
```
docs/research-log-analysis/dashboard-*.json
```

### Custom Dashboard

**API Endpoint:**
```python
# Flask/FastAPI example
@app.route('/api/dashboard/<date>')
def get_dashboard_data(date):
    dashboard_file = f"docs/research-log-analysis/dashboard-{date}.json"
    return json.load(open(dashboard_file))
```

---

## 🔄 Workflow Automation

### Complete Daily Workflow

```bash
#!/bin/bash
# Complete daily workflow

# 1. Find data
python3 scripts/find_data_windows.py

# 2. Generate report
python3 scripts/generate_findings_report.py --year YYYY --month MM --day DD

# 3. Create dashboard
python3 scripts/create_dashboard_data.py --year YYYY --month MM --day DD

# 4. Check alerts
python3 scripts/monitor_waf_logs.py --once

# 5. Send summary (if configured)
# send_summary_email.sh
```

### Weekly Aggregation

```bash
#!/bin/bash
# Weekly aggregation script

# Aggregate daily reports
# Generate weekly summary
# Update baselines
# Create weekly dashboard
```

---

## 📈 Monitoring & Metrics

### Key Metrics to Track

1. **Query Performance**
   - Execution time
   - Success rate
   - Error rate

2. **Threat Detection**
   - Threats detected
   - Alert volume
   - False positive rate

3. **System Health**
   - Script execution
   - Data availability
   - Alert delivery

### Monitoring Dashboard

**Metrics to Display:**
- Total requests (24h)
- Threats detected (24h)
- Top attacking IPs
- Attack types breakdown
- Geographic distribution
- WAF action distribution

---

## 🛠️ Maintenance

### Regular Tasks

**Daily:**
- Review automation logs
- Check alert delivery
- Verify data availability

**Weekly:**
- Review query performance
- Update thresholds
- Optimize queries

**Monthly:**
- Comprehensive review
- Update documentation
- Review automation effectiveness

### Log Management

**Log Locations:**
- Automation logs: `docs/research-log-analysis/automation-*.log`
- Alert logs: `docs/research-log-analysis/alerts.log`
- Monitoring logs: `monitor.log`

**Rotation:**
```bash
# Rotate logs weekly
find docs/research-log-analysis -name "*.log" -mtime +7 -delete
```

---

## 🔐 Security Best Practices

1. **Credential Management**
   - Use environment variables
   - Rotate credentials regularly
   - Limit access

2. **Alert Security**
   - Encrypt sensitive data
   - Secure alert channels
   - Access controls

3. **Data Privacy**
   - Anonymize IPs if needed
   - Secure data storage
   - Retention policies

---

## 📋 Checklist

### Initial Setup

- [ ] Install dependencies
- [ ] Configure credentials
- [ ] Set up cron jobs
- [ ] Configure alerts
- [ ] Test automation
- [ ] Set up monitoring

### Ongoing Maintenance

- [ ] Review logs daily
- [ ] Check alerts weekly
- [ ] Update thresholds monthly
- [ ] Optimize queries quarterly
- [ ] Review automation annually

---

**Last Updated:** 2025-12-22  
**Status:** Production Ready

