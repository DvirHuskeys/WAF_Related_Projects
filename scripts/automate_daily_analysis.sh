#!/bin/bash
# Daily WAF Log Analysis Automation Script
# Run via cron: 0 9 * * * /path/to/scripts/automate_daily_analysis.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Get yesterday's date
YESTERDAY=$(date -d yesterday +%Y-%m-%d 2>/dev/null || date -v-1d +%Y-%m-%d 2>/dev/null || date -d "1 day ago" +%Y-%m-%d)
YEAR=$(date -d yesterday +%Y 2>/dev/null || date -v-1d +%Y 2>/dev/null || date -d "1 day ago" +%Y)
MONTH=$(date -d yesterday +%m 2>/dev/null || date -v-1d +%m 2>/dev/null || date -d "1 day ago" +%m)
DAY=$(date -d yesterday +%d 2>/dev/null || date -v-1d +%d 2>/dev/null || date -d "1 day ago" +%d)

LOG_FILE="$PROJECT_ROOT/docs/research-log-analysis/automation-$(date +%Y%m%d).log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting daily WAF log analysis for $YESTERDAY"

# Step 1: Find data windows
log "Step 1: Finding data windows..."
python3 scripts/find_data_windows.py >> "$LOG_FILE" 2>&1 || log "Warning: Data window search completed with issues"

# Step 2: Generate findings report
log "Step 2: Generating findings report..."
python3 scripts/generate_findings_report.py \
    --year "$YEAR" \
    --month "$MONTH" \
    --day "$DAY" \
    --hour 0 \
    --customer Quillbot >> "$LOG_FILE" 2>&1 || log "Warning: Report generation completed with issues"

# Step 3: Generate dashboard data
log "Step 3: Generating dashboard data..."
python3 scripts/create_dashboard_data.py \
    --year "$YEAR" \
    --month "$MONTH" \
    --day "$DAY" >> "$LOG_FILE" 2>&1 || log "Warning: Dashboard data generation completed with issues"

# Step 4: Check for alerts
log "Step 4: Checking for threats..."
python3 scripts/monitor_waf_logs.py \
    --once \
    --year "$YEAR" \
    --month "$MONTH" \
    --day "$DAY" \
    --hour 0 >> "$LOG_FILE" 2>&1 || log "Warning: Threat monitoring completed with issues"

log "Daily analysis complete. Check $LOG_FILE for details."

# Optional: Send summary email (configure as needed)
# mail -s "Daily WAF Analysis - $YESTERDAY" security@example.com < "$LOG_FILE"

exit 0

