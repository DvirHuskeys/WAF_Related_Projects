import csv
import random
from datetime import datetime, timedelta
import uuid
import ipaddress

# --- CONFIGURATION ---
FILENAME_LOGS = "waf_logs_v3.csv"
FILENAME_CONFIG = "current_waf_config.txt"
NUM_ROWS = 400000
START_TIME = datetime.utcnow() - timedelta(hours=24)
random.seed(99)

# --- ATTACKER & MISCONFIG PERSONAS ---
SCENARIOS = {
    "SQLI_MISCONFIG": {
        "ip": "45.155.205.112",
        "desc": "SQL Injection attempt that is currently ONLY in 'LOG' mode (Misconfig)",
        "path": "/api/v1/search",
        "payload": "'; DROP TABLE users;--",
        "ua": "sqlmap/1.7",
        "status": 200 # It should be 403, but misconfig makes it 200
    },
    "TIKTOK_FP": {
        "ips": [f"172.58.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(100)],
        "desc": "Legitimate TikTok users blocked by a too-broad 'Bot Block' rule",
        "path": "/promo/tiktok-sale",
        "ua_fragment": "TikTok-App-UA",
        "status": 403 # False Positive
    },
    "SMS_BRUTE": {
        "ip": "103.207.32.88",
        "desc": "SMS Brute force bypass because it's hitting a legacy endpoint not covered by rate limits",
        "path": "/legacy/v1/sms-send",
        "status": 201
    }
}

# --- GENERATOR LOGIC ---
def generate_dataset():
    print("Generating v3 Logs (Engineering & Misconfig focus)...")
    
    with open(FILENAME_LOGS, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "ClientIP", "Path", "Method", "Status", "UserAgent", "MatchedRuleID", "WAFAction"])

        current_time = START_TIME
        for i in range(NUM_ROWS):
            current_time += timedelta(milliseconds=random.randint(1, 100))
            dice = random.random()

            # Scenario 1: The SQLi Misconfig (Action is 'Log', should be 'Block')
            if dice < 0.02:
                s = SCENARIOS["SQLI_MISCONFIG"]
                writer.writerow([current_time.isoformat(), s["ip"], s["path"], "GET", 200, s["ua"], "100001", "LOG"])

            # Scenario 2: The TikTok False Positive (Rule 200005 is too aggressive)
            elif dice < 0.08:
                s = SCENARIOS["TIKTOK_FP"]
                ip = random.choice(s["ips"])
                ua = f"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) {s['ua_fragment']}"
                writer.writerow([current_time.isoformat(), ip, s["path"], "GET", 403, ua, "200005", "BLOCK"])

            # Scenario 3: The Unprotected Legacy Endpoint
            elif dice < 0.11:
                s = SCENARIOS["SMS_BRUTE"]
                writer.writerow([current_time.isoformat(), s["ip"], s["path"], "POST", 201, "python-requests/2.28", "None", "ALLOW"])

            # Normal Traffic
            else:
                writer.writerow([current_time.isoformat(), "192.0.2."+str(random.randint(1,255)), "/index.html", "GET", 200, "Mozilla/5.0", "None", "ALLOW"])

    # Create the 'WAF Config' for the candidate to read
    with open(FILENAME_CONFIG, 'w') as f:
        f.write("=== CURRENT WAF ACTIVE RULES ===\n")
        f.write("RuleID: 100001 | Name: SQLi-Detection | Action: LOG | Note: Testing new signature patterns.\n")
        f.write("RuleID: 200005 | Name: Global-Bot-Block | Action: BLOCK | Logic: Block if User-Agent contains 'App' or 'Bot'.\n")
        f.write("RuleID: 300010 | Name: Rate-Limit-Login | Action: RATE_LIMIT | Path: /api/v1/sms-send | Threshold: 5 req/min.\n")

    print(f"Files ready: {FILENAME_LOGS} and {FILENAME_CONFIG}")

if __name__ == "__main__": generate_dataset()
