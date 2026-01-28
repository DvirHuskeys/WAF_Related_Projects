import csv
import random
import uuid
import hashlib
import ipaddress
from datetime import datetime, timedelta

# --- CONFIGURATION & REPRODUCIBILITY ---
NUM_ROWS = 400000
START_TIME = datetime.utcnow() - timedelta(hours=48)
random.seed(2026) 

# --- REAL WAN IP POOLS ---
ISP_POOLS = {
    "COMCAST": ["73.0.0.0/8", "98.192.0.0/10", "67.160.0.0/11"],
    "VERIZON_FIOS": ["71.160.0.0/12", "108.0.0.0/12"],
    "ATT_WIRELESS": ["172.48.0.0/12", "107.192.0.0/10"], 
    "DATACENTER_AWS": ["54.204.0.0/15", "3.80.0.0/12"],
    "TOR_EXIT": ["185.220.101.0/24"]
}

def get_ip(pool_name):
    # strict=False fixes the 'host bits set' error
    net = ipaddress.ip_network(random.choice(ISP_POOLS[pool_name]), strict=False)
    return str(net[random.randint(1, net.num_addresses - 2)])

# --- SCENARIO DATA ---
SQLI_IP = get_ip("TOR_EXIT")
TIKTOK_MOBILE_IPS = [get_ip("ATT_WIRELESS") for _ in range(100)]
SMS_ABUSER_IP = get_ip("COMCAST")
BOTNET_IPS = [get_ip("DATACENTER_AWS") for _ in range(50)]

UA_TIKTOK = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.2 Mobile/15E148 TikTok/43.1.0"
UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
UA_BOT = "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)"

# --- WAF RULES DICTIONARY ---
WAF_RULES = {
    "SQLI": ("100001", "SQLi-Core-Detection", "LOG"), # The Misconfig
    "TIKTOK_BLOCK": ("200005", "Bot-Shield-Aggressive", "BLOCK"), # The False Positive
    "SMS_LIMIT": ("300010", "SMS-Rate-Limit", "BLOCK"), # The Policy Gap Target
    "GEO_US": ("400001", "Geo-US-Validation", "ALLOW"),
    "GEO_EU": ("400002", "Geo-EU-Validation", "ALLOW"),
    "BROWSER_CHECK": ("500001", "Browser-Integrity-Check", "ALLOW"),
    "PROTOCOL": ("500002", "HTTP-Protocol-Violation", "ALLOW"),
    "ASSET_CACHE": ("600001", "Static-Asset-Optimization", "ALLOW"),
    "GENERIC_BOT": ("200001", "Known-Crawler-Detection", "ALLOW"),
    "XSS_SILENT": ("100005", "XSS-Detection-Passive", "LOG"),
    "RATE_LIMIT_GLOBAL": ("300001", "Global-L7-Rate-Limit", "ALLOW"),
    "API_SHIELD": ("700001", "API-Shield-Verification", "ALLOW")
}

# --- GENERATOR ---
def generate_kit():
    print("🚀 Generating Comprehensive WAF Evaluation Kit (v6)...")
    
    with open("waf_logs_unclean.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "ClientIP", "ClientRequestPath", "ClientRequestUserAgent", "EdgeResponseStatus", "RayID", "JA3", "Cookies", "MatchedRuleID", "WAFAction"])

        curr = START_TIME
        for i in range(NUM_ROWS):
            curr += timedelta(milliseconds=random.randint(1, 100))
            dice = random.random()

            # SCENARIO A: SQLi MISCONFIG
            if dice < 0.015:
                rid, rname, raction = WAF_RULES["SQLI"]
                writer.writerow([curr.isoformat() + "Z", SQLI_IP, "/api/v1/users?id=1'%20OR%20'1'='1", "sqlmap/1.8", 200, uuid.uuid4().hex[:16], "e7d705a3286e19ccd71985b3f9635276", "php_sessid=99ab2", rid, raction])

            # SCENARIO B: TIKTOK FALSE POSITIVE
            elif dice < 0.06:
                rid, rname, raction = WAF_RULES["TIKTOK_BLOCK"]
                writer.writerow([curr.isoformat() + "Z", random.choice(TIKTOK_MOBILE_IPS), "/promo/tiktok-winter-sale", UA_TIKTOK, 403, uuid.uuid4().hex[:16], "b32309a26951912be7dba376398abcde", "-", rid, raction])

            # SCENARIO C: POLICY GAP (SMS)
            elif dice < 0.08:
                rid, rname, raction = WAF_RULES["API_SHIELD"]
                writer.writerow([curr.isoformat() + "Z", SMS_ABUSER_IP, "/v1.0/legacy/auth/sms-otp", "python-requests/2.31", 201, uuid.uuid4().hex[:16], "a0e9f5d64349fb13191bc781f81f42e1", "session=none", rid, raction])

            # SCENARIO D: ROTATING BOTNET
            elif dice < 0.11:
                ip = random.choice(BOTNET_IPS)
                rid, rname, raction = WAF_RULES["RATE_LIMIT_GLOBAL"]
                writer.writerow([curr.isoformat() + "Z", ip, "/products/pricing/competitor-match", UA_CHROME, 200, uuid.uuid4().hex[:16], hashlib.md5(ip.encode()).hexdigest(), "cf_clearance=true", rid, raction])

            # NORMAL TRAFFIC (The "Ocean" of Noise)
            else:
                path = random.choice(["/index.html", "/assets/main.css", "/assets/app.js", "/api/v1/status", "/favicon.ico"])
                ip = get_ip(random.choice(["COMCAST", "VERIZON_FIOS"]))
                
                # Assign a semi-random "Noise" rule
                if ".js" in path or ".css" in path:
                    rid, rname, raction = WAF_RULES["ASSET_CACHE"]
                elif i % 10 == 0:
                    rid, rname, raction = WAF_RULES["BROWSER_CHECK"]
                else:
                    rid, rname, raction = WAF_RULES["GEO_US"]

                writer.writerow([curr.isoformat() + "Z", ip, path, UA_CHROME, 200, uuid.uuid4().hex[:16], uuid.uuid4().hex[:32], "user_token="+uuid.uuid4().hex[:6], rid, raction])

    # --- WAF CONFIGURATION MANIFEST ---
    with open("waf_config_v4.txt", 'w') as f:
        f.write("WAF ACTIVE POLICY - PRODUCTION (Last Updated: 2026-01-01)\n")
        f.write("-" * 80 + "\n")
        for key, (rid, name, action) in WAF_RULES.items():
            logic = "Path-based/Behavioral"
            if key == "TIKTOK_BLOCK": logic = "Block if UserAgent contains 'App'"
            if key == "SQLI": logic = "SQLi Core Signatures v2.4"
            if key == "SMS_LIMIT": logic = "Rate-Limit: 3 req/min for path /api/v2/sms-send"
            f.write(f"RuleID: {rid} | Name: {name} | Action: {action} | Logic: {logic}\n")

    # --- SOLUTION KEY ---
    with open("solution_key.txt", 'w') as f:
        f.write("MASTER SOLUTION KEY (v6)\n" + "="*20 + "\n")
        f.write(f"1. MISCONFIG: SQLi from {SQLI_IP} (Tor) returning 200. Rule 100001 is LOG only.\n")
        f.write(f"2. FALSE POSITIVE: Mobile users blocked by Rule 200005 due to 'App' in TikTok UA.\n")
        f.write(f"3. POLICY GAP: {SMS_ABUSER_IP} abusing legacy endpoint /v1.0/legacy/ - Rule 300010 only covers /api/v2/.\n")
        f.write(f"4. BOTNET: Coordinated AWS IP scraping. Use JA3/Rate limiting on Pricing path.\n")

    print("✅ Done! Analysis requires correlating specific RuleIDs to anomalous outcomes.")

if __name__ == "__main__":
    generate_kit()
