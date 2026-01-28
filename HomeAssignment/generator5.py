import csv
import random
import uuid
import hashlib
from datetime import datetime, timedelta

# --- CONFIGURATION & REPRODUCIBILITY ---
NUM_ROWS = 400000
START_TIME = datetime.utcnow() - timedelta(hours=48)
random.seed(2026) 

# --- REAL WAN IP POOLS (2026 Verified Ranges) ---
ISP_POOLS = {
    "COMCAST": ["73.0.0.0/8", "98.192.0.0/10", "67.160.0.0/11"],
    "VERIZON_FIOS": ["71.160.0.0/12", "108.0.0.0/12"],
    "ATT_WIRELESS": ["172.48.0.0/12", "107.192.0.0/10"], # Changed 172.56 to 172.48
    "DATACENTER_AWS": ["54.204.0.0/15", "3.80.0.0/12"],
    "TOR_EXIT": ["185.220.101.0/24"]
}

def get_ip(pool_name):
    import ipaddress
    net = ipaddress.ip_network(random.choice(ISP_POOLS[pool_name]))
    return str(net[random.randint(1, net.num_addresses - 2)])

# --- SCENARIO DATA ---
# 1. SQLi Misconfig: Attacker uses a common Tor Exit node.
SQLI_IP = get_ip("TOR_EXIT")
# 2. TikTok False Positive: IPs from AT&T Wireless (Mobile users).
TIKTOK_MOBILE_IPS = [get_ip("ATT_WIRELESS") for _ in range(100)]
# 3. SMS Abuse: Using a Comcast Residential IP to blend in.
SMS_ABUSER_IP = get_ip("COMCAST")
# 4. Rotating Botnet: Coming from AWS US-East-1 nodes.
BOTNET_IPS = [get_ip("DATACENTER_AWS") for _ in range(50)]

# Authentic 2026 User Agents
UA_TIKTOK = "Mozilla/5.0 (iPhone; CPU iPhone OS 19_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.2 Mobile/15E148 TikTok/43.1.0"
UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

# --- GENERATOR ---
def generate_kit():
    print("🚀 Generating Comprehensive WAF Evaluation Kit...")
    
    with open("waf_logs_unclean.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "ClientIP", "ClientRequestPath", "ClientRequestUserAgent", "EdgeResponseStatus", "RayID", "JA3", "Cookies", "MatchedRuleID", "WAFAction"])

        curr = START_TIME
        for i in range(NUM_ROWS):
            curr += timedelta(milliseconds=random.randint(1, 150))
            dice = random.random()

            # SCENARIO A: SQLi MISCONFIG (Matched but Action=LOG)
            if dice < 0.015:
                writer.writerow([curr.isoformat() + "Z", SQLI_IP, "/api/v1/users?id=1'%20OR%20'1'='1", "sqlmap/1.8", 200, uuid.uuid4().hex[:16], "e7d705a3286e19ccd71985b3f9635276", "php_sessid=99ab2", "100001", "LOG"])

            # SCENARIO B: TIKTOK FALSE POSITIVE (Action=BLOCK)
            elif dice < 0.06:
                writer.writerow([curr.isoformat() + "Z", random.choice(TIKTOK_MOBILE_IPS), "/promo/tiktok-winter-sale", UA_TIKTOK, 403, uuid.uuid4().hex[:16], "b32309a26951912be7dba376398abcde", "-", "200005", "BLOCK"])

            # SCENARIO C: POLICY GAP (Bypassing Rate Limit via Legacy API)
            elif dice < 0.09:
                writer.writerow([curr.isoformat() + "Z", SMS_ABUSER_IP, "/v1.0/legacy/auth/sms-otp", "python-requests/2.31", 201, uuid.uuid4().hex[:16], "a0e9f5d64349fb13191bc781f81f42e1", "session=none", "None", "ALLOW"])

            # SCENARIO D: ROTATING BOTNET (Scraping Pricing)
            elif dice < 0.12:
                ip = random.choice(BOTNET_IPS)
                writer.writerow([curr.isoformat() + "Z", ip, "/products/pricing/competitor-match", UA_CHROME, 200, uuid.uuid4().hex[:16], hashlib.md5(ip.encode()).hexdigest(), "cf_clearance=true", "None", "ALLOW"])

            # NORMAL TRAFFIC
            else:
                writer.writerow([curr.isoformat() + "Z", get_ip("COMCAST"), "/index.html", UA_CHROME, 200, uuid.uuid4().hex[:16], uuid.uuid4().hex[:32], "user_token="+uuid.uuid4().hex[:6], "None", "ALLOW"])

    # --- WAF CONFIGURATION MANIFEST ---
    with open("waf_config_v4.txt", 'w') as f:
        f.write("WAF ACTIVE POLICY - PRODUCTION (Last Updated: 2026-01-01)\n")
        f.write("-" * 60 + "\n")
        f.write("RuleID: 100001 | Name: SQLi-Core-Detection | Action: LOG | Note: Tracking 2026 injection variants.\n")
        f.write("RuleID: 200005 | Name: Bot-Shield-Aggressive | Action: BLOCK | Logic: Block if UserAgent contains 'App'.\n")
        f.write("RuleID: 300010 | Name: SMS-Rate-Limit | Action: BLOCK | Path: /api/v2/sms-send | Threshold: 3 req/min.\n")
        f.write("RuleID: 400001 | Name: Geo-Block-High-Risk | Action: BLOCK | Logic: Block if Country is RU, CN, KP.\n")

    # --- SOLUTION KEY (FOR INTERVIEWER ONLY) ---
    with open("solution_key.txt", 'w') as f:
        f.write("MASTER SOLUTION KEY\n" + "="*20 + "\n")
        f.write(f"1. SECURITY MISCONFIG: IP {SQLI_IP} (Tor) is successfully injecting SQL (200 OK) because Rule 100001 is set to 'LOG'. Fix: Change Action to 'BLOCK'.\n")
        f.write(f"2. FALSE POSITIVE: Mobile users on AT&T are being blocked (403) from the TikTok promo. The 'Bot-Shield' rule (200005) is too broad (triggers on 'App' in UA). Fix: Add exception for TikTok UA or specific promo path.\n")
        f.write(f"3. POLICY GAP: IP {SMS_ABUSER_IP} is abusing SMS on a legacy endpoint (/v1.0/legacy/...) which is not covered by Rule 300010. Fix: Update rule to cover all /sms endpoints.\n")
        f.write(f"4. BOTNET: Coordinated scraping from AWS IPs (JA3 fingerprints may vary but traffic pattern is pricing-specific). Fix: Deploy Managed Bot Challenge or Rate Limit on the specific Pricing URI.\n")

    print("✅ Files generated: waf_logs_unclean.csv, waf_config_v4.txt, solution_key.txt")

if __name__ == "__main__":
    generate_kit()
