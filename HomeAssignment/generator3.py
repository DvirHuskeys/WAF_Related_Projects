import csv
import random
import time
from datetime import datetime, timedelta
import uuid
import ipaddress

# --- CONFIGURATION ---
FILENAME_LOGS = "waf_logs_unclean.csv"
FILENAME_KEY = "solution_key.txt"
NUM_ROWS = 400000
START_TIME = datetime.utcnow() - timedelta(hours=48)
random.seed(42)  # Ensures reproducible results every time

# --- REALISTIC PUBLIC IP POOLS ---
# We pick from these ranges to ensure "Normal" traffic looks like real ISPs.
NORMAL_POOLS = {
    "US_RESIDENTIAL": ["67.160.0.0/12", "73.0.0.0/8", "98.192.0.0/12"], # Comcast/Verizon
    "US_MOBILE": ["172.56.0.0/12", "166.128.0.0/9"], # T-Mobile/AT&T
    "EU_RESIDENTIAL": ["80.128.0.0/11", "92.224.0.0/11"], # Deutsche Telekom
    "ASIA_BUSINESS": ["119.23.0.0/16", "203.116.0.0/14"] # Singtel/Alibaba
}

# --- ATTACKER PERSONAS (The Answers) ---
ATTACKERS = {
    "BRUTE_FORCE": {
        "ip": "185.220.101.45", # Known Tor Exit Node
        "desc": "Tor Exit Node performing Credential Stuffing",
        "ua": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0",
        "ja3": "e7d705a3286e19ccd71985b3f9635276",
        "target": "/auth/v2/login"
    },
    "SMS_ABUSE": {
        "ip": "73.15.22.109", # Comcast Residential IP (Hard to block via subnet)
        "desc": "Residential IP abusing SMS endpoint (infected device)",
        "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
        "ja3": "b32309a26951912be7dba376398abcde",
        "target": "/api/notifications/sms/send"
    },
    "JWT_SCRAPER": {
        "ip": "54.205.110.23", # AWS EC2 US-East-1 (Data Center IP)
        "desc": "Cloud hosted script scraping User IDs",
        "ua": "Go-http-client/1.1",
        "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
        "target": "/api/v1/user/profile/details"
    },
    "BOTNET": {
        "ips": [f"103.207.32.{i}" for i in range(10, 60)], # Rotating Subnet
        "desc": "Low & Slow Distributed Botnet (Search Scraper)",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "target": "/products/pricing"
    }
}

# --- HELPER FUNCTIONS ---
def get_random_ip_from_cidr(cidr):
    net = ipaddress.ip_network(cidr)
    # Pick a random offset
    random_int = random.randint(0, net.num_addresses - 1)
    return str(net[random_int])

def get_normal_ip():
    # 50% US, 30% EU, 20% Asia
    pool = "US_RESIDENTIAL"
    dice = random.random()
    if dice > 0.5: pool = "EU_RESIDENTIAL"
    if dice > 0.8: pool = "ASIA_BUSINESS"
    
    cidr = random.choice(NORMAL_POOLS[pool])
    return get_random_ip_from_cidr(cidr)

PATHS = [
    "/", "/about", "/contact", "/products/pricing", "/api/v1/status", 
    "/assets/logo.png", "/assets/main.css", "/assets/app.js", "/login", "/dashboard"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15"
]

def generate_row(timestamp, ip, path, method, status, ua, country, user_id="-", ja3=""):
    if not ja3: ja3 = uuid.uuid4().hex[:32]
    return [
        timestamp.isoformat(),
        ip,
        method,
        path,
        status,
        ua,
        country,
        random.randint(100, 5000), # Bytes
        random.randint(10, 800),   # Duration
        uuid.uuid4().hex[:16],     # RayID
        ja3,
        user_id
    ]

# --- MAIN GENERATOR ---
def generate_dataset():
    print(f"Generating {NUM_ROWS} rows...")
    
    rows = []
    current_time = START_TIME
    
    for i in range(NUM_ROWS):
        if i % 50000 == 0: print(f"Progress: {i}/{NUM_ROWS}")
        current_time += timedelta(milliseconds=random.randint(5, 150))
        dice = random.random()
        
        # Default values
        row_data = None
        
        # 1. Tor Brute Force (Loud) - 4% of traffic
        if dice < 0.04:
            p = ATTACKERS["BRUTE_FORCE"]
            status = 403 if random.random() < 0.85 else 401
            row_data = generate_row(current_time, p["ip"], p["target"], "POST", status, p["ua"], "T1", ja3=p["ja3"])

        # 2. SMS Abuse (Residential) - 2% of traffic
        elif dice < 0.06:
            p = ATTACKERS["SMS_ABUSE"]
            row_data = generate_row(current_time, p["ip"], p["target"], "POST", 201, p["ua"], "US", ja3=p["ja3"])

        # 3. JWT Scraper (Cloud) - 3% of traffic
        elif dice < 0.09:
            p = ATTACKERS["JWT_SCRAPER"]
            fake_user = f"uid_{random.randint(1000,9999)}"
            row_data = generate_row(current_time, p["ip"], p["target"], "GET", 200, p["ua"], "US", user_id=fake_user, ja3=p["ja3"])
            
        # 4. Botnet (Low & Slow) - 5% of traffic
        elif dice < 0.14:
            p = ATTACKERS["BOTNET"]
            ip = random.choice(p["ips"])
            row_data = generate_row(current_time, ip, p["target"], "GET", 200, p["ua"], "VN", ja3=uuid.uuid4().hex[:32])

        # Normal Traffic
        else:
            ip = get_normal_ip()
            path = random.choice(PATHS)
            method = "POST" if "login" in path else "GET"
            status = 200
            ua = random.choice(USER_AGENTS)
            row_data = generate_row(current_time, ip, path, method, status, ua, "US")
            
        rows.append(row_data)

    # Write Logs
    with open(FILENAME_LOGS, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "ClientIP", "Method", "Path", "Status", "UserAgent", "Country", "Bytes", "DurationMS", "RayID", "JA3", "UserID"])
        writer.writerows(rows)

    # Write Answer Key
    with open(FILENAME_KEY, 'w', encoding='utf-8') as f:
        f.write("=== INTERVIEWER ANSWER KEY ===\n\n")
        f.write(f"1. Brute Force IP: {ATTACKERS['BRUTE_FORCE']['ip']} (Tor Exit Node)\n")
        f.write(f"   Look for: High volume 403/401 on /login\n\n")
        f.write(f"2. SMS Abuser IP: {ATTACKERS['SMS_ABUSE']['ip']} (Comcast Residential)\n")
        f.write(f"   Look for: 201 Created on /sms/send\n\n")
        f.write(f"3. JWT Scraper IP: {ATTACKERS['JWT_SCRAPER']['ip']} (AWS Cloud)\n")
        f.write(f"   Look for: 'Go-http-client' UA and high unique UserIDs\n\n")
        f.write(f"4. Botnet Subnet: 103.207.32.0/24\n")
        f.write(f"   Look for: Multiple IPs hitting pricing page constantly\n")

    print("Done. Files generated:")
    print(f"- {FILENAME_LOGS} (Give this to candidate)")
    print(f"- {FILENAME_KEY} (Keep for yourself)")

if __name__ == "__main__":
    generate_dataset()
