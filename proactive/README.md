# Proactive Security Research Tools

> ⚠️ **AUTHORIZED USE ONLY** - These tools are for authorized security research, penetration testing, and bug bounty programs only.

## Clawdbot Comprehensive Reconnaissance Tool v2.0

Advanced Shodan reconnaissance for Clawdbot infrastructure with deep service enumeration and sensitive data extraction.

### Key Capabilities

| Feature | Description |
|---------|-------------|
| **mDNS Service Parsing** | Extracts gateway, bridge, canvas, SSH ports from Shodan mDNS data |
| **Multi-Port Enumeration** | Probes ALL discovered ports (18789, 18790, 18793, 22, etc.) |
| **Tailnet DNS Resolution** | Resolves and probes `.ts.net` Tailscale addresses |
| **100+ Sensitive Paths** | Comprehensive file path coverage |
| **40+ Secret Patterns** | AWS keys, DB creds, private keys, tokens, and more |
| **Per-IP Results** | Organized folder structure per target |

### mDNS Data Extraction

The tool parses rich mDNS service discovery data like:

```
mDNS:
  services:
    18790/tcp clawdbot-bridge:
      role=gateway
      gatewayPort=18789
      bridgePort=18790
      canvasPort=18793
      tailnetDns=ubuntu-8gb-nbg1-1.tailb3e5a3.ts.net
      sshPort=22
```

And automatically probes **all** discovered ports.

### Installation

```bash
cd proactive
pip install -r requirements.txt
```

### Quick Start

```bash
# Set Shodan API key
export SHODAN_API_KEY="your-key"

# Full reconnaissance
python shodan_clawdbot_recon.py --confirm

# Target specific host with all common ports
python shodan_clawdbot_recon.py --target 15.204.11.97 --confirm

# Target with specific ports
python shodan_clawdbot_recon.py --target 46.224.192.71 --ports 18789,18790,18793,22,80,443 --confirm

# Custom Shodan query
python shodan_clawdbot_recon.py -k YOUR_KEY --query 'mDNS clawdbot' --confirm
```

### Shodan Queries Used

The tool executes 18+ targeted queries:

```
mDNS clawdbot
mDNS "_clawdbot-bridge._tcp"
title:"Clawdbot"
http.html:"clawdbot-bridge"
"gatewayPort" "clawdbot"
"tailnetDns" "clawdbot"
".ts.net" "clawdbot"
"role=gateway"
ssl.cert.subject.cn:"clawdbot"
... and more
```

### Sensitive Paths Probed (100+)

**Environment & Config:**
- `.env`, `.env.local`, `.env.production`, `.env.backup`
- `config.json`, `settings.yaml`, `application.yml`

**Credentials:**
- `credentials.json`, `secrets.json`, `api_keys.json`
- `.aws/credentials`, `serviceAccountKey.json`

**Clawdbot Specific:**
- `/api/config`, `/api/debug`, `/api/env`
- `/.clawdbot/config`, `/bridge/config`, `/gateway/config`
- `/actuator/env`, `/actuator/configprops`

**Git Exposure:**
- `.git/config`, `.git/HEAD`, `.git/logs/HEAD`

**Keys & Certificates:**
- `id_rsa`, `private.key`, `private.pem`

**Backups:**
- `backup.sql`, `dump.sql`, `backup.zip`

### Secret Patterns Detected (40+)

| Category | Patterns |
|----------|----------|
| **Credentials** | password, secret, api_key, auth_token |
| **Database** | database_url, mysql://, postgres://, mongodb:// |
| **AWS** | AKIA..., aws_access_key, aws_secret |
| **Private Keys** | BEGIN RSA PRIVATE KEY, BEGIN OPENSSH PRIVATE KEY |
| **JWT/Session** | jwt_secret, session_secret, encryption_key |
| **Payment** | stripe_key, sk_live_, paypal_secret |
| **OAuth** | client_secret, oauth_secret |

### Output Structure

```
results/
├── 46_224_192_71/
│   ├── shodan_raw.json          # Full Shodan banner
│   ├── services.json            # Parsed mDNS services
│   ├── summary.json             # Scan summary
│   ├── findings/
│   │   ├── 001_env.txt
│   │   ├── 002_config_json.txt
│   │   └── ...
│   └── SENSITIVE/               # Highlighted sensitive files
│       ├── 001_env.txt
│       └── ...
├── 15_204_11_97/
│   └── ...
├── recon.log                    # Full audit log
└── MASTER_REPORT.md             # Executive summary
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--api-key, -k` | Shodan API key |
| `--target, -t` | Direct target IP |
| `--ports, -p` | Ports to probe (default: 80,443,8080,8443,18789,18790,18793) |
| `--query, -q` | Custom Shodan query |
| `--limit, -l` | Max results per query (default: 100) |
| `--output, -o` | Output directory (default: ./results) |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--dry-run` | Preview without requests |
| `--verbose, -v` | Verbose logging |
| `--confirm` | Skip authorization prompt |

### Example Targets

Based on Shodan results:

```bash
# Example exposed host
python shodan_clawdbot_recon.py --target 15.204.11.97 --confirm

# Host with mDNS service discovery
python shodan_clawdbot_recon.py --target 46.224.192.71 \
    --ports 18789,18790,18793,22,80,443 --confirm
```

### Master Report

Generates `MASTER_REPORT.md` with:

- Executive summary (totals, sensitive counts)
- Sensitive data types breakdown
- High-value targets (sorted by severity)
- Per-target findings tables
- Service enumeration results

### Legal Disclaimer

This tool is for **authorized security testing only**. Users must:

1. Have explicit written authorization
2. Comply with applicable laws
3. Follow responsible disclosure
4. Not use for malicious purposes

---

*Part of the WAF Security Research Project - Proactive Division*
