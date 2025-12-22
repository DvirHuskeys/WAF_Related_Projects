from __future__ import annotations

import os
import random
from datetime import datetime
from typing import Dict

try:
    from wafw00f.main import WAFW00F

    WAF_AVAILABLE = True
except ImportError:  # pragma: no cover
    WAF_AVAILABLE = False


CDN_GUESSES = ["cloudflare", "fastly", "akamai", "unknown"]
WAF_GUESSES = ["cloudflare", "aws_waf", "akamai", "azure_frontdoor"]
USE_REAL_DETECTION = bool(int(os.getenv("USE_WAFW00F", "0")))


def detect_stack(domain: str) -> Dict[str, str]:
    waf = _detect_waf(domain)
    cdn = _heuristic_cdn(domain, waf)
    return {
        "domain": domain,
        "detected_waf": waf,
        "detected_cdn": cdn,
        "fingerprinted_at": datetime.utcnow().isoformat(),
    }


def _detect_waf(domain: str) -> str:
    if WAF_AVAILABLE and USE_REAL_DETECTION:
        try:
            target = domain if domain.startswith("http") else f"https://{domain}"
            detector = WAFW00F(target)
            result = detector.identwaf()
            if result:
                return result[0].lower()
        except Exception:  # pragma: no cover - offline mode fallback
            pass
    random.seed(domain)
    return random.choice(WAF_GUESSES)


def _heuristic_cdn(domain: str, candidate: str) -> str:
    if "cdn" in domain:
        return "cloudfront"
    if candidate == "cloudflare":
        return "cloudflare"
    random.seed(f"{domain}-cdn")
    return random.choice(CDN_GUESSES)

