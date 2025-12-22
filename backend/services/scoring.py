from __future__ import annotations

from typing import Dict


def derive_scores(record: Dict) -> Dict[str, float]:
    scores = {
        "config_drift": float(record.get("config_drift_score", 0.0)),
        "downtime_risk": float(record.get("downtime_risk_score", 0.0)),
        "attack_surface": float(record.get("attack_surface_score", 0.0)),
    }
    scores["priority_index"] = round(
        (scores["config_drift"] * 0.4)
        + (scores["downtime_risk"] * 0.35)
        + (scores["attack_surface"] * 0.25),
        2,
    )
    return scores


def build_story(persona_id: str, record: Dict, scores: Dict[str, float]) -> str:
    waf = record.get("detected_waf", "unknown WAF")
    cdn = record.get("detected_cdn", "unknown CDN")

    if persona_id == "ae":
        hooks = []
        if scores["config_drift"] > 0.6:
            hooks.append("lead with configuration coherence and drift prevention")
        if scores["downtime_risk"] > 0.5:
            hooks.append("highlight proactive failover and runbook automation")
        if not hooks:
            hooks.append("position unified visibility as a quick win")
        return (
            f"{record['domain']} appears to run {waf} in front of {cdn}. "
            f"Priority index {scores['priority_index']:.2f}. "
            f"{' & '.join(hooks)}."
        )

    if persona_id == "ciso":
        highlight = (
            "Rule overlap looks thin compared to peers—show the rule remix demo."
            if scores["attack_surface"] > 0.55
            else "Use the WAFtotal explorer to contrast vendor philosophy."
        )
        return (
            f"{record['domain']} likely leans on {waf}. "
            f"Attack surface score {scores['attack_surface']:.2f}. {highlight}"
        )

    return "No story available yet."

