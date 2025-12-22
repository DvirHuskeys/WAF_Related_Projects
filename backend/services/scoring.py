from __future__ import annotations

import random
from typing import Dict, List, Tuple

from backend.services import hooks as hook_loader

SCORE_SEED_OFFSET = 42


def derive_scores(domain: str, waf_name: str) -> Dict[str, float]:
    base_seed = hash(domain) + SCORE_SEED_OFFSET
    random.seed(base_seed)
    config_drift = round(min(1.0, 0.35 + random.random()), 2)
    downtime_risk = round(min(1.0, 0.25 + random.random()), 2)
    attack_surface = round(min(1.0, 0.2 + random.random()), 2)

    if waf_name == "cloudflare":
        config_drift = min(1.0, config_drift + 0.1)
    if waf_name == "aws_waf":
        attack_surface = min(1.0, attack_surface + 0.08)

    scores = {
        "config_drift": config_drift,
        "downtime_risk": downtime_risk,
        "attack_surface": attack_surface,
    }
    scores["priority_index"] = round(
        (scores["config_drift"] * 0.4)
        + (scores["downtime_risk"] * 0.35)
        + (scores["attack_surface"] * 0.25),
        2,
    )
    return scores


def build_story(
    persona_id: str, record: Dict, scores: Dict[str, float]
) -> Tuple[str, List[Dict[str, str]]]:
    waf = record.get("detected_waf", "unknown WAF")
    cdn = record.get("detected_cdn", "unknown CDN")

    persona_hooks = hook_loader.get_hooks_for_persona(persona_id)
    matched_hooks: List[Dict[str, str]] = []
    for hook in persona_hooks:
        score_key = hook.get("score")
        threshold = hook.get("min", 0)
        if not score_key:
            continue
        if scores.get(score_key, 0) >= threshold:
            matched_hooks.append(
                {
                    "id": hook.get("id", score_key),
                    "title": hook.get("title", ""),
                    "description": hook.get("description", ""),
                    "score_reason": f"{score_key}={scores.get(score_key, 0):.2f}",
                }
            )
    if not matched_hooks and persona_hooks:
        hook = persona_hooks[-1]
        matched_hooks.append(
            {
                "id": hook.get("id", "default"),
                "title": hook.get("title", ""),
                "description": hook.get("description", ""),
                "score_reason": hook.get("score", ""),
            }
        )

    hook_text = " ".join(h["description"] for h in matched_hooks)
    story = (
        f"{record['domain']} appears to run {waf} in front of {cdn}. "
        f"Priority index {scores['priority_index']:.2f}. {hook_text}"
    )
    return story, matched_hooks

