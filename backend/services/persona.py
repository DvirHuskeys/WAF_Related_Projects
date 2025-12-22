from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from backend.services import scoring, storage

PERSONA_TEMPLATES: Dict[str, Dict[str, str]] = {
    "ae": {
        "name": "Account Executive Alex",
        "goal": "Prioritize outreach and craft an opening narrative.",
        "focus": "Actionable GTM guidance",
    },
    "ciso": {
        "name": "CISO Cassandra",
        "goal": "Understand rule coverage gaps across vendors.",
        "focus": "Rule transparency and risk framing",
    },
}


def list_personas() -> List[Dict[str, str]]:
    return [
        {"id": persona_id, **meta} for persona_id, meta in PERSONA_TEMPLATES.items()
    ]


def generate_persona_view(persona_id: str, domain: str) -> Dict[str, str]:
    persona_id = persona_id.lower()
    if persona_id not in PERSONA_TEMPLATES:
        raise ValueError(f"Unknown persona '{persona_id}'.")

    record = storage.fetch_domain(domain)
    if not record:
        raise ValueError(f"No enrichment record found for {domain}.")

    scores = scoring.derive_scores(record)
    story = scoring.build_story(persona_id, record, scores)

    return {
        "persona": PERSONA_TEMPLATES[persona_id],
        "domain": domain,
        "detected_waf": record.get("detected_waf"),
        "detected_cdn": record.get("detected_cdn"),
        "scores": scores,
        "story_prompt": story,
        "last_updated": record.get("last_observed", datetime.utcnow().isoformat()),
    }

