from __future__ import annotations

from datetime import datetime
from typing import Dict, List

from backend.services import freshness, scoring, storage


class PersonaNotFound(ValueError):
    pass


class DomainNotFound(ValueError):
    pass

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
        raise PersonaNotFound(f"Unknown persona '{persona_id}'.")

    record = storage.fetch_domain(domain)
    if not record:
        raise DomainNotFound(f"No enrichment record found for {domain}.")

    scores = scoring.derive_scores(
        record["domain"], record.get("detected_waf", "unknown")
    )
    stale_warning = freshness.get_warning(record.get("last_observed"))
    story_prompt, hooks = scoring.build_story(persona_id, record, scores)

    return {
        "persona_id": persona_id,
        "persona": PERSONA_TEMPLATES[persona_id],
        "domain": domain,
        "detected_waf": record.get("detected_waf"),
        "detected_cdn": record.get("detected_cdn"),
        "scores": scores,
        "story_prompt": story_prompt,
        "hooks": hooks,
        "last_updated": record.get("last_observed", datetime.utcnow().isoformat()),
        "stale_warning": stale_warning,
    }

