from __future__ import annotations

import yaml
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

CONFIG_PATH = Path("config/persona_hooks.yaml")


@lru_cache(maxsize=1)
def load_hooks() -> Dict[str, List[dict]]:
    if not CONFIG_PATH.exists():
        return {}
    with CONFIG_PATH.open() as handle:
        data = yaml.safe_load(handle) or {}
    return data.get("persona_hooks", {})


def get_hooks_for_persona(persona_id: str) -> List[dict]:
    hooks = load_hooks()
    return hooks.get(persona_id, [])


