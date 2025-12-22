# Rule Sync Adapter Contract

Adapters live under `scripts/rule_sync/` and expose a single function:

```python
from pathlib import Path
from typing import List, Dict

def load_rules(source: Path) -> List[Dict]:
    ...
```

Each returned dict must provide the following keys:

| Key | Description |
| --- | --- |
| `vendor` | Lowercase vendor identifier (e.g., `cloudflare`) |
| `rule_id` | Stable rule identifier provided by vendor |
| `name` | Friendly rule name |
| `category` | Attack category or logical grouping |
| `detection_pattern` | Expression or matching hint |
| `mitigation` | Default action or recommended response |
| `severity` | Normalized severity label |
| `metadata` | JSON-encoded string containing the full vendor payload |

Drop-in workflow:

1. Create `scripts/rule_sync/<vendor>.py` with the `load_rules` function.
2. Run `python scripts/rule_sync/run.py <vendor> --source path/to/export.json`.
3. No CLI changes are required; modules are resolved dynamically.


