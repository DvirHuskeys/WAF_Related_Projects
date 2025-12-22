# GTM Radar Metrics

| Metric | Target | Notes |
| --- | --- | --- |
| Domains enriched per run | 100 | Limit via CLI flag to keep runs short. |
| Detection confidence | ≥ 0.7 | Heuristic today; replace with signal-based scoring later. |
| Drift score accuracy | Visual validation vs. rule overlap (manual). |
| Story prompt adoption | Track copy events in UI (future). |

## Calculation ideas
- **Priority Index** = 0.4 config drift + 0.35 downtime + 0.25 attack surface.
- **Rule Overlap %** = shared categories / total categories vs. benchmark vendor.
- **Freshness Days** = now - `metadata.last_updated` from rule pack.

