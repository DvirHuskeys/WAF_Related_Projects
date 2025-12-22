# Story Prompt Playbook

## Persona cheat sheet

| Persona | Goal | Hook |
| --- | --- | --- |
| **AE Alex** | Prioritize outreach and open with a compelling GTM angle. | Use config drift + downtime risk to suggest a narrative (`"Lead with coherence"` / `"Pitch predictive failover"`). |
| **CISO Cassandra** | Compare vendor philosophies and surface blind spots. | Show Rule Remix deltas (e.g., missing bot thresholds) and tie to attack-surface score. |

## Prompt recipes

### AE Alex
1. Report stack snapshot: `{detected_waf} + {detected_cdn}`.
2. Translate scores:
   - Config drift > 0.6 ⇒ “Lead with cross-vendor policy harmonizer.”
   - Downtime risk > 0.5 ⇒ “Offer chaos runbook / redundancy tooling.”
   - Attack surface > 0.5 ⇒ “Upsell managed threat rehearsal.”
3. CTA: “Book 20-min discovery to see domain-specific replay.”

### CISO Cassandra
1. Highlight rule gaps (“Rule overlap with peers: 62%”).
2. Contrast vendor intent (“Vendor favors anomaly scoring vs deterministic signatures”).
3. CTA: “Run WAFtotal explorer live to remix their current rule.”

## Data needed per prompt

| Prompt | Fields |
| --- | --- |
| Config drift story | `config_drift_score`, `managed_rules` overlap |
| Downtime story | `downtime_risk_score`, fingerprint freshness |
| Rule remix | `managed_rules.category`, `detection_pattern` |
| Threat rehearsal | Domain-specific attack scenarios (future) |

