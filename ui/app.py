import streamlit as st

from backend.services import persona as persona_service
from backend.services import storage

st.set_page_config(page_title="WAF Security Lab", layout="wide")
st.title("WAF Security Lab")
st.caption("Local sandbox for GTM Radar + WAFtotal experiments")

domains = storage.list_domains()
if not domains:
    st.warning("No domain data yet. Run `python scripts/domain_enrich.py data/samples/domains.csv`.")
    st.stop()

domain_names = [row["domain"] for row in domains]
selected_domain = st.selectbox("Domain", domain_names)
persona_options = persona_service.list_personas()
persona_labels = {item["id"]: item["name"] for item in persona_options}
selected_persona = st.selectbox(
    "Persona View",
    options=list(persona_labels.keys()),
    format_func=lambda value: persona_labels[value],
)

record = next(item for item in domains if item["domain"] == selected_domain)
scores = {
    "Config Drift": record["config_drift_score"],
    "Downtime Risk": record["downtime_risk_score"],
    "Attack Surface": record["attack_surface_score"],
}
for label, value in scores.items():
    st.metric(label, f"{value:.2f}")

persona_payload = persona_service.generate_persona_view(
    selected_persona, selected_domain
)

left, right = st.columns(2)
with left:
    st.subheader("Stack Snapshot")
    st.write(
        {
            "WAF": persona_payload["detected_waf"],
            "CDN": persona_payload["detected_cdn"],
            "Last Updated": persona_payload["last_updated"],
        }
    )

with right:
    st.subheader("Story Prompt")
    st.write(persona_payload["story_prompt"])

st.divider()
st.subheader("Raw Record")
st.json(record)

