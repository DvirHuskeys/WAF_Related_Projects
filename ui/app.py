import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.services import persona as persona_service
from backend.services import (
    storage,
    freshness,
    export as export_service,
    logging as usage_logging,
)
from ui.components.persona_card import render_persona_card
from ui.components.radar_table import PERSONA_VIEW_KEY, render_radar_table
from ui.components.rule_drawer import render_rule_drawer
from ui.components.rule_utils import parse_rule_synced_at

THEME = {
    "primary": "#2D7BFF",
    "accent": "#0BD3D3",
    "surface": "#1A1F2B",
    "muted": "#9AA5CE",
}


def inject_theme():
    st.markdown(
        f"""
        <style>
        .persona-card {{
            background-color: {THEME["surface"]};
            padding: 1.2rem;
            border-radius: 0.8rem;
            border: 1px solid rgba(255,255,255,0.08);
            color: #F4F6FB;
            margin-top: 0.75rem;
        }}
        .persona-chip {{
            display:inline-flex;
            align-items:center;
            padding:0.15rem 0.6rem;
            border-radius:999px;
            font-size:0.75rem;
            margin-right:0.35rem;
            background: {THEME["primary"]};
        }}
        .persona-chip--muted {{
            background: rgba(244,246,251,0.1);
            color:{THEME["muted"]};
        }}
        .persona-warning {{
            display:inline-flex;
            align-items:center;
            border-radius:999px;
            padding:0.2rem 0.6rem;
            font-size:0.75rem;
            background: #F5A524;
            color:#10131B;
            margin-right:0.35rem;
            margin-top:0.4rem;
        }}
        .diff-chip {{
            display:inline-flex;
            align-items:center;
            padding:0.15rem 0.45rem;
            border-radius:999px;
            font-size:0.75rem;
            background: rgba(11,211,211,0.15);
            color:#F4F6FB;
            margin-right:0.25rem;
        }}
        .skeleton-row {{
            display:flex;
            gap:0.5rem;
            margin-bottom:0.4rem;
        }}
        .skeleton-bar {{
            flex:1;
            height:1.2rem;
            border-radius:0.4rem;
            background: linear-gradient(90deg, rgba(255,255,255,0.08), rgba(255,255,255,0.18), rgba(255,255,255,0.08));
            animation: shimmer 1.8s infinite;
        }}
        .radar-row {{
            background-color: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 0.8rem;
            padding: 0.9rem 1.1rem;
            margin-bottom: 0.65rem;
        }}
        .radar-row--selected {{
            border-color: {THEME["accent"]};
            box-shadow: 0 0 0 1px rgba(11,211,211,0.35);
        }}
        .score-badge {{
            display:inline-flex;
            align-items:center;
            font-size:0.8rem;
            padding:0.15rem 0.55rem;
            border-radius:999px;
            margin-bottom:0.25rem;
            margin-right:0.35rem;
            background: rgba(255,255,255,0.08);
            color:#F4F6FB;
        }}
        .score-badge--high {{ background: rgba(247,87,100,0.2); color:#F75764; }}
        .score-badge--medium {{ background: rgba(245,165,36,0.2); color:#F5A524; }}
        .score-badge--low {{ background: rgba(11,211,211,0.15); color:#0BD3D3; }}
        .score-badge--emphasis {{
            border: 1px solid rgba(11,211,211,0.4);
        }}
        .freshness-chip {{
            display:inline-flex;
            align-items:center;
            padding:0.15rem 0.5rem;
            border-radius:999px;
            font-size:0.75rem;
            margin-bottom:0.4rem;
        }}
        .freshness-chip--stale {{
            background: rgba(247,87,100,0.18);
            color:#F75764;
        }}
        .freshness-chip--fresh {{
            background: rgba(11,211,211,0.18);
            color:#0BD3D3;
        }}
        @keyframes shimmer {{
            0% {{background-position:-2rem;}}
            100% {{background-position:6rem;}}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def load_domains() -> tuple[List[Dict], Optional[str]]:
    try:
        return storage.list_domains(), None
    except Exception as exc:  # pragma: no cover - visual only
        return [], str(exc)


def render_metrics(record: Optional[Dict], warning: Optional[str]):
    st.subheader("Radar Metrics")
    metric_cols = st.columns(3)
    metrics = [
        ("Config Drift", "config_drift_score"),
        ("Downtime Risk", "downtime_risk_score"),
        ("Attack Surface", "attack_surface_score"),
    ]
    for col, (label, key) in zip(metric_cols, metrics):
        with col:
            value = f"{record.get(key, 0):.2f}" if record else "—"
            col.metric(label, value)
    if warning:
        st.markdown(
            f"<span class='persona-warning'>{warning}</span>", unsafe_allow_html=True
        )


def render_connection_error(error: str):
    st.error(
        f"Cannot connect to DuckDB: {error}\n\nRun `make init-db` and ensure `data/warehouse.db` is accessible.",
        icon="⚠️",
    )


def render_export_section():
    st.subheader("Exports")
    domains_col, rules_col, usage_col = st.columns(3)
    with domains_col:
        if st.button("Domains CSV"):
            _trigger_export(lambda: export_service.export_domains("csv"), "Domains CSV")
        if st.button("Domains Parquet"):
            _trigger_export(
                lambda: export_service.export_domains("parquet"), "Domains Parquet"
            )
    with rules_col:
        if st.button("Rules CSV"):
            _trigger_export(lambda: export_service.export_rules("csv"), "Rules CSV")
        if st.button("Rules Parquet"):
            _trigger_export(
                lambda: export_service.export_rules("parquet"), "Rules Parquet"
            )
    with usage_col:
        if st.button("Usage CSV"):
            _trigger_export(
                lambda: export_service.export_usage("csv"), "Persona Usage CSV"
            )
        if st.button("Usage Parquet"):
            _trigger_export(
                lambda: export_service.export_usage("parquet"),
                "Persona Usage Parquet",
            )


def _trigger_export(action, label: str):
    try:
        result = action()
    except Exception as exc:
        st.error(f"{label} failed: {exc}")
        return
    st.success(f"{label} saved to {result.path} (Job {result.job_id})")
    st.code(str(result.path))
    if result.footnote_path:
        st.caption(f"Stale notes: {result.footnote_path}")


def render_rule_empty_state():
    st.info(
        "No managed rules detected. Run `python scripts/rule_sync/run.py cloudflare --source data/rules/cloudflare_sample.json` to seed Rule Studio.",
        icon="ℹ️",
    )


def render_rule_studio(active_domain: Optional[str] = None):
    st.subheader("Rule Studio")
    rules = storage.list_rules()
    if not rules:
        render_rule_empty_state()
        return

    drawer_state_key = "rule_drawer_state"
    if drawer_state_key not in st.session_state:
        st.session_state[drawer_state_key] = {"open": False, "rules": {}}

    main_cols = st.columns([0.63, 0.37], gap="large")

    with main_cols[0]:
        df = pd.DataFrame(rules)
        df["_synced_dt"] = df.apply(
            lambda row: parse_rule_synced_at(row.get("synced_at"), row.get("metadata")),
            axis=1,
        )
        def _freshness_label(dt):
            stale, _ = freshness.is_stale(dt)
            return "Stale" if stale else "Fresh"

        def _sync_badge(dt):
            if not dt:
                return "Unknown"
            stale, _ = freshness.is_stale(dt)
            prefix = "⚠️" if stale else "✅"
            return f"{prefix} Synced {dt.strftime('%Y-%m-%d')}"

        df["freshness"] = df["_synced_dt"].apply(_freshness_label)
        df["sync_badge"] = df["_synced_dt"].apply(_sync_badge)
        df["source"] = df["source"].fillna("—")

        vendor_options = sorted(df["vendor"].dropna().unique())
        category_options = sorted(df["category"].dropna().unique())
        severity_options = sorted(df["severity"].dropna().unique())

        filter_cols = st.columns(4)
        with filter_cols[0]:
            selected_vendors = st.multiselect(
                "Vendors", vendor_options, default=vendor_options
            )
        with filter_cols[1]:
            selected_categories = st.multiselect(
                "Categories", category_options, default=category_options
            )
        with filter_cols[2]:
            selected_severity = st.multiselect(
                "Severity", severity_options, default=severity_options
            )
        with filter_cols[3]:
            freshness_filter = st.radio(
                "Freshness", ["All", "Fresh", "Stale"], horizontal=True
            )

        search_term = st.text_input("Search rule name or ID").strip()

        if selected_vendors:
            df = df[df["vendor"].isin(selected_vendors)]
        if selected_categories:
            df = df[df["category"].isin(selected_categories)]
        if selected_severity:
            df = df[df["severity"].isin(selected_severity)]
        if freshness_filter != "All":
            df = df[df["freshness"] == freshness_filter]
        if search_term:
            mask = df["name"].str.contains(search_term, case=False, na=False) | df[
                "rule_id"
            ].str.contains(search_term, case=False, na=False)
            df = df[mask]

        if df.empty:
            st.warning("No rules match the current filters.", icon="⚠️")
        else:
            selection_state_key = "rule_studio_selection"
            if selection_state_key not in st.session_state:
                st.session_state[selection_state_key] = set()

            df["selected"] = df.apply(
                lambda row: (row["vendor"], row["rule_id"])
                in st.session_state[selection_state_key],
                axis=1,
            )

            display_columns = [
                "selected",
                "vendor",
                "rule_id",
                "name",
                "category",
                "severity",
            "freshness",
            "sync_badge",
            "source",
            ]

            data = df[display_columns]
            edited = st.data_editor(
                data,
                hide_index=True,
                use_container_width=True,
                column_config={
                    "selected": st.column_config.CheckboxColumn("Select"),
                    "vendor": st.column_config.TextColumn("Vendor", disabled=True),
                    "rule_id": st.column_config.TextColumn("Rule ID", disabled=True),
                    "name": st.column_config.TextColumn("Rule Name", disabled=True),
                    "category": st.column_config.TextColumn("Category", disabled=True),
                    "severity": st.column_config.TextColumn("Severity", disabled=True),
                    "freshness": st.column_config.TextColumn("Freshness", disabled=True),
                    "sync_badge": st.column_config.TextColumn(
                        "Sync",
                        disabled=True,
                        help="Shows last sync date and SLA status",
                    ),
                    "source": st.column_config.TextColumn(
                        "Source", disabled=True, help="Origin of the vendor export"
                    ),
                },
                key="rule_studio_table",
            )

            selected_pairs = {
                (row["vendor"], row["rule_id"])
                for _, row in edited.iterrows()
                if row["selected"]
            }
            st.session_state[selection_state_key] = selected_pairs

            selected_count = len(selected_pairs)
            st.caption(
                f"{selected_count} rule{'s' if selected_count != 1 else ''} selected"
            )
            compare_clicked = st.button(
                "Compare selected",
                disabled=selected_count < 2,
                help="Pick two or more rules, then click to open the drawer.",
            )
            if compare_clicked and selected_count >= 2:
                _open_rule_drawer(selected_pairs, rules, st.session_state[drawer_state_key])

    with main_cols[1]:
        render_rule_drawer(
            st.session_state.get(drawer_state_key),
            active_domain,
        )


def _open_rule_drawer(
    selected_pairs: Set[Tuple[str, str]],
    rules: List[Dict[str, str]],
    drawer_state: Dict,
):
    lookup = {(row["vendor"], row["rule_id"]): row for row in rules}
    ordered_pairs = sorted(selected_pairs)
    selected_records = {
        pair: lookup[pair]
        for pair in ordered_pairs
        if pair in lookup
    }
    if len(selected_records) < 2:
        st.warning("Unable to load at least two rules for comparison.", icon="⚠️")
        return
    drawer_state["open"] = True
    drawer_state["rules"] = selected_records
    first_two = list(selected_records.keys())[:2]
    drawer_state["selected_a"] = f"{first_two[0][0]}:{first_two[0][1]}"
    drawer_state["selected_b"] = f"{first_two[1][0]}:{first_two[1][1]}"


RADAR_SUMMARY_STATE_KEY = "radar_summary_state"


def render_radar_summary_tools(
    domain: Optional[str], persona_id: str, persona_label: str
):
    st.subheader("Radar Summary Export")
    state = st.session_state.setdefault(RADAR_SUMMARY_STATE_KEY, {})
    if not domain:
        st.info("Select a domain in the radar table to enable exports.", icon="ℹ️")
        return

    create_pdf = st.checkbox(
        "Also create PDF output",
        key="radar-summary-pdf",
        help="Adds a PDF next to the Markdown export.",
    )
    if st.button(
        "Generate Radar Summary",
        key="radar-summary-generate",
        type="primary",
    ):
        with st.spinner("Generating radar summary..."):
            try:
                result = export_service.generate_radar_summary(
                    domain,
                    persona_id=persona_id,
                    create_pdf=create_pdf,
                )
            except Exception as exc:  # pragma: no cover - UI messaging
                st.error(f"Radar export failed: {exc}", icon="⚠️")
            else:
                st.toast(
                    f"Radar summary ready for {domain} ({persona_label})",
                    icon="✅",
                )
                state["preview"] = result.preview
                state["paths"] = {
                    "markdown": str(result.markdown_path),
                    "pdf": str(result.pdf_path) if result.pdf_path else None,
                }
                state["job_id"] = result.job_id

    if state.get("preview"):
        st.markdown("#### Latest Radar Summary Preview")
        st.markdown(state["preview"])
        paths = state.get("paths", {})
        if paths.get("markdown"):
            st.code(paths["markdown"])
        if paths.get("pdf"):
            st.caption(f"PDF saved to {paths['pdf']}")


def main():
    st.set_page_config(page_title="WAF Security Lab", layout="wide")
    inject_theme()
    st.title("WAF Security Lab")
    st.caption("Local sandbox for GTM Radar + WAFtotal experiments")

    persona_options = persona_service.list_personas()
    if not persona_options:
        st.error("No personas configured. Update backend.services.persona to proceed.", icon="⚠️")
        return
    persona_labels = {item["id"]: item["name"] for item in persona_options}
    st.session_state.setdefault(PERSONA_VIEW_KEY, persona_options[0]["id"])
    selected_persona = st.selectbox(
        "Persona View",
        options=list(persona_labels.keys()),
        format_func=lambda value: persona_labels[value],
        key=PERSONA_VIEW_KEY,
    )

    if st.button("Refresh Persona Data", key="refresh-persona"):
        st.experimental_rerun()

    domains, load_error = load_domains()
    if load_error:
        render_connection_error(load_error)
        render_persona_card(
            None,
            persona_labels[selected_persona],
            selected_persona,
            None,
            on_copy=None,
        )
        return

    radar_result = render_radar_table(domains, persona_labels, persona_state_key=PERSONA_VIEW_KEY)
    record: Optional[Dict] = radar_result.record
    selected_domain: Optional[str] = radar_result.domain
    stale_warning: Optional[str] = (
        freshness.get_warning(record.get("last_observed")) if record else None
    )

    layout_cols = st.columns([0.62, 0.38], gap="large")
    with layout_cols[0]:
        if record:
            render_metrics(record, stale_warning)
        else:
            st.caption("Select a domain from the radar table to view scorecards.")
        render_export_section()
        if record:
            st.divider()
            st.subheader("Raw Record")
            st.json(record)

    with layout_cols[1]:
        st.markdown("<span id='persona-card-anchor'></span>", unsafe_allow_html=True)
        persona_payload = None
        if record and selected_domain:
            try:
                persona_payload = persona_service.generate_persona_view(
                    selected_persona, selected_domain  # type: ignore[arg-type]
                )
            except (
                persona_service.DomainNotFound,
                persona_service.PersonaNotFound,
            ):
                persona_payload = None

        copy_callback = None
        if persona_payload and selected_domain:
            copy_callback = lambda: usage_logging.log_persona_usage(
                persona_payload.get("persona_id", selected_persona),
                selected_domain,
                "copy",
                "UI",
            )

        render_persona_card(
            persona_payload,
            persona_labels[selected_persona],
            selected_persona,
            stale_warning,
            on_copy=copy_callback,
        )
        render_radar_summary_tools(
            selected_domain,
            selected_persona,
            persona_labels[selected_persona],
        )

        if st.session_state.pop("persona_autoscroll", False):
            st.markdown(
                "<script>document.getElementById('persona-card-anchor').scrollIntoView({behavior: 'smooth', block: 'start'});</script>",
                unsafe_allow_html=True,
            )

    st.divider()
    render_rule_studio(selected_domain)


if __name__ == "__main__":
    main()

