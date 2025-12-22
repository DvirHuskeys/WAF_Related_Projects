from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st

from backend.services import freshness, jobs
from backend.services import hooks as hook_loader

PERSONA_VIEW_KEY = "persona_view"
RADAR_SELECTED_DOMAIN_KEY = "selected_domain"
RADAR_VENDOR_KEY = "radar_vendor_filter"
RADAR_PERSONA_KEY = "radar_persona_filter"
RADAR_FRESHNESS_KEY = "radar_freshness_filter"
RADAR_SEARCH_KEY = "radar_search_filter"
RADAR_SORT_KEY = "radar_sort_by"
RADAR_SORT_DIR_KEY = "radar_sort_direction"
RADAR_LAST_JOB_KEY = "radar_last_seen_job"

SORT_OPTIONS = {
    "priority_index": "Priority Index",
    "config_drift_score": "Config Drift",
    "downtime_risk_score": "Downtime Risk",
    "attack_surface_score": "Attack Surface",
}

VENDOR_ICONS = {
    "cloudflare": "☁️",
    "aws_waf": "🟧",
    "akamai": "🌀",
    "fastly": "⚡",
    "unknown": "🛰️",
}

CDN_ICONS = {
    "cloudflare": "☁️",
    "aws": "🟧",
    "fastly": "⚡",
    "akamai": "🌀",
    "unknown": "🛰️",
}


@dataclass
class RadarTableResult:
    domain: Optional[str]
    record: Optional[Dict[str, Any]]
    total: int
    filtered: int


def render_empty_state() -> None:
    st.info(
        "No enrichment records found. Run the bootstrap CLI to populate domain data.",
        icon="ℹ️",
    )
    st.code("python scripts/domain_enrich.py data/samples/domains.csv")
    st.caption(
        "Need help? Check README → Bootstrap Workflow or rerun `make init-db` followed by enrichment."
    )


def render_radar_table(
    records: List[Dict[str, Any]],
    persona_labels: Dict[str, str],
    persona_state_key: str = PERSONA_VIEW_KEY,
    selection_state_key: str = RADAR_SELECTED_DOMAIN_KEY,
) -> RadarTableResult:
    if not records:
        render_empty_state()
        st.session_state.setdefault(selection_state_key, None)
        return RadarTableResult(None, None, total=0, filtered=0)

    vendor_map = _build_vendor_map(records)
    persona_ids = list(persona_labels.keys())
    _hydrate_multiselect_state(RADAR_VENDOR_KEY, list(vendor_map))
    _hydrate_multiselect_state(RADAR_PERSONA_KEY, persona_ids)
    _hydrate_simple_state(RADAR_FRESHNESS_KEY, "All")
    _hydrate_simple_state(RADAR_SEARCH_KEY, "")
    _hydrate_simple_state(RADAR_SORT_KEY, "priority_index")
    _hydrate_simple_state(RADAR_SORT_DIR_KEY, "desc")

    job_info = jobs.latest_job("domain_enrich")
    _prime_job_state(job_info)

    with st.container():
        _render_controls(vendor_map, persona_ids)
        _render_refresh_controls(job_info)

    rows = [_build_row(record, persona_labels) for record in records]
    filters = _current_filters()
    filtered_rows = _apply_filters(rows, filters)
    sorted_rows = _sort_rows(filtered_rows, filters["sort_by"], filters["sort_dir"])

    selection = _ensure_selection(sorted_rows, selection_state_key)
    selected_record = next(
        (row["record"] for row in sorted_rows if row["domain"] == selection), None
    )

    _render_rows(
        sorted_rows,
        selection,
        persona_labels,
        persona_state_key,
        selection_state_key,
    )

    return RadarTableResult(
        selection,
        selected_record,
        total=len(records),
        filtered=len(sorted_rows),
    )


def _render_controls(vendor_map: Dict[str, str], persona_ids: List[str]) -> None:
    vendor_options = list(vendor_map.keys())
    vendor_options.sort(key=lambda key: vendor_map[key])
    filters_col, search_col = st.columns([0.7, 0.3])
    with filters_col:
        st.multiselect(
            "WAF Vendor",
            vendor_options,
            format_func=lambda key: vendor_map[key],
            key=RADAR_VENDOR_KEY,
        )
        st.multiselect(
            "Persona relevance",
            persona_ids,
            format_func=lambda value: value.upper(),
            key=RADAR_PERSONA_KEY,
        )
        st.radio(
            "Freshness",
            options=["All", "Fresh", "Stale"],
            horizontal=True,
            key=RADAR_FRESHNESS_KEY,
        )
        sort_row = st.columns(2)
        with sort_row[0]:
            st.selectbox(
                "Sort by",
                options=list(SORT_OPTIONS.keys()),
                format_func=lambda key: SORT_OPTIONS[key],
                key=RADAR_SORT_KEY,
            )
        with sort_row[1]:
            st.selectbox(
                "Order",
                options=["desc", "asc"],
                format_func=lambda value: "Descending" if value == "desc" else "Ascending",
                key=RADAR_SORT_DIR_KEY,
            )
        reset_col1, reset_col2 = st.columns([0.5, 0.5])
        with reset_col1:
            if st.button("Reset filters", type="secondary"):
                st.session_state[RADAR_VENDOR_KEY] = vendor_options.copy()
                st.session_state[RADAR_PERSONA_KEY] = persona_ids.copy()
                st.session_state[RADAR_FRESHNESS_KEY] = "All"
                st.session_state[RADAR_SEARCH_KEY] = ""
                st.session_state[RADAR_SORT_KEY] = "priority_index"
                st.session_state[RADAR_SORT_DIR_KEY] = "desc"
                st.experimental_rerun()
    with search_col:
        st.text_input(
            "Search domains",
            placeholder="Search domain, WAF, CDN",
            key=RADAR_SEARCH_KEY,
        )


def _render_refresh_controls(job_info: Optional[Dict[str, Any]]) -> None:
    refresh_cols = st.columns([0.2, 0.8])
    with refresh_cols[0]:
        if st.button("Refresh data", key="radar-refresh", type="primary"):
            st.session_state["radar_manual_refresh"] = datetime.utcnow().isoformat()
            st.experimental_rerun()
    with refresh_cols[1]:
        if job_info:
            finished = job_info.get("finished_at") or job_info.get("started_at")
            finished_str = (
                finished.strftime("%Y-%m-%d %H:%M UTC") if isinstance(finished, datetime) else ""
            )
            st.caption(
                f"Last enrichment job {job_info['job_id']} • {job_info.get('status', 'unknown').title()} • {finished_str}"
            )
        else:
            st.caption("No enrichment jobs have been recorded yet.")
        auto_msg = st.session_state.pop("radar_auto_refresh_reason", None)
        if auto_msg:
            st.success(auto_msg, icon="🔄")


def _apply_filters(rows: List[Dict[str, Any]], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    vendor_filter = set(filters["vendors"]) if filters["vendors"] else None
    persona_filter = set(filters["personas"]) if filters["personas"] else None
    freshness_filter = filters["freshness"]
    search_term = filters["search"]
    results: List[Dict[str, Any]] = []
    for row in rows:
        if vendor_filter and row["vendor_key"] not in vendor_filter:
            continue
        if persona_filter and not persona_filter.intersection(row["persona_matches"]):
            continue
        if freshness_filter == "Fresh" and row["stale"]:
            continue
        if freshness_filter == "Stale" and not row["stale"]:
            continue
        if search_term and search_term not in row["search_blob"]:
            continue
        results.append(row)
    return results


def _sort_rows(rows: List[Dict[str, Any]], sort_key: str, sort_dir: str) -> List[Dict[str, Any]]:
    reverse = sort_dir == "desc"
    return sorted(rows, key=lambda row: row.get(sort_key, 0), reverse=reverse)


def _render_rows(
    rows: List[Dict[str, Any]],
    selection: Optional[str],
    persona_labels: Dict[str, str],
    persona_state_key: str,
    selection_state_key: str,
) -> None:
    st.caption(f"Showing {len(rows)} domain(s)")
    if not rows:
        st.warning("No domains match the current filters.", icon="⚠️")
        return

    for row in rows:
        row_container = st.container()
        if selection == row["domain"]:
            row_container.markdown(
                "<div class='radar-row radar-row--selected'>", unsafe_allow_html=True
            )
        else:
            row_container.markdown("<div class='radar-row'>", unsafe_allow_html=True)

        domain_col, score_col, persona_col = row_container.columns([0.45, 0.3, 0.25])

        with domain_col:
            st.markdown(f"**{row['domain']}**")
            st.caption(
                f"{row['waf_icon']} {row['vendor_label']} • {row['cdn_icon']} {row['cdn_label']}"
            )
            st.markdown(row["freshness_chip"], unsafe_allow_html=True)
            st.caption(row["last_observed_label"])
            if st.button(
                "Focus",
                key=f"focus-{row['domain']}",
                type="secondary",
                use_container_width=True,
            ):
                _select_domain(row["domain"], selection_state_key)

        with score_col:
            for badge in row["score_badges"]:
                st.markdown(badge, unsafe_allow_html=True)
            st.markdown(row["priority_badge"], unsafe_allow_html=True)

        with persona_col:
            st.caption("Persona quick links")
            if row["persona_matches"]:
                btn_cols = st.columns(len(row["persona_matches"]))
                for col, persona_id in zip(btn_cols, row["persona_matches"]):
                    label = persona_labels.get(persona_id, persona_id.upper())
                    button_text = persona_id.upper()
                    with col:
                        if st.button(
                            button_text,
                            key=f"persona-link-{row['domain']}-{persona_id}",
                            type="secondary",
                            help=label,
                        ):
                            st.session_state[persona_state_key] = persona_id
                            _select_domain(row["domain"], selection_state_key)
            else:
                st.caption("No persona hooks yet.")

        row_container.markdown("</div>", unsafe_allow_html=True)


def _select_domain(domain: str, selection_state_key: str) -> None:
    st.session_state[selection_state_key] = domain
    st.session_state["persona_autoscroll"] = True


def _ensure_selection(
    rows: List[Dict[str, Any]], selection_state_key: str
) -> Optional[str]:
    if not rows:
        st.session_state[selection_state_key] = None
        return None
    current = st.session_state.get(selection_state_key)
    available_domains = [row["domain"] for row in rows]
    if current not in available_domains:
        st.session_state[selection_state_key] = available_domains[0]
        return available_domains[0]
    return current


def _build_row(record: Dict[str, Any], persona_labels: Dict[str, str]) -> Dict[str, Any]:
    vendor_key, vendor_label = _normalize_stack(record.get("detected_waf"))
    cdn_key, cdn_label = _normalize_stack(record.get("detected_cdn"))
    scores = _extract_scores(record)
    stale, age_days = freshness.is_stale(record.get("last_observed"))
    freshness_chip = _freshness_chip(stale, age_days)
    persona_matches = _match_personas(scores, persona_labels)
    score_badges = [
        _score_badge_html("Drift", scores["config_drift"]),
        _score_badge_html("Downtime", scores["downtime_risk"]),
        _score_badge_html("Attack", scores["attack_surface"]),
    ]
    priority_badge = _score_badge_html("Priority", scores["priority_index"], emphasize=True)
    return {
        "domain": record.get("domain"),
        "record": record,
        "vendor_key": vendor_key,
        "vendor_label": vendor_label,
        "cdn_label": cdn_label,
        "waf_icon": VENDOR_ICONS.get(vendor_key, VENDOR_ICONS["unknown"]),
        "cdn_icon": CDN_ICONS.get(cdn_key, CDN_ICONS["unknown"]),
        "stale": stale,
        "freshness_chip": freshness_chip,
        "last_observed_label": _format_observed(record.get("last_observed"), age_days),
        "persona_matches": persona_matches,
        "score_badges": score_badges,
        "priority_badge": priority_badge,
        "priority_index": scores["priority_index"],
        "config_drift_score": scores["config_drift"],
        "downtime_risk_score": scores["downtime_risk"],
        "attack_surface_score": scores["attack_surface"],
        "search_blob": _build_search_blob(record),
    }


def _match_personas(scores: Dict[str, float], persona_labels: Dict[str, str]) -> List[str]:
    hooks = hook_loader.load_hooks()
    matches: List[str] = []
    for persona_id, definitions in hooks.items():
        if persona_id not in persona_labels:
            continue
        for definition in definitions:
            score_key = definition.get("score")
            threshold = float(definition.get("min", 0))
            if not score_key:
                continue
            value = scores.get(score_key)
            if value is not None and value >= threshold:
                matches.append(persona_id)
                break
    if not matches:
        return []
    # Preserve persona_labels order
    ordered = [pid for pid in persona_labels.keys() if pid in matches]
    return ordered


def _extract_scores(record: Dict[str, Any]) -> Dict[str, float]:
    drift = float(record.get("config_drift_score") or 0)
    downtime = float(record.get("downtime_risk_score") or 0)
    attack = float(record.get("attack_surface_score") or 0)
    priority = round((drift * 0.4) + (downtime * 0.35) + (attack * 0.25), 2)
    return {
        "config_drift": drift,
        "downtime_risk": downtime,
        "attack_surface": attack,
        "priority_index": priority,
    }


def _score_badge_html(label: str, value: float, emphasize: bool = False) -> str:
    level = "high" if value >= 0.75 else "medium" if value >= 0.5 else "low"
    extra = " score-badge--emphasis" if emphasize else ""
    return (
        f"<span class='score-badge score-badge--{level}{extra}'>"
        f"{label}: {value:.2f}</span>"
    )


def _freshness_chip(stale: bool, age_days: Optional[int]) -> str:
    if stale:
        label = "Stale"
        detail = f"{age_days}d old" if age_days is not None else "Unknown age"
        return f"<span class='freshness-chip freshness-chip--stale'>⚠️ {label} • {detail}</span>"
    detail = f"{age_days}d old" if age_days is not None else "Just updated"
    return f"<span class='freshness-chip freshness-chip--fresh'>✅ Fresh • {detail}</span>"


def _format_observed(value: Any, age_days: Optional[int]) -> str:
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value)) if value else None
        except ValueError:
            dt = None
    if dt and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if not dt:
        return "Observed date unavailable"
    suffix = f" ({age_days}d ago)" if age_days is not None else ""
    return f"Observed {dt.strftime('%Y-%m-%d %H:%M UTC')}{suffix}"


def _build_vendor_map(records: List[Dict[str, Any]]) -> Dict[str, str]:
    vendor_map: Dict[str, str] = {}
    for record in records:
        key, label = _normalize_stack(record.get("detected_waf"))
        vendor_map[key] = label
    if "unknown" not in vendor_map:
        vendor_map["unknown"] = "Unknown"
    return vendor_map


def _normalize_stack(value: Optional[str]) -> Tuple[str, str]:
    if not value:
        return "unknown", "Unknown"
    raw = str(value).strip()
    key = raw.lower().replace(" ", "_")
    label = raw.replace("_", " ").title()
    return key, label


def _build_search_blob(record: Dict[str, Any]) -> str:
    parts = [
        str(record.get("domain") or "").lower(),
        str(record.get("detected_waf") or "").lower(),
        str(record.get("detected_cdn") or "").lower(),
    ]
    return " ".join(parts)


def _current_filters() -> Dict[str, Any]:
    vendor_selection = st.session_state.get(RADAR_VENDOR_KEY, [])
    persona_selection = st.session_state.get(RADAR_PERSONA_KEY, [])
    search_term = (st.session_state.get(RADAR_SEARCH_KEY) or "").strip().lower()
    return {
        "vendors": vendor_selection,
        "personas": persona_selection,
        "freshness": st.session_state.get(RADAR_FRESHNESS_KEY, "All"),
        "search": search_term,
        "sort_by": st.session_state.get(RADAR_SORT_KEY, "priority_index"),
        "sort_dir": st.session_state.get(RADAR_SORT_DIR_KEY, "desc"),
    }


def _hydrate_multiselect_state(key: str, options: List[str]) -> None:
    current = st.session_state.get(key)
    if current is None:
        st.session_state[key] = options.copy()
        return
    filtered = [value for value in current if value in options]
    if not filtered:
        filtered = options.copy()
    if filtered != current:
        st.session_state[key] = filtered


def _hydrate_simple_state(key: str, default: Any) -> None:
    if key not in st.session_state:
        st.session_state[key] = default


def _prime_job_state(job_info: Optional[Dict[str, Any]]) -> None:
    if not job_info:
        return
    job_id = job_info.get("job_id")
    if RADAR_LAST_JOB_KEY not in st.session_state:
        st.session_state[RADAR_LAST_JOB_KEY] = job_id
        return
    if job_id and st.session_state[RADAR_LAST_JOB_KEY] != job_id:
        st.session_state[RADAR_LAST_JOB_KEY] = job_id
        if job_info.get("status") == "success" and job_info.get("finished_at"):
            st.session_state["radar_auto_refresh_reason"] = (
                f"Auto-refreshed after job {job_id} completed."
            )
            st.experimental_rerun()

