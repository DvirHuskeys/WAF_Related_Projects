from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional, Tuple

import streamlit as st

from backend.services import (
    export as export_service,
    freshness,
    rules as rules_service,
)
from ui.components.rule_utils import parse_rule_synced_at
from ui.components.utils import copy_to_clipboard

SEVERITY_COLORS = {
    "critical": "#ff5a5f",
    "high": "#ff8c42",
    "medium": "#f5a524",
    "low": "#0bd3d3",
}

RULE_BRIEF_STATE_KEY = "rule_brief_state"


def render_rule_drawer(
    drawer_state: Optional[Dict], selected_domain: Optional[str] = None
):
    container = st.container(border=True)
    with container:
        st.markdown("### Rule Comparison Drawer")
        st.caption("Press ESC or select Close to dismiss. Tab navigation moves focus into the drawer.")

        if not drawer_state or not drawer_state.get("open"):
            st.info("Select two rules and click Compare to open the drawer.", icon="ℹ️")
            return

        rule_records: Dict[Tuple[str, str], Dict] = drawer_state.get("rules", {})
        if len(rule_records) < 2:
            st.info("Select at least two rules in Rule Studio to compare.", icon="ℹ️")
            return

        options = [f"{vendor}:{rule_id}" for vendor, rule_id in rule_records.keys()]
        if len(options) > 2:
            st.info(
                "More than two rules selected. Choose which pair to compare below.",
                icon="ℹ️",
            )

        default_a = drawer_state.get("selected_a", options[0])
        default_b = drawer_state.get(
            "selected_b", options[1 if len(options) > 1 else 0]
        )

        col_select_a, col_select_b = st.columns(2)
        with col_select_a:
            selected_a = st.selectbox(
                "Rule A",
                options,
                index=options.index(default_a) if default_a in options else 0,
                key="rule_drawer_select_a",
            )
        with col_select_b:
            selected_b = st.selectbox(
                "Rule B",
                options,
                index=options.index(default_b) if default_b in options else 0,
                key="rule_drawer_select_b",
            )

        if selected_a == selected_b:
            st.warning("Choose two different rules to compare.", icon="⚠️")
            return

        drawer_state["selected_a"] = selected_a
        drawer_state["selected_b"] = selected_b

        rule_a = rule_records[_to_key(selected_a)]
        rule_b = rule_records[_to_key(selected_b)]

        summary = _build_diff_summary(rule_a, rule_b)
        tabs = st.tabs(["Diff Summary", "Details", "Notes"])

        with tabs[0]:
            st.write(summary)
            if st.button("Copy summary", key="rule_diff_copy"):
                copy_to_clipboard(summary)
                st.toast("Summary copied to clipboard.", icon="✅")

        with tabs[1]:
            detail_cols = st.columns(2)
            _render_rule_card(detail_cols[0], rule_a, "Rule A", rule_b)
            _render_rule_card(detail_cols[1], rule_b, "Rule B", rule_a)

        with tabs[2]:
            _render_notes_tab(rule_a, rule_b)

        st.divider()
        st.markdown("#### Rule Brief Export")
        export_state = st.session_state.setdefault(RULE_BRIEF_STATE_KEY, {})
        domain_key = "rule_brief_domain_input"
        if selected_domain and not st.session_state.get(domain_key):
            st.session_state[domain_key] = selected_domain

        domain_value = st.text_input(
            "Domain for brief",
            key=domain_key,
            help="Used for file naming (docs/reports/<domain>-rule-brief-...).",
        ).strip()
        include_pdf = st.checkbox(
            "Also create PDF output",
            key="rule_brief_pdf",
            help="Adds a PDF alongside the Markdown brief.",
        )
        if st.button(
            "Generate Rule Brief",
            key="rule_brief_generate",
            disabled=not domain_value,
        ):
            with st.spinner("Generating rule brief..."):
                try:
                    result = export_service.generate_rule_brief(
                        domain_value,
                        _to_key(selected_a),
                        _to_key(selected_b),
                        create_pdf=include_pdf,
                    )
                except Exception as exc:  # pragma: no cover - UI feedback only
                    st.error(f"Rule brief export failed: {exc}", icon="⚠️")
                else:
                    st.toast(
                        f"Rule brief ready for {domain_value}",
                        icon="✅",
                    )
                    export_state["preview"] = result.preview
                    export_state["paths"] = {
                        "markdown": str(result.markdown_path),
                        "pdf": str(result.pdf_path) if result.pdf_path else None,
                    }
                    export_state["domain"] = domain_value

        if export_state.get("preview"):
            st.markdown("##### Latest Rule Brief Preview")
            st.markdown(export_state["preview"])
            paths = export_state.get("paths", {})
            if paths.get("markdown"):
                st.code(paths["markdown"])
            if paths.get("pdf"):
                st.caption(f"PDF saved to {paths['pdf']}")

        close_col1, close_col2 = st.columns([0.6, 0.4])
        with close_col2:
            if st.button("Close drawer"):
                drawer_state["open"] = False


def _render_rule_card(column, rule: Dict, label: str, counterpart: Dict):
    with column:
        st.markdown(f"**{label}**")
        st.markdown(f"*{rule.get('vendor')} · {rule.get('rule_id')}*")
        st.write(rule.get("name"))
        st.caption(rule.get("category", ""))
        severity = rule.get("severity", "—")
        severity_color = SEVERITY_COLORS.get(str(severity).lower(), "#9AA5CE")
        severity_differs = severity != counterpart.get("severity")
        st.markdown(
            f"Severity: {_highlight_badge(severity, severity_color, severity_differs)}",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"Mitigation: {_format_diff(rule.get('mitigation'), counterpart.get('mitigation'))}",
            unsafe_allow_html=True,
        )
        st.markdown(
            f"Pattern: {_format_diff(rule.get('detection_pattern'), counterpart.get('detection_pattern'), code=True)}",
            unsafe_allow_html=True,
        )
        source_label = rule.get("source") or "unknown"
        st.markdown(f"Source: `{source_label}`")
        freshness_text, freshness_differs = _sync_detail(rule, counterpart)
        st.markdown(
            f"Freshness: {_format_diff(freshness_text, None, highlight=freshness_differs)}",
            unsafe_allow_html=True,
        )


def _format_diff(
    value: Optional[str],
    counterpart: Optional[str],
    code: bool = False,
    highlight: bool = False,
) -> str:
    display = value or "—"
    other = display if counterpart is None else (counterpart or "—")
    differs = highlight or display != other
    content = f"<code>{display}</code>" if code and value else display
    if not differs:
        return content
    return f"<span class='diff-chip'>{content}</span>"


def _highlight_badge(value: Optional[str], color: str, differs: bool) -> str:
    label = value or "—"
    base_style = "padding:0.15rem 0.5rem;border-radius:0.35rem;font-weight:600;"
    style = (
        f"{base_style}background:{color};color:#10131B;"
        if differs
        else f"{base_style}border:1px solid rgba(255,255,255,0.2);color:{color};"
    )
    return f"<span class='diff-chip' style='{style}'>{label}</span>"


def _build_diff_summary(rule_a: Dict, rule_b: Dict) -> str:
    sync_phrase_a = _sync_phrase(rule_a)
    sync_phrase_b = _sync_phrase(rule_b)

    return (
        f"{rule_a['vendor']} rule {rule_a['rule_id']} ({rule_a['name']}) "
        f"{_describe_pattern(rule_a)} with mitigation `{rule_a.get('mitigation', '—')}`; {sync_phrase_a}. "
        f"{rule_b['vendor']} rule {rule_b['rule_id']} ({rule_b['name']}) "
        f"{_describe_pattern(rule_b)} with mitigation `{rule_b.get('mitigation', '—')}`; {sync_phrase_b}. "
        f"Severity delta: {rule_a.get('severity', 'unknown')} vs {rule_b.get('severity', 'unknown')}."
    )


def _describe_pattern(rule: Dict) -> str:
    pattern = rule.get("detection_pattern")
    if not pattern:
        return "does not expose a detection pattern"
    return f"detects via `{pattern}`"


def _to_key(option: str) -> Tuple[str, str]:
    vendor, rule_id = option.split(":", 1)
    return vendor, rule_id


def _sync_detail(rule: Dict, counterpart: Dict) -> Tuple[str, bool]:
    synced = parse_rule_synced_at(rule.get("synced_at"), rule.get("metadata"))
    counter_synced = parse_rule_synced_at(
        counterpart.get("synced_at"), counterpart.get("metadata")
    )
    stale, days = freshness.is_stale(synced)
    counter_stale, _ = freshness.is_stale(counter_synced)
    freshness_label = "Stale" if stale else "Fresh"
    freshness_text = f"{freshness_label} · Last synced {synced.strftime('%Y-%m-%d %H:%M') if synced else 'unknown'}"
    if stale and days:
        freshness_text += f" ({days}d old)"
    return freshness_text, stale != counter_stale


def _sync_phrase(rule: Dict) -> str:
    synced = parse_rule_synced_at(rule.get("synced_at"), rule.get("metadata"))
    stale, days = freshness.is_stale(synced)
    if not synced:
        return "sync date unknown"
    age = f"{days}d ago" if days is not None else "recently"
    source = rule.get("source") or "unknown source"
    prefix = "⚠️ " if stale else ""
    return f"{prefix}synced {age} ({synced.strftime('%Y-%m-%d')}, {source})"


def _render_notes_tab(rule_a: Dict, rule_b: Dict):
    st.caption(
        "Annotations capture customer-specific tweaks so comparisons stay grounded in context."
    )
    _render_rule_notes(rule_a, "Rule A")
    st.divider()
    _render_rule_notes(rule_b, "Rule B")


def _render_rule_notes(rule: Dict, label: str):
    st.markdown(f"#### {label}: {rule.get('vendor')} · {rule.get('rule_id')}")
    st.caption(
        f"Notes will be saved as **{rules_service.author_label()}**. Markdown is supported."
    )
    _render_add_note_form(rule)
    notes = rules_service.list_notes(rule.get("vendor", ""), rule.get("rule_id", ""))
    if not notes:
        st.info(
            "No annotations yet. Use notes to record overrides or customer-specific changes.",
            icon="📝",
        )
        return
    for note in notes:
        _render_note_entry(rule, note)


def _render_add_note_form(rule: Dict):
    vendor = rule.get("vendor")
    rule_id = rule.get("rule_id")
    content_key = f"new-note-{vendor}-{rule_id}"
    with st.expander("Add Note", expanded=False):
        st.text_area(
            "Note content",
            key=content_key,
            placeholder="e.g., Customer X disables threshold during Black Friday load-testing.",
            height=120,
        )
        if st.button("Save note", key=f"save-note-{vendor}-{rule_id}"):
            content = st.session_state.get(content_key, "").strip()
            if not content:
                st.warning("Add note content before saving.", icon="⚠️")
                return
            rules_service.add_note(vendor, rule_id, content)
            st.session_state[content_key] = ""
            st.success("Note saved.", icon="✅")
            st.experimental_rerun()


def _render_note_entry(rule: Dict, note: Dict):
    note_id = note.get("note_id")
    edit_flag_key = f"note-edit-{note_id}"
    text_key = f"note-edit-content-{note_id}"
    editing = st.session_state.get(edit_flag_key, False)
    can_edit_note = rules_service.can_edit(note)
    created_label = _format_timestamp(note.get("created_at"))
    updated_label = _format_timestamp(note.get("updated_at"))
    meta = f"{note.get('author')} · {created_label}"
    if updated_label:
        meta += f" · edited {updated_label}"
    st.caption(meta)
    if editing:
        if text_key not in st.session_state:
            st.session_state[text_key] = note.get("content", "")
        st.text_area(
            "Edit note",
            key=text_key,
            height=120,
            label_visibility="collapsed",
        )
        action_cols = st.columns([0.35, 0.3, 0.35])
        with action_cols[0]:
            if st.button("Save changes", key=f"note-save-{note_id}"):
                updated = st.session_state.get(text_key, "").strip()
                if not updated:
                    st.warning("Note cannot be empty.", icon="⚠️")
                elif rules_service.update_note(note_id, updated):
                    st.success("Note updated.", icon="✅")
                    st.session_state[edit_flag_key] = False
                    st.experimental_rerun()
        with action_cols[1]:
            if st.button("Cancel", key=f"note-cancel-{note_id}"):
                st.session_state[edit_flag_key] = False
                st.session_state[text_key] = note.get("content", "")
        with action_cols[2]:
            if st.button("Delete note", key=f"note-delete-{note_id}"):
                if rules_service.delete_note(note_id):
                    st.success("Note deleted.", icon="✅")
                    st.session_state[edit_flag_key] = False
                    st.experimental_rerun()
    else:
        st.markdown(note.get("content", ""))
        if can_edit_note:
            action_cols = st.columns([0.2, 0.2, 0.6])
            with action_cols[0]:
                if st.button("Edit", key=f"note-edit-btn-{note_id}"):
                    st.session_state[edit_flag_key] = True
                    st.session_state[text_key] = note.get("content", "")
                    st.experimental_rerun()
            with action_cols[1]:
                if st.button("Delete", key=f"note-delete-btn-{note_id}"):
                    if rules_service.delete_note(note_id):
                        st.success("Note deleted.", icon="✅")
                        st.experimental_rerun()


def _format_timestamp(value: Optional[datetime]) -> Optional[str]:
    if not value:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime("%Y-%m-%d %H:%M")



