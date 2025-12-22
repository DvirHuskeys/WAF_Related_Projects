from __future__ import annotations

import time
from typing import Callable, Dict, List, Optional

import streamlit as st

from ui.components.utils import copy_to_clipboard

AVATARS = {
    "ae": "🧑‍💼",
    "ciso": "🛡️",
    "winston": "🧑‍💻",
}


def render_persona_card(
    persona_payload: Optional[Dict],
    persona_label: str,
    persona_id: str,
    stale_warning: Optional[str],
    on_copy: Optional[Callable[[], None]] = None,
):
    card = st.container(border=True)
    if not persona_payload:
        with card:
            st.caption(
                "Persona data unavailable. Run `python scripts/domain_enrich.py data/samples/domains.csv` "
                "and refresh to generate insights."
            )
        return

    persona_meta = persona_payload.get("persona", {})
    avatar = AVATARS.get(persona_id, "👤")
    with card:
        header_col_avatar, header_col_meta = st.columns([0.18, 0.82])
        with header_col_avatar:
            st.markdown(f"<div style='font-size:3rem'>{avatar}</div>", unsafe_allow_html=True)
        with header_col_meta:
            st.markdown(f"### {persona_label}")
            st.caption(persona_meta.get("goal", ""))

        stack_waf = persona_payload.get("detected_waf", "—")
        stack_cdn = persona_payload.get("detected_cdn", "—")
        st.markdown(f"**Stack Snapshot:** {stack_waf} WAF · {stack_cdn} CDN")

        scores = persona_payload.get("scores", {})
        score_cols = st.columns(3)
        for col, (label, key) in zip(
            score_cols,
            [
                ("Config Drift", "config_drift"),
                ("Downtime Risk", "downtime_risk"),
                ("Attack Surface", "attack_surface"),
            ],
        ):
            with col:
                value = scores.get(key, 0.0)
                st.metric(label, f"{value:.2f}")

        hooks = persona_payload.get("hooks") or []
        hook_titles = [hook.get("title", f"Hook {idx+1}") for idx, hook in enumerate(hooks)]
        hook_state_key = f"hook-select-{persona_id}"
        badge_markup = ""
        if hooks:
            badge_markup = " ".join(
                f"<span class='persona-chip persona-chip--muted'>{title}</span>"
                for title in hook_titles
            )
            default_hook = hook_titles[0]
            selected_title = st.radio(
                "Narrative hooks",
                hook_titles,
                horizontal=True,
                index=hook_titles.index(st.session_state.get(hook_state_key, default_hook))
                if st.session_state.get(hook_state_key) in hook_titles
                else 0,
                key=hook_state_key,
            )
            selected_hook = hooks[hook_titles.index(selected_title)]
            if badge_markup:
                st.markdown(badge_markup, unsafe_allow_html=True)
        else:
            selected_hook = {
                "title": "Insight preview",
                "description": persona_payload.get("story_prompt", ""),
                "score_reason": "",
            }

        st.markdown(
            f"**Primary Hook:** {selected_hook.get('description', 'No hook available.')}"
        )
        if selected_hook.get("score_reason"):
            st.caption(selected_hook["score_reason"])

        if stale_warning:
            st.warning(stale_warning, icon="⏱️")

        copy_state_key = f"{persona_id}-copy-ts"
        copy_label = "Copy message"
        last_copied = st.session_state.get(copy_state_key)
        if last_copied and time.time() - last_copied < 2:
            copy_label = "Copied!"
        if st.button(copy_label, key=f"copy-btn-{persona_id}"):
            st.session_state[copy_state_key] = time.time()
            message = f"{persona_payload.get('story_prompt', '')} — {persona_label} · WAF Security Lab"
            copy_to_clipboard(message)
            st.toast("Copied!", icon="✅")
            if on_copy:
                on_copy()

