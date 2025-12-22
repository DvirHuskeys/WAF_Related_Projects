from __future__ import annotations

import json

import streamlit.components.v1 as components


def copy_to_clipboard(text: str):
    components.html(
        f"""
        <script>
        const text = {json.dumps(text)};
        if (navigator.clipboard && window.isSecureContext) {{
            navigator.clipboard.writeText(text);
        }} else {{
            var textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.left = '-1000px';
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);
        }}
        </script>
        """,
        height=0,
    )












