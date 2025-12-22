from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from fpdf import FPDF
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

import pandas as pd

from backend.services import (
    freshness,
    jobs,
    persona as persona_service,
    rules as rules_service,
    storage,
)

RULE_EXPORT_QUERY = """
WITH note_summary AS (
    SELECT
        rule_vendor AS vendor,
        rule_id,
        STRING_AGG(
            author || ' [' || strftime(created_at, '%Y-%m-%d') || ']: ' || content,
            '\n---\n'
            ORDER BY created_at DESC
        ) AS notes
    FROM rule_notes
    WHERE deleted_at IS NULL
    GROUP BY 1, 2
)
SELECT
    mr.vendor,
    mr.rule_id,
    mr.name,
    mr.category,
    mr.severity,
    mr.detection_pattern,
    mr.mitigation,
    mr.metadata,
    mr.source,
    mr.synced_at,
    COALESCE(ns.notes, '') AS notes
FROM managed_rules mr
LEFT JOIN note_summary ns
    ON mr.vendor = ns.vendor
    AND mr.rule_id = ns.rule_id
"""

EXPORT_DIR = Path(os.getenv("EXPORT_DIR", "exports"))
REPORTS_DIR = Path("docs/reports")
TEMPLATES_DIR = Path("docs/templates")
RADAR_TEMPLATE_PATH = TEMPLATES_DIR / "radar_summary.md.jinja"
RULE_BRIEF_TEMPLATE_PATH = TEMPLATES_DIR / "rule_brief.md.jinja"


@dataclass
class ExportResult:
    path: Path
    job_id: str
    footnote_path: Optional[Path]


@dataclass
class RadarSummaryResult:
    markdown_path: Path
    pdf_path: Optional[Path]
    preview: str
    job_id: str


@dataclass
class RuleBriefResult:
    markdown_path: Path
    pdf_path: Optional[Path]
    preview: str
    job_id: str


def export_domains(
    fmt: str = "csv", output_dir: Optional[Path] = None
) -> ExportResult:
    return _export_data(
        query="SELECT * FROM domain_enrichment",
        fmt=fmt,
        output_dir=output_dir,
        prefix="domains",
        job_type="export_domains",
        label="Domain",
        stale_extractor=lambda row: (row.get("domain"), row.get("last_observed")),
    )


def export_rules(fmt: str = "csv", output_dir: Optional[Path] = None) -> ExportResult:
    return _export_data(
        query=RULE_EXPORT_QUERY,
        fmt=fmt,
        output_dir=output_dir,
        prefix="rules",
        job_type="export_rules",
        label="Rule",
        stale_extractor=_rule_timestamp,
    )


def export_usage(fmt: str = "csv", output_dir: Optional[Path] = None) -> ExportResult:
    return _export_data(
        query="SELECT * FROM persona_usage ORDER BY created_at DESC",
        fmt=fmt,
        output_dir=output_dir,
        prefix="persona_usage",
        job_type="export_usage",
        label="Usage event",
        stale_extractor=_usage_timestamp,
    )


def _export_data(
    query: str,
    fmt: str,
    output_dir: Optional[Path],
    prefix: str,
    job_type: str,
    label: str,
    stale_extractor: Callable[[dict], Tuple[str, Optional[str]]],
) -> ExportResult:
    fmt = fmt.lower()
    if fmt not in {"csv", "parquet"}:
        raise ValueError("Format must be 'csv' or 'parquet'")

    job_id = jobs.start_job(job_type, {"format": fmt, "prefix": prefix})
    try:
        with storage.get_connection() as conn:
            df = conn.execute(query).df()
    except Exception as exc:  # pragma: no cover
        jobs.complete_job(job_id, "failed", {"error": str(exc)})
        raise

    if df.empty:
        jobs.complete_job(job_id, "failed", {"error": "No records to export"})
        raise ValueError("No records available to export.")

    stale_notes: List[str] = []
    warnings: List[Optional[str]] = []
    for _, row in df.iterrows():
        identifier, timestamp = stale_extractor(row)
        warning = freshness.get_warning(timestamp, label=label)
        warnings.append(warning)
        stale, days = freshness.is_stale(timestamp)
        if stale:
            suffix = "unknown age" if days is None else f"{days}d"
            stale_notes.append(f"{identifier}: {suffix}")

    df["stale_warning"] = warnings

    output_path = _write_dataframe(df, fmt, output_dir, prefix)
    footnote = _write_footnote(output_path, stale_notes, job_id)

    jobs.complete_job(
        job_id,
        "success",
        {"format": fmt, "path": str(output_path), "records": len(df)},
    )
    return ExportResult(path=output_path, job_id=job_id, footnote_path=footnote)


def _rule_timestamp(row) -> Tuple[str, Optional[str]]:
    if row.get("synced_at"):
        return f"{row.get('vendor')}:{row.get('rule_id')}", row.get("synced_at")
    metadata_raw = row.get("metadata")
    timestamp = None
    if metadata_raw:
        try:
            metadata = json.loads(metadata_raw)
            timestamp = metadata.get("synced_at")
        except json.JSONDecodeError:
            timestamp = None
    identifier = f"{row.get('vendor')}:{row.get('rule_id')}"
    return identifier, timestamp


def _usage_timestamp(row) -> Tuple[str, Optional[str]]:
    identifier = f"{row.get('persona_id')}:{row.get('domain')}"
    return identifier, row.get("created_at")


def _write_dataframe(
    df: pd.DataFrame, fmt: str, output_dir: Optional[Path], prefix: str
) -> Path:
    export_dir = Path(output_dir) if output_dir else EXPORT_DIR
    export_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{prefix}-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.{fmt}"
    path = export_dir / filename
    if fmt == "csv":
        df.to_csv(path, index=False)
    else:
        df.to_parquet(path, index=False)
    return path


def _write_footnote(path: Path, notes: List[str], job_id: str) -> Optional[Path]:
    if not notes:
        return None
    footnote_path = path.with_suffix(path.suffix + ".notes.txt")
    content = ["Stale items detected:"]
    content.extend(f"- {item}" for item in notes)
    content.append(f"(Job {job_id})")
    footnote_path.write_text("\n".join(content))
    return footnote_path


def generate_radar_summary(
    domain: str,
    persona_id: str = "ae",
    *,
    output_dir: Optional[Path] = None,
    template_path: Optional[Path] = None,
    create_pdf: bool = False,
) -> RadarSummaryResult:
    template_file = template_path or RADAR_TEMPLATE_PATH
    job_id = jobs.start_job(
        "radar_summary",
        {
            "domain": domain,
            "persona_id": persona_id,
            "template": str(template_file),
            "create_pdf": create_pdf,
        },
    )
    try:
        record = storage.fetch_domain(domain)
        if not record:
            raise ValueError(f"No enrichment record found for {domain}")
        persona_payload = persona_service.generate_persona_view(
            persona_id, domain
        )
        context = _build_radar_context(record, persona_payload, job_id)
        markdown = _render_template(template_file, context)

        reports_dir = Path(output_dir) if output_dir else REPORTS_DIR
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        markdown_path = reports_dir / f"{domain}-radar-{timestamp}.md"
        markdown_path.write_text(markdown, encoding="utf-8")

        pdf_path = None
        if create_pdf:
            pdf_path = markdown_path.with_suffix(".pdf")
            _markdown_to_pdf(markdown, pdf_path)

        jobs.complete_job(
            job_id,
            "success",
            {
                "markdown_path": str(markdown_path),
                "pdf_path": str(pdf_path) if pdf_path else None,
                "domain": domain,
            },
        )
        return RadarSummaryResult(
            markdown_path=markdown_path,
            pdf_path=pdf_path,
            preview=markdown,
            job_id=job_id,
        )
    except Exception as exc:
        jobs.complete_job(job_id, "failed", {"error": str(exc)})
        raise


def generate_rule_brief(
    domain: str,
    rule_a: Tuple[str, str],
    rule_b: Tuple[str, str],
    *,
    output_dir: Optional[Path] = None,
    template_path: Optional[Path] = None,
    create_pdf: bool = False,
) -> RuleBriefResult:
    domain_slug = _slugify_domain(domain)
    template_file = template_path or RULE_BRIEF_TEMPLATE_PATH
    job_id = jobs.start_job(
        "rule_brief",
        {
            "domain": domain_slug,
            "rule_a": ":".join(rule_a),
            "rule_b": ":".join(rule_b),
            "create_pdf": create_pdf,
        },
    )
    try:
        record_a = _fetch_rule(rule_a)
        record_b = _fetch_rule(rule_b)
        brief_context = _build_rule_brief_context(
            domain_slug, record_a, record_b, job_id
        )
        markdown = _render_template(template_file, brief_context)

        reports_dir = Path(output_dir) if output_dir else REPORTS_DIR
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        markdown_path = reports_dir / f"{domain_slug}-rule-brief-{timestamp}.md"
        markdown_path.write_text(markdown, encoding="utf-8")

        pdf_path = None
        if create_pdf:
            pdf_path = markdown_path.with_suffix(".pdf")
            _markdown_to_pdf(markdown, pdf_path)

        jobs.complete_job(
            job_id,
            "success",
            {
                "markdown_path": str(markdown_path),
                "pdf_path": str(pdf_path) if pdf_path else None,
                "domain": domain_slug,
            },
        )
        return RuleBriefResult(
            markdown_path=markdown_path,
            pdf_path=pdf_path,
            preview=markdown,
            job_id=job_id,
        )
    except Exception as exc:
        jobs.complete_job(job_id, "failed", {"error": str(exc)})
        raise


def _render_template(path: Path, context: Dict) -> str:
    if not path.exists():
        raise FileNotFoundError(f"Template not found: {path}")
    env = Environment(
        loader=FileSystemLoader(str(path.parent)),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    try:
        template = env.get_template(path.name)
    except TemplateNotFound as exc:
        raise FileNotFoundError(f"Unable to load template {path}") from exc
    output = template.render(**context).strip()
    return output + "\n"


def _build_radar_context(
    record: Dict[str, str],
    persona_payload: Dict[str, Dict],
    job_id: str,
) -> Dict:
    generated_at = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
    last_observed = _format_timestamp(record.get("last_observed"))

    scores = persona_payload.get("scores", {})
    hooks = persona_payload.get("hooks", [])

    risk_signals = []
    for key, label in (
        ("config_drift", "Config Drift"),
        ("downtime_risk", "Downtime Risk"),
        ("attack_surface", "Attack Surface"),
    ):
        value = float(scores.get(key, 0))
        summary = _summarize_signal(label, value)
        risk_signals.append(
            {
                "id": key,
                "label": label,
                "value": f"{value:.2f}",
                "summary": summary,
            }
        )

    next_steps: List[str] = []
    for hook in hooks:
        title = hook.get("title", "Follow up")
        next_steps.append(
            f'Frame outreach around "{title}" and reference the hook trigger ({hook.get("score_reason", "threshold met")}).'
        )
    if persona_payload.get("stale_warning"):
        next_steps.append("Surface the stale data warning and schedule a fresh enrichment run.")
    next_steps.append("Attach the generated Markdown/PDF to your GTM workspace or email thread.")

    freshness_note = (
        persona_payload.get("stale_warning")
        or freshness.get_warning(record.get("last_observed"), label="Radar data")
        or "Radar data is within the freshness threshold."
    )

    return {
        "domain": record.get("domain"),
        "generated_at": generated_at,
        "persona": persona_payload.get("persona", {}),
        "stack": {
            "detected_waf": record.get("detected_waf", "unknown"),
            "detected_cdn": record.get("detected_cdn", "unknown"),
            "last_observed": last_observed,
        },
        "story_prompt": persona_payload.get("story_prompt", ""),
        "priority_index": f"{scores.get('priority_index', 0):.2f}",
        "risk_signals": risk_signals,
        "hooks": hooks,
        "next_steps": next_steps,
        "freshness_note": freshness_note,
        "job_id": job_id,
    }


def _summarize_signal(label: str, value: float) -> str:
    if value >= 0.75:
        severity = "High"
        action = "prioritize immediate follow-up"
    elif value >= 0.5:
        severity = "Medium"
        action = "prep an enablement note"
    else:
        severity = "Low"
        action = "monitor while sharing context"
    return f"{severity} {label.lower()} pressure - {action}."


def _format_timestamp(value: Optional[object]) -> str:
    if not value:
        return "unknown"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _markdown_to_pdf(markdown_text: str, destination: Path) -> None:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)

    for raw_line in markdown_text.splitlines():
        line = raw_line.strip()
        if line.startswith("# "):
            pdf.set_font("Helvetica", "B", 16)
            pdf.multi_cell(0, 8, line[2:])
            pdf.ln(2)
            pdf.set_font("Helvetica", size=11)
        elif line.startswith("## "):
            pdf.set_font("Helvetica", "B", 13)
            pdf.multi_cell(0, 7, line[3:])
            pdf.ln(1)
            pdf.set_font("Helvetica", size=11)
        else:
            pdf.multi_cell(0, 6, line or " ")
    destination.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(destination))


def _build_rule_brief_context(
    domain: str,
    rule_a: Dict[str, str],
    rule_b: Dict[str, str],
    export_job_id: str,
) -> Dict:
    generated_at = datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
    rule_sync_job = _latest_rule_sync_job()

    normalized_a = _normalize_rule_entry(rule_a)
    normalized_b = _normalize_rule_entry(rule_b)

    deltas = {
        "pattern": _describe_delta(
            normalized_a["detection_pattern"],
            normalized_b["detection_pattern"],
            "detection pattern",
        ),
        "mitigation": _describe_delta(
            normalized_a["mitigation"], normalized_b["mitigation"], "mitigation"
        ),
        "severity": _describe_delta(
            normalized_a["severity"], normalized_b["severity"], "severity"
        ),
        "freshness": _describe_delta(
            normalized_a["freshness"], normalized_b["freshness"], "freshness"
        ),
    }
    freshness_alert = _freshness_alert(
        normalized_a["freshness_is_stale"], normalized_b["freshness_is_stale"]
    )
    comparison_summary = _rule_summary(normalized_a, normalized_b, domain)
    recommendations = _build_rule_recommendations(
        normalized_a, normalized_b, freshness_alert
    )

    note_authors = sorted(
        {
            note["author"]
            for note in normalized_a["notes"] + normalized_b["notes"]
            if note.get("author")
        }
    )

    return {
        "domain": domain,
        "generated_at": generated_at,
        "rule_sync_job_id": rule_sync_job,
        "comparison_summary": comparison_summary,
        "rule_a": normalized_a,
        "rule_b": normalized_b,
        "deltas": deltas,
        "freshness_alert": freshness_alert,
        "recommendations": recommendations,
        "note_authors": note_authors,
        "export_job_id": export_job_id,
    }


def _fetch_rule(identifier: Tuple[str, str]) -> Dict[str, str]:
    vendor, rule_id = identifier
    with storage.get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                vendor, rule_id, name, category, detection_pattern, mitigation,
                severity, metadata, source, synced_at
            FROM managed_rules
            WHERE vendor = ? AND rule_id = ?
            """,
            [vendor, rule_id],
        ).fetchall()
        columns = [desc[0] for desc in conn.description]
    if not rows:
        raise ValueError(f"No rule found for {vendor}:{rule_id}")
    return dict(zip(columns, rows[0]))


def _normalize_rule_entry(record: Dict[str, str]) -> Dict[str, str]:
    synced_at = record.get("synced_at") or _metadata_synced_at(record.get("metadata"))
    synced_dt = _parse_datetime(synced_at)
    synced_label = (
        synced_dt.strftime("%Y-%m-%d %H:%M")
        if synced_dt
        else (synced_at or "unknown")
    )
    stale, days = freshness.is_stale(synced_dt)
    freshness_text = (
        f"{'Stale' if stale else 'Fresh'} - synced {synced_label}"
        + (f" ({days}d old)" if days else "")
    )
    notes_raw = rules_service.list_notes(record.get("vendor", ""), record.get("rule_id", ""))
    notes = [
        {
            "author": note.get("author", "unknown"),
            "timestamp": _format_note_timestamp(note.get("created_at")),
            "content": note.get("content", "").strip(),
        }
        for note in notes_raw
    ]
    return {
        "vendor": record.get("vendor"),
        "rule_id": record.get("rule_id"),
        "name": record.get("name"),
        "category": record.get("category"),
        "detection_pattern": record.get("detection_pattern") or "",
        "mitigation": record.get("mitigation") or "",
        "severity": record.get("severity") or "unknown",
        "source": record.get("source") or "unknown",
        "synced_at": synced_at or "unknown",
        "freshness": freshness_text,
        "freshness_is_stale": stale,
        "notes": notes,
    }


def _metadata_synced_at(metadata_raw: Optional[str]) -> Optional[str]:
    if not metadata_raw:
        return None
    if isinstance(metadata_raw, dict):
        return metadata_raw.get("synced_at")
    try:
        metadata = json.loads(metadata_raw)
    except (json.JSONDecodeError, TypeError):
        return None
    return metadata.get("synced_at")


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _describe_delta(value_a: str, value_b: str, label: str) -> str:
    if value_a == value_b:
        return f"Both rules share the same {label}."
    return f"{label.title()} differs: '{value_a or 'n/a'}' vs '{value_b or 'n/a'}'."


def _freshness_alert(stale_a: bool, stale_b: bool) -> str:
    if stale_a and stale_b:
        return "Both rules are stale; rerun rule sync before briefing leadership."
    if stale_a:
        return "Rule A is stale compared to Rule B; highlight refresh priority."
    if stale_b:
        return "Rule B is stale compared to Rule A; highlight refresh priority."
    return "Both rules are within the freshness threshold."


def _rule_summary(rule_a: Dict[str, str], rule_b: Dict[str, str], domain: str) -> str:
    return (
        f"For {domain}, compare {rule_a['vendor']} {rule_a['rule_id']} ({rule_a['name']}) "
        f"with {rule_b['vendor']} {rule_b['rule_id']} ({rule_b['name']}) to explain severity "
        f"deltas ({rule_a['severity']} vs {rule_b['severity']}) and freshness ({rule_a['freshness']} / {rule_b['freshness']})."
    )


def _build_rule_recommendations(
    rule_a: Dict[str, str],
    rule_b: Dict[str, str],
    freshness_alert: str,
) -> List[str]:
    recs = [
        f"Lead with detection pattern delta ({rule_a['detection_pattern'] or 'n/a'} vs {rule_b['detection_pattern'] or 'n/a'}) to frame coverage gaps.",
        f"Call out mitigation contrast ({rule_a['mitigation'] or 'n/a'} vs {rule_b['mitigation'] or 'n/a'}) and map to executive risk themes.",
        freshness_alert,
    ]
    if rule_a["severity"] != rule_b["severity"]:
        recs.append(
            f"Tie severity difference ({rule_a['severity']} vs {rule_b['severity']}) to renewal or migration decision points."
        )
    return recs


def _format_note_timestamp(value: Optional[str]) -> str:
    if not value:
        return "unknown"
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return str(value)
    return dt.strftime("%Y-%m-%d %H:%M")


def _latest_rule_sync_job() -> str:
    record = jobs.latest_job("rule_sync")
    if not record:
        return "unknown"
    return record.get("job_id", "unknown")


def _slugify_domain(domain: str) -> str:
    if not domain or not domain.strip():
        raise ValueError("Domain is required for rule brief export")
    cleaned = re.sub(r"[^a-zA-Z0-9.-]", "-", domain.strip().lower())
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-")
    return cleaned or "domain"


