import pytest
import typer

from scripts.rule_sync import run as rule_sync


def test_validate_rule_success():
    rule = {
        "vendor": "cloudflare",
        "rule_id": "1",
        "name": "rule",
        "category": "sql",
        "detection_pattern": "contains(sql)",
        "mitigation": "block",
        "severity": "high",
        "metadata": "{}",
    "source": "cloudflare_export",
    "synced_at": "2025-01-01T00:00:00Z",
    }
    assert rule_sync._validate_rule(rule) == rule


def test_validate_rule_missing_field():
    rule = {
        "vendor": "cloudflare",
        "rule_id": "1",
        "name": "rule",
    }
    with pytest.raises(typer.BadParameter):
        rule_sync._validate_rule(rule)


