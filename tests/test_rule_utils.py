from datetime import timezone

from ui.components.rule_utils import parse_rule_synced_at


def test_parse_rule_synced_at_valid_iso():
    parsed = parse_rule_synced_at("2025-01-05T12:30:00Z")
    assert parsed is not None
    assert parsed.year == 2025
    assert parsed.tzinfo == timezone.utc


def test_parse_rule_synced_at_missing_field():
    metadata = '{"other":"value"}'
    assert parse_rule_synced_at(None, metadata) is None


def test_parse_rule_synced_at_bad_json():
    assert parse_rule_synced_at(None, "not-json") is None

