from datetime import datetime, timedelta, timezone

from backend.services import freshness


def test_is_stale_false():
    recent = datetime.now(timezone.utc) - timedelta(days=5)
    stale, days = freshness.is_stale(recent, threshold_days=30)
    assert stale is False
    assert days == 5


def test_is_stale_true_for_old_timestamp():
    old = datetime.now(timezone.utc) - timedelta(days=45)
    stale, days = freshness.is_stale(old, threshold_days=30)
    assert stale is True
    assert days >= 45


def test_get_warning_unknown_timestamp():
    warning = freshness.get_warning(None, label="Rule")
    assert warning == "Rule freshness unknown - re-run enrichment"

