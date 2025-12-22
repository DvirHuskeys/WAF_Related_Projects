from pathlib import Path

import pytest

from scripts import domain_enrich


def test_is_valid_domain():
    assert domain_enrich._is_valid_domain("example.com")
    assert not domain_enrich._is_valid_domain("not a domain")
    assert not domain_enrich._is_valid_domain("bad_domain")


def test_load_domains(tmp_path: Path):
    csv_path = tmp_path / "domains.csv"
    csv_path.write_text("domain\nexample.com\nexample.com\nbad-domain\n")
    domains = domain_enrich._load_domains(csv_path)
    assert domains == ["example.com", "example.com", "bad-domain"]

    with pytest.raises(ValueError):
        bad_csv = tmp_path / "bad.csv"
        bad_csv.write_text("url\nexample.com\n")
        domain_enrich._load_domains(bad_csv)

