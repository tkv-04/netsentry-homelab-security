from datetime import datetime, timezone

import pytest

from netsentry.checks import CertificateResult, check_certificate


@pytest.mark.parametrize("host,port,timeout", [("", 443, 5), ("example.com", 0, 5), ("a", 443, 0)])
def test_rejects_invalid_parameters(host, port, timeout):
    with pytest.raises(ValueError):
        check_certificate(host, port, timeout)


def test_certificate_result_shape():
    result = CertificateResult("example.com", 443, "CN=example.com", "CN=Issuer",
                               datetime.now(timezone.utc), 30)
    assert result.host == "example.com"
    assert result.days_remaining == 30


def test_load_targets_skips_comments_and_blank_lines(tmp_path):
    from netsentry.checks import load_targets

    target_file = tmp_path / "targets.txt"
    target_file.write_text("# homelab\nha.home.arpa\n\nnas.home.arpa\n", encoding="utf-8")
    assert load_targets(target_file) == ["ha.home.arpa", "nas.home.arpa"]


def test_load_targets_enforces_batch_limit(tmp_path):
    from netsentry.checks import load_targets

    target_file = tmp_path / "targets.txt"
    target_file.write_text("one\ntwo\nthree\n", encoding="utf-8")
    with pytest.raises(ValueError, match="at most 2"):
        load_targets(target_file, limit=2)
