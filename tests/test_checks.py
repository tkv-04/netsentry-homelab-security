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


def test_caddy_inspection_redacts_secret_lines(tmp_path):
    from netsentry.inspection import inspect_caddy_config

    config = tmp_path / "Caddyfile"
    config.write_text("ha.home.arpa {\n reverse_proxy localhost:8123\n header Authorization secret-value\n}\n")
    report = inspect_caddy_config(config)
    assert "reverse_proxy localhost:8123" in report["output"]
    assert "secret-value" not in report["output"]
    assert "[REDACTED]" in report["output"]


def test_inspection_commands_do_not_use_a_shell(monkeypatch):
    import subprocess

    from netsentry.inspection import _run

    observed = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout="listening", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    report = _run(["ss", "-lntup"])
    assert report["output"] == "listening"
    assert observed["shell"] is not True
    assert observed["timeout"] == 10
