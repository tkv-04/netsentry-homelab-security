from datetime import datetime, timezone

from typer.testing import CliRunner

from netsentry import cli
from netsentry.cli import app


def test_version():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "NetSentry 0.1.0" in result.output


def test_help_is_available():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "check-https" in result.output


def test_gui_escapes_host_in_form():
    from netsentry.gui import _page

    page = _page('<script>alert(1)</script>')
    assert '<script>alert(1)</script>' not in page
    assert '&lt;script&gt;' in page


def test_check_list_reports_each_target(tmp_path, monkeypatch):

    from netsentry.checks import CertificateResult

    target_file = tmp_path / "targets.txt"
    target_file.write_text("one.example\ntwo.example\n", encoding="utf-8")

    def fake_check(host, port):
        if host == "two.example":
            raise OSError("connection refused")
        return CertificateResult(host, port, "CN=one.example", "CN=issuer",
                                 datetime(2030, 1, 1, tzinfo=timezone.utc), 30)

    monkeypatch.setattr(cli, "check_certificate", fake_check)
    result = CliRunner().invoke(app, ["check-list", str(target_file)])
    assert result.exit_code == 1
    assert "OK one.example:443" in result.output
    assert "FAIL two.example:443" in result.output




def test_inspect_commands_are_registered():
    result = CliRunner().invoke(app, ["inspect", "--help"])
    assert result.exit_code == 0
    assert "docker-ports" in result.output
    assert "firewall" in result.output
