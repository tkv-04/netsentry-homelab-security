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


def test_apply_caddy_command_requires_explicit_approval_option():
    result = CliRunner().invoke(app, ["apply-caddy", "--help"])
    assert result.exit_code == 0
    assert "--approve" in result.output
    assert "--caddyfile" in result.output
    assert "--audit-log" in result.output
    assert "--ca-cert" in result.output

def test_plan_prints_hash_for_current_caddy_and_routes(tmp_path, monkeypatch):
    from netsentry import inspection
    from netsentry.execution import approval_digest, sha256_bytes

    policy_path = tmp_path / "policies.json"
    policy_path.write_text('{"version":1,"apps":[{"name":"App","exposure":"lan","domains":["app.home.arpa"],"upstreams":["127.0.0.1:9000"]}]}', encoding="utf-8")
    caddyfile = tmp_path / "Caddyfile"
    raw = b"old.home.arpa {\n}\n"
    caddyfile.write_bytes(raw)
    monkeypatch.setattr(inspection, "inspect_docker_ports", lambda: {"available": True, "containers": []})
    monkeypatch.setattr(inspection, "inspect_caddy_config", lambda _path: {"available": True, "output": raw.decode()})
    monkeypatch.setattr(inspection, "inspect_firewall", lambda: {"available": True, "results": []})
    monkeypatch.setattr(inspection, "inspect_ports", lambda: {"output": ""})
    result = CliRunner().invoke(app, ["plan", str(policy_path), "--caddyfile", str(caddyfile), "--json"])
    assert result.exit_code == 0, result.output
    report = __import__("json").loads(result.output)
    assert report["approval_sha256"] == approval_digest(sha256_bytes(raw), report["proposed_routes"])
    assert report["base_sha256"] == sha256_bytes(raw)

def test_validate_plan_command_help_is_available():
    result = CliRunner().invoke(app, ["validate-plan", "--help"])
    assert result.exit_code == 0
    assert "never reload or replace" in " ".join(result.output.split())
