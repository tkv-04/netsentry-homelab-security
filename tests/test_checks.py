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


def test_docker_report_formats_container_names_and_published_ports():
    from netsentry.inspection import format_report

    report = {
        "available": True,
        "containers": [
            {"Names": "homeassistant", "Image": "homeassistant:stable", "Ports": "0.0.0.0:8123->8123/tcp"},
            {"Names": "dns", "Ports": "(no published ports)"},
        ],
    }
    output = format_report(report)
    assert "homeassistant [homeassistant:stable]: 0.0.0.0:8123->8123/tcp" in output
    assert "dns [image unknown]: (no published ports)" in output


def test_docker_report_handles_no_running_containers():
    from netsentry.inspection import format_report

    assert format_report({"available": True, "containers": []}) == "No running containers."


def test_policy_requires_a_supported_exposure(tmp_path):
    from netsentry.policy import load_policy

    path = tmp_path / "policy.json"
    path.write_text('{"version":1,"apps":[{"name":"x","exposure":"guess"}]}', encoding="utf-8")
    with pytest.raises(ValueError, match="exposure"):
        load_policy(path)


def test_docker_bindings_parse_wildcard_and_lan_addresses():
    from netsentry.audit import docker_bindings

    bindings = docker_bindings({"containers": [
        {"Names": "jackett", "Image": "example/jackett", "Ports": "0.0.0.0:9117->9117/tcp, [::]:9117->9117/tcp"},
        {"Names": "adguard", "Ports": "192.168.0.5:3000->3000/tcp"},
    ]})
    assert [(item["container"], item["host_ip"], item["host_port"]) for item in bindings] == [
        ("jackett", "0.0.0.0", 9117), ("jackett", "::", 9117), ("adguard", "192.168.0.5", 3000)
    ]


def test_proxy_only_policy_flags_a_wildcard_docker_publication():
    from netsentry.audit import audit_policy

    findings = audit_policy(
        {"apps": [{"name": "Jackett", "exposure": "proxy-only", "container_names": ["jackett"],
                   "domains": ["jackett.home.arpa"], "upstreams": ["jackett:9117"]}]},
        {"available": True, "containers": [{"Names": "jackett", "Ports": "0.0.0.0:9117->9117/tcp"}]},
        {"available": True, "output": "jackett.home.arpa { reverse_proxy jackett:9117 }"},
        {"results": []}, {"output": ""},
    )
    assert any(item["code"] == "proxy-only-published" and item["severity"] == "mismatch" for item in findings)


def test_lan_policy_flags_unrestricted_ufw_rule():
    from netsentry.audit import audit_policy

    findings = audit_policy(
        {"apps": [{"name": "GUI", "exposure": "lan", "host_ports": [8081],
                   "allowed_sources": ["192.168.0.0/24"]}]},
        {"available": True, "containers": []}, {"available": False},
        {"results": [{"command": ["ufw", "status", "verbose"],
                      "output": "8081 ALLOW IN Anywhere\n8081 (v6) ALLOW IN Anywhere (v6)"}]},
        {"output": "tcp LISTEN 0 128 0.0.0.0:8081 0.0.0.0:*"},
    )
    assert any(item["code"] == "lan-ufw-anywhere" and item["severity"] == "mismatch" for item in findings)


def test_audit_scopes_container_policy_to_selected_container_ports():
    from netsentry.audit import audit_policy

    policy = {"apps": [{"name": "DNS", "exposure": "lan", "container_names": ["adguardhome"],
                        "container_ports": [53], "allowed_sources": ["192.168.0.0/24"]}]}
    docker = {"available": True, "containers": [{
        "Names": "adguardhome", "Ports": "192.168.0.5:53->53/tcp, 192.168.0.5:3000->3000/tcp"
    }]}
    findings = audit_policy(policy, docker, {"available": False}, {"results": []}, {"output": ""})
    unassigned = [item for item in findings if item["code"] == "unassigned-published-container"]
    assert len(unassigned) == 1
    assert "3000" in unassigned[0]["message"]




def test_policy_rejects_invalid_allowed_source_network(tmp_path):
    from netsentry.policy import load_policy

    path = tmp_path / "policy.json"
    path.write_text('{"version":1,"apps":[{"name":"x","exposure":"lan","allowed_sources":["home"]}]}', encoding="utf-8")
    with pytest.raises(ValueError, match="CIDR"):
        load_policy(path)


def test_lan_policy_can_also_require_a_caddy_route():
    from netsentry.audit import audit_policy

    findings = audit_policy(
        {"apps": [{"name": "AdGuard UI", "exposure": "lan", "container_names": ["adguardhome"],
                   "container_ports": [3000], "domains": ["adguard.home.arpa"],
                   "upstreams": ["192.168.0.5:3000"], "allowed_sources": ["192.168.0.0/24"]}]},
        {"available": True, "containers": [{"Names": "adguardhome", "Ports": "192.168.0.5:3000->3000/tcp"}]},
        {"available": True, "output": ""}, {"results": []}, {"output": ""},
    )
    assert any(item["code"] == "caddy-route-missing" for item in findings)
    assert any(item["code"] == "caddy-upstream-missing" for item in findings)
