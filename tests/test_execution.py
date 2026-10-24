from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from netsentry.execution import (
    ExecutionError,
    apply_caddy_update,
    approval_digest,
    sha256_bytes,
)

ROUTES = [{"domain": "app.home.arpa", "block": "https://app.home.arpa {\n    tls internal\n    reverse_proxy 127.0.0.1:9000\n}"}]


def _setup(tmp_path):
    config = tmp_path / "Caddyfile"
    original = b"https://old.home.arpa {\n    tls internal\n}\n"
    config.write_bytes(original)
    audit = tmp_path / "state" / "audit.jsonl"
    base_hash = sha256_bytes(original)
    digest = approval_digest(base_hash, ROUTES)
    return config, audit, original, base_hash, digest


def _runner(fail_validate=False, fail_reload=False):
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        failed = (command[1] == "validate" and fail_validate) or (command[1] == "reload" and fail_reload)
        return subprocess.CompletedProcess(command, 1 if failed else 0, "", "simulated failure" if failed else "")
    return run, calls


def test_controlled_caddy_update_validates_backs_up_and_audits(tmp_path):
    config, audit, original, base_hash, digest = _setup(tmp_path)
    runner, calls = _runner()
    result = apply_caddy_update(config, ROUTES, base_hash, digest, ["https://app.home.arpa"], audit,
                                runner=runner, checker=lambda _url: 200)
    assert result["status"] == "success"
    assert (config.parent / result["backup"]).read_bytes() == original
    assert "reverse_proxy 127.0.0.1:9000" in config.read_text()
    assert [call[1] for call in calls] == ["validate", "reload"]
    assert json.loads(audit.read_text().splitlines()[0])["status"] == "success"


def test_invalid_caddy_validation_never_replaces_file(tmp_path):
    config, audit, original, base_hash, digest = _setup(tmp_path)
    runner, calls = _runner(fail_validate=True)
    with pytest.raises(ExecutionError, match="validation failed"):
        apply_caddy_update(config, ROUTES, base_hash, digest, ["https://app.home.arpa"], audit,
                           runner=runner, checker=lambda _url: 200)
    assert config.read_bytes() == original
    assert len(calls) == 1
    assert json.loads(audit.read_text().splitlines()[0])["status"] == "failed"


def test_failed_connectivity_check_rolls_back_and_reloads_original(tmp_path):
    config, audit, original, base_hash, digest = _setup(tmp_path)
    runner, calls = _runner()
    with pytest.raises(ExecutionError, match="connectivity check failed"):
        apply_caddy_update(config, ROUTES, base_hash, digest, ["https://app.home.arpa"], audit,
                           runner=runner, checker=lambda _url: 503)
    assert config.read_bytes() == original
    assert [call[1] for call in calls] == ["validate", "reload", "reload"]
    assert json.loads(audit.read_text().splitlines()[0])["rollback_reload"] == "success"


def test_stale_or_unapproved_plan_is_rejected_without_writing(tmp_path):
    config, audit, original, base_hash, _digest = _setup(tmp_path)
    with pytest.raises(ExecutionError, match="approval hash"):
        apply_caddy_update(config, ROUTES, base_hash, "bad", ["https://app.home.arpa"], audit)
    assert config.read_bytes() == original
    assert not audit.exists()


def test_modified_caddyfile_invalidates_approval(tmp_path):
    config, audit, original, base_hash, digest = _setup(tmp_path)
    config.write_bytes(original + b"# edited\n")
    with pytest.raises(ExecutionError, match="changed since"):
        apply_caddy_update(config, ROUTES, base_hash, digest, ["https://app.home.arpa"], audit)
    assert not audit.exists()


def test_rejects_http_connectivity_check(tmp_path):
    config, audit, _original, base_hash, digest = _setup(tmp_path)
    with pytest.raises(ExecutionError, match="must use an https"):
        apply_caddy_update(config, ROUTES, base_hash, digest, ["http://app.home.arpa"], audit)



def test_execution_refuses_plan_with_blockers():
    from netsentry.execution import ExecutionError, ensure_plan_executable

    plan = {"summary": {"blocked": 1}, "proposed_routes": [{"domain": "app.home.arpa", "block": "x"}]}
    with pytest.raises(ExecutionError, match="resolve them"):
        ensure_plan_executable(plan)


def test_execution_allows_unblocked_route_plan():
    from netsentry.execution import ensure_plan_executable

    ensure_plan_executable({"summary": {"blocked": 0},
                            "proposed_routes": [{"domain": "app.home.arpa", "block": "x"}]})


def test_validate_caddy_proposal_checks_temp_file_and_preserves_original(tmp_path):
    from netsentry.execution import validate_caddy_proposal

    config, _audit, original, base_hash, _digest = _setup(tmp_path)
    observed = {}
    def runner(command, **kwargs):
        staged = Path(command[3])
        observed["staged"] = staged
        observed["staged_content"] = staged.read_bytes()
        observed["original_content"] = config.read_bytes()
        return subprocess.CompletedProcess(command, 0, "valid", "")

    result = validate_caddy_proposal(config, ROUTES, base_hash, runner=runner)
    assert result["valid"] is True
    assert config.read_bytes() == original
    assert observed["original_content"] == original
    assert b"reverse_proxy 127.0.0.1:9000" in observed["staged_content"]
    assert not observed["staged"].exists()
    assert list(tmp_path.glob("*.bak")) == []


def test_validate_caddy_proposal_validation_failure_preserves_original(tmp_path):
    from netsentry.execution import validate_caddy_proposal

    config, _audit, original, base_hash, _digest = _setup(tmp_path)
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, "", "bad Caddy syntax")

    with pytest.raises(ExecutionError, match="proposed Caddyfile is invalid"):
        validate_caddy_proposal(config, ROUTES, base_hash, runner=runner)
    assert config.read_bytes() == original
    assert list(tmp_path.glob(".*.tmp")) == []
