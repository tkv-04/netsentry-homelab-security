"""Narrow, approval-gated Caddy configuration transaction helpers."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


class ExecutionError(RuntimeError):
    """A guarded configuration update was refused or rolled back."""

def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

def approval_digest(base_sha256: str, routes: list[dict[str, str]]) -> str:
    canonical = json.dumps(routes, sort_keys=True, separators=(",", ":"))
    return sha256_bytes(f"netsentry-caddy-v1\n{base_sha256}\n{canonical}".encode())

def _validate_check_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ExecutionError("connectivity checks must use an https:// URL without embedded credentials")

def _check_https(url: str, timeout: float = 5.0, ca_cert: Path | None = None) -> int:
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": "NetSentry/0.1"})
    context = ssl.create_default_context(cafile=str(ca_cert) if ca_cert else None)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)

def _record(audit_log: Path, record: dict[str, object]) -> None:
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    with audit_log.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")

def apply_caddy_update(caddyfile: Path, routes: list[dict[str, str]], expected_base_sha256: str,
                       approved_sha256: str, check_urls: list[str], audit_log: Path, *,
                       runner: Callable[..., subprocess.CompletedProcess] | None = None,
                       checker: Callable[[str], int] | None = None) -> dict[str, object]:
    """Validate, back up, atomically install, reload and health-check an approved Caddy addition."""
    run, check = runner or subprocess.run, checker or _check_https
    path = caddyfile.expanduser()
    if path.is_symlink() or not path.is_file():
        raise ExecutionError("Caddyfile must be an existing regular file, not a symlink")
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ExecutionError("Caddy execution requires root; rerun explicitly with sudo after reviewing the plan")
    if not routes or any(set(route) != {"domain", "block"} for route in routes):
        raise ExecutionError("only planner-generated Caddy route additions are supported")
    if not check_urls:
        raise ExecutionError("at least one HTTPS connectivity check URL is required")
    for url in check_urls:
        _validate_check_url(url)
    original = path.read_bytes()
    base_hash = sha256_bytes(original)
    if base_hash != expected_base_sha256:
        raise ExecutionError("Caddyfile changed since planning; create and review a fresh plan")
    if approval_digest(base_hash, routes) != approved_sha256:
        raise ExecutionError("approval hash does not match this Caddyfile and proposed routes")
    try:
        original_text = original.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ExecutionError("Caddyfile must be UTF-8") from error
    separator = "" if not original_text or original_text.endswith("\n") else "\n"
    updated = (original_text + separator + "\n".join(route["block"] for route in routes) + "\n").encode()
    path = path.resolve(strict=True)
    metadata = path.stat()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_name(f"{path.name}.netsentry-{timestamp}.bak")
    temp_name: str | None = None
    record: dict[str, object] = {"timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": "caddy-route-addition", "caddyfile": str(path), "base_sha256": base_hash,
        "proposed_sha256": sha256_bytes(updated), "routes": [route["domain"] for route in routes], "status": "started"}
    try:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.netsentry-", suffix=".tmp", dir=path.parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(updated); stream.flush(); os.fsync(stream.fileno())
        shutil.copystat(path, temp_name)
        if hasattr(os, "chown") and os.name == "posix":
            os.chown(temp_name, metadata.st_uid, metadata.st_gid)
        validation = run(["caddy", "validate", "--config", temp_name, "--adapter", "caddyfile"],
                         capture_output=True, text=True, timeout=30, check=False, shell=False)
        if validation.returncode != 0:
            raise ExecutionError("Caddy validation failed: " + (validation.stderr or validation.stdout).strip())
        if sha256_bytes(path.read_bytes()) != base_hash:
            raise ExecutionError("Caddyfile changed while validating; no replacement was made")
        with backup.open("xb") as stream:
            stream.write(original); stream.flush(); os.fsync(stream.fileno())
        shutil.copystat(path, backup)
        os.replace(temp_name, path); temp_name = None
        reload = run(["caddy", "reload", "--config", str(path), "--adapter", "caddyfile"],
                     capture_output=True, text=True, timeout=30, check=False, shell=False)
        if reload.returncode != 0:
            raise ExecutionError("Caddy reload failed: " + (reload.stderr or reload.stdout).strip())
        checks = []
        for url in check_urls:
            status = check(url)
            checks.append({"url": url, "status_code": status, "passed": 200 <= status < 400})
            if not 200 <= status < 400:
                raise ExecutionError(f"HTTPS connectivity check failed for {url} (HTTP {status})")
        record.update({"status": "success", "backup": str(backup), "connectivity": checks})
        _record(audit_log, record)
        return {"status": "success", "backup": str(backup), "audit_log": str(audit_log),
                "connectivity": checks, "new_sha256": sha256_bytes(updated)}
    except Exception as error:
        rollback_problem = None
        if backup.exists() and path.exists() and path.read_bytes() == updated:
            fd, rollback_name = tempfile.mkstemp(prefix=f".{path.name}.rollback-", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(original); stream.flush(); os.fsync(stream.fileno())
                shutil.copystat(backup, rollback_name)
                if hasattr(os, "chown") and os.name == "posix":
                    os.chown(rollback_name, metadata.st_uid, metadata.st_gid)
                os.replace(rollback_name, path)
                rollback = run(["caddy", "reload", "--config", str(path), "--adapter", "caddyfile"],
                               capture_output=True, text=True, timeout=30, check=False, shell=False)
                record["rollback_reload"] = "success" if rollback.returncode == 0 else "failed"
                if rollback.returncode != 0:
                    rollback_problem = "Rollback file was restored, but Caddy reload also failed: " + (rollback.stderr or rollback.stdout).strip()
            finally:
                if os.path.exists(rollback_name): os.unlink(rollback_name)
        message = str(error) + (f"; {rollback_problem}" if rollback_problem else "")
        record.update({"status": "failed", "error": message, "backup": str(backup) if backup.exists() else None})
        try: _record(audit_log, record)
        except OSError: pass
        raise ExecutionError(message) from error
    finally:
        if temp_name and os.path.exists(temp_name): os.unlink(temp_name)

