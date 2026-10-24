"""Read-only inspection of local host exposure and configuration."""

from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
from pathlib import Path

_SECRET_LINE = re.compile(
    r"(?i)(\b(?:password|passwd|token|secret|api[_-]?key|authorization|private[_-]?key)\b\s*[:=]?\s*).+"
)


def _run(command: list[str], timeout: int = 10) -> dict[str, object]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, shell=False)
    except FileNotFoundError:
        return {"command": command, "available": False, "output": "Command not installed."}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"command": command, "available": True, "error": str(error), "output": ""}
    output = (result.stdout + result.stderr).strip()
    return {
        "command": command,
        "available": True,
        "return_code": result.returncode,
        "output": output or "(no output)",
    }


def inspect_ports() -> dict[str, object]:
    """List TCP/UDP listeners using the platform's standard read-only utility."""
    if platform.system() == "Linux":
        return _run(["ss", "-lntup"])
    if platform.system() == "Windows":
        return _run(["netstat", "-ano"])
    return {"available": False, "output": f"Unsupported platform: {platform.system()}"}


def inspect_docker_ports() -> dict[str, object]:
    """List Docker containers and their published host ports, without changing them."""
    command = ["docker", "ps", "--format", "{{json .}}"]
    result = _run(command)
    if not result.get("available") or result.get("return_code", 0) != 0:
        return result
    lines = str(result["output"]).splitlines()
    try:
        containers = [json.loads(line) for line in lines if line and line != "(no output)"]
    except json.JSONDecodeError as error:
        return {**result, "error": f"Could not parse Docker output: {error}"}
    return {"command": command, "available": True, "containers": containers}


def inspect_caddy_config(path: Path = Path("/etc/caddy/Caddyfile")) -> dict[str, object]:
    """Read a Caddyfile and redact lines that appear to contain credentials."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return {"path": str(path), "available": False, "error": str(error)}
    redacted = []
    for line in content.splitlines():
        redacted.append(_SECRET_LINE.sub(r"\1[REDACTED]", line))
    return {"path": str(path), "available": True, "output": "\n".join(redacted)}


def inspect_firewall() -> dict[str, object]:
    """Read common Linux firewall status and rules, without changing them."""
    if platform.system() != "Linux":
        return {"available": False, "output": f"Linux firewall inspection unavailable on {platform.system()}."}
    candidates = [
        ["ufw", "status", "verbose"],
        ["nft", "list", "ruleset"],
        ["iptables", "-S"],
        ["ip6tables", "-S"],
    ]
    reports = []
    for command in candidates:
        if shutil.which(command[0]):
            result = _run(command)
            output = str(result.get("output", ""))
            if len(output) > 12000:
                result["output"] = output[:12000] + "\n[output truncated]"
            reports.append(result)
    if not reports:
        return {"available": False, "output": "No supported firewall utility found (ufw, nft, iptables)."}
    return {"available": True, "results": reports,
            "note": "Permission limits may hide firewall details; no rules were changed."}


def format_report(report: dict[str, object], as_json: bool = False) -> str:
    """Format an inspection report for CLI output."""
    if as_json:
        return json.dumps(report, indent=2)
    if "results" in report:
        blocks = []
        for result in report["results"]:
            blocks.append(f"$ {' '.join(result.get('command', []))}\n{result.get('output', result.get('error', ''))}")
        return "\n\n".join(blocks) + f"\n\n{report.get('note', '')}"
    if "containers" in report:
        containers = report["containers"]
        if not containers:
            return "No running containers."
        return "\n".join(
            f"{container.get('Names', container.get('ID', 'unknown'))} [{container.get('Image', 'image unknown')}]: "
            f"{container.get('Ports') or '(no published ports)'}"
            for container in containers
        )
    return str(report.get("output", report.get("error", "No inspection result.")))



