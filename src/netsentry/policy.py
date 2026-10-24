"""Versioned JSON policy loading and validation."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

EXPOSURES = {"proxy-only", "lan", "public"}


def load_policy(path: Path) -> dict[str, object]:
    policy = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise ValueError("policy must be a JSON object with version 1")
    apps = policy.get("apps")
    if not isinstance(apps, list):
        raise TypeError("policy 'apps' must be a list")
    names: set[str] = set()
    for app in apps:
        if not isinstance(app, dict):
            raise TypeError("each app policy must be a JSON object")
        name = app.get("name")
        exposure = app.get("exposure")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("each app policy needs a non-empty name")
        if name in names:
            raise ValueError(f"duplicate app policy name: {name}")
        names.add(name)
        if not isinstance(exposure, str) or exposure not in EXPOSURES:
            raise ValueError(f"{name}: exposure must be one of {', '.join(sorted(EXPOSURES))}")
        for key in ("container_names", "domains", "upstreams", "allowed_sources"):
            value = app.get(key, [])
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValueError(f"{name}: '{key}' must be a list of strings")
            if key == "allowed_sources":
                try:
                    for source in value:
                        ipaddress.ip_network(source, strict=False)
                except ValueError as error:
                    raise ValueError(f"{name}: allowed_sources must contain CIDR networks") from error
        for key in ("host_ports", "container_ports"):
            ports = app.get(key, [])
            if not isinstance(ports, list) or any(
                not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
                for port in ports
            ):
                raise ValueError(f"{name}: '{key}' must contain valid port numbers")
    return policy
