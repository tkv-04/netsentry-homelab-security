from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from netsentry.dashboard_api import create_dashboard_api


def test_dashboard_api_routes_reuse_read_only_policy_audit_and_planner(tmp_path, monkeypatch):
    from netsentry import inspection

    policy_file = tmp_path / "policies.json"
    policy_file.write_text(json.dumps({"version": 1, "apps": []}), encoding="utf-8")
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text("", encoding="utf-8")
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("dashboard", encoding="utf-8")
    monkeypatch.setattr(inspection, "inspect_docker_ports", lambda: {"available": True, "containers": []})
    monkeypatch.setattr(inspection, "inspect_caddy_config", lambda _path: {"available": True, "output": ""})
    monkeypatch.setattr(inspection, "inspect_firewall", lambda: {"available": True, "results": []})
    monkeypatch.setattr(inspection, "inspect_ports", lambda: {"available": True, "output": ""})

    app = create_dashboard_api(policy_file, caddyfile, static)
    routes = {route.path: route for route in app.routes if getattr(route, "path", "").startswith("/api/")}
    assert set(routes) == {"/api/health", "/api/policies", "/api/audit", "/api/plan"}
    assert all(route.methods == {"GET"} for route in routes.values())
    assert routes["/api/health"].endpoint() == {"status": "ok", "mode": "read-only"}
    assert routes["/api/policies"].endpoint() == {"version": 1, "apps": []}
    assert routes["/api/audit"].endpoint()["summary"] == {"mismatch": 0, "review": 1, "pass": 0}
    assert routes["/api/plan"].endpoint()["mode"] == "dry-run"
    assert any(item.cls.__name__ == "_SecurityHeadersMiddleware" for item in app.user_middleware)
    assert (static / "index.html").read_text(encoding="utf-8") == "dashboard"
