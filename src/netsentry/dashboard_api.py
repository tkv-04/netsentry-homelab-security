"""Read-only JSON API used by the React dashboard."""
from __future__ import annotations

from pathlib import Path
from typing import Any


class _SecurityHeadersMiddleware:
    """Add browser security headers without buffering or altering API responses."""

    def __init__(self, app):
        self.app = app
        self.headers = [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"cache-control", b"no-store"),
            (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
        ]

    async def __call__(self, scope, receive, send):
        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + self.headers
            await send(message)
        await self.app(scope, receive, send_with_headers)


def create_dashboard_api(policy_file: Path, caddyfile: Path, static_directory: Path | None = None):
    """Create an API bound to explicit local policy and Caddyfile paths."""
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.staticfiles import StaticFiles
    except ImportError as error:
        raise RuntimeError('Dashboard API dependencies are missing; install NetSentry with `pip install -e ".[web]"`.') from error

    from netsentry.audit import audit_policy
    from netsentry.inspection import (
        inspect_caddy_config,
        inspect_docker_ports,
        inspect_firewall,
        inspect_ports,
    )
    from netsentry.planner import build_plan
    from netsentry.policy import load_policy

    static_root = static_directory or Path(__file__).with_name("dashboard")
    app = FastAPI(title="NetSentry API", docs_url=None, redoc_url=None, openapi_url=None)

    app.add_middleware(_SecurityHeadersMiddleware)

    def collect() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
        try:
            policy = load_policy(policy_file)
        except (OSError, TypeError, ValueError) as error:
            raise HTTPException(status_code=400, detail=f"Could not load policy: {error}") from error
        return (
            policy,
            inspect_docker_ports(),
            inspect_caddy_config(caddyfile),
            inspect_firewall(),
            inspect_ports(),
        )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "read-only"}

    @app.get("/api/policies")
    def policies() -> dict[str, Any]:
        policy, *_ = collect()
        return policy

    @app.get("/api/audit")
    def audit() -> dict[str, Any]:
        policy, docker, caddy, firewall, ports = collect()
        try:
            findings = audit_policy(policy, docker, caddy, firewall, ports)
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(status_code=500, detail=f"Audit failed: {error}") from error
        summary = {severity: sum(item["severity"] == severity for item in findings)
                   for severity in ("mismatch", "review", "pass")}
        return {"summary": summary, "findings": findings}

    @app.get("/api/plan")
    def plan() -> dict[str, Any]:
        policy, docker, caddy, firewall, ports = collect()
        try:
            return build_plan(policy, docker, caddy, firewall, ports)
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(status_code=500, detail=f"Plan generation failed: {error}") from error

    if static_root.is_dir() and (static_root / "index.html").is_file():
        app.mount("/", StaticFiles(directory=static_root, html=True), name="dashboard")
    return app


def serve_dashboard(
    host: str = "127.0.0.1", port: int = 8090,
    policy_file: Path = Path("policies.json"),
    caddyfile: Path = Path("/etc/caddy/Caddyfile"),
) -> None:
    """Run the dashboard API and bundled React assets."""
    try:
        import uvicorn
    except ImportError as error:
        raise RuntimeError('Dashboard server dependencies are missing; install NetSentry with `pip install -e ".[web]"`.') from error
    app = create_dashboard_api(policy_file.expanduser().resolve(), caddyfile.expanduser().resolve())
    uvicorn.run(app, host=host, port=port, server_header=False, access_log=False)
