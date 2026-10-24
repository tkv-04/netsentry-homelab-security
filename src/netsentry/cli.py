"""Command-line interface for NetSentry."""

from __future__ import annotations

import json
import logging
from datetime import timezone
from pathlib import Path
from typing import Annotated

import typer

from netsentry import __version__
from netsentry.checks import check_certificate, load_targets
from netsentry.gui import serve

app = typer.Typer(help="Read-only homelab network checks.", no_args_is_help=True)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"NetSentry {__version__}")
        raise typer.Exit()


@app.callback()
def main(version: bool | None = typer.Option(
    None, "--version", callback=version_callback, is_eager=True, help="Show version and exit."
)) -> None:
    """Inspect explicitly supplied hosts using read-only checks."""


@app.command("check-https")
def check_https(
    host: str = typer.Argument(..., help="Hostname or IP address to check."),
    port: int = typer.Option(443, min=1, max=65535, help="HTTPS port."),
    timeout: float = typer.Option(5.0, min=0.1, help="Connection timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    """Check a host's HTTPS certificate using normal TLS validation."""
    try:
        result = check_certificate(host, port, timeout)
    except (OSError, ValueError) as exc:
        logging.getLogger("netsentry").error("HTTPS check failed for %s:%s: %s", host, port, exc)
        raise typer.Exit(code=1) from exc
    if json_output:
        typer.echo(json.dumps({"host": result.host, "port": result.port, "subject": result.subject,
                               "issuer": result.issuer,
                               "expires_at": result.expires_at.astimezone(timezone.utc).isoformat(),
                               "days_remaining": result.days_remaining}, indent=2))
    else:
        typer.echo(f"Host: {result.host}:{result.port}")
        typer.echo(f"Subject: {result.subject or '(not provided)'}")
        typer.echo(f"Issuer: {result.issuer or '(not provided)'}")
        typer.echo(f"Expires: {result.expires_at.isoformat()}")
        typer.echo(f"Days remaining: {result.days_remaining}")




@app.command("check-list")
def check_list(
    target_file: Annotated[Path, typer.Argument(exists=True, readable=True, help="UTF-8 file with one host per line.")],
    port: int = typer.Option(443, min=1, max=65535, help="HTTPS port used for each host."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    """Check certificates for up to 25 explicitly listed hosts."""
    try:
        hosts = load_targets(target_file)
    except (OSError, ValueError) as error:
        typer.echo(f"Could not load targets: {error}", err=True)
        raise typer.Exit(code=1) from error
    results = []
    for host in hosts:
        try:
            result = check_certificate(host, port)
            results.append({"host": host, "port": port, "ok": True,
                            "subject": result.subject, "issuer": result.issuer,
                            "expires_at": result.expires_at.isoformat(),
                            "days_remaining": result.days_remaining})
        except (OSError, ValueError) as error:
            results.append({"host": host, "port": port, "ok": False, "error": str(error)})
    if json_output:
        typer.echo(json.dumps(results, indent=2))
    else:
        for result in results:
            state = f"{result['days_remaining']} days remaining" if result["ok"] else result["error"]
            typer.echo(("OK " if result["ok"] else "FAIL ") + result["host"] + f":{port} - {state}")
    if any(not result["ok"] for result in results):
        raise typer.Exit(code=1)
@app.command("gui")
def gui(
    host: str = typer.Option("127.0.0.1", "--host", help="Interface to bind; use 0.0.0.0 for LAN access."),
    port: int = typer.Option(8080, min=1, max=65535, help="Web interface port."),
) -> None:
    """Start the browser interface (localhost only by default)."""
    serve(host, port)




inspect_app = typer.Typer(help="Read-only inspection of this machine.", no_args_is_help=True)
app.add_typer(inspect_app, name="inspect")


@inspect_app.command("ports")
def inspect_ports_command(json_output: bool = typer.Option(False, "--json")) -> None:
    """Inspect local listening TCP/UDP ports."""
    from netsentry.inspection import format_report, inspect_ports

    typer.echo(format_report(inspect_ports(), json_output))


@inspect_app.command("docker-ports")
def inspect_docker_ports_command(json_output: bool = typer.Option(False, "--json")) -> None:
    """Inspect Docker-published ports and container names."""
    from netsentry.inspection import format_report, inspect_docker_ports

    typer.echo(format_report(inspect_docker_ports(), json_output))


@inspect_app.command("caddy")
def inspect_caddy_command(
    path: Annotated[Path, typer.Option("--path", help="Caddyfile path.")] = Path("/etc/caddy/Caddyfile"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    """Read the Caddyfile, redacting lines that look like secrets."""
    from netsentry.inspection import format_report, inspect_caddy_config

    typer.echo(format_report(inspect_caddy_config(path), json_output))


@inspect_app.command("firewall")
def inspect_firewall_command(json_output: bool = typer.Option(False, "--json")) -> None:
    """Inspect UFW, nftables, and iptables state on Linux."""
    from netsentry.inspection import format_report, inspect_firewall

    typer.echo(format_report(inspect_firewall(), json_output))


@app.command("audit")
def audit(
    policy_file: Annotated[Path, typer.Argument(exists=True, readable=True, help="Version 1 JSON exposure policy.")],
    caddyfile: Annotated[Path, typer.Option("--caddyfile", help="Caddyfile to inspect.")] = Path("/etc/caddy/Caddyfile"),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable findings."),
) -> None:
    """Compare declared app exposure policies with local read-only observations."""
    from netsentry.audit import audit_policy
    from netsentry.inspection import (
        inspect_caddy_config,
        inspect_docker_ports,
        inspect_firewall,
        inspect_ports,
    )
    from netsentry.policy import load_policy

    try:
        policy = load_policy(policy_file)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        typer.echo(f"Could not load policy: {error}", err=True)
        raise typer.Exit(code=2) from error
    findings = audit_policy(
        policy,
        inspect_docker_ports(),
        inspect_caddy_config(caddyfile),
        inspect_firewall(),
        inspect_ports(),
    )
    counts = {severity: sum(item["severity"] == severity for item in findings)
              for severity in ("mismatch", "review", "pass")}
    report = {"summary": counts, "findings": findings}
    if json_output:
        typer.echo(json.dumps(report, indent=2))
    elif findings:
        for finding in findings:
            typer.echo(f"{finding['severity'].upper()} [{finding['code']}] {finding['app']}: {finding['message']}")
        typer.echo("Summary: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
    else:
        typer.echo("No policy findings. Add app policies to detect unmanaged exposure.")
    if counts["mismatch"]:
        raise typer.Exit(code=1)



@app.command("plan")
def plan(
    policy_file: Annotated[Path, typer.Argument(exists=True, readable=True, help="Version 1 JSON exposure policy.")],
    caddyfile: Annotated[Path, typer.Option("--caddyfile", help="Caddyfile to inspect.")] = Path("/etc/caddy/Caddyfile"),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable plan."),
) -> None:
    """Show a dry-run configuration proposal and review blockers; never apply changes."""
    from netsentry.inspection import (
        inspect_caddy_config,
        inspect_docker_ports,
        inspect_firewall,
        inspect_ports,
    )
    from netsentry.planner import build_plan
    from netsentry.policy import load_policy

    try:
        policy = load_policy(policy_file)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        typer.echo(f"Could not load policy: {error}", err=True)
        raise typer.Exit(code=2) from error
    result = build_plan(policy, inspect_docker_ports(), inspect_caddy_config(caddyfile),
                        inspect_firewall(), inspect_ports())
    from netsentry.execution import approval_digest, sha256_bytes
    try:
        base_hash = sha256_bytes(caddyfile.read_bytes())
    except OSError:
        base_hash = None
    result["base_sha256"] = base_hash
    result["approval_sha256"] = approval_digest(base_hash, result["proposed_routes"]) if base_hash else None
    if json_output:
        typer.echo(json.dumps(result, indent=2))
        return
    typer.echo("DRY RUN ONLY — no files or system settings changed.")
    for item in result["items"]:
        typer.echo(f"{item['status'].upper()} [{item['code']}] {item['app']}: {item['message']}")
    typer.echo("Summary: " + ", ".join(f"{key}={value}" for key, value in result["summary"].items()))
    if result["diff"]:
        typer.echo("\nProposed Caddy diff:\n" + result["diff"])
    if result["proposed_routes"]:
        typer.echo("Approval hash (binds this Caddyfile and proposed routes): " + str(result["approval_sha256"]))
    typer.echo(result["note"])
    if result["summary"]["blocked"]:
        raise typer.Exit(code=1)

@app.command("validate-plan")
def validate_plan_command(
    policy_file: Annotated[Path, typer.Argument(exists=True, readable=True, help="Version 1 JSON exposure policy.")],
    caddyfile: Annotated[Path, typer.Option("--caddyfile", help="Caddyfile to read; never overwritten.")] = Path("/etc/caddy/Caddyfile"),
) -> None:
    """Validate proposed Caddy additions using a temporary file; never reload or replace config."""
    from netsentry.execution import (
        ExecutionError,
        sha256_bytes,
        validate_caddy_proposal,
    )
    from netsentry.inspection import (
        inspect_caddy_config,
        inspect_docker_ports,
        inspect_firewall,
        inspect_ports,
    )
    from netsentry.planner import build_plan
    from netsentry.policy import load_policy

    try:
        policy = load_policy(policy_file)
        result = build_plan(policy, inspect_docker_ports(), inspect_caddy_config(caddyfile),
                            inspect_firewall(), inspect_ports())
        if not result["proposed_routes"]:
            raise ExecutionError("the plan contains no proposed Caddy routes to validate")
        outcome = validate_caddy_proposal(caddyfile, result["proposed_routes"], sha256_bytes(caddyfile.read_bytes()))
    except (OSError, TypeError, ValueError, ExecutionError) as error:
        typer.echo(f"Caddy proposal validation failed: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo("VALID: " + ", ".join(outcome["routes"]))
    typer.echo(outcome["message"])
    if result["summary"]["blocked"]:
        typer.echo(f"Audit still reports {result['summary']['blocked']} blocker(s); this command only checks Caddy syntax.")


@app.command("apply-caddy")
def apply_caddy_command(
    policy_file: Annotated[Path, typer.Argument(exists=True, readable=True, help="Version 1 JSON exposure policy.")],
    approve: Annotated[str, typer.Option("--approve", help="Approval SHA-256 printed by the reviewed plan.")],
    caddyfile: Annotated[Path, typer.Option("--caddyfile", help="Caddyfile to update.")] = Path("/etc/caddy/Caddyfile"),
    audit_log: Annotated[Path | None, typer.Option("--audit-log", help="Execution audit log path.")] = None,
    ca_cert: Annotated[Path | None, typer.Option("--ca-cert", help="Optional CA file for internal Caddy HTTPS checks.")] = None,
) -> None:
    """Apply only approved Caddy routes; validates, backs up, checks, audits, and rolls back on failure."""
    from netsentry.execution import (
        ExecutionError,
        apply_caddy_update,
        approval_digest,
        ensure_plan_executable,
        sha256_bytes,
    )
    from netsentry.inspection import (
        inspect_caddy_config,
        inspect_docker_ports,
        inspect_firewall,
        inspect_ports,
    )
    from netsentry.planner import build_plan
    from netsentry.policy import load_policy

    try:
        policy = load_policy(policy_file)
        result = build_plan(policy, inspect_docker_ports(), inspect_caddy_config(caddyfile),
                            inspect_firewall(), inspect_ports())
        ensure_plan_executable(result)
        routes = result["proposed_routes"]
        base_hash = sha256_bytes(caddyfile.read_bytes())
        expected = approval_digest(base_hash, routes)
        if approve != expected:
            raise ExecutionError("approval hash is stale or does not match; review the latest netsentry plan output")
        urls = [f"https://{route['domain']}" for route in routes]
        typer.echo("Applying only these reviewed Caddy additions: " + ", ".join(route["domain"] for route in routes))
        audit_log = audit_log or (Path.home() / ".local/state/netsentry/execution.jsonl")
        from netsentry.execution import _check_https
        if ca_cert is not None and (ca_cert.is_symlink() or not ca_cert.is_file()):
            raise ExecutionError("--ca-cert must reference an existing regular CA file")
        checker = (lambda url: _check_https(url, ca_cert=ca_cert)) if ca_cert else None
        outcome = apply_caddy_update(caddyfile, routes, base_hash, approve, urls, audit_log, checker=checker)
    except (OSError, TypeError, ValueError, ExecutionError) as error:
        typer.echo(f"Caddy update failed safely: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo("Caddy update succeeded; backup: " + str(outcome["backup"]))
    typer.echo("Execution audit: " + str(outcome["audit_log"]))
    for check in outcome["connectivity"]:
        typer.echo(f"HTTPS check passed: {check['url']} (HTTP {check['status_code']})")

@app.command("dashboard")
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", help="Interface to bind; localhost by default."),
    port: int = typer.Option(8090, min=1, max=65535, help="Dashboard port."),
    policy_file: Annotated[Path, typer.Option("--policy-file", help="Local policy JSON read by the dashboard.")] = Path("policies.json"),
    caddyfile: Annotated[Path, typer.Option("--caddyfile", help="Caddyfile to inspect.")] = Path("/etc/caddy/Caddyfile"),
) -> None:
    """Serve the read-only React security dashboard and local JSON API."""
    from netsentry.dashboard_api import serve_dashboard

    try:
        serve_dashboard(host, port, policy_file, caddyfile)
    except RuntimeError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(code=1) from error


if __name__ == "__main__":
    app()









