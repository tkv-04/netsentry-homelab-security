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





if __name__ == "__main__":
    app()



