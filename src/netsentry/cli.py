"""Command-line interface for NetSentry."""

from __future__ import annotations

import json
import logging
from datetime import timezone
from typing import Optional

import typer

from netsentry import __version__
from netsentry.checks import check_certificate
from netsentry.gui import serve

app = typer.Typer(help="Read-only homelab network checks.", no_args_is_help=True)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"NetSentry {__version__}")
        raise typer.Exit()


@app.callback()
def main(version: Optional[bool] = typer.Option(
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


if __name__ == "__main__":
    app()


@app.command("gui")
def gui(
    host: str = typer.Option("127.0.0.1", "--host", help="Interface to bind; use 0.0.0.0 for LAN access."),
    port: int = typer.Option(8080, min=1, max=65535, help="Web interface port."),
) -> None:
    """Start the browser interface (localhost only by default)."""
    serve(host, port)


