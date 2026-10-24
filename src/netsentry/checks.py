"""Read-only HTTPS certificate checks."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class CertificateResult:
    host: str
    port: int
    subject: str
    issuer: str
    expires_at: datetime
    days_remaining: int




def load_targets(path: Path, limit: int = 25) -> list[str]:
    """Read a bounded newline-delimited list of explicitly selected hosts."""
    hosts = [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if not hosts:
        raise ValueError("target file contains no hosts")
    if len(hosts) > limit:
        raise ValueError(f"target file may contain at most {limit} hosts")
    return hosts
def check_certificate(host: str, port: int = 443, timeout: float = 5.0) -> CertificateResult:
    """Fetch and validate a server certificate without sending application data."""
    if not host.strip():
        raise ValueError("host must not be empty")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_socket, context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
        certificate = tls_socket.getpeercert()
    not_after = certificate.get("notAfter")
    if not_after is None:
        raise ssl.SSLError("server certificate has no expiry date")
    expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    remaining = expires_at - datetime.now(timezone.utc)
    return CertificateResult(host, port, _format_name(certificate.get("subject", ())),
                             _format_name(certificate.get("issuer", ())), expires_at, remaining.days)


def _format_name(name: tuple) -> str:
    return ", ".join(f"{key}={value}" for group in name for key, value in group)





