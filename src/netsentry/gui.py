"""Small standard-library browser interface for NetSentry."""

from __future__ import annotations

from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from netsentry.checks import check_certificate

MAX_TARGETS = 25


class NetSentryHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._respond(_page())

    def do_POST(self) -> None:
        length = min(int(self.headers.get("Content-Length", "0")), 8192)
        fields = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        hosts = [line.strip() for line in fields.get("hosts", [""])[0].splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        port_text = fields.get("port", ["443"])[0]
        try:
            port = int(port_text)
            if not 1 <= port <= 65535:
                raise ValueError("port must be between 1 and 65535")
            if not hosts:
                raise ValueError("enter at least one host")
            if len(hosts) > MAX_TARGETS:
                raise ValueError(f"enter no more than {MAX_TARGETS} hosts")
            rows = []
            for host in hosts:
                try:
                    result = check_certificate(host, port)
                    rows.append(
                        f"<tr><td>{escape(host)}:{port}</td><td>OK</td>"
                        f"<td>{escape(result.subject or '(not provided)')}</td>"
                        f"<td>{escape(result.expires_at.isoformat())}</td>"
                        f"<td>{result.days_remaining}</td></tr>"
                    )
                except (OSError, ValueError) as error:
                    rows.append(
                        f'<tr><td>{escape(host)}:{port}</td><td class="error">Failed</td>'
                        f'<td colspan="3">{escape(str(error))}</td></tr>'
                    )
            details = (
                "<table><thead><tr><th>Host</th><th>Status</th><th>Subject</th>"
                "<th>Expires</th><th>Days left</th></tr></thead><tbody>"
                + "".join(rows) + "</tbody></table>"
            )
        except ValueError as error:
            details = f'<p class="error">Check failed: {escape(str(error))}</p>'
        self._respond(_page("\n".join(hosts), port_text, details))

    def _respond(self, body: str) -> None:
        content = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: object) -> None:
        pass


def _page(hosts: str = "", port: str = "443", details: str = "") -> str:
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSentry</title><style>
body {{ font:16px system-ui,sans-serif;background:#f3f6fa;color:#152238;margin:0;padding:3rem 1rem }}
main {{ max-width:900px;margin:auto;background:white;padding:2rem;border-radius:16px;box-shadow:0 8px 32px #19365b18 }}
form {{ display:grid;gap:1rem;grid-template-columns:1fr 140px }} label {{ display:grid;gap:.4rem;font-weight:600 }}
textarea,input,button {{ font:inherit;padding:.75rem;border:1px solid #cbd5e1;border-radius:8px }} textarea {{ min-height:140px }}
button {{ grid-column:1/-1;background:#155eef;color:white;border:0;cursor:pointer }} table {{ width:100%;border-collapse:collapse;margin-top:2rem;font-size:.9rem }}
th,td {{ text-align:left;padding:.6rem;border-bottom:1px solid #e2e8f0 }} .error {{ color:#b42318 }}
</style><main><h1>NetSentry</h1><p>Read-only HTTPS checks for explicitly listed hosts (up to {MAX_TARGETS}).</p>
<form method="post"><label>Hosts, one per line<textarea name="hosts" required placeholder="ha.home.arpa&#10;nas.home.arpa">{escape(hosts)}</textarea></label>
<label>HTTPS port<input name="port" type="number" min="1" max="65535" value="{escape(str(port), quote=True)}"></label>
<button type="submit">Check certificates</button></form>{details}</main></html>"""


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run the browser interface until interrupted."""
    server = ThreadingHTTPServer((host, port), NetSentryHandler)
    try:
        print(f"NetSentry GUI listening at http://{host}:{port}")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
