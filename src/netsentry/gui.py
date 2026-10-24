"""Small standard-library browser interface for NetSentry."""

from __future__ import annotations

from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from netsentry.checks import check_certificate


class NetSentryHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._respond(_page())

    def do_POST(self) -> None:
        length = min(int(self.headers.get("Content-Length", "0")), 4096)
        fields = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        host = fields.get("host", [""])[0].strip()
        try:
            port = int(fields.get("port", ["443"])[0])
            result = check_certificate(host, port)
            details = (
                f"<dl><dt>Subject</dt><dd>{escape(result.subject or '(not provided)')}</dd>"
                f"<dt>Issuer</dt><dd>{escape(result.issuer or '(not provided)')}</dd>"
                f"<dt>Expires</dt><dd>{escape(result.expires_at.isoformat())}</dd>"
                f"<dt>Days remaining</dt><dd>{result.days_remaining}</dd></dl>"
            )
        except (OSError, ValueError) as error:
            details = f'<p class="error">Check failed: {escape(str(error))}</p>'
        self._respond(_page(host, port, details))

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


def _page(host: str = "", port: int = 443, details: str = "") -> str:
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSentry</title><style>
body {{ font: 16px system-ui,sans-serif; background:#f3f6fa; color:#152238; margin:0; padding:3rem 1rem }}
main {{ max-width:680px; margin:auto; background:white; padding:2rem; border-radius:16px; box-shadow:0 8px 32px #19365b18 }}
h1 {{ margin-top:0 }} p {{ color:#526177 }} form {{ display:grid; gap:1rem; grid-template-columns:1fr 130px }}
label {{ display:grid; gap:.4rem; font-weight:600 }} input,button {{ font:inherit; padding:.75rem; border:1px solid #cbd5e1; border-radius:8px }}
button {{ grid-column:1/-1; background:#155eef; color:white; border:0; cursor:pointer }}
dl {{ display:grid; grid-template-columns:150px 1fr; gap:.7rem; margin-top:2rem }}
dt {{ font-weight:700 }} dd {{ margin:0; overflow-wrap:anywhere }} .error {{ color:#b42318 }}
</style><main><h1>NetSentry</h1><p>Read-only HTTPS certificate check for one host.</p>
<form method="post"><label>Host<input name="host" required value="{escape(host, quote=True)}" placeholder="nas.home.arpa"></label>
<label>Port<input name="port" type="number" min="1" max="65535" value="{port}"></label>
<button type="submit">Check certificate</button></form>{details}</main></html>"""


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
