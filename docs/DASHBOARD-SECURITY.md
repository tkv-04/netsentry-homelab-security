# Dashboard security notes

The dashboard API exposes policy names, audit results, and a proposed Caddy diff. It accepts only GET requests and reads the policy and Caddyfile paths selected when the server starts. It has no authentication and is bound to `127.0.0.1` by default. Binding to all interfaces exposes the information to reachable clients; use only on a trusted LAN and avoid public forwarding. The API has no policy-edit, apply, Docker-mutation, or firewall-mutation endpoints.

The optional server process may need permission to inspect Docker and firewall state. Do not run it with elevated privileges while exposing it beyond localhost unless you have considered the consequences. Prefer a local-only process or a narrowly controlled access path.
