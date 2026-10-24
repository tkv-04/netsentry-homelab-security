# NetSentry project status

## Roadmap

1. **Foundation and read-only CLI** — package, tests, and inspection of listening ports, Docker-published ports, Caddy configuration, and firewall state. No system changes.
2. **Security policy and audit engine** — define app exposure intent and compare it with observed configuration.

## Phase 1

- [x] Installable Python package, Typer CLI, initial tests, examples, and docs.
- [x] Read-only checks for HTTPS certificates (single host and explicit batches).
- [x] Browser GUI for explicit HTTPS checks; localhost by default, optional LAN bind.
- [x] Inspect listeners, Docker-published ports, Caddyfile, and firewall state.
- [x] Pi use confirmed for HTTPS checks, Caddy trust, listener and Docker inspection.

## Phase 2: in progress

- [x] Versioned JSON policy format with `proxy-only`, `lan`, and `public` categories.
- [x] Read-only audit command collects local listener, Docker, Caddyfile, and firewall observations.
- [x] Detect direct non-loopback publication for proxy-only apps.
- [x] Check expected Caddy domain/upstream strings and report missing or unavailable evidence.
- [x] Flag unmanaged published Docker containers and broad LAN firewall rules.
- [ ] Confirm each app's intended exposure and populate `policies.json`.
- [ ] Validate Docker-specific filtering and run the audit against the Pi's policy file.
- [ ] Refine parsing against the actual Caddyfile and expand test coverage as needed.

## Verify

Run `python -m pytest -q` and `ruff check src tests` from the project folder. Run the audit on the Pi with permission to read Docker and firewall state.
