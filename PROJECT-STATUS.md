# NetSentry project status

## Development roadmap

1. **Foundation and read-only CLI** — installable package, tests, and inspection of listeners, Docker-published ports, Caddy configuration, and firewall state. No system changes.
2. **Security policy and audit engine** — define app exposure intent and compare it with observed configuration.
3. **Dry-run change planner** — generate proposed Caddy/firewall changes, show diffs, identify conflicts, and reject unsafe plans without modifying the server.
4. **Controlled execution** — backups, strict validation, narrowly scoped privileged operations, connectivity checks, audit records, and rollback.
5. **Web dashboard** — React interface on top of the API, using the same policies and plans as the CLI.
6. **Portfolio release** — automated security tests, CI, screenshots, architecture and threat-model documentation, and reproducible installation guide.

## Phase 1: complete

- [x] Installable Python package, Typer CLI, initial tests, examples, and docs.
- [x] Read-only HTTPS checks for a single host and explicit batches.
- [x] Browser GUI for explicit HTTPS checks; localhost by default, optional LAN bind.
- [x] Inspect listeners, Docker-published ports, Caddyfile, and firewall state.
- [x] Pi use confirmed for HTTPS checks, Caddy trust, listener and Docker inspection.

## Phase 2: complete

- [x] Versioned JSON policy format with `proxy-only`, `lan`, and `public` categories.
- [x] Read-only audit compares policy with local listener, Docker, Caddyfile, and firewall observations.
- [x] Detect direct non-loopback publication for proxy-only apps.
- [x] Check expected Caddy domains/upstreams and flag unmanaged published containers.
- [x] Audit run on the Pi; the remaining findings are home-network remediation tasks, not missing audit features.

## Phase 3: dry-run planner

- [x] Propose a Caddy diff for missing, unambiguous routes with safe domain/upstream values.
- [x] Block proxy-only exposure fixes when authoritative Docker deployment configuration is unavailable.
- [x] Flag Docker/firewall changes for operator review instead of guessing commands.
- [x] Keep planning read-only; no apply, validation, restart, or write operation.
- [ ] Review generated plans on the Pi and confirm the proposed routes match the intended configuration.

## Verify

From the project folder, run `python -m pytest -q` and `ruff check src tests`. On the Pi, use `netsentry audit` to review observed state and `netsentry plan` to inspect proposals. Neither command changes system configuration.
