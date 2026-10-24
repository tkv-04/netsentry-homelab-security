# NetSentry project status

## Development roadmap

1. **Foundation and read-only CLI** — installable package, tests, and inspection of listeners, Docker-published ports, Caddy configuration, and firewall state.
2. **Security policy and audit engine** — define app exposure intent and compare it with observed configuration.
3. **Dry-run change planner** — generate proposed changes, show diffs, identify conflicts, and reject unsafe plans without modifying the server.
4. **Controlled execution** — backups, strict validation, narrowly scoped privileged operations, connectivity checks, audit records, and rollback.
5. **Web dashboard** — React interface on top of the API, using the same policies and plans as the CLI.
6. **Portfolio release** — automated security tests, CI, screenshots, architecture and threat-model documentation, and a reproducible installation guide.

## Phase 1: complete

- [x] Installable Python package, Typer CLI, tests, examples, and docs.
- [x] Read-only HTTPS checks for a single host and explicit batches.
- [x] Browser GUI for explicit HTTPS checks; localhost by default, optional LAN bind.
- [x] Inspect listeners, Docker-published ports, Caddyfile, and firewall state.
- [x] Pi use confirmed for HTTPS checks, Caddy trust, listener and Docker inspection.

## Phase 2: complete

- [x] Versioned JSON policy format with `proxy-only`, `lan`, and `public` categories.
- [x] Read-only audit compares policy with local listener, Docker, Caddyfile, and firewall observations.
- [x] Detect direct non-loopback publication for proxy-only apps.
- [x] Check expected Caddy domains/upstreams and flag unmanaged published containers.
- [x] Audit run on the Pi; remaining findings are home-network remediation tasks.

## Phase 3: complete

- [x] Propose a Caddy diff for missing, unambiguous routes with safe domain/upstream values.
- [x] Block proxy-only exposure fixes when authoritative Docker deployment configuration is unavailable.
- [x] Flag Docker/firewall changes for operator review instead of guessing commands.
- [x] Keep planning read-only; no apply, validation, restart, or write operation in `plan`.
- [x] Plan run on the Pi and output reviewed.

## Phase 4: implementation complete; Pi execution unverified

- [x] Approval hash binds the raw Caddyfile and exact proposed routes; stale state is rejected.
- [x] Validate staged Caddyfile before replacement; keep timestamped backup and preserve file metadata.
- [x] Atomic replacement, Caddy reload, HTTPS connectivity checks, JSON-lines audit log, and rollback attempt.
- [x] Restrict execution to Caddy route additions; refuse blocked plans; Docker/firewall execution remains unsupported.
- [x] Validate-only Caddy proposal tested successfully on the Pi without modifying its live file.
- [ ] Validate apply/rollback transaction on a non-production test Caddy instance.

## Phase 5: implementation complete locally; Pi review pending

- [x] Add read-only API routes for health, local policies, audit findings, and dry-run plan.
- [x] Add a React dashboard for exposure overview, audit findings, policy services, and proposed Caddy diffs.
- [x] Default dashboard bind is localhost; no API endpoints can edit policies or apply plans.
- [x] Add optional Python `web` dependencies and Vite build setup.
- [x] Install frontend/API dependencies and build the production React static bundle.
- [x] Test API route handlers against the existing policy, audit, and planner logic.
- [ ] Run the API and browser together in an end-to-end session.
- [ ] Package, install, and review dashboard behavior on the Pi.

## Verify

Run `python -m pytest -q` and `ruff check src tests` in the local venv. Current local result: 44 tests pass and Ruff passes. The React production bundle builds. API handler tests run with the optional web dependency installed; a live browser/API session and Pi deployment remain unverified.
