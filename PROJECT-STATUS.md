# NetSentry project status

Roadmap from the project brief:

1. **Foundation and read-only CLI** — installable package, tests, and local inspection commands for listeners, Docker-published ports, Caddy configuration, and firewall state. No system changes.
2. **Security policy and audit engine** — record whether each app should be proxy-only, LAN-accessible, or deliberately public, then compare those policies with observed configuration.

## Phase 1 checklist

- [x] Installable Python package, project metadata, and ignore rules.
- [x] Typer CLI and initial automated tests.
- [x] Read-only HTTPS certificate checks for one host and explicit target lists.
- [x] Browser GUI for explicit HTTPS checks; localhost by default, optional LAN bind.
- [x] Inspect local listening ports (`netsentry inspect ports`).
- [x] Inspect Docker-published ports (`netsentry inspect docker-ports`).
- [x] Read Caddyfile configuration with basic credential-line redaction (`netsentry inspect caddy`).
- [x] Inspect available UFW, nftables, and iptables firewall state (`netsentry inspect firewall`).
- [x] README, Windows/Linux setup, example target list, and safety documentation.
- [x] Pi HTTPS validation with Caddy's internal CA after adding its root certificate to the Pi trust store.

The inspection commands query the machine where NetSentry runs. Run them on the Pi to inspect the Pi. They do not alter system state. Some commands may show limited detail without elevated read permissions.

## Phase 2 checklist

- [ ] Define per-app exposure policy: proxy-only, LAN-accessible, or deliberately public.
- [ ] Collect observed state from listeners, Docker-published ports, Caddy configuration, and firewall rules.
- [ ] Compare intended policy with observed state and report mismatches.
- [ ] Add tests and documentation for policy format and audit results.

Phase 2 has **not started**. The multi-host HTTPS batch feature is an additional read-only utility; it is not the policy/audit engine.

## Verification

Run `python -m pytest -q` and `ruff check src tests` from the project directory.
