# Phase 3 dry-run planner

`netsentry plan` collects the same read-only observations as `netsentry audit`, then presents proposed changes separately from unresolved findings.

## Current behavior

- Proposes a unified Caddyfile diff only when policy domains and upstreams pair one-to-one, the domain is absent, and both values use supported simple syntax.
- Adds `tls internal` to generated `.home.arpa` site blocks.
- Blocks route proposals when the Caddyfile is unavailable, route pairing is ambiguous, a value contains unsupported syntax, or the domain already appears in the file.
- Marks proxy-only direct publications as blocked. It does not invent Docker Compose changes because the project has no authoritative deployment file to edit.
- Marks LAN/Docker firewall conditions for operator review. It does not generate firewall commands because Docker-published traffic may bypass UFW and the firewall backend/chain ordering needs inspection.
- Prints JSON with `--json`; a blocked plan exits with status 1.
- Prints an approval hash bound to the raw Caddyfile and exact proposed route additions.

## Phase 4 execution boundary

`netsentry apply-caddy` supports only proposed route additions. It requires the current approval hash, rejects changed Caddyfiles and symlinks, validates a staged copy with `caddy validate`, creates a timestamped backup, atomically replaces the Caddyfile, reloads Caddy, performs HTTPS checks, and writes a JSON-lines audit record. It rolls back the file and attempts a reload when the reload or connectivity check fails. On Linux it requires root. It never executes Docker or firewall changes.

Execution is an explicit operator action. The planning command remains read-only; no apply command was run against the Pi during development. A successful Caddy update is not proof that direct Docker exposure is resolved; rerun the audit and review remaining findings.

## Raspberry Pi usage

```bash
sudo "$(command -v netsentry)" plan policies.json --caddyfile /etc/caddy/Caddyfile
sudo "$(command -v netsentry)" apply-caddy policies.json --caddyfile /etc/caddy/Caddyfile --approve <approval-sha256> --ca-cert /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt
```

For Caddy internal certificates, pass the local root certificate with `--ca-cert`; use the actual path found on the Pi. Use the hash from the immediately preceding reviewed plan. A changed policy, Caddyfile, or observation that changes the proposed route set requires a new plan and hash.
