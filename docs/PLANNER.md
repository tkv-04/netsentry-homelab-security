# Phase 3 dry-run planner

`netsentry plan` collects the same read-only observations as `netsentry audit`, then presents proposed changes separately from unresolved findings.

## Current behavior

- Proposes a unified Caddyfile diff only when policy domains and upstreams pair one-to-one, the domain is absent, and both values use supported simple syntax.
- Adds `tls internal` to generated `.home.arpa` site blocks.
- Blocks route proposals when the Caddyfile is unavailable, route pairing is ambiguous, a value contains unsupported syntax, or the domain already appears in the file.
- Marks proxy-only direct publications as blocked. It does not invent Docker Compose changes because the project has no authoritative deployment file to edit.
- Marks LAN/Docker firewall conditions for operator review. It does not generate firewall commands because Docker-published traffic may bypass UFW and the firewall backend/chain ordering needs inspection.
- Prints JSON with `--json`; a blocked plan exits with status 1.

## Safety boundary

This phase is proposal-only. It does not write configuration, policy, backups, or temporary files; execute generated commands; invoke `caddy validate`; alter containers; or reload/restart services. `safe_to_apply` is always false. Review the diff and validate it against the actual host before applying any change manually.

## Raspberry Pi usage

```bash
sudo "$(command -v netsentry)" plan policies.json --caddyfile /etc/caddy/Caddyfile
```

The command needs read access to Docker, listener, firewall, policy, and Caddy state to produce a useful plan. It does not need write access to those system configurations.
