# NetSentry

NetSentry is a read-only homelab security tool with a Typer CLI and browser interface. The roadmap and implementation status are tracked in [PROJECT-STATUS.md](PROJECT-STATUS.md).

## Install

Requires Python 3.10 or newer.

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest -q
```

Raspberry Pi OS / Linux:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

## Read-only inspection CLI

Run these commands on the machine you want to inspect:

```bash
netsentry inspect ports
netsentry inspect docker-ports
netsentry inspect caddy
netsentry inspect caddy --path /etc/caddy/Caddyfile
netsentry inspect firewall
```

Add `--json` for machine-readable output. Docker and firewall details may require root. In an activated Linux venv, use `sudo "$(command -v netsentry)" inspect docker-ports` or `sudo "$(command -v netsentry)" inspect firewall`. These commands only read state.

## Phase 2: policy audit

Copy `examples/policies.example.json` to a local policy file and add a policy for each app. Choose `proxy-only`, `lan`, or `public` based on your intent; see [docs/POLICY.md](docs/POLICY.md) for fields and limitations.

```bash
sudo "$(command -v netsentry)" audit policies.json --caddyfile /etc/caddy/Caddyfile
sudo "$(command -v netsentry)" audit policies.json --caddyfile /etc/caddy/Caddyfile --json
```

The audit compares declared policies with local Docker publications, listeners, Caddyfile content, and UFW observations. It reports mismatches and items needing review. It does not change system configuration. Internet reachability and Docker-specific filtering require human review.

## HTTPS checks

Check one host or a manually supplied list of up to 25:

```bash
netsentry check-https ha.home.arpa --port 443
netsentry check-list examples/targets.txt --port 443 --json
```

The target file has one hostname or IP per line. Blank lines and `#` comments are ignored. TLS certificate and hostname validation uses the local system trust store.

## Browser GUI

Start the GUI on a free port:

```bash
netsentry gui --host 0.0.0.0 --port 8081
```

Open `http://<pi-ip-address>:8081` from your LAN. The default bind is `127.0.0.1`; use `0.0.0.0` only for LAN access you intend to allow. The GUI has no login or TLS of its own, so restrict its network access accordingly.

## Safety

NetSentry inspection and audit commands are read-only. They do not modify listening services, Docker, Caddy, firewall rules, or policy files. See [docs/SECURITY.md](docs/SECURITY.md).

## Phase 3: dry-run change planner

Generate a proposal from current observations. The planner can show a unified diff for missing Caddy routes when each declared domain has one safe, paired upstream. It flags direct Docker exposure as blocked when the deployment source needed for a safe binding change is unavailable, and it leaves Docker firewall changes for operator review.

```bash
sudo "$(command -v netsentry)" plan policies.json --caddyfile /etc/caddy/Caddyfile
sudo "$(command -v netsentry)" plan policies.json --caddyfile /etc/caddy/Caddyfile --json
```

The planner never writes the Caddyfile or policies, runs firewall commands, changes Docker, or restarts services. A proposed diff still needs review and validation before anyone applies it. See [docs/PLANNER.md](docs/PLANNER.md).
