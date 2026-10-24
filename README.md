# NetSentry

NetSentry is a read-only homelab security tool with a Typer CLI and a small browser interface. Its original roadmap is tracked in [PROJECT-STATUS.md](PROJECT-STATUS.md).

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

Run these commands on the machine you want to inspect (for example, the Pi):

```bash
netsentry inspect ports
netsentry inspect docker-ports
netsentry inspect caddy
netsentry inspect caddy --path /etc/caddy/Caddyfile
netsentry inspect firewall
```

Add `--json` to any inspection command for machine-readable output. Port inspection uses `ss` on Linux and `netstat` on Windows. Docker output lists containers and published ports. Caddy inspection reads the Caddyfile and redacts lines that look like credentials. Firewall inspection reports available UFW, nftables, and iptables state. These commands only read local state; permission limits can make some details unavailable.

## HTTPS checks

Check one host or an explicit list of up to 25 hosts:

```bash
netsentry check-https ha.home.arpa --port 443
netsentry check-list examples/targets.txt --port 443 --json
```

The target file uses one hostname or IP address per line, with optional blank lines and `#` comments. Every check validates TLS and hostname identity using the local system trust store.

## Browser GUI

Start the GUI on a free port:

```bash
netsentry gui --host 0.0.0.0 --port 8081
```

Open `http://<pi-ip-address>:8081` from a device on the same home network. The default bind address is `127.0.0.1`; use `0.0.0.0` only when LAN access is wanted. The GUI supports manual HTTPS checks for up to 25 listed hosts.

## Safety

NetSentry does not change ports, Docker containers, Caddy configuration, firewall rules, or server settings. Inspection commands only query the current machine. See [docs/SECURITY.md](docs/SECURITY.md).

Docker may deny access to `/var/run/docker.sock` for a normal user. To inspect Docker once without changing group membership, run `sudo "$(command -v netsentry)" inspect docker-ports` from the activated virtual environment. The command only invokes `docker ps`.
