# NetSentry

NetSentry is a read-only homelab HTTPS certificate checker with both a command-line interface and a small browser interface.

## Requirements and installation

Python 3.10 or newer is required. On Windows, open this folder in VS Code and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest -q
```

On Raspberry Pi OS or another Linux system:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

## Use the CLI

Check one explicitly selected host:

```bash
netsentry check-https ha.home.arpa --port 443
netsentry check-https example.com --json
```

Check a list of up to 25 explicitly selected hosts, one hostname or IP per line:

```bash
netsentry check-list examples/targets.txt --port 443
netsentry check-list examples/targets.txt --port 443 --json
```

Blank lines and lines beginning with `#` are ignored. All hosts in a list use the same port. Each failed host is reported; the command exits with status 1 if any check fails.

## Use the browser GUI

Start it on the Pi, using a free port:

```bash
netsentry gui --host 0.0.0.0 --port 8081
```

From a device on the same home network, open `http://<pi-ip-address>:8081`. The GUI accepts up to 25 hosts, one per line, and checks them on the selected HTTPS port. For local-only access, omit `--host 0.0.0.0`; the default bind address is `127.0.0.1`.

The check validates TLS certificates against the Pi's system trust store. If Caddy uses its internal CA, install Caddy's root CA on the Pi running NetSentry. Use a hostname that resolves on the Pi and matches the certificate. Caddy's HTTPS listener is usually port 443; its HTTP upstream port is not an HTTPS check target.

## Scope

NetSentry only connects to the host and port explicitly entered by the user. It does not discover hosts, scan port ranges, authenticate, send HTTP requests, change services, or alter server configuration. See [docs/SECURITY.md](docs/SECURITY.md) and [PROJECT-STATUS.md](PROJECT-STATUS.md).
