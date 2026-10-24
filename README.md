# NetSentry

NetSentry is a small, read-only homelab security utility. The initial release checks HTTPS certificate details for one explicitly named host.

## Install

Requires Python 3.10 or newer. On Windows, follow [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) to create a virtual environment and install the package.

## Use

```powershell
netsentry --help
netsentry check-https example.com
netsentry check-https example.com --json
netsentry check-https nas.home.arpa --port 8443
```

The certificate check validates TLS using the system trust store and reports subject, issuer, expiry, and remaining days. It makes no application-level request and changes no configuration. See [docs/SECURITY.md](docs/SECURITY.md) for scope.

## Project layout

- `src/netsentry/` Python package and CLI
- `tests/` automated tests
- `examples/targets.txt` sample target list format (not automatically read)
- `docs/` safety and development notes

## GitHub setup

The connected GitHub integration can work with existing repositories but does not expose a repository-creation action. Create a repository named `netsentry-homelab-security` in GitHub, then from this folder run:

```powershell
git init
git add .
git commit -m "Initial NetSentry project"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/netsentry-homelab-security.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username. Run these after reviewing the local project.

Open `http://127.0.0.1:8080` for the browser interface. To access it from another device on your LAN, start `netsentry gui --host 0.0.0.0` and open `http://<pi-ip-address>:8080` from that device. The GUI listens on localhost by default.
