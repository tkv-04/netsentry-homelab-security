# Windows and VS Code setup

1. Install Python 3.10 or newer and Git.
2. Open this folder in VS Code and select its Python interpreter.
3. In the integrated PowerShell terminal, run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest
```

If PowerShell blocks activation, use `.venv\Scripts\python.exe -m pip install -e ".[dev]"`.

Run a check with `netsentry check-https example.com`; use `--json` for JSON output. The command only connects to the explicitly named host and port.

Start the local browser interface with `netsentry gui` and open `http://127.0.0.1:8080`. For access from another device on your LAN, use `netsentry gui --host 0.0.0.0` and browse to the machine's LAN IP on port `8080`.
