# NetSentry project status

## Completed

- [x] Phase 1: single-host HTTPS certificate check with normal TLS certificate and hostname validation.
- [x] Phase 1: read-only Typer CLI with human-readable and JSON output.
- [x] Phase 1: browser GUI, bound to localhost by default and configurable for LAN use.
- [x] Phase 1: Windows/VS Code setup notes, safety documentation, example target list, and tests.
- [x] Pi validation: GUI reached from Windows; local DNS resolution and Caddy HTTPS were configured; Caddy's internal CA was trusted by the Pi; the check succeeded.
- [x] Phase 2: manually supplied multi-host HTTPS checks in both CLI and GUI, capped at 25 hosts per batch.
- [x] Phase 2: per-host success/failure details, including certificate subject and expiry for successful checks.
- [x] Phase 2: CLI JSON output and nonzero exit status when any target fails.

## Phase 2 usage

Add one host per line to `examples/targets.txt`, then run:

```bash
netsentry check-list examples/targets.txt --port 443
```

In the GUI, enter one hostname per line and click **Check certificates**. Each batch has a shared port and a 25-host limit. NetSentry only contacts the hosts explicitly listed; it does not perform network discovery.

## Verification

Run the tests after installing development dependencies:

```bash
python -m pytest -q
```

## Next ideas

- Saved, editable inventory and scan history.
- Expiry warning thresholds and report export.
- Optional scheduled checks.

These are future ideas, not implemented features.
