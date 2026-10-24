"""Build review-only configuration proposals from policy audit findings."""
from __future__ import annotations

import difflib
import re
from typing import Any

from netsentry.audit import audit_policy

_DOMAIN = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::\d+)?\Z")
_UPSTREAM = re.compile(r"(?:[A-Za-z0-9_.:-]|\[[0-9A-Fa-f:]+\])+\Z")


def _caddy_block(domain: str, upstream: str) -> str:
    lines = [f"https://{domain} {{"]
    if domain.endswith(".home.arpa"):
        lines.append("    tls internal")
    lines.extend((f"    reverse_proxy {upstream}", "}"))
    return "\n".join(lines)


def build_plan(policy: dict[str, Any], docker: dict[str, Any], caddy: dict[str, Any],
               firewall: dict[str, Any], ports: dict[str, Any]) -> dict[str, Any]:
    """Return a proposed Caddy diff and review items; never writes files."""
    findings = audit_policy(policy, docker, caddy, firewall, ports)
    caddy_text = str(caddy.get("output", "")) if caddy.get("available") else ""
    proposed_blocks: list[tuple[str, str]] = []
    items: list[dict[str, str]] = []
    findings_by_app: dict[str, list[dict[str, str]]] = {}
    for finding in findings:
        findings_by_app.setdefault(finding["app"], []).append(finding)

    for app in policy["apps"]:
        name = app["name"]
        domains, upstreams = app.get("domains", []), app.get("upstreams", [])
        app_findings = findings_by_app.get(name, [])
        missing = any(item["code"] in {"caddy-route-missing", "caddy-upstream-missing"}
                      for item in app_findings)
        if missing:
            if not caddy.get("available"):
                items.append({"status": "blocked", "app": name, "code": "caddy-unavailable",
                              "message": "Cannot propose a Caddy diff because the Caddyfile could not be read."})
            elif len(domains) != len(upstreams) or not domains:
                items.append({"status": "blocked", "app": name, "code": "route-pairing-ambiguous",
                              "message": "Each Caddy domain needs exactly one corresponding upstream in the same order."})
            else:
                invalid = [f"{domain} -> {upstream}" for domain, upstream in zip(domains, upstreams)
                           if not _DOMAIN.fullmatch(domain) or not _UPSTREAM.fullmatch(upstream)]
                if invalid:
                    items.append({"status": "blocked", "app": name, "code": "unsafe-route-value",
                                  "message": "Domain or upstream contains unsupported Caddy syntax: " + ", ".join(invalid)})
                elif any(domain in caddy_text for domain in domains):
                    items.append({"status": "blocked", "app": name, "code": "partial-caddy-route",
                                  "message": "A domain already appears in the Caddyfile; refusing a possibly duplicate or conflicting site block."})
                else:
                    proposed_blocks.extend((domain, _caddy_block(domain, upstream))
                                           for domain, upstream in zip(domains, upstreams))
                    items.append({"status": "proposed", "app": name, "code": "caddy-route-addition",
                                  "message": f"Propose a Caddy site block for {', '.join(domains)}. Review and validate it before applying."})

        for finding in app_findings:
            code = finding["code"]
            if code == "proxy-only-published":
                items.append({"status": "blocked", "app": name, "code": code,
                              "message": "Direct exposure conflicts with proxy-only intent. A safe binding change needs the authoritative Compose/run configuration; NetSentry will not guess or alter Docker state."})
            elif code in {"docker-firewall-review", "lan-wildcard-bind", "lan-ufw-anywhere",
                          "lan-source-rule-missing"}:
                items.append({"status": "review", "app": name, "code": code,
                              "message": "Firewall or Docker source filtering needs operator review. No firewall command is generated because published Docker traffic may bypass UFW."})
            elif code in {"unassigned-published-container", "policy-empty"}:
                items.append({"status": "review", "app": name, "code": code, "message": finding["message"]})

    proposed = caddy_text
    if proposed_blocks:
        if proposed and not proposed.endswith("\n"):
            proposed += "\n"
        proposed += "\n".join(block for _, block in sorted(proposed_blocks)) + "\n"
    diff_lines = list(difflib.unified_diff(
        caddy_text.splitlines(), proposed.splitlines(),
        fromfile=str(caddy.get("path", "Caddyfile")), tofile="Caddyfile (proposed)",
        lineterm="",
    ))
    diff = "\n".join(diff_lines) + ("\n" if diff_lines else "")
    unique_items = []
    seen_items = set()
    for item in items:
        identity = (item["status"], item["app"], item["code"], item["message"])
        if identity not in seen_items:
            seen_items.add(identity)
            unique_items.append(item)
    items = unique_items
    if not items:
        items.append({"status": "no-change", "app": "policy", "code": "no-proposal",
                      "message": "No supported changes were identified from current observations."})
    return {
        "mode": "dry-run", "writes_performed": False, "safe_to_apply": False,
        "summary": {status: sum(item["status"] == status for item in items)
                    for status in ("proposed", "review", "blocked", "no-change")},
        "items": items, "diff": diff,
        "note": "Proposal only. NetSentry does not write configuration, apply firewall rules, restart services, or validate against the running server.",
    }


