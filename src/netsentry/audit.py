"""Compare declared app exposure policies with read-only observations."""

from __future__ import annotations

import ipaddress
import re
from typing import Any


def docker_bindings(report: dict[str, Any]) -> list[dict[str, Any]]:
    bindings = []
    pattern = re.compile(r"(?:(\[[^]]+\]|[^,:]+):)?(\d+)-(?:\d+)->(\d+)-(?:\d+)/(tcp|udp)")
    single_pattern = re.compile(r"(?:(\[[^]]+\]|[^,:]+):)?(\d+)->(\d+)/(tcp|udp)")
    for container in report.get("containers", []):
        published = str(container.get("Ports", ""))
        for item in published.split(","):
            entry = item.strip()
            match = single_pattern.fullmatch(entry) or pattern.fullmatch(entry)
            if not match:
                continue
            host_ip, host_port, container_port, protocol = match.groups()
            bindings.append({
                "container": container.get("Names", container.get("ID", "unknown")),
                "image": container.get("Image", ""),
                "host_ip": (host_ip or "0.0.0.0").strip("[]"),
                "host_port": int(host_port),
                "container_port": int(container_port),
                "protocol": protocol,
            })
    return bindings


def _is_wildcard(address: str) -> bool:
    return address in {"0.0.0.0", "::", "*", ""}


def _is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return address == "localhost"


def _ufw_rules(report: dict[str, Any]) -> list[dict[str, Any]]:
    rules = []
    for result in report.get("results", []):
        if "ufw" not in " ".join(result.get("command", [])):
            continue
        for line in str(result.get("output", "")).splitlines():
            if "ALLOW IN" not in line:
                continue
            left, right = line.split("ALLOW IN", 1)
            port_tokens = [token for token in left.split()
                           if re.fullmatch(r"\d+(?:/(?:tcp|udp))?", token)]
            if not port_tokens:
                continue
            port = int(port_tokens[-1].split("/", 1)[0])
            source = right.strip().split()[0] if right.strip() else ""
            rules.append({"port": port, "source": source, "line": line.strip()})
    return rules

def _host_listeners(report: dict[str, Any]) -> set[tuple[str, int]]:
    listeners: set[tuple[str, int]] = set()
    for line in str(report.get("output", "")).splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[1] not in {"LISTEN", "UNCONN"}:
            continue
        endpoint = parts[4]
        if endpoint.startswith("[") and "]:" in endpoint:
            address, port = endpoint[1:].rsplit("]:", 1)
        elif ":" in endpoint:
            address, port = endpoint.rsplit(":", 1)
        else:
            continue
        if port.isdigit():
            listeners.add((address, int(port)))
    return listeners


def audit_policy(
    policy: dict[str, Any], docker: dict[str, Any], caddy: dict[str, Any], firewall: dict[str, Any], ports: dict[str, Any]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not policy["apps"]:
        findings.append({"severity": "review", "code": "policy-empty", "app": "policy",
                         "message": "No app exposure policies are defined; add apps before treating this audit as meaningful."})
    bindings = docker_bindings(docker)
    ufw = _ufw_rules(firewall)
    listeners = _host_listeners(ports)
    configured_bindings: set[tuple[str, int, str]] = set()
    caddy_text = str(caddy.get("output", "")) if caddy.get("available") else ""
    docker_available = docker.get("available") and "containers" in docker

    for app in policy["apps"]:
        name = app["name"]
        exposure = app["exposure"]
        app_containers = set(app.get("container_names", []))
        app_ports = set(app.get("host_ports", []))
        container_ports = set(app.get("container_ports", []))
        matched = [item for item in bindings if item["container"] in app_containers
                   and (not container_ports or item["container_port"] in container_ports)]
        configured_bindings.update((item["container"], item["container_port"], item["protocol"])
                                   for item in matched)
        observed_ports = {item["host_port"] for item in matched}
        observed_ports.update(port for _, port in listeners if port in app_ports)

        if app_containers and not docker_available:
            findings.append({"severity": "review", "code": "docker-inventory-unavailable", "app": name,
                             "message": "Docker inventory is unavailable; run the audit with permission to query Docker."})
        if app_containers and docker_available and not any(
            item.get("Names", item.get("ID")) in app_containers for item in docker.get("containers", [])
        ):
            findings.append({"severity": "review", "code": "container-not-found", "app": name,
                             "message": "No configured Docker container name matched the current inventory."})

        if exposure != "proxy-only":
            for domain in app.get("domains", []):
                if not caddy.get("available"):
                    findings.append({"severity": "review", "code": "caddy-unavailable", "app": name,
                                     "message": f"Could not inspect Caddy to verify route for {domain}."})
                elif domain not in caddy_text:
                    findings.append({"severity": "mismatch", "code": "caddy-route-missing", "app": name,
                                     "message": f"Configured Caddyfile does not contain domain {domain}."})
            for upstream in app.get("upstreams", []):
                if not caddy.get("available"):
                    findings.append({"severity": "review", "code": "caddy-unavailable", "app": name,
                                     "message": f"Could not inspect Caddy to verify upstream {upstream}."})
                elif upstream not in caddy_text:
                    findings.append({"severity": "mismatch", "code": "caddy-upstream-missing", "app": name,
                                     "message": f"Configured Caddyfile does not contain upstream {upstream}."})
        if exposure == "proxy-only":
            broad = [item for item in matched if not _is_loopback(item["host_ip"])]
            broad.extend({"host_ip": address, "host_port": port} for address, port in listeners
                         if port in app_ports and not _is_loopback(address))
            if broad:
                ports_text = ", ".join(f"{item['host_ip']}:{item['host_port']}" for item in broad)
                findings.append({"severity": "mismatch", "code": "proxy-only-published", "app": name,
                                 "message": f"Direct host or Docker ports are bound outside loopback: {ports_text}."})
            for domain in app.get("domains", []):
                if not caddy.get("available"):
                    findings.append({"severity": "review", "code": "caddy-unavailable", "app": name,
                                     "message": f"Could not inspect Caddy to verify route for {domain}."})
                elif domain not in caddy_text:
                    findings.append({"severity": "mismatch", "code": "caddy-route-missing", "app": name,
                                     "message": f"Configured Caddyfile does not contain domain {domain}."})
            for upstream in app.get("upstreams", []):
                if caddy.get("available") and upstream not in caddy_text:
                    findings.append({"severity": "mismatch", "code": "caddy-upstream-missing", "app": name,
                                     "message": f"Configured Caddyfile does not contain upstream {upstream}."})
            if not app.get("domains") or not app.get("upstreams"):
                findings.append({"severity": "review", "code": "proxy-route-incomplete", "app": name,
                                 "message": "Add expected Caddy domains and upstreams to verify the proxy route."})
            if docker_available and not broad and not any(item["app"] == name for item in findings):
                findings.append({"severity": "pass", "code": "proxy-only-direct-access", "app": name,
                                 "message": "No non-loopback Docker port publication was observed for this app."})

        elif exposure == "lan":
            sources = set(app.get("allowed_sources", []))
            if not sources:
                findings.append({"severity": "review", "code": "lan-sources-unspecified", "app": name,
                                 "message": "Add allowed_sources (for example, a LAN CIDR) to make this policy testable."})
            for binding in matched:
                if _is_wildcard(binding["host_ip"]):
                    findings.append({"severity": "review", "code": "lan-wildcard-bind", "app": name,
                                     "message": f"Docker port {binding['host_port']} binds to all interfaces; verify Docker-specific source filtering."})
                else:
                    findings.append({"severity": "review", "code": "docker-firewall-review", "app": name,
                                     "message": f"Docker port {binding['host_port']} needs source filtering review; UFW rules alone may not filter published Docker traffic."})
            docker_ports = {item["host_port"] for item in matched}
            for port in app_ports - docker_ports:
                if not any(address in {"0.0.0.0", "::", "*"} or not _is_loopback(address)
                           for address, listener_port in listeners if listener_port == port):
                    findings.append({"severity": "review", "code": "listener-not-observed", "app": name,
                                     "message": f"Expected host port {port} was not found listening."})
                    continue
                rules = [rule for rule in ufw if rule["port"] == port]
                if any(rule["source"] == "Anywhere" or rule["source"] == "Anywhere(v6)" for rule in rules):
                    findings.append({"severity": "mismatch", "code": "lan-ufw-anywhere", "app": name,
                                     "message": f"UFW allows host port {port} from Anywhere, broader than this LAN policy."})
                elif any(rule["source"] in sources for rule in rules):
                    findings.append({"severity": "pass", "code": "lan-source-rule", "app": name,
                                     "message": f"UFW has a matching source rule for host port {port}."})
                else:
                    findings.append({"severity": "review", "code": "lan-source-rule-missing", "app": name,
                                     "message": f"No matching UFW source rule was found for host port {port}."})
            if not matched and not app_ports:
                findings.append({"severity": "review", "code": "lan-target-unspecified", "app": name,
                                 "message": "Set container_names or host_ports so the observed service can be checked."})

        else:
            if not observed_ports:
                findings.append({"severity": "review", "code": "public-reachability-unverified", "app": name,
                                 "message": "No matching published/listening port was observed; router and internet reachability are not inspected."})
            else:
                findings.append({"severity": "review", "code": "public-reachability-unverified", "app": name,
                                 "message": f"Observed host ports {', '.join(map(str, sorted(observed_ports)))}; router, DNS, and external reachability still require verification."})

    if docker_available:
        for container in docker.get("containers", []):
            name = container.get("Names", container.get("ID", "unknown"))
            published = [item for item in bindings if item["container"] == name
                         and (item["container"], item["container_port"], item["protocol"]) not in configured_bindings]
            if published:
                findings.append({"severity": "review", "code": "unassigned-published-container", "app": name,
                                 "message": f"Published ports {', '.join(str(item['host_port']) for item in published)} have no exposure policy; image: {container.get('Image', 'unknown')}."})
    elif policy["apps"]:
        findings.append({"severity": "review", "code": "docker-inventory-unavailable", "app": "inventory",
                         "message": "Docker inventory is unavailable; run the audit with permission to query Docker."})

    return findings















