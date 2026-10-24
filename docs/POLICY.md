# Exposure policy format

NetSentry policies are JSON documents with `version: 1` and an `apps` array. Each app declares an `exposure` of `proxy-only`, `lan`, or `public`.

Example entry:

```json
{
  "name": "Example dashboard",
  "exposure": "proxy-only",
  "container_names": ["example-dashboard"],
  "container_ports": [8080],
  "host_ports": [],
  "domains": ["dashboard.home.arpa"],
  "upstreams": ["example-dashboard:8080"],
  "allowed_sources": []
}
```

`container_names` must match Docker's exact container name. `container_ports` narrows a container to specific internal ports when one container serves more than one exposure type. `host_ports` identifies non-Docker listeners belonging to the app. For `proxy-only`, list the expected Caddy `domains` and `upstreams`; the audit checks whether those strings appear in the Caddyfile and flags non-loopback direct listeners/publications. For `lan`, set `allowed_sources` to the intended CIDR(s), such as `192.168.0.0/24`. For `public`, the audit reports observed ports but marks internet reachability for manual review because it cannot inspect router/NAT or external DNS.

The audit is intentionally conservative. Docker-published traffic can bypass UFW's normal input rules, so a LAN policy for a Docker-published port requires review of Docker-specific filtering (such as `DOCKER-USER`) and external reachability. `pass` means only that the specific checked condition matched; it is not a complete security certification. `review` means evidence is incomplete or needs human interpretation. `mismatch` means an observed setting conflicts with the declared policy.

The audit only reads local information. It does not edit firewall rules, Caddy configuration, Docker containers, or policies.


