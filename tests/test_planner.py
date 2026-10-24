from netsentry.planner import build_plan


def _base(policy, caddy_text=""):
    return build_plan(
        policy,
        {"available": True, "containers": []},
        {"available": True, "path": "Caddyfile", "output": caddy_text},
        {"available": True, "results": []},
        {"output": ""},
    )


def test_plan_proposes_private_caddy_site_without_writing():
    result = _base({"apps": [{"name": "Jackett", "exposure": "proxy-only",
                              "domains": ["jackett.home.arpa"], "upstreams": ["192.168.0.5:9117"]}]})
    assert "https://jackett.home.arpa {" in result["diff"]
    assert "tls internal" in result["diff"]
    assert "reverse_proxy 192.168.0.5:9117" in result["diff"]
    assert result["writes_performed"] is False
    assert result["safe_to_apply"] is False


def test_plan_blocks_proxy_only_published_port_and_keeps_caddy_proposal():
    policy = {"apps": [{"name": "Jackett", "exposure": "proxy-only", "container_names": ["jackett"],
                       "container_ports": [9117], "domains": ["jackett.home.arpa"],
                       "upstreams": ["192.168.0.5:9117"]}]}
    result = build_plan(policy,
                        {"available": True, "containers": [{"Names": "jackett", "Ports": "0.0.0.0:9117->9117/tcp"}]},
                        {"available": True, "output": ""}, {"results": []}, {"output": ""})
    assert result["summary"]["blocked"] >= 1
    assert any(item["code"] == "proxy-only-published" for item in result["items"])
    assert "https://jackett.home.arpa {" in result["diff"]


def test_plan_refuses_unsafe_caddy_values():
    result = _base({"apps": [{"name": "Bad", "exposure": "lan", "domains": ["x.home.arpa {\nfoo"],
                              "upstreams": ["127.0.0.1:1"]}]})
    assert result["diff"] == ""
    assert any(item["code"] == "unsafe-route-value" and item["status"] == "blocked"
               for item in result["items"])


def test_plan_refuses_duplicate_or_partial_caddy_site():
    result = _base({"apps": [{"name": "App", "exposure": "lan", "domains": ["app.home.arpa"],
                              "upstreams": ["127.0.0.1:1234"]}]}, "https://app.home.arpa {\n}\n")
    assert result["diff"] == ""
    assert any(item["code"] == "partial-caddy-route" for item in result["items"])


def test_plan_does_not_generate_firewall_commands_for_docker():
    policy = {"apps": [{"name": "Portainer", "exposure": "lan", "container_names": ["portainer"],
                       "container_ports": [9443], "allowed_sources": ["192.168.0.0/24"]}]}
    result = build_plan(policy,
                        {"available": True, "containers": [{"Names": "portainer", "Ports": "0.0.0.0:9443->9443/tcp"}]},
                        {"available": True, "output": ""}, {"results": []}, {"output": ""})
    assert result["diff"] == ""
    assert any(item["status"] == "review" and item["code"] == "lan-wildcard-bind"
               for item in result["items"])
    assert "iptables" not in str(result)

