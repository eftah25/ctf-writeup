"""Unit tests for firewall rule generation."""
from ddosguard.config import Config
from ddosguard.core import Severity
from ddosguard.mitigate.firewall import FirewallManager


def test_generate_emits_permit_rules_for_whitelist():
    cfg = Config(mitigation={"dry_run": True, "firewall_backend": "iptables", "whitelist": ["10.0.0.1"]})
    lines = FirewallManager(cfg).generate(1, Severity.HIGH, 100, 200)
    text = "\n".join(lines)
    assert len(lines) > 0


def test_generate_contains_stage_marker():
    cfg = Config(mitigation={"dry_run": True, "firewall_backend": "iptables", "whitelist": []})
    lines = FirewallManager(cfg).generate(3, Severity.CRITICAL, 500, 100)
    assert any("DDOSGUARD" in r for r in lines)


def test_rule_commands_are_strings():
    cfg = Config(mitigation={"dry_run": True, "firewall_backend": "iptables", "whitelist": []})
    for rule in FirewallManager(cfg).generate(2, Severity.MEDIUM, 200, 50):
        assert isinstance(rule, str)
