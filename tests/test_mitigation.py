"""Unit tests for M8 — mitigation safety rails (fully mocked, nothing executed)."""

from types import SimpleNamespace

import pytest

import exfiltrap.mitigation as mit
from exfiltrap import config
from exfiltrap.mitigation import (
    IptablesMitigation,
    LogOnlyMitigation,
    SafetyError,
    validate_ip,
)


def assessment(risk="HIGH", ip="10.99.0.2"):
    return SimpleNamespace(src_ip=ip, risk_level=risk, timestamp=1.0)


class TestValidation:
    @pytest.mark.parametrize("bad", ["999.1.1.1", "abc", "", "10.0.0", "1.2.3.4.5"])
    def test_malformed_ips_refused(self, bad):
        with pytest.raises(SafetyError):
            validate_ip(bad)

    def test_valid_ip_passes(self):
        assert validate_ip("10.99.0.2") == "10.99.0.2"


class TestLogOnly:
    def test_blocks_high_and_confirmed(self):
        log = LogOnlyMitigation()
        assert log.notify(assessment("CONFIRMED", ip="10.99.0.2")) is True
        assert log.notify(assessment("HIGH", ip="10.99.0.3")) is True
        assert log.blocked_ips == {"10.99.0.2", "10.99.0.3"}

    def test_ignores_low_and_medium(self):
        log = LogOnlyMitigation()
        assert log.notify(assessment("LOW")) is False
        assert log.notify(assessment("MEDIUM")) is False
        assert log.blocked_ips == set()

    def test_dedups(self):
        log = LogOnlyMitigation()
        assert log.notify(assessment("HIGH")) is True
        assert log.notify(assessment("HIGH")) is False
        assert len(log.events) == 1


class TestIptablesPaths:
    def test_inside_namespace_direct_iptables(self, monkeypatch):
        monkeypatch.setattr(mit, "running_inside_namespace", lambda name: True)
        m = IptablesMitigation(dry_run=True)
        assert m.block_ip("10.99.0.2") is True
        assert m.pending_commands() == [
            ["iptables", "-A", "INPUT", "-s", "10.99.0.2", "-j", "DROP"]
        ]

    def test_inside_namespace_executes_when_not_dry(self, monkeypatch):
        monkeypatch.setattr(mit, "running_inside_namespace", lambda name: True)
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stderr=b"")

        monkeypatch.setattr(mit.subprocess, "run", fake_run)
        m = IptablesMitigation(dry_run=False)
        assert m.block_ip("10.99.0.2") is True
        assert calls == [["iptables", "-A", "INPUT", "-s", "10.99.0.2", "-j", "DROP"]]
        assert m.errors() == []
        # Duplicate suppression: second call is a no-op.
        assert m.block_ip("10.99.0.2") is False
        assert len(calls) == 1

    def test_host_with_namespace_scopes_via_netns_exec(self, monkeypatch):
        monkeypatch.setattr(mit, "running_inside_namespace", lambda name: False)
        monkeypatch.setattr(mit, "namespace_exists", lambda name: True)
        monkeypatch.setattr(mit, "current_netns_key", lambda: (1, 100))
        monkeypatch.setattr(mit, "host_netns_key", lambda: (1, 100))
        monkeypatch.setattr(mit, "named_netns_key", lambda name: (2, 200))
        m = IptablesMitigation(dry_run=True)
        m.block_ip("10.99.0.2")
        assert m.pending_commands()[0] == [
            "ip", "netns", "exec", "nsA", "iptables",
            "-A", "INPUT", "-s", "10.99.0.2", "-j", "DROP",
        ]

    def test_unreadable_namespace_keys_fall_back_to_netns_exec(self, monkeypatch):
        # Sandbox/restricted stat: keys unreadable. The netns-exec route
        # targets nsA's ruleset explicitly, safe regardless of location.
        monkeypatch.setattr(mit, "running_inside_namespace", lambda name: False)
        monkeypatch.setattr(mit, "namespace_exists", lambda name: True)
        monkeypatch.setattr(mit, "current_netns_key", lambda: None)
        monkeypatch.setattr(mit, "host_netns_key", lambda: (1, 100))
        monkeypatch.setattr(mit, "named_netns_key", lambda name: None)
        m = IptablesMitigation(dry_run=True)
        assert m.block_ip("10.99.0.2") is True
        assert m.pending_commands()[0][:4] == ["ip", "netns", "exec", "nsA"]

    def test_other_namespace_refused(self, monkeypatch):
        monkeypatch.setattr(mit, "running_inside_namespace", lambda name: False)
        monkeypatch.setattr(mit, "namespace_exists", lambda name: True)
        monkeypatch.setattr(mit, "current_netns_key", lambda: (3, 300))
        monkeypatch.setattr(mit, "host_netns_key", lambda: (1, 100))
        monkeypatch.setattr(mit, "named_netns_key", lambda name: (2, 200))
        executed = []
        monkeypatch.setattr(mit.subprocess, "run", lambda a, **k: executed.append(a))
        m = IptablesMitigation(dry_run=False)
        with pytest.raises(SafetyError, match="non-host namespace"):
            m.block_ip("10.99.0.2")
        assert executed == []

    def test_missing_namespace_without_override_refused(self, monkeypatch):
        monkeypatch.setattr(mit, "running_inside_namespace", lambda name: False)
        monkeypatch.setattr(mit, "namespace_exists", lambda name: False)
        executed = []
        monkeypatch.setattr(mit.subprocess, "run", lambda a, **k: executed.append(a))
        m = IptablesMitigation(dry_run=False)
        with pytest.raises(SafetyError, match="i-know-this-is-isolated"):
            m.block_ip("10.99.0.2")
        assert executed == []

    def test_missing_namespace_with_override_allowed(self, monkeypatch):
        monkeypatch.setattr(mit, "running_inside_namespace", lambda name: False)
        monkeypatch.setattr(mit, "namespace_exists", lambda name: False)
        calls = []
        monkeypatch.setattr(
            mit.subprocess, "run",
            lambda argv, **k: calls.append(argv) or SimpleNamespace(
                returncode=0, stderr=b""),
        )
        m = IptablesMitigation(
            dry_run=False, override_flag=config.IPTABLES_OVERRIDE_FLAG
        )
        assert m.block_ip("10.99.0.2") is True
        assert calls == [["iptables", "-A", "INPUT", "-s", "10.99.0.2", "-j", "DROP"]]

    def test_failed_execution_recorded(self, monkeypatch):
        monkeypatch.setattr(mit, "running_inside_namespace", lambda name: True)
        monkeypatch.setattr(
            mit.subprocess, "run",
            lambda argv, **k: SimpleNamespace(returncode=2, stderr=b"boom"),
        )
        m = IptablesMitigation(dry_run=False)
        assert m.block_ip("10.99.0.2") is False
        assert m.errors() and "rc=2" in m.errors()[0]
        assert not m.is_blocked("10.99.0.2")

    def test_notify_respects_risk_levels(self, monkeypatch):
        monkeypatch.setattr(mit, "running_inside_namespace", lambda name: True)
        m = IptablesMitigation(dry_run=True)
        assert m.notify(assessment("LOW")) is False
        assert m.notify(assessment("HIGH")) is True


class TestRealHostDefaults:
    def test_no_namespace_here_means_refusal_by_default(self):
        # On a plain host without the lab set up, dry-run mode must still
        # raise because no safe target ruleset exists.
        if mit.namespace_exists(config.NAMESPACE_NAME):
            pytest.skip("lab namespace present on this machine")
        m = IptablesMitigation(dry_run=True)
        with pytest.raises(SafetyError):
            m.block_ip("10.99.0.2")
