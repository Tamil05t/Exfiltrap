"""Unit tests for M8 — mitigation safety rails (fully mocked, nothing executed)."""

import time
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


class TestDomainSinkhole:
    """Domain-level response: flagged hostnames sinkholed via the hosts
    file (single-host deployments where source-blocking = self-blocking).

    The escalation rules encode the shipped-1.4.0 outage fix: a single
    suspicious query can never take a machine offline — decode-confirmed
    verdicts sink immediately, probability-only verdicts need strikes on
    the same base domain, session-level timing evidence alone never sinks,
    and popular infrastructure is refused unconditionally.
    """

    def _make(self, tmp_path, ttl=3600.0, clock=time.time, strikes=3):
        from exfiltrap.mitigation import DomainSinkhole
        hosts = tmp_path / "hosts"
        hosts.write_text("127.0.0.1 localhost\n")
        return (DomainSinkhole(hosts_path=str(hosts), ttl=ttl, clock=clock,
                               strikes=strikes), hosts)

    @staticmethod
    def _assessment(qname, risk="HIGH", prob=0.9, confirmed=False,
                    domain_signal=False, ts=1.0, src_ip="10.99.0.2"):
        from types import SimpleNamespace

        reasons = [f"test {risk}"]
        if domain_signal:
            reasons.append("domain-level signal")
        return SimpleNamespace(
            risk_level=risk, src_ip=src_ip, qname=qname, timestamp=ts,
            rf_probability=prob, confirmed_exfiltration=confirmed,
            domain_signal=domain_signal, reasons=reasons)

    def test_block_and_unblock_domain(self, tmp_path):
        sn, hosts = self._make(tmp_path)
        assert sn.block_domain("evil.tunnel.example") is True
        text = hosts.read_text()
        assert "0.0.0.0 evil.tunnel.example" in text
        assert ":: evil.tunnel.example" in text  # both address families
        assert sn.MARKER in text
        # the base domain sinks too: sibling labels are the same channel
        assert sn.blocked_domains() == ["evil.tunnel.example",
                                        "tunnel.example"]
        assert sn.unblock_domain("evil.tunnel.example") is True
        assert "evil.tunnel.example" not in hosts.read_text()
        assert "tunnel.example" not in hosts.read_text()
        assert sn.blocked_domains() == []

    def test_idempotent_no_duplicate_lines(self, tmp_path):
        sn, hosts = self._make(tmp_path)
        sn.block_domain("a.example")
        sn.block_domain("a.example")
        text = hosts.read_text()
        # exactly one A line + one AAAA line, no matter how often sunk
        assert text.count("0.0.0.0 a.example") == 1
        assert text.count(":: a.example") == 1

    def test_injection_refused(self, tmp_path):
        sn, hosts = self._make(tmp_path)
        assert sn.block_domain("evil.example\n0.0.0.0 google.com") is False
        assert sn.block_domain("evil.example extra stuff") is False
        assert hosts.read_text() == "127.0.0.1 localhost\n"

    def test_ttl_expiry_removes_entry(self, tmp_path):
        clock = {"t": 1000.0}
        sn, hosts = self._make(tmp_path, ttl=600.0, clock=lambda: clock["t"])
        sn.block_domain("drip.example", timestamp=1000.0)
        assert "drip.example" in hosts.read_text()
        clock["t"] += 601.0
        assert sn.reap_expired() == ["drip.example"]
        assert "drip.example" not in hosts.read_text()

    # -- evidence gating (the 1.4.0 outage fix) ---------------------------

    def test_confirmed_sinks_immediately(self, tmp_path):
        sn, hosts = self._make(tmp_path)
        assert sn.notify(self._assessment("x.tunnel.example",
                                          confirmed=True)) is True
        assert "0.0.0.0 x.tunnel.example" in hosts.read_text()

    def test_single_high_prob_verdict_does_not_sink(self, tmp_path):
        sn, hosts = self._make(tmp_path)
        assert sn.notify(self._assessment("maybe.example", prob=0.9)) is False
        assert hosts.read_text() == "127.0.0.1 localhost\n", \
            "one probability verdict must never cut a hostname"

    def test_high_strikes_accumulate_per_base_domain(self, tmp_path):
        sn, hosts = self._make(tmp_path, strikes=3)
        # rotating labels under one base domain: 1st and 2nd defer...
        assert sn.notify(self._assessment("l1.evil.example", ts=1.0)) is False
        assert sn.notify(self._assessment("l2.evil.example", ts=2.0)) is False
        # ...the 3rd convicts the base: this label AND the base sink
        assert sn.notify(self._assessment("l3.evil.example", ts=3.0)) is True
        text = hosts.read_text()
        assert "l3.evil.example" in text and "evil.example" in text

    def test_convicted_base_sinks_new_labels_on_sight(self, tmp_path):
        sn, hosts = self._make(tmp_path, strikes=2)
        sn.notify(self._assessment("l1.evil.example", ts=1.0))
        assert sn.notify(self._assessment("l2.evil.example", ts=2.0)) is True
        # conviction active: a brand-new label sinks without more strikes
        assert sn.notify(self._assessment("brand-new.evil.example",
                                          ts=3.0)) is True
        assert "brand-new.evil.example" in hosts.read_text()

    def test_session_only_evidence_never_sinks(self, tmp_path):
        """Per-source timing flags (slow-drip/beacon on the operator's own
        machine) must NEVER sink domains — this was the google.com outage."""
        sn, hosts = self._make(tmp_path)
        for i in range(10):
            a = self._assessment(f"site{i}.example.com", prob=0.0, ts=i)
            # simulate a session-flag-only HIGH: prob below threshold,
            # no decode, no domain signal
            assert sn.notify(a) is False
        assert "google" not in hosts.read_text()
        assert "example.com" not in hosts.read_text()

    def test_popular_domains_never_sink(self, tmp_path):
        sn, hosts = self._make(tmp_path)
        from exfiltrap import reputation

        reputation.reload()  # ensure the shipped corpus is loaded
        assert sn.notify(self._assessment("accounts.google.com",
                                          confirmed=True)) is False
        assert sn.notify(self._assessment("l1.gstatic.com",
                                          confirmed=True)) is False
        assert sn.notify(self._assessment("weird.l1.gstatic.com",
                                          confirmed=True)) is False
        assert "google" not in hosts.read_text()
        assert "gstatic" not in hosts.read_text()

    def test_cleanup_removes_every_managed_entry(self, tmp_path):
        sn, hosts = self._make(tmp_path)
        sn.block_domain("a.example")
        sn.block_domain("b.example")
        hosts.write_text(hosts.read_text() + "1.2.3.4 operator-entry\n")
        freed = sn.cleanup()
        assert freed == 2
        text = hosts.read_text()
        assert "a.example" not in text and "b.example" not in text
        assert "operator-entry" in text, "operator lines must survive"
        assert sn.blocked_domains() == []

    def test_is_sunk_and_hits(self, tmp_path):
        sn, _ = self._make(tmp_path)
        sn.block_domain("a.evil.example")
        # the sunk qname AND every sibling under the (auto-sunk) base
        assert sn.is_sunk("a.evil.example") is True
        assert sn.is_sunk("b.evil.example") is True
        assert sn.is_sunk("other.example") is False
        assert sn.register_hit("a.evil.example") == 1
        assert sn.register_hit("a.evil.example") == 2
        assert sn.hits() == {"evil.example": 2}

    def test_notify_low_level_ignored(self, tmp_path):
        sn, hosts = self._make(tmp_path)
        assert sn.notify(self._assessment("x.example", risk="MEDIUM",
                                          prob=0.7)) is False
        assert hosts.read_text() == "127.0.0.1 localhost\n"

    # -- policy: self-DoS guard and allowlist -----------------------------

    def test_notify_high_only_and_allowlisted_source_skipped(self, tmp_path):
        from exfiltrap.policy import make_policy
        from exfiltrap.mitigation import LogOnlyMitigation

        sn, hosts = self._make(tmp_path)
        pol = make_policy(LogOnlyMitigation(), allowlist=["10.0.0.9"],
                          sinkhole=sn)
        # remote attacker, decode-confirmed qname: sinks + source-blocks
        pol.notify(self._assessment("bad.example", confirmed=True, ts=1.0))
        assert "bad.example" in hosts.read_text()
        # allowlisted source: neither sink nor firewall — policy decision
        pol.notify(self._assessment("allowed.example", confirmed=True,
                                    ts=2.0, src_ip="10.0.0.9"))
        assert "allowed.example" not in hosts.read_text()
        pol.notify(self._assessment("quiet.example", risk="LOW", prob=0.1,
                                    ts=3.0))
        assert "quiet.example" not in hosts.read_text()

    def test_own_source_never_firewalled(self, tmp_path):
        """The single-host self-DoS guard: loopback / own LAN IP sources
        are never firewall targets; the domain response handles them."""
        from exfiltrap.policy import make_policy
        from exfiltrap.mitigation import LogOnlyMitigation

        sn, hosts = self._make(tmp_path)
        pol = make_policy(LogOnlyMitigation(), sinkhole=sn,
                          own_ips=("10.0.0.5",))
        # own LAN IP, CONFIRMED qname: domain response fires, source not blocked
        assert pol.notify(self._assessment("x.evil.example", confirmed=True,
                                           src_ip="10.0.0.5")) is True
        assert "0.0.0.0 x.evil.example" in hosts.read_text()
        assert pol.is_blocked("10.0.0.5") is False
        assert pol.last_response == "domain"
        assert pol.last_target == "x.evil.example"
        # loopback source: same guard
        assert pol.notify(self._assessment("lo.evil.example", confirmed=True,
                                           src_ip="127.0.0.1")) is True
        assert not pol.is_blocked("127.0.0.1")
        # own IP, no sinkhole configured: explicitly deferred, not blocked
        pol2 = make_policy(LogOnlyMitigation(), own_ips=("10.0.0.5",))
        assert pol2.notify(self._assessment("y.evil.example", confirmed=True,
                                            src_ip="10.0.0.5")) is False
        assert pol2.last_response == "deferred"
        assert not pol2.is_blocked("10.0.0.5") and not pol2.is_blocked("127.0.0.1")
        # remote source still gets the classic firewall response
        pol3 = make_policy(LogOnlyMitigation(), own_ips=("10.0.0.5",))
        assert pol3.notify(self._assessment("z.evil.example",
                                            confirmed=True)) is True
        assert pol3.last_response == "source"
        assert pol3.last_target == "10.99.0.2"
