"""Tests for platform support: netsh mitigation backend and privileges."""

from types import SimpleNamespace

import pytest

import exfiltrap.mitigation as mit
import exfiltrap.privileges as priv
from exfiltrap.mitigation import NetshMitigation, SafetyError, make_mitigation


def assessment(risk="HIGH", ip="10.99.0.2"):
    return SimpleNamespace(src_ip=ip, risk_level=risk, timestamp=1.0)


class TestNetshMitigation:
    def test_dry_run_records_command(self, monkeypatch):
        monkeypatch.setattr(priv, "is_root", lambda: True)
        m = NetshMitigation(dry_run=True)
        assert m.block_ip("10.99.0.2") is True
        cmd = m.pending_commands()[0]
        assert cmd[0:5] == ["netsh", "advfirewall", "firewall", "add", "rule"]
        assert "name=ExfilTrap-block-10.99.0.2" in cmd
        assert "remoteip=10.99.0.2" in cmd
        assert "action=block" in cmd

    def test_non_admin_refused(self, monkeypatch):
        monkeypatch.setattr(priv, "is_root", lambda: False)
        m = NetshMitigation(dry_run=True)
        with pytest.raises(SafetyError, match="elevated"):
            m.block_ip("10.99.0.2")

    def test_admin_check_skippable(self, monkeypatch):
        monkeypatch.setattr(priv, "is_root", lambda: False)
        m = NetshMitigation(dry_run=True, require_admin=False)
        assert m.block_ip("10.99.0.2") is True

    def test_duplicate_suppressed(self, monkeypatch):
        monkeypatch.setattr(priv, "is_root", lambda: True)
        m = NetshMitigation(dry_run=True)
        assert m.block_ip("10.99.0.2") is True
        assert m.block_ip("10.99.0.2") is False
        assert len(m.pending_commands()) == 1

    def test_execution_path(self, monkeypatch):
        monkeypatch.setattr(priv, "is_root", lambda: True)
        calls = []
        monkeypatch.setattr(
            mit.subprocess, "run",
            lambda argv, **k: calls.append(argv) or SimpleNamespace(
                returncode=0, stderr=b""),
        )
        m = NetshMitigation(dry_run=False)
        assert m.block_ip("192.168.1.7") is True
        assert calls and calls[0][0] == "netsh"
        assert m.errors() == []

    def test_failed_execution_recorded(self, monkeypatch):
        monkeypatch.setattr(priv, "is_root", lambda: True)
        monkeypatch.setattr(
            mit.subprocess, "run",
            lambda argv, **k: SimpleNamespace(returncode=1, stderr=b"denied"),
        )
        m = NetshMitigation(dry_run=False)
        assert m.block_ip("192.168.1.7") is False
        assert m.errors() and "rc=1" in m.errors()[0]
        assert not m.is_blocked("192.168.1.7")

    def test_unblock_uses_own_prefix_only(self, monkeypatch):
        monkeypatch.setattr(priv, "is_root", lambda: True)
        m = NetshMitigation(dry_run=True)
        m.unblock_ip("10.0.0.5")
        cmd = m.pending_commands()[-1]
        assert "delete" in cmd
        assert any("ExfilTrap-block-10.0.0.5" in part for part in cmd)

    def test_malformed_ip_refused(self, monkeypatch):
        monkeypatch.setattr(priv, "is_root", lambda: True)
        with pytest.raises(SafetyError):
            NetshMitigation(dry_run=True).block_ip("10.0.0.999")

    def test_notify_respects_risk_levels(self, monkeypatch):
        monkeypatch.setattr(priv, "is_root", lambda: True)
        m = NetshMitigation(dry_run=True)
        assert m.notify(assessment("LOW")) is False
        assert m.notify(assessment("CONFIRMED")) is True


class TestFactory:
    def test_auto_selects_by_platform(self, monkeypatch):
        monkeypatch.setattr(mit.platform, "system", lambda: "Windows")
        assert isinstance(make_mitigation("auto"), NetshMitigation)
        monkeypatch.setattr(mit.platform, "system", lambda: "Linux")
        assert isinstance(make_mitigation("auto"), mit.IptablesMitigation)

    def test_log_forced(self):
        assert isinstance(make_mitigation("log"), mit.LogOnlyMitigation)

    def test_unknown_kind(self):
        with pytest.raises(ValueError):
            make_mitigation("pf")


class TestPrivileges:
    def test_linux_root_implies_all(self, monkeypatch):
        monkeypatch.setattr(priv, "is_windows", lambda: False)
        monkeypatch.setattr(priv.os, "geteuid", lambda: 0)
        assert priv.is_root() is True
        assert priv.has_capture_capability() is True
        assert priv.has_firewall_capability() is True

    def test_capabilities_detected(self, monkeypatch):
        monkeypatch.setattr(priv, "is_windows", lambda: False)
        monkeypatch.setattr(priv, "is_linux", lambda: True)
        monkeypatch.setattr(priv.os, "geteuid", lambda: 1000)
        # CapEff with only CAP_NET_RAW (bit 13) set.
        monkeypatch.setattr(priv, "_cap_eff_bits", lambda: 1 << 13)
        assert priv.has_capture_capability() is True
        assert priv.has_firewall_capability() is False
        rep = priv.privilege_report()
        assert rep["capabilities"]["CAP_NET_RAW"] is True
        assert rep["capabilities"]["CAP_NET_ADMIN"] is False

    def test_unprivileged_user(self, monkeypatch):
        monkeypatch.setattr(priv, "is_windows", lambda: False)
        monkeypatch.setattr(priv, "is_linux", lambda: True)
        monkeypatch.setattr(priv.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(priv, "_cap_eff_bits", lambda: 0)
        assert priv.has_capture_capability() is False
        assert priv.has_firewall_capability() is False

    def test_windows_admin_path(self, monkeypatch):
        monkeypatch.setattr(priv, "is_windows", lambda: True)

        class FakeWindll:
            class shell32:
                @staticmethod
                def IsUserAnAdmin():
                    return 1

        fake_ctypes = SimpleNamespace(windll=FakeWindll)
        monkeypatch.setitem(__import__("sys").modules, "ctypes", fake_ctypes)
        # On Windows is_root consults ctypes.windll.shell32.IsUserAnAdmin.
        import ctypes as real_ctypes

        monkeypatch.setattr(real_ctypes, "windll", FakeWindll(), raising=False)
        assert priv.is_root() is True
