"""Tests for network interface auto-detection."""

from exfiltrap.netif import default_interface, list_interfaces


class TestNetif:
    def test_default_interface_is_valid_or_none(self):
        name = default_interface()
        if name is not None:
            assert name in list_interfaces()
            assert name != "lo"

    def test_list_interfaces_excludes_loopback(self):
        names = list_interfaces()
        assert isinstance(names, list)
        assert "lo" not in names

    def test_detection_is_consistent(self):
        # Two consecutive detections agree (the default route does not
        # flap between calls on a healthy machine).
        a, b = default_interface(), default_interface()
        assert a == b


class TestResolveInterfaces:
    def test_default_includes_loopback_stub(self, monkeypatch):
        from exfiltrap import netif, service

        monkeypatch.setattr(netif, "default_interface", lambda: "wlo1")
        assert service.resolve_interfaces(None) == ["wlo1", "lo"]

    def test_explicit_name_wins(self, monkeypatch):
        from exfiltrap import netif, service

        monkeypatch.setattr(netif, "default_interface", lambda: "wlo1")
        assert service.resolve_interfaces("eth0") == ["eth0"]

    def test_any_single_device(self, monkeypatch):
        from exfiltrap import netif, service

        monkeypatch.setattr(netif, "default_interface", lambda: "wlo1")
        assert service.resolve_interfaces("any") == ["any"]

    def test_auto_detect_failure_returns_none(self, monkeypatch):
        from exfiltrap import netif, service

        monkeypatch.setattr(netif, "default_interface", lambda: None)
        assert service.resolve_interfaces("auto") is None
