"""Tests for --check-mac, which reports the interface MAC used to reach the ONT.

The magic MAC is needed by the --new method of the upstream tool. Our client
does not implement that method, so this is a diagnostic helper only, and the
tests here cover the selection logic rather than the machine's real interfaces.
"""

from collections import namedtuple

import pytest

from zte_unlock import factory_mode

SnicAddr = namedtuple("SnicAddr", "family address")


class FakeIface:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


@pytest.fixture
def ifaces(monkeypatch):
    """Install a fake interface table."""
    table = {
        "lo0": [SnicAddr(family=2, address="127.0.0.1")],
        "en0": [
            SnicAddr(family=2, address="192.168.0.103"),
            SnicAddr(family=18, address="02:00:00:00:00:00"),
        ],
        "eth9": [
            SnicAddr(family=2, address="192.168.0.103"),
            SnicAddr(family=18, address="00:07:29:55:35:57"),
        ],
        "wlan0": [
            SnicAddr(family=2, address="10.0.0.5"),
            SnicAddr(family=18, address="aa:bb:cc:dd:ee:ff"),
        ],
    }
    monkeypatch.setattr(
        factory_mode.psutil, "net_if_addrs", lambda: table
    )
    monkeypatch.setattr(
        factory_mode.psutil, "AF_LINK", 18, raising=False
    )
    return table


class TestMacNormalisation:
    def test_colons_and_dashes_are_equivalent(self):
        assert factory_mode._normalise_mac("00-07-29-55-35-57") == factory_mode._normalise_mac("00:07:29:55:35:57")

    def test_case_is_ignored(self):
        assert factory_mode._normalise_mac("AA:BB:CC") == "aa:bb:cc"


class TestRouteSelection:
    def test_finds_the_interface_holding_the_source_address(self, monkeypatch):
        table = {
            "lo0": [SnicAddr(family=2, address="127.0.0.1")],
            "en0": [SnicAddr(family=2, address="192.168.0.103")],
        }
        monkeypatch.setattr(factory_mode.psutil, "net_if_addrs", lambda: table)

        # _route_to probes the kernel for the source address; stub that probe
        # by pointing at a host that always resolves locally.
        name, local_ip = factory_mode._route_to("127.0.0.1", 80)

        assert name == "lo0"
        assert local_ip == "127.0.0.1"

    def test_returns_none_when_no_interface_owns_the_address(self, monkeypatch):
        monkeypatch.setattr(factory_mode.psutil, "net_if_addrs", lambda: {})

        assert factory_mode._route_to("127.0.0.1", 80) is None


class TestCheckMac:
    def test_reports_success_when_the_magic_mac_is_present(self, ifaces, monkeypatch, capsys):
        monkeypatch.setattr(
            factory_mode, "_route_to", lambda host, port: ("eth9", "192.168.0.103")
        )

        rc = factory_mode._check_mac("192.168.1.1")

        assert rc == 0
        assert "ok" in capsys.readouterr().out

    def test_reports_failure_and_names_the_current_mac(self, ifaces, monkeypatch, capsys):
        monkeypatch.setattr(
            factory_mode, "_route_to", lambda host, port: ("en0", "192.168.0.103")
        )

        rc = factory_mode._check_mac("192.168.1.1")

        assert rc == 1
        out = capsys.readouterr().out
        assert factory_mode._MAGIC_MAC in out
        assert "02:00:00:00:00:00" in out

    def test_explains_the_windows_restriction_on_failure(self, ifaces, monkeypatch, capsys):
        monkeypatch.setattr(
            factory_mode, "_route_to", lambda host, port: ("en0", "192.168.0.103")
        )

        factory_mode._check_mac("192.168.1.1")

        assert "wired" in capsys.readouterr().out

    def test_handles_an_interface_with_no_link_address(self, monkeypatch, capsys):
        monkeypatch.setattr(
            factory_mode.psutil,
            "net_if_addrs",
            lambda: {"tun0": [SnicAddr(family=2, address="10.1.1.1")]},
        )
        monkeypatch.setattr(
            factory_mode, "_route_to", lambda host, port: ("tun0", "10.1.1.1")
        )

        rc = factory_mode._check_mac("192.168.1.1")

        assert rc == 1
        assert "no MAC" in capsys.readouterr().out

    def test_reports_when_there_is_no_local_route(self, monkeypatch, capsys):
        monkeypatch.setattr(
            factory_mode, "_route_to", lambda host, port: None
        )

        rc = factory_mode._check_mac("192.168.1.1")

        assert rc == 1
        assert "No local address" in capsys.readouterr().out