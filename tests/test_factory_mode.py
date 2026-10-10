"""Tests for the factory-mode client.

The AES conformance tests in test_aes.py are the real gate. These cover the
protocol logic: key derivation, credential parsing, and the handshake sequence
against a fake ONT.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from zte_unlock import aes, factory_mode
from zte_unlock.factory_mode import FactoryError, FactoryMode, derive_key


class TestKeyDerivation:
    def test_v1_uses_second_as_index(self):
        """v1 firmware slices the pool at the seconds value."""
        rand = 30
        expected = bytes(
            b ^ 0xA5
            for b in factory_mode._KEY_POOL_V1[rand:rand + 24]
        )

        assert derive_key(rand, 0, 1) == expected

    def test_v2_uses_reordered_index(self):
        """v2 mixes the seconds value with the newrand the ONT returns."""
        rand, new_rand = 17, 5
        index = (((0x1000193 * rand) & 0x3F) ^ new_rand) % 60
        expected = bytes(
            b ^ 0xA5 for b in factory_mode._KEY_POOL_V2[index:index + 24]
        )

        assert derive_key(rand, new_rand, 2) == expected

    def test_key_is_24_bytes(self):
        """AES-192 requires exactly 24."""
        for version in (1, 2):
            assert len(derive_key(0, 0, version)) == 24

    def test_different_seconds_give_different_keys(self):
        """The key must vary per session or replay would be trivial."""
        assert derive_key(1, 0, 1) != derive_key(2, 0, 1)

    def test_index_near_end_of_pool_does_not_overrun(self):
        """rand can reach 59; 59+24 exceeds nothing but must not wrap."""
        key = derive_key(59, 0, 1)

        assert len(key) == 24


class FakeONT(BaseHTTPRequestHandler):
    """Minimal ONT that speaks just enough of the protocol to test against."""

    # Set by the test to the key the fake expects back.
    expected_key = None
    received_commands = []

    def log_message(self, *args):
        pass

    def _read(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        body = self._read()

        if self.path == "/webFac":
            if body.startswith(b"SendSq.gch?rand="):
                FakeONT.received_commands.append(("negotiate", body))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"newrand=5")
            elif body == b"SendSq.gch":
                self.send_response(400)   # already reset
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
            return

        if self.path == "/webFacEntry":
            FakeONT.received_commands.append(("encrypted", body))
            try:
                plain = aes.unpad(aes.decrypt(body, FakeONT.expected_key))
            except Exception:
                self.send_response(400)
                self.end_headers()
                return

            if plain.startswith(b"CheckLoginAuth"):
                status = 200 if b"user=admin" in plain else 401
            elif plain.startswith(b"FactoryMode"):
                payload = b"http://x/?user=teluser&pass=telpass"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(aes.encrypt(payload, FakeONT.expected_key))
                return
            else:
                status = 200

            self.send_response(status)
            self.end_headers()

    def do_PUT(self):
        self.do_POST()


@pytest.fixture
def ont():
    """Run a fake ONT and yield a client pointed at it."""
    server = HTTPServer(("127.0.0.1", 0), FakeONT)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    FakeONT.received_commands = []
    client = FactoryMode(ip="127.0.0.1", port=server.server_port, timeout=5)

    try:
        yield client
    finally:
        server.shutdown()
        server.server_close()


def test_handshake_produces_credentials(ont):
    """The full sequence yields the telnet credentials."""
    # Pin the fake's key to whatever our client derives.
    FakeONT.expected_key = derive_key(
        __import__("time").localtime().tm_sec, 5, 2
    )

    ont.reset()
    ont.request_factory_mode()
    version = ont.negotiate()
    assert version == 2

    ont.authenticate("admin", "admin", version)
    user, password = ont.enter()

    assert (user, password) == ("teluser", "telpass")


def test_bad_credentials_raise(ont):
    """A 401 from CheckLoginAuth must surface as a clear error."""
    FakeONT.expected_key = derive_key(
        __import__("time").localtime().tm_sec, 5, 2
    )

    ont.reset()
    ont.request_factory_mode()
    version = ont.negotiate()

    with pytest.raises(FactoryError, match="credentials rejected"):
        ont.authenticate("wrong", "wrong", version)


def test_unreachable_host_fails_cleanly():
    """No traceback for a dead address."""
    client = FactoryMode(ip="127.0.0.1", port=1, timeout=1)

    with pytest.raises(FactoryError, match="cannot reach"):
        client.reset()


def test_entry_without_key_is_refused(ont):
    """Sending encrypted data before negotiating must not happen silently."""
    with pytest.raises(FactoryError, match="session key not established"):
        ont._post_encrypted(b"FactoryMode.gch?mode=2&user=notused")


def test_open_factory_mode_rejects_partial_credentials():
    """Half a credential pair is a usage error, not a silent default."""
    with pytest.raises(FactoryError, match="must be given together"):
        factory_mode.open_factory_mode(ip="192.0.2.1", username="admin")


def test_default_credential_lists_are_paired():
    """zip() would silently truncate on a length mismatch."""
    assert len(factory_mode.DEFAULT_USERS) == len(factory_mode.DEFAULT_PASSWORDS)