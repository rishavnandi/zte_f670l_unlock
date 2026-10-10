"""End-to-end handshake tests against a mock ONT.

These exercise the whole protocol the way a real device does: one persistent
connection, a hang-up on RequestFactoryMode, and AES-encrypted bodies. They
exist because the request-level unit tests could not catch connection-reuse
and header bugs.
"""

import http.server
import socket
import threading

import pytest

from zte_unlock import aes, factory_mode
from zte_unlock.factory_mode import FactoryError, open_factory_mode


class MockONT(http.server.BaseHTTPRequestHandler):
    """A mock ONT. Subclasses set behaviour via class attributes."""

    protocol_version = "HTTP/1.1"
    version = 2
    auth_status = 200
    factory_status = 200
    log = []
    connections = []

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        MockONT.connections.append(id(self.connection))

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        MockONT.log.append({"m": "GET", "ua": self.headers.get("User-Agent"),
                            "conn": self.headers.get("Connection")})
        self.send_response(400)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        body = self._body()

        if b"RequestFactoryMode" in body:
            MockONT.log.append({"m": "POST", "cmd": "RequestFactoryMode"})
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            return

        if body == b"SendSq.gch":
            MockONT.log.append({"m": "POST", "cmd": "SendSq.gch"})
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if body.startswith(b"SendSq.gch?rand="):
            self.rand = int(body.split(b"rand=")[1].split(b"\r")[0])
            MockONT.log.append({"m": "POST", "cmd": "SendSq.gch?rand=N"})
            reply = b"" if self.version == 1 else b"newrand=5"
            self.send_response(200)
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            if reply:
                self.wfile.write(reply)
            return

        key = factory_mode.derive_key(self.rand, 5, self.version)
        plain = aes.unpad(aes.decrypt(body, key))

        if plain.startswith(b"SendInfo"):
            MockONT.log.append({"m": "POST", "cmd": "SendInfo"})
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if plain.startswith(b"CheckLoginAuth"):
            MockONT.log.append({"m": "POST", "cmd": plain.decode()})
            self.send_response(self.auth_status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if plain.startswith(b"FactoryMode"):
            MockONT.log.append({"m": "POST", "cmd": plain.decode()})
            out = aes.encrypt(b"http://x/?user=TELUSER&pass=TELPASS", key)
            self.send_response(self.factory_status)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return

        self.send_response(400)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def ont():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockONT)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    MockONT.log = []
    MockONT.connections = []
    MockONT.version = 2
    MockONT.auth_status = 200
    MockONT.factory_status = 200
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()


def commands():
    return [e.get("cmd", e["m"]) for e in MockONT.log]


class TestFullHandshake:
    def test_v2_happy_path(self, ont):
        result = open_factory_mode(
            ip="127.0.0.1", port=ont,
            username="admin", password="admin", timeout=5,
        )

        assert result == ("TELUSER", "TELPASS")
        assert commands() == [
            "GET", "SendSq.gch", "RequestFactoryMode", "SendSq.gch?rand=N",
            "SendInfo", "CheckLoginAuth.gch?&version61&user=admin&pass=admin",
            "FactoryMode.gch?mode=2&user=notused",
        ]

    def test_v1_skips_send_info(self, ont):
        """Version 1 firmware has no SendInfo step."""
        MockONT.version = 1

        result = open_factory_mode(
            ip="127.0.0.1", port=ont,
            username="admin", password="admin", timeout=5,
        )

        assert result == ("TELUSER", "TELPASS")
        assert "SendInfo" not in commands()

    def test_reuses_one_connection(self, ont):
        """The handshake must ride a single persistent connection.

        The ONT tracks factory-mode state per connection. urllib's default is
        Connection: close, which silently broke the handshake against a mock
        that tracked state the way a real device does.
        """
        open_factory_mode(
            ip="127.0.0.1", port=ont,
            username="admin", password="admin", timeout=5,
        )

        # The hang-up on RequestFactoryMode closes the socket, so allow for
        # that one reopen; everything before it must share a connection.
        assert len(set(MockONT.connections)) <= 2

    def test_no_connection_close_header(self, ont):
        """Requests must not ask for Connection: close."""
        open_factory_mode(
            ip="127.0.0.1", port=ont,
            username="admin", password="admin", timeout=5,
        )

        closes = [e for e in MockONT.log if e.get("conn") == "close"]
        assert not closes

    def test_credentials_returned_even_with_factory_400(self, ont):
        """A non-200 on FactoryMode still carries a readable body."""
        MockONT.factory_status = 400

        result = open_factory_mode(
            ip="127.0.0.1", port=ont,
            username="admin", password="admin", timeout=5,
        )

        assert result == ("TELUSER", "TELPASS")

    def test_rejected_credentials_raise(self, ont):
        MockONT.auth_status = 401

        with pytest.raises(FactoryError, match="no credential pair worked"):
            open_factory_mode(
                ip="127.0.0.1", port=ont,
                username="admin", password="admin", timeout=5, attempts=2,
            )

    def test_full_command_strings_match_the_protocol(self, ont):
        """Byte-exact command strings, including the odd '?&'."""
        open_factory_mode(
            ip="127.0.0.1", port=ont,
            username="admin", password="admin", timeout=5,
        )

        cmds = commands()
        assert "CheckLoginAuth.gch?&version61&user=admin&pass=admin" in cmds
        assert "FactoryMode.gch?mode=2&user=notused" in cmds