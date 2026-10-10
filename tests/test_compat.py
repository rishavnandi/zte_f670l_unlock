"""Regression tests for protocol-compatibility bugs.

Each test here corresponds to a real divergence from the reference
implementation that was found by differential testing against the compiled Go
tool. They are written to fail loudly if the behaviour regresses.
"""

import http.server
import threading
import time

import pytest

from zte_unlock import factory_mode
from zte_unlock.factory_mode import FactoryError, FactoryMode


class HangingONT(http.server.BaseHTTPRequestHandler):
    """An ONT that hangs up on RequestFactoryMode, like the real device.

    The reference client treats that bare hang-up as success. If our client
    treats it as a network error, the normal path is broken.
    """

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _read(self):
        n = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        self.send_response(400)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        body = self._read()
        if b"RequestFactoryMode" in body:
            # Hang up with no response at all.
            self.close_connection = True
            self.wfile.close()
            return
        self.send_response(400)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def hanging_ont():
    server = http.server.HTTPServer(("127.0.0.1", 0), HangingONT)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()


class TestRequestFactoryModeHangUp:
    def test_hangup_is_success_not_an_error(self, hanging_ont):
        """RequestFactoryMode hanging up is the ONT's success signal.

        urllib raises http.client.RemoteDisconnected here, which is an
        OSError subclass -- NOT a URLError. Catching only URLError made this
        the single most damaging bug: the ordinary path raised.
        """
        client = FactoryMode(ip="127.0.0.1", port=hanging_ont, timeout=5)

        # Must not raise.
        client.request_factory_mode()

    def test_wakeup_request_sends_expected_user_agent(self, hanging_ont):
        """The GET / that wakes the ONT must not leak a urllib user agent.

        The ONT is documented to care about the client string.
        """
        seen = {}

        class Recorder(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self):
                seen["ua"] = self.headers.get("User-Agent")
                seen["ae"] = self.headers.get("Accept-Encoding")
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()

        server = http.server.HTTPServer(("127.0.0.1", 0), Recorder)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            client = FactoryMode(ip="127.0.0.1", port=server.server_port, timeout=5)
            with pytest.raises(FactoryError):
                client.reset()
        finally:
            server.shutdown()
            server.server_close()

        assert seen["ua"] == factory_mode._USER_AGENT
        assert seen["ua"] != "Python-urllib/3.13"


class TestNegotiation:
    def _client(self, reply):
        client = FactoryMode(ip="127.0.0.1", port=1, timeout=1)
        client._post = lambda *a, **k: (200, reply)
        return client

    def test_v1_empty_reply_does_not_crash(self):
        """Firmware that answers with an empty body is protocol version 1.

        This previously raised UnboundLocalError because new_rand was only
        assigned in the v2 branch, killing the entire v1 path.
        """
        client = self._client(b"")

        version = client.negotiate()

        assert version == 1
        assert client._key is not None
        assert len(client._key) == 24

    def test_v1_key_is_derived_with_zero_newrand(self):
        client = self._client(b"")
        client.negotiate()

        rand = time.localtime().tm_sec
        assert client._key == factory_mode.derive_key(rand, 0, 1)

    def test_v2_reply_with_trailing_newline(self):
        """The reference client trims before parsing; so must ours."""
        client = self._client(b"newrand=42\n")

        assert client.negotiate() == 2
        rand = time.localtime().tm_sec
        assert client._key == factory_mode.derive_key(rand, 42, 2)

    def test_non_numeric_newrand_falls_back_to_zero(self):
        """A garbage counter must not raise out of the handshake."""
        client = self._client(b"newrand=abc")

        assert client.negotiate() == 2
        rand = time.localtime().tm_sec
        assert client._key == factory_mode.derive_key(rand, 0, 2)

    def test_bare_newrand_keyword_is_still_v2(self):
        """The reference client tests for 'newrand', not 'newrand='."""
        client = self._client(b"newrand")

        assert client.negotiate() == 2

    def test_unexpected_reply_is_an_error(self):
        client = self._client(b"nonsense")

        with pytest.raises(FactoryError, match="unexpected negotiation reply"):
            client.negotiate()

    def test_non_200_status_is_an_error(self):
        client = FactoryMode(ip="127.0.0.1", port=1, timeout=1)
        client._post = lambda *a, **k: (500, b"boom")

        with pytest.raises(FactoryError, match="negotiation failed"):
            client.negotiate()


class TestResetStatusHandling:
    def test_only_400_counts_as_reset_ok(self):
        """The reference client treats 400 as success and anything else as
        failure. Accepting 200 too hides a genuine problem."""
        client = FactoryMode(ip="127.0.0.1", port=1, timeout=1)
        # reset() wakes the ONT first; stub that hop out so we reach the
        # SendSq.gch status check under test.
        client._get = lambda: None
        client._post = lambda *a, **k: (200, b"")

        with pytest.raises(FactoryError, match="reset failed"):
            client.reset()

    def test_400_is_accepted_as_reset_ok(self):
        client = FactoryMode(ip="127.0.0.1", port=1, timeout=1)
        client._get = lambda: None
        client._post = lambda *a, **k: (400, b"")

        client.reset()  # must not raise


class TestEnterIgnoresStatus:
    def test_credentials_are_read_even_with_non_200_status(self):
        """The reference client never inspects this status code."""
        client = FactoryMode(ip="127.0.0.1", port=1, timeout=1)
        client._key = bytes(24)
        client._post_encrypted = lambda command: (
            400,
            b"http://x/?user=TELUSER&pass=TELPASS",
        )

        assert client.enter() == ("TELUSER", "TELPASS")

    def test_empty_body_is_an_error(self):
        client = FactoryMode(ip="127.0.0.1", port=1, timeout=1)
        client._key = bytes(24)
        client._post_encrypted = lambda command: (400, b"")

        with pytest.raises(FactoryError, match="factory mode refused"):
            client.enter()


class TestRetries:
    def test_each_attempt_gets_a_fresh_handshake(self, monkeypatch):
        """A failed attempt must not reuse its session key.

        The reference client builds a new client for every attempt, so state
        from a failed handshake never leaks into the next one.
        """
        clients = []

        class Boom(FactoryMode):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                clients.append(self)

            def reset(self):
                raise FactoryError("nope")

        monkeypatch.setattr(factory_mode, "FactoryMode", Boom)
        monkeypatch.setattr(time, "sleep", lambda *_: None)

        # One credential pair, so clients == attempts.
        with pytest.raises(FactoryError, match="no credential pair worked"):
            factory_mode.open_factory_mode(
                ip="127.0.0.1", username="u", password="p", attempts=3
            )

        assert len(clients) == 3

    def test_default_pairs_are_all_attempted(self, monkeypatch):
        attempts = []

        class Deny(FactoryMode):
            def reset(self):
                attempts.append(1)
                raise FactoryError("denied")

        monkeypatch.setattr(factory_mode, "FactoryMode", Deny)
        monkeypatch.setattr(time, "sleep", lambda *_: None)

        with pytest.raises(FactoryError):
            factory_mode.open_factory_mode(ip="127.0.0.1", attempts=1)

        assert len(attempts) == len(factory_mode.DEFAULT_USERS)

    def test_success_returns_credentials(self, monkeypatch):
        class Good(FactoryMode):
            def reset(self):
                pass

            def request_factory_mode(self):
                pass

            def negotiate(self):
                return 2

            def authenticate(self, user, password, version):
                pass

            def enter(self):
                return ("TELUSER", "TELPASS")

        monkeypatch.setattr(factory_mode, "FactoryMode", Good)

        result = factory_mode.open_factory_mode(
            ip="127.0.0.1", username="u", password="p"
        )

        assert result == ("TELUSER", "TELPASS")