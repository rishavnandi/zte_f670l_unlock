"""Tests for the read-only --info command.

--info exists so an already-unlocked ONT can be checked without any risk of
changing it, so these tests are as much about what it must NOT do as what it
prints.
"""

import http.server
import threading

import pytest

from zte_unlock import factory_mode

STATUS_PAGE = b"""<html><body><table>
<tr><td>Device Type</td><td>F670LV9.0</td></tr>
<tr><td>Hardware Version</td><td>V9.0</td></tr>
<tr><td>Software Version</td><td>V9.0.11P1N40</td></tr>
<tr><td>Boot Version</td><td>V9.0.11P10N1</td></tr>
</table></body></html>"""


class StatusServer(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        StatusServer.seen.append((self.command, self.path))
        self.send_response(200)
        self.send_header("Content-Length", str(len(STATUS_PAGE)))
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(STATUS_PAGE)

    # Any write verb would be a bug for a read-only command.
    def do_POST(self):
        StatusServer.seen.append((self.command, self.path))
        self.send_response(500)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_PUT = do_POST
    do_DELETE = do_POST


@pytest.fixture
def status_server():
    StatusServer.seen = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StatusServer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()


class TestInfo:
    def test_reports_versions(self, status_server, capsys):
        rc = factory_mode.main(["-i", "127.0.0.1", "-p", str(status_server), "--info"])

        assert rc == 0
        out = capsys.readouterr().out
        assert "F670LV9.0" in out
        assert "9.0.11P1N40" in out

    def test_sends_only_a_get(self, status_server):
        factory_mode.main(["-i", "127.0.0.1", "-p", str(status_server), "--info"])

        assert StatusServer.seen
        assert all(method == "GET" for method, _ in StatusServer.seen)

    def test_reports_when_no_version_field_is_present(self, status_server, capsys):
        """A page with only unrelated labels must still say so.

        The fields dict can be non-empty while containing none of the four
        labels -- that has to produce the hint, not a blank report with a
        success exit code.
        """
        global STATUS_PAGE
        original = STATUS_PAGE
        STATUS_PAGE = b"<table><tr><td>Uptime</td><td>99 days</td></tr></table>"
        try:
            rc = factory_mode.main(
                ["-i", "127.0.0.1", "-p", str(status_server), "--info"]
            )
        finally:
            STATUS_PAGE = original

        assert rc == 0
        assert "no version fields found" in capsys.readouterr().out

    def test_states_that_nothing_changed(self, status_server, capsys):
        factory_mode.main(["-i", "127.0.0.1", "-p", str(status_server), "--info"])

        assert "nothing was changed" in capsys.readouterr().out

    def test_survives_a_non_http_reply(self):
        """A read-only diagnostic must not raise a traceback.

        http.client.HTTPException is not an OSError, so a socket that answers
        with garbage would otherwise crash -- which is the opposite of useful
        when someone is trying to work out why their ONT is unreachable.
        """
        import socket
        import threading

        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            conn, _ = server.accept()
            conn.recv(4096)
            conn.sendall(b"NOT-HTTP GARBAGE\r\n\r\n")
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            rc = factory_mode.main(["-i", "127.0.0.1", "-p", str(port), "-t", "2", "--info"])
        finally:
            server.close()

        assert rc == 1

    def test_unreachable_host_exits_nonzero(self, capsys):
        rc = factory_mode.main(["-i", "127.0.0.1", "-p", "1", "-t", "1", "--info"])

        assert rc == 1
        assert "cannot read" in capsys.readouterr().err


class TestSuccessOutputWarns:
    def test_credentials_message_warns_about_firmware(self, capsys):
        """The success path must warn against the destructive operations."""
        from unittest.mock import patch

        with patch.object(
            factory_mode, "open_factory_mode", return_value=("U", "P")
        ):
            rc = factory_mode.main(["-i", "192.0.2.1"])

        assert rc == 0
        out = capsys.readouterr().out
        assert "does not flash firmware" in out
        assert "Software Upgrade" in out
        assert "hardware reset" in out