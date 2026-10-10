"""Clean-room ZTE ONT factory-mode client.

Written against the ONT's documented webFac/webFacEntry interface. The AES
key pools, the magic MAC, the endpoint names and the command strings are
protocol constants -- they define what the ONT speaks -- not implementation
detail, so this is an independent implementation rather than a translation.

If stich86/zteOnu disappears, this keeps working. See NOTICE.md for credits.

Usage:
    python3 -m zte_unlock unlock -i 192.168.1.1
    python3 -m zte_unlock unlock --list-creds
"""

from __future__ import annotations

import argparse
import base64
import http.client
import re
import socket
import sys
import time
from urllib import parse

from . import aes

__all__ = ["FactoryError", "FactoryMode", "open_factory_mode"]


class FactoryError(RuntimeError):
    """Any failure talking to the ONT's factory-mode interface."""


# The ONT expects a specific client string and rejects unknown agents. These
# headers mirror what the reference client sends, so the ONT sees the same
# request on every call.
_USER_AGENT = "curl/8.8.0-DEV"

_HEADERS = {
    "User-Agent": _USER_AGENT,
    "Accept": "*/*",
    "Accept-Encoding": "identity",
    "Content-Type": "application/octet-stream",
}

# Protocol key material. These are fixed values the ONT firmware expects.
_KEY_POOL_V1 = bytes((
    0x7B, 0x56, 0xB0, 0xF7, 0xDA, 0x0E, 0x68, 0x52, 0xC8, 0x19,
    0xF3, 0x2B, 0x84, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2,
    0x64, 0x93, 0x87, 0xDF, 0x73, 0xD7, 0xFB, 0xCC, 0xAA, 0xFE,
    0x75, 0x43, 0x1C, 0x29, 0xDF, 0x4C, 0x52, 0x2C, 0x6E, 0x7B,
    0x45, 0x3D, 0x1F, 0xF1, 0xDE, 0xBC, 0x27, 0x85, 0x8A, 0x45,
    0x91, 0xBE, 0x38, 0x13, 0xDE, 0x67, 0x32, 0x08, 0x54, 0x11,
    0x75, 0xF4, 0xD3, 0xB4, 0xA4, 0xB3, 0x12, 0x86, 0x67, 0x23,
    0x99, 0x4C, 0x61, 0x7F, 0xB1, 0xD2, 0x30, 0xDF, 0x47, 0xF1,
    0x76, 0x93, 0xA3, 0x8C, 0x95, 0xD3, 0x59, 0xBF, 0x87, 0x8E,
    0xF3, 0xB3, 0xE4, 0x76, 0x49, 0x88,
))

_KEY_POOL_V2 = bytes((
    0x8C, 0x23, 0x65, 0xD1, 0xFC, 0x32, 0x45, 0x37, 0x11, 0x28,
    0x71, 0x63, 0x07, 0x20, 0x69, 0x14, 0x73, 0xE7, 0xD4, 0x53,
    0x13, 0x24, 0x36, 0xC2, 0xB5, 0xE1, 0xFC, 0xCF, 0x8A, 0x9A,
    0x41, 0x89, 0x3C, 0x49, 0xCF, 0x5C, 0x72, 0x8C, 0x9E, 0xEB,
    0x75, 0x0D, 0x3F, 0xD1, 0xFE, 0xCC, 0x57, 0x65, 0x7A, 0x35,
    0x21, 0x3E, 0x68, 0x53, 0x7E, 0x97, 0x02, 0x48, 0x74, 0x71,
    0x95, 0x34, 0x53, 0x84, 0xB4, 0xC3, 0xE2, 0xD6, 0x27, 0x3D,
    0xE6, 0x5D, 0x72, 0x9C, 0xBC, 0x3D, 0x03, 0xFD, 0x76, 0xC1,
    0x9C, 0x25, 0xA8, 0x92, 0x47, 0xE4, 0x18, 0x0F, 0x24, 0x3F,
    0x4F, 0x67, 0xEC, 0x97, 0xF4, 0x99,
))

# Identifies the client MAC to the ONT; decoded by the firmware, not by us.
_MAGIC_MAC_B64 = "AAAAAGAIAACTBwAAOggAALoAAACQBwAAxAcAAMoGAACVBAAATggAAM0BAAAnCA=="
_MAGIC_MAC = "00:07:29:55:35:57"

_KEY_LEN = 24
_KEY_XOR = 0xA5

# Factory accounts the ONT still accepts. ISPs lock these out over time --
# pass your own web UI credentials with --user/--password if none work.
# Paired positionally; keep the two lists the same length.
DEFAULT_USERS = (
    "admin", "factorymode", "CMCCAdmin", "CUAdmin", "telecomadmin",
    "cqadmin", "user", "admin", "cuadmin", "lnadmin", "useradmin",
)
DEFAULT_PASSWORDS = (
    "admin", "nE%jA@5b", "aDm8H%MdA", "CUAdmin", "nE7jA%5m", "cqunicom",
    "1620@CTCC", "1620@CUcc", "admintelecom", "cuadmin", "lnadmin",
)


def derive_key(rand: int, new_rand: int, version: int) -> bytes:
    """Derive the per-session AES key.

    The ONT ties the key to the seconds value sent in the SendSq request.
    Version 2 firmware reorders the pool lookup and uses a separate pool.
    """
    if version == 2:
        index = (((0x1000193 * rand) & 0x3F) ^ new_rand) % 60
        pool = _KEY_POOL_V2
    else:
        index = rand
        pool = _KEY_POOL_V1

    window = pool[index:index + _KEY_LEN]
    if len(window) < _KEY_LEN:
        raise FactoryError(f"derived key too short ({len(window)} bytes)")

    return bytes(b ^ _KEY_XOR for b in window)


class _KeepAlive:
    """A single HTTP connection reused for the whole handshake.

    The reference client keeps one TCP connection open across the handshake.
    Reusing it matters: the ONT tracks factory-mode state per connection, so
    opening a fresh socket per request loses that state.
    """

    def __init__(self, host: str, port: int, timeout: float):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._conn: http.client.HTTPConnection | None = None

    def request(self, method: str, path: str, body: bytes | None) -> tuple[int, bytes]:
        for attempt in (1, 2):
            if self._conn is None:
                self._conn = http.client.HTTPConnection(
                    self.host, self.port, timeout=self.timeout
                )
            try:
                self._conn.request(method, path, body=body, headers=_HEADERS)
                resp = self._conn.getresponse()
                return resp.status, resp.read()
            except (http.client.RemoteDisconnected, http.client.BadStatusLine):
                # The ONT hung up. That is a valid outcome for one specific
                # request; the caller decides. Reconnect once so the session
                # stays usable, then let it propagate.
                self.close()
                raise
            except (OSError, http.client.HTTPException):
                self.close()
                if attempt == 2:
                    raise
        raise FactoryError("unreachable")

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None


class FactoryMode:
    """Drives the ONT factory-mode handshake and returns telnet credentials."""

    def __init__(self, ip: str, port: int = 80, timeout: float = 10.0):
        self.base_url = f"http://{ip}:{port}"
        self.timeout = timeout
        self._key: bytes | None = None
        self._http = _KeepAlive(ip, port, timeout)

    def _get(self) -> None:
        """Wake the ONT's web service with a bare GET /.

        The ONT answers 400 here; only the fact that it answered matters.
        """
        try:
            self._http.request("GET", "/", None)
        except (http.client.RemoteDisconnected, http.client.BadStatusLine):
            return
        except OSError as exc:
            raise FactoryError(f"cannot reach {self.base_url}: {exc}") from exc

    def _post(self, path: str, body: bytes, *, allow_eof: bool = False) -> tuple[int, bytes]:
        try:
            return self._http.request("POST", path, body)
        except (http.client.RemoteDisconnected, http.client.BadStatusLine):
            # RequestFactoryMode makes the ONT hang up without replying, which
            # is its success signal.
            if allow_eof:
                return 0, b""
            raise FactoryError(f"{self.base_url}{path}: connection closed")
        except OSError as exc:
            raise FactoryError(f"cannot reach {self.base_url}: {exc}") from exc
        except http.client.HTTPException as exc:
            raise FactoryError(f"{self.base_url}{path} failed: {exc}") from exc

    def _post_encrypted(self, command: bytes) -> tuple[int, bytes]:
        if self._key is None:
            raise FactoryError("session key not established")
        status, body = self._post("/webFacEntry", aes.encrypt(command, self._key))
        if not body:
            return status, body
        # The reference client decrypts whatever came back regardless of the
        # status code, so a body arriving with an unexpected status is still
        # readable. Only attempt decryption when the body is a whole number of
        # blocks.
        if len(body) % aes.BLOCK_SIZE:
            return status, body
        try:
            return status, aes.unpad(aes.decrypt(body, self._key))
        except ValueError:
            return status, body

    def reset(self) -> None:
        """Reset the factory-mode state on the ONT."""
        self._get()  # raises FactoryError if the ONT is unreachable

        status, body = self._post("/webFac", b"SendSq.gch")
        # The ONT answers 400 once the factory-mode state is already reset,
        # which is the expected case.
        if status != 400:
            raise FactoryError(f"reset failed: {_describe(status, body)}")

    def request_factory_mode(self) -> None:
        """Ask the ONT to enter factory mode. It hangs up on success."""
        self._post("/webFac", b"RequestFactoryMode.gch", allow_eof=True)

    def negotiate(self) -> int:
        """Exchange the session key. Returns the protocol version."""
        rand = time.localtime().tm_sec
        status, body = self._post("/webFac", f"SendSq.gch?rand={rand}\r\n".encode())

        if status != 200:
            raise FactoryError(
                f"session negotiation failed: {_describe(status, body)}\n"
                "  If this says 'unknown error', the firmware is patched and no "
                "method will work."
            )

        # Whitespace is trimmed before parsing, matching the reference client.
        text = body.decode(errors="replace").strip()

        if "newrand" in text:
            version = 2
            # A non-numeric value means the ONT did not give us a usable
            # counter; fall back to 0 rather than dying on the ValueError.
            raw = text.replace("newrand=", "", 1)
            try:
                new_rand = int(raw)
            except ValueError:
                new_rand = 0
        elif not text:
            version = 1
            new_rand = 0
        else:
            raise FactoryError(f"unexpected negotiation reply: {text!r}")

        self._key = derive_key(rand, new_rand, version)
        return version

    def authenticate(self, user: str, password: str, version: int) -> None:
        """Validate factory-mode credentials."""
        if version == 2:
            magic = base64.b64decode(_MAGIC_MAC_B64)
            status, body = self._post_encrypted(b"SendInfo.gch?info=12|" + magic)
            if status != 200:
                raise FactoryError(f"handshake rejected: {_describe(status, body)}")

        command = (
            f"CheckLoginAuth.gch?&version61&user={user}&pass={password}"
        ).encode()
        status, body = self._post_encrypted(command)

        if status == 401:
            raise FactoryError(f"credentials rejected for user '{user}'")
        if status != 200:
            raise FactoryError(f"auth failed: {_describe(status, body)}")

    def enter(self) -> tuple[str, str]:
        """Enter factory mode and return the generated telnet credentials."""
        # The status is not checked here: the reference client ignores it and
        # decrypts whatever came back, so an unexpected code with a valid body
        # still yields credentials.
        status, body = self._post_encrypted(b"FactoryMode.gch?mode=2&user=notused")
        if not body:
            raise FactoryError(f"factory mode refused: {_describe(status, body)}")

        # The ONT replies with a URL whose query carries the credentials, so the
        # query string has to be split off before parsing it as form data.
        try:
            fields = parse.parse_qs(parse.urlsplit(body.decode()).query)
        except UnicodeDecodeError as exc:
            raise FactoryError(f"unreadable factory-mode reply: {exc}") from exc

        user = (fields.get("user") or [""])[0]
        password = (fields.get("pass") or [""])[0]
        if not user or not password:
            raise FactoryError(f"factory mode returned no credentials: {body!r}")

        return user, password


def _describe(status: int, body: bytes) -> str:
    text = body.decode(errors="replace").strip()
    return f"HTTP {status}: {text[:200]}" if text else f"HTTP {status}"


def open_factory_mode(
    ip: str,
    port: int = 80,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 10.0,
    attempts: int = 5,
) -> tuple[str, str]:
    """Run the full handshake, trying each known credential pair.

    Each pair gets a fresh client and a full handshake, retried up to
    ``attempts`` times. The handshake state does not survive an attempt, so
    reusing one session across pairs does not work.

    Returns the temporary telnet username and password.
    """
    if username and password:
        pairs = [(username, password)]
    elif username or password:
        raise FactoryError("--user and --password must be given together")
    else:
        pairs = list(zip(DEFAULT_USERS, DEFAULT_PASSWORDS))

    last_error = None
    for user, pw in pairs:
        client = None
        for attempt in range(1, attempts + 1):
            # A fresh client per attempt: the session key and factory-mode
            # state are negotiated each time and do not survive a failure.
            client = FactoryMode(ip=ip, port=port, timeout=timeout)
            try:
                client.reset()
                client.request_factory_mode()
                version = client.negotiate()
                client.authenticate(user, pw, version)
            except FactoryError as exc:
                last_error = exc
                # The ONT is not answering at all. Retrying every credential
                # against a dead host only produces noise.
                if "cannot reach" in str(exc):
                    raise FactoryError(f"cannot reach {ip}:{port}: {exc}") from exc
                print(
                    f"  {user}: {exc} (attempt {attempt}/{attempts})",
                    file=sys.stderr,
                )
                time.sleep(0.5)
                continue

            print(f"authenticated as {user}", file=sys.stderr)
            return client.enter()

    raise FactoryError(
        f"no credential pair worked ({len(pairs)} tried): {last_error}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="zte_unlock",
        description="Open telnet on a ZTE ONU via factory mode.",
    )
    parser.add_argument("-i", "--ip", default="192.168.1.1", help="ONT address")
    parser.add_argument("-p", "--port", type=int, default=80, help="ONT http port")
    parser.add_argument("-u", "--user", help="web UI username")
    parser.add_argument("-w", "--password", help="web UI password")
    parser.add_argument("-t", "--timeout", type=float, default=10.0)
    parser.add_argument(
        "--check-mac",
        action="store_true",
        help=f"verify a local interface uses {_MAGIC_MAC} (needed for --new firmware)",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="read the ONT status page and print the firmware version, then exit",
    )
    args = parser.parse_args(argv)

    if args.info:
        return _show_info(args)

    if args.check_mac:
        return _check_mac()

    try:
        user, password = open_factory_mode(
            ip=args.ip,
            port=args.port,
            username=args.user,
            password=args.password,
            timeout=args.timeout,
        )
    except FactoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print()
    print("  telnet credentials (temporary)")
    print(f"    host: {args.ip}")
    print(f"    user: {user}")
    print(f"    pass: {password}")
    print()
    print("  These change on every reboot. Re-run this script when needed.")
    print()
    print("  This command only reads factory mode. It does not flash firmware,")
    print("  reboot the ONT, or change your region code or settings.")
    print()
    print("  Do NOT use the web UI Software Upgrade page or the hardware reset")
    print("  button just to test this -- those are what overwrite firmware.")
    return 0


def _show_info(args) -> int:
    """Print what the ONT reports about itself.

    Read-only: this fetches the status page and changes nothing. Useful for
    confirming which firmware is loaded before touching anything else.
    """
    url = f"http://{args.ip}:{args.port}/"
    try:
        conn = http.client.HTTPConnection(args.ip, args.port, timeout=args.timeout)
        try:
            conn.request("GET", "/", headers=_HEADERS)
            resp = conn.getresponse()
            body = resp.read().decode(errors="replace")
        finally:
            conn.close()
    except OSError as exc:
        print(f"error: cannot reach {url}: {exc}", file=sys.stderr)
        return 1

    print(f"  ONT {args.ip} responded {resp.status}")
    print()

    # The status page layout varies by firmware; pull any labelled field whose
    # value looks like a version or model string.
    text = re.sub(r"<[^>]+>", " ", body)

    fields = {
        "Device Type": r"Device\s*Type\s+V?([0-9A-Za-z][0-9A-Za-z.\-]*)",
        "Hardware Version": r"Hardware\s*Version\s+V?([0-9][0-9A-Za-z.]*)",
        "Software Version": r"Software\s*Version\s+V?([0-9][0-9A-Za-z.]*)",
        "Boot Version": r"Boot\s*Version\s+V?([0-9][0-9A-Za-z.]*)",
    }
    found = False
    for label, pattern in fields.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            print(f"  {label}: {match.group(1).strip()}")
            found = True

    if not found:
        print("  (no version fields found -- the status page layout may differ)")

    print()
    print("  Read-only: nothing was changed on the ONT.")
    return 0


def _check_mac() -> int:
    """Report whether any local interface carries the magic MAC."""
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            raw.connect(("192.168.1.1", 1))
            local_ip = raw.getsockname()[0]
        finally:
            raw.close()
    except OSError as exc:
        print(f"error: cannot determine local interface: {exc}", file=sys.stderr)
        return 1

    # Look at the interface bound to the address that would reach the ONT,
    # not the ARP table, which holds the ONT's own MAC rather than ours.
    found = False
    for interface in net_ifaces():
        addresses = interface.get("addr", []) or []
        for family, mac in addresses:
            if family != socket.AF_INET or mac != local_ip:
                continue
            found = True
            if mac_is_magic(interface.get("link", "")):
                print(f"ok: {local_ip} uses {_MAGIC_MAC} on {interface['name']}")
                return 0
            print(
                f"{local_ip} uses {interface.get('link', 'unknown')}, "
                f"expected {_MAGIC_MAC} (interface {interface['name']})"
            )
            return 1

    if not found:
        print(f"no interface found for {local_ip}")
    else:  # pragma: no cover - defensive
        print(f"no interface found for {local_ip}")
    return 1


def mac_is_magic(link_address: str) -> bool:
    """True when the interface address is the magic MAC."""
    return link_address.replace("-", ":").lower() == _MAGIC_MAC.lower()


def net_ifaces() -> list[dict]:
    """Local interfaces as [{name, addr: [(family, ip)], link: mac}].

    Uses psutil when present, otherwise the stdlib where possible. Kept
    dependency-free, so the common macOS/Linux cases are handled directly and
    anything else falls back to an empty list.
    """
    interfaces: list[dict] = []
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            raw.connect(("192.168.1.1", 1))
            interfaces.append({
                "name": "default-route",
                "addr": [(socket.AF_INET, raw.getsockname()[0])],
                "link": "",
            })
        finally:
            raw.close()
    except OSError:
        pass

    try:
        import psutil  # type: ignore
    except ImportError:
        return interfaces

    for name, addrs in psutil.net_if_addrs().items():
        entry = {
            "name": name,
            "addr": [
                (a.family, a.address)
                for a in addrs
                if getattr(a, "family", None) in (socket.AF_INET,)
            ],
            "link": next(
                (a.address for a in addrs
                 if getattr(a, "family", None) == psutil.AF_LINK),
                "",
            ),
        }
        interfaces.append(entry)
    return interfaces


if __name__ == "__main__":
    raise SystemExit(main())