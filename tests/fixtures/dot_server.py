"""Local DoT (DNS-over-TLS) server fixture.

TLS-wraps a TCP socket serving length-prefixed DNS wire messages (RFC 7858)
through the same authoritative zone as dns_authority.py. Certificates are
generated via the openssl CLI like tests/fixtures/doh_server.py.
"""

from __future__ import annotations

import socket
import socketserver
import ssl
import struct
import tempfile
import threading
from pathlib import Path

import dnslib

from tests.fixtures.dns_authority import _AuthResolver
from tests.fixtures.doh_server import _generate_self_signed_cert


def _handle_wire(wire: bytes) -> bytes:
    """Resolve a wire-format DNS query through the local authoritative resolver."""
    resolver = _AuthResolver()
    try:
        request = dnslib.DNSRecord.parse(wire)
    except Exception:
        return dnslib.DNSRecord().reply().pack()
    reply = resolver.resolve(request, None)  # type: ignore[arg-type]
    return reply.pack()


def _recv_exact(conn: socket.socket, size: int) -> bytes | None:
    data = b""
    while len(data) < size:
        try:
            chunk = conn.recv(size - len(data))
        except OSError:
            return None
        if not chunk:
            return None
        data += chunk
    return data


class _DoTHandler(socketserver.BaseRequestHandler):
    """Serve DoT queries: ``<uint16 length><dns wire>`` frames over TLS."""

    def handle(self) -> None:
        conn = self.request
        while True:
            header = _recv_exact(conn, 2)
            if header is None:
                return
            (length,) = struct.unpack("!H", header)
            wire = _recv_exact(conn, length)
            if wire is None:
                return
            response = _handle_wire(wire)
            try:
                conn.sendall(struct.pack("!H", len(response)) + response)
            except OSError:
                return


class _ThreadedTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class DoTServerFixture:
    """Local DoT server with a self-signed TLS certificate (openssl CLI)."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host
        self.port: int = 0
        self._ssl_ctx: ssl.SSLContext | None = None
        self._client_ssl_ctx: ssl.SSLContext | None = None
        self._verifying_client_ssl_ctx: ssl.SSLContext | None = None
        self._server: _ThreadedTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None

    @property
    def client_ssl_context(self) -> ssl.SSLContext:
        """Context that trusts the self-signed cert without hostname checks."""
        assert self._client_ssl_ctx is not None
        return self._client_ssl_ctx

    @property
    def verifying_client_ssl_context(self) -> ssl.SSLContext:
        """Context that trusts the cert and enforces hostname verification."""
        assert self._verifying_client_ssl_ctx is not None
        return self._verifying_client_ssl_ctx

    def _setup_tls(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp = Path(self._tmpdir.name)
        cert_path = tmp / "cert.pem"
        key_path = tmp / "key.pem"
        _generate_self_signed_cert(self.host, cert_path, key_path)

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(cert_path), str(key_path))
        self._ssl_ctx = server_ctx

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.load_verify_locations(str(cert_path))
        client_ctx.check_hostname = False
        self._client_ssl_ctx = client_ctx

        verifying_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        verifying_ctx.load_verify_locations(str(cert_path))
        verifying_ctx.check_hostname = True
        verifying_ctx.verify_mode = ssl.CERT_REQUIRED
        self._verifying_client_ssl_ctx = verifying_ctx

    def _run(self) -> None:
        assert self._server is not None
        self._server.serve_forever()

    def start(self) -> None:
        self._setup_tls()
        self._server = _ThreadedTCPServer((self.host, 0), _DoTHandler)
        self._server.socket = self._ssl_ctx.wrap_socket(  # type: ignore[union-attr]
            self._server.socket, server_side=True
        )
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._tmpdir:
            self._tmpdir.cleanup()
            self._tmpdir = None

    def __enter__(self) -> DoTServerFixture:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
