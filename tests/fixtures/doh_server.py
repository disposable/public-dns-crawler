"""Local DoH server fixture with TLS via openssl CLI.

Uses stdlib http.server + ssl (cert generated via subprocess openssl) to
serve DNS-over-HTTPS on a random localhost port. No third-party C
extensions required — openssl is available on all CI runners.
The same authoritative zone as dns_authority.py is served.
"""

from __future__ import annotations

import base64
import http.server
import ssl
import subprocess
import tempfile
import threading
import urllib.parse
from pathlib import Path

import dnslib

from tests.fixtures.dns_authority import _AuthResolver

DOH_PATH = "/dns-query"
_CONTENT_TYPE = "application/dns-message"


def _handle_wire(wire: bytes) -> bytes:
    """Resolve a wire-format DNS query through the local authoritative resolver."""
    resolver = _AuthResolver()
    try:
        request = dnslib.DNSRecord.parse(wire)
    except Exception:
        return dnslib.DNSRecord().reply().pack()
    reply = resolver.resolve(request, None)  # type: ignore[arg-type]
    return reply.pack()


class _DoHHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP/1.1 handler for DNS-over-HTTPS POST and GET requests."""

    def log_message(self, fmt: str, *args: object) -> None:
        pass  # suppress request logging in tests

    def _send_dns_response(self, wire: bytes) -> None:
        response = _handle_wire(wire)
        self.send_response(200)
        self.send_header("Content-Type", _CONTENT_TYPE)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_POST(self) -> None:
        if not self.path.startswith(DOH_PATH):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        wire = self.rfile.read(length)
        self._send_dns_response(wire)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if not parsed.path.startswith(DOH_PATH):
            self.send_error(404)
            return
        params = urllib.parse.parse_qs(parsed.query)
        dns_param = params.get("dns", [""])[0]
        if not dns_param:
            self.send_error(400)
            return
        padding = "=" * (-len(dns_param) % 4)
        wire = base64.urlsafe_b64decode(dns_param + padding)
        self._send_dns_response(wire)


def _generate_self_signed_cert(host: str, cert_path: Path, key_path: Path) -> None:
    """Generate a self-signed certificate via the openssl CLI."""
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            f"/CN={host}",
            "-addext",
            f"subjectAltName=IP:{host}",
        ],
        check=True,
        capture_output=True,
    )


class DoHServerFixture:
    """Local DoH server with a self-signed TLS certificate (openssl CLI)."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host
        self.port: int = 0
        self._ssl_ctx: ssl.SSLContext | None = None
        self._client_ssl_ctx: ssl.SSLContext | None = None
        self._server: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._tmpdir: tempfile.TemporaryDirectory[str] | None = None

    @property
    def url(self) -> str:
        return f"https://{self.host}:{self.port}{DOH_PATH}"

    @property
    def client_ssl_context(self) -> ssl.SSLContext:
        """Return an SSL context that trusts the self-signed cert."""
        assert self._client_ssl_ctx is not None
        return self._client_ssl_ctx

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

    def _run(self) -> None:
        assert self._server is not None
        self._server.serve_forever()

    def start(self) -> None:
        self._setup_tls()
        self._server = http.server.HTTPServer((self.host, 0), _DoHHandler)
        self._server.socket = self._ssl_ctx.wrap_socket(  # type: ignore[union-attr]
            self._server.socket, server_side=True
        )
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._tmpdir:
            self._tmpdir.cleanup()
            self._tmpdir = None

    def __enter__(self) -> DoHServerFixture:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
