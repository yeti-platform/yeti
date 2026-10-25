import http.server
import os
import threading
import unittest
from unittest import mock

import requests
from urllib3 import poolmanager
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

from core.schemas import observable


class Handler(http.server.BaseHTTPRequestHandler):
    """Serves PAGE, or redirects to REDIRECT when it is set."""

    page = b"1.1.1.1\nexample.com\n"
    redirect: str | None = None
    requests_seen: list[str] = []

    def do_GET(self) -> None:
        self.requests_seen.append(self.server.server_address[0])
        if self.redirect:
            self.send_response(302)
            self.send_header("Location", self.redirect)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(self.page)

    def log_message(self, *args) -> None:
        pass


def serve(host: str) -> str:
    server = http.server.HTTPServer((host, 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://{host}:{server.server_address[1]}/"


def internal_urls(allowed: bool):
    value = "true" if allowed else "false"
    return mock.patch.dict(
        "os.environ", {"YETI_SYSTEM_ALLOW_INTERNAL_URL_IMPORTS": value}
    )


def allow_only(*addresses: str):
    """Treats only *addresses* as public, so local servers can stand in."""
    return mock.patch.object(
        observable, "_is_public", side_effect=lambda address: address in addresses
    )


class UrlImportAddressesTest(unittest.TestCase):
    def setUp(self) -> None:
        Handler.redirect = None
        Handler.requests_seen = []

    def test_internal_addresses_are_allowed_by_default(self) -> None:
        url = serve("127.0.0.1")
        with mock.patch.dict("os.environ"):
            os.environ.pop("YETI_SYSTEM_ALLOW_INTERNAL_URL_IMPORTS", None)
            response = observable._fetch(url)
        self.assertEqual(response.content, Handler.page)

    def test_a_private_address_is_refused_before_any_request(self) -> None:
        url = serve("127.0.0.1")
        with (
            internal_urls(allowed=False),
            self.assertRaisesRegex(requests.ConnectionError, "not a public address"),
        ):
            observable._fetch(url)
        self.assertEqual(Handler.requests_seen, [])

    def test_a_redirect_to_a_private_address_is_refused(self) -> None:
        private_url = serve("127.0.0.2")
        public_url = serve("127.0.0.1")
        Handler.redirect = private_url
        with (
            internal_urls(allowed=False),
            allow_only("127.0.0.1"),
            self.assertRaisesRegex(requests.ConnectionError, "not a public address"),
        ):
            observable._fetch(public_url)
        self.assertEqual(Handler.requests_seen, ["127.0.0.1"])

    def test_a_public_address_is_fetched(self) -> None:
        url = serve("127.0.0.1")
        with internal_urls(allowed=False), allow_only("127.0.0.1"):
            self.assertEqual(observable._fetch(url).content, Handler.page)
        # Other requests in the process keep urllib3's default pools.
        self.assertEqual(
            poolmanager.pool_classes_by_scheme,
            {"http": HTTPConnectionPool, "https": HTTPSConnectionPool},
        )

    def test_the_public_address_check(self) -> None:
        for address, public in (
            ("8.8.8.8", True),
            ("127.0.0.1", False),
            ("10.1.2.3", False),
            ("169.254.169.254", False),
            ("::1", False),
            ("::ffff:127.0.0.1", False),
            ("fd00::1", False),
            ("2001:4860:4860::8888", True),
        ):
            with self.subTest(address=address):
                self.assertEqual(observable._is_public(address), public)
