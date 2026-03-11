"""Behavior tests for EdictumServerClient HTTPS enforcement.

Verifies that plaintext HTTP connections are refused by default,
allowed with allow_insecure=True (with a warning), and that
localhost/loopback addresses are exempt.
"""

from __future__ import annotations

import logging

import pytest

from edictum.server.client import EdictumServerClient


class TestHttpsEnforcement:
    """Observable effect: allow_insecure controls whether http:// URLs are accepted."""

    def test_https_url_accepted(self):
        """HTTPS URLs are always accepted without error."""
        client = EdictumServerClient("https://example.com", "key")
        assert client.base_url == "https://example.com"

    def test_http_url_raises_by_default(self):
        """Plaintext HTTP to a non-loopback host raises ValueError."""
        with pytest.raises(ValueError, match="Refusing plaintext HTTP connection to example.com"):
            EdictumServerClient("http://example.com", "key")

    def test_http_url_with_allow_insecure_warns(self, caplog):
        """allow_insecure=True allows HTTP but logs a warning."""
        with caplog.at_level(logging.WARNING, logger="edictum.server.client"):
            client = EdictumServerClient("http://example.com", "key", allow_insecure=True)
        assert client.base_url == "http://example.com"
        assert "Plaintext HTTP connection to example.com" in caplog.text
        assert "Use HTTPS in production" in caplog.text

    def test_http_localhost_allowed(self):
        """http://localhost is exempt (common for development)."""
        client = EdictumServerClient("http://localhost:8080", "key")
        assert client.base_url == "http://localhost:8080"

    def test_http_127_0_0_1_allowed(self):
        """http://127.0.0.1 is exempt (IPv4 loopback)."""
        client = EdictumServerClient("http://127.0.0.1:8080", "key")
        assert client.base_url == "http://127.0.0.1:8080"

    def test_http_ipv6_loopback_allowed(self):
        """http://[::1] is exempt (IPv6 loopback)."""
        client = EdictumServerClient("http://[::1]:8080", "key")
        assert client.base_url == "http://[::1]:8080"

    @pytest.mark.security
    def test_http_non_loopback_raises(self):
        """Private network IPs over HTTP are not exempt."""
        with pytest.raises(ValueError, match="Refusing plaintext HTTP connection to 192.168.1.1"):
            EdictumServerClient("http://192.168.1.1", "key")

    def test_warning_message_contains_host(self, caplog):
        """The warning message includes the specific hostname."""
        with caplog.at_level(logging.WARNING, logger="edictum.server.client"):
            EdictumServerClient("http://my-server.internal", "key", allow_insecure=True)
        assert "my-server.internal" in caplog.text

    @pytest.mark.security
    def test_http_no_host_raises(self):
        """HTTP URL with empty hostname is not exempt."""
        # urlparse("http://") gives hostname="" — should not pass as loopback
        with pytest.raises(ValueError, match="Refusing plaintext HTTP"):
            EdictumServerClient("http://", "key")

    @pytest.mark.security
    def test_http_10_x_raises(self):
        """Private 10.x.x.x addresses over HTTP are denied by default."""
        with pytest.raises(ValueError, match="Refusing plaintext HTTP connection to 10.0.0.1"):
            EdictumServerClient("http://10.0.0.1:8080", "key")

    def test_allow_insecure_false_is_default(self):
        """Verify that omitting allow_insecure defaults to strict enforcement."""
        # HTTPS works fine without allow_insecure
        client = EdictumServerClient("https://example.com", "key")
        assert client.base_url == "https://example.com"

        # HTTP to non-loopback fails without allow_insecure
        with pytest.raises(ValueError):
            EdictumServerClient("http://example.com", "key")
