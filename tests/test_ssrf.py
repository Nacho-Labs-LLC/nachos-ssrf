"""
Tests for nachos_ssrf.SSRFProtection.

Uses asyncio.run() for async tests — no pytest-asyncio required for basic coverage,
but pytest-asyncio is available via the dev extras and will be used if installed.
"""

from __future__ import annotations

import asyncio
import re

import pytest

from nachos_ssrf import SSRFConfig, SSRFProtection, SSRFResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):
    """Run a coroutine synchronously (works without pytest-asyncio)."""
    return asyncio.run(coro)


def make_ssrf(**kwargs) -> SSRFProtection:
    return SSRFProtection(SSRFConfig(**kwargs))


# ---------------------------------------------------------------------------
# Protocol checks
# ---------------------------------------------------------------------------

class TestProtocol:
    def test_http_allowed(self):
        ssrf = make_ssrf(allowed_domains=["*"])
        result = run(ssrf.validate_url("http://example.com/path"))
        assert result.valid, result.errors

    def test_https_allowed(self):
        ssrf = make_ssrf(allowed_domains=["*"])
        result = run(ssrf.validate_url("https://example.com/path"))
        assert result.valid, result.errors

    def test_ftp_blocked(self):
        ssrf = make_ssrf(allowed_domains=["*"])
        result = run(ssrf.validate_url("ftp://example.com/file"))
        assert not result.valid
        assert any("ftp" in e.lower() or "protocol" in e.lower() for e in result.errors)

    def test_file_blocked(self):
        ssrf = make_ssrf(allowed_domains=["*"])
        result = run(ssrf.validate_url("file:///etc/passwd"))
        assert not result.valid

    def test_invalid_url_blocked(self):
        ssrf = make_ssrf(allowed_domains=["*"])
        result = run(ssrf.validate_url("not-a-url"))
        assert not result.valid


# ---------------------------------------------------------------------------
# Domain allowlist
# ---------------------------------------------------------------------------

class TestDomainAllowlist:
    def test_exact_domain_allowed(self):
        ssrf = make_ssrf(allowed_domains=["example.com"], block_private_ips=False, block_localhost=False)
        # Use a raw IP to skip DNS so the test is deterministic.
        ssrf2 = make_ssrf(allowed_domains=["example.com"])
        result = run(ssrf2.validate_url("https://example.com/"))
        # May fail on DNS, but domain check should pass — test domain rejection separately.
        # Just verify it's not blocked for domain reasons.
        # (DNS resolution may fail in CI; we only care about the domain logic here.)
        # If DNS fails, errors won't mention "allowlist".
        if not result.valid:
            assert not any("allowlist" in e for e in result.errors), result.errors

    def test_subdomain_allowed(self):
        ssrf = make_ssrf(allowed_domains=["example.com"])
        result = run(ssrf.validate_url("https://api.example.com/"))
        # Subdomain of allowed domain should pass domain check.
        if not result.valid:
            assert not any("allowlist" in e for e in result.errors), result.errors

    def test_other_domain_blocked(self):
        ssrf = make_ssrf(allowed_domains=["example.com"])
        result = run(ssrf.validate_url("https://evil.com/"))
        assert not result.valid
        assert any("allowlist" in e for e in result.errors)

    def test_wildcard_allows_any_domain(self):
        ssrf = make_ssrf(allowed_domains=["*"])
        result = run(ssrf.validate_url("https://anything.example.org/"))
        # Should not be blocked for domain reasons.
        if not result.valid:
            assert not any("allowlist" in e for e in result.errors), result.errors

    def test_empty_allowlist_blocks_all(self):
        ssrf = make_ssrf(allowed_domains=[])
        result = run(ssrf.validate_url("https://example.com/"))
        assert not result.valid
        assert any("allowlist" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Private IPv4 ranges
# ---------------------------------------------------------------------------

class TestPrivateIPv4:
    """Direct IP addresses in the URL — no DNS resolution needed."""

    def _check(self, ip: str) -> SSRFResult:
        ssrf = make_ssrf(allowed_domains=["*"], block_private_ips=True, block_localhost=True)
        return run(ssrf.validate_url(f"http://{ip}/"))

    def test_class_a_private(self):
        assert not self._check("10.0.0.1").valid

    def test_class_a_private_high(self):
        assert not self._check("10.255.255.255").valid

    def test_class_b_private_low(self):
        assert not self._check("172.16.0.1").valid

    def test_class_b_private_mid(self):
        assert not self._check("172.24.10.5").valid

    def test_class_b_private_high(self):
        assert not self._check("172.31.255.255").valid

    def test_class_b_not_private(self):
        # 172.15.x is NOT in RFC1918
        result = self._check("172.15.0.1")
        # Should not be blocked as private (may still be blocked for other reasons)
        assert result.valid or not any("private" in e.lower() for e in result.errors)

    def test_class_c_private(self):
        assert not self._check("192.168.1.1").valid

    def test_class_c_private_high(self):
        assert not self._check("192.168.255.254").valid


# ---------------------------------------------------------------------------
# Localhost / loopback
# ---------------------------------------------------------------------------

class TestLocalhost:
    def _check(self, target: str) -> SSRFResult:
        ssrf = make_ssrf(allowed_domains=["*"], block_localhost=True)
        return run(ssrf.validate_url(f"http://{target}/"))

    def test_localhost_ip(self):
        assert not self._check("127.0.0.1").valid

    def test_loopback_range(self):
        assert not self._check("127.0.0.2").valid

    def test_unspecified_ipv4(self):
        assert not self._check("0.0.0.0").valid

    def test_ipv6_loopback(self):
        assert not self._check("[::1]").valid

    def test_ipv6_unspecified(self):
        assert not self._check("[::]").valid


# ---------------------------------------------------------------------------
# Link-local
# ---------------------------------------------------------------------------

class TestLinkLocal:
    def _check(self, ip: str) -> SSRFResult:
        ssrf = make_ssrf(allowed_domains=["*"], block_private_ips=True)
        return run(ssrf.validate_url(f"http://{ip}/"))

    def test_ipv4_link_local(self):
        assert not self._check("169.254.0.1").valid

    def test_ipv4_link_local_high(self):
        assert not self._check("169.254.255.254").valid

    def test_ipv6_link_local(self):
        assert not self._check("[fe80::1]").valid


# ---------------------------------------------------------------------------
# IPv4-mapped IPv6 (the key novel protection)
# ---------------------------------------------------------------------------

class TestIPv4MappedIPv6:
    """
    IPv4-mapped IPv6 addresses must be blocked when their embedded IPv4 is private/loopback.
    Without proper unwrapping, ::ffff:127.0.0.1 would bypass naive IPv4 checks.
    """

    def _check(self, ipv6: str) -> SSRFResult:
        ssrf = make_ssrf(allowed_domains=["*"], block_private_ips=True, block_localhost=True)
        return run(ssrf.validate_url(f"http://[{ipv6}]/"))

    def test_mapped_loopback(self):
        assert not self._check("::ffff:127.0.0.1").valid

    def test_mapped_class_a_private(self):
        assert not self._check("::ffff:10.0.0.1").valid

    def test_mapped_class_b_private(self):
        assert not self._check("::ffff:172.16.0.1").valid

    def test_mapped_class_c_private(self):
        assert not self._check("::ffff:192.168.1.1").valid


# ---------------------------------------------------------------------------
# Custom blocked IPs
# ---------------------------------------------------------------------------

class TestCustomBlockedIPs:
    def test_exact_ip_blocked(self):
        ssrf = make_ssrf(
            allowed_domains=["*"],
            block_private_ips=False,
            block_localhost=False,
            blocked_ips=["203.0.113.5"],
        )
        result = run(ssrf.validate_url("http://203.0.113.5/"))
        assert not result.valid
        assert any("blocked" in e.lower() for e in result.errors)

    def test_other_ip_not_blocked(self):
        ssrf = make_ssrf(
            allowed_domains=["*"],
            block_private_ips=False,
            block_localhost=False,
            blocked_ips=["203.0.113.5"],
        )
        result = run(ssrf.validate_url("http://203.0.113.6/"))
        assert result.valid

    def test_regex_pattern_blocked(self):
        ssrf = make_ssrf(
            allowed_domains=["*"],
            block_private_ips=False,
            block_localhost=False,
            blocked_ips=[re.compile(r"^198\.51\.100\.")],
        )
        result = run(ssrf.validate_url("http://198.51.100.1/"))
        assert not result.valid

    def test_ip_not_matching_regex(self):
        ssrf = make_ssrf(
            allowed_domains=["*"],
            block_private_ips=False,
            block_localhost=False,
            blocked_ips=[re.compile(r"^198\.51\.100\.")],
        )
        result = run(ssrf.validate_url("http://198.51.101.1/"))
        assert result.valid


# ---------------------------------------------------------------------------
# DNS resolution failure
# ---------------------------------------------------------------------------

class TestDNSResolution:
    def test_nonexistent_domain_returns_invalid(self):
        ssrf = make_ssrf(allowed_domains=["*"])
        # Use a domain guaranteed not to resolve.
        result = run(ssrf.validate_url("https://this-domain-absolutely-does-not-exist-nachos-ssrf-test.invalid/"))
        assert not result.valid
        assert any("dns" in e.lower() or "resolv" in e.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# SSRFResult bool behaviour
# ---------------------------------------------------------------------------

class TestSSRFResult:
    def test_valid_result_is_truthy(self):
        assert SSRFResult(valid=True)

    def test_invalid_result_is_falsy(self):
        assert not SSRFResult(valid=False, errors=["bad"])

    def test_errors_default_empty(self):
        r = SSRFResult(valid=True)
        assert r.errors == []
