"""
nachos_ssrf — SSRF protection with DNS rebinding defense and IPv4-mapped IPv6 coverage.

Port of the TypeScript SSRFProtection class from nachos/packages/core/gateway.
Key improvement over the original: uses Python's ipaddress module instead of regexes,
which handles IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) natively and correctly.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Union
from urllib.parse import urlparse


@dataclass
class SSRFConfig:
    """Configuration for SSRFProtection."""

    # Use ['*'] to allow all domains.
    allowed_domains: List[str] = field(default_factory=list)

    # Block RFC1918 private IP addresses (default: True).
    block_private_ips: bool = True

    # Block localhost / loopback addresses (default: True).
    block_localhost: bool = True

    # Additional IPs to block (exact string or compiled regex pattern).
    blocked_ips: List[Union[str, re.Pattern]] = field(default_factory=list)


@dataclass
class SSRFResult:
    """Result of a URL validation check."""

    valid: bool
    errors: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.valid


def _is_ip_address(hostname: str) -> bool:
    """Return True if *hostname* is a bare IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _classify_ip(addr_str: str) -> tuple[bool, bool, bool]:
    """
    Classify an IP address string.

    Returns (is_loopback, is_private, is_link_local).

    Uses ipaddress.ip_address() which transparently handles:
      - IPv4-mapped IPv6 (::ffff:10.0.0.1) via .ipv4_mapped
      - All RFC1918 ranges, link-local, loopback, and multicast
    """
    try:
        addr = ipaddress.ip_address(addr_str)
    except ValueError:
        # Not parseable — treat as non-IP (won't reach here via normal paths)
        return False, False, False

    # Unwrap IPv4-mapped IPv6 (::ffff:x.x.x.x) so is_private etc. work correctly.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    loopback = addr.is_loopback or addr == ipaddress.ip_address("0.0.0.0") or addr == ipaddress.ip_address("::")
    private = addr.is_private
    link_local = addr.is_link_local

    return loopback, private, link_local


class SSRFProtection:
    """
    Validates URLs against SSRF (Server-Side Request Forgery) attacks.

    Checks:
      1. Protocol — only http/https allowed.
      2. Domain allowlist — wildcard '*' passes everything through.
      3. IP address classification — blocks private, loopback, link-local ranges.
      4. DNS resolution — resolves A + AAAA records and checks every resolved IP
         to defend against DNS rebinding attacks.
    """

    def __init__(self, config: Optional[SSRFConfig] = None) -> None:
        if config is None:
            config = SSRFConfig(allowed_domains=["*"])
        self._config = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def validate_url(self, url: str) -> SSRFResult:
        """Validate *url* for SSRF safety.  Returns SSRFResult."""
        try:
            parsed = urlparse(url)

            # Require an explicit scheme and a netloc so bare paths don't slip through.
            if not parsed.scheme or not parsed.netloc:
                return SSRFResult(valid=False, errors=[f"Invalid or unparseable URL: {url!r}"])

            # Protocol check — only http/https.
            if parsed.scheme not in ("http", "https"):
                return SSRFResult(
                    valid=False,
                    errors=[
                        f"Protocol {parsed.scheme!r} not allowed. "
                        "Only 'http' and 'https' are supported."
                    ],
                )

            hostname = parsed.hostname or ""
            if not hostname:
                return SSRFResult(valid=False, errors=["URL has no hostname."])

            # Strip IPv6 brackets that urlparse leaves in for bare bracket notation.
            if hostname.startswith("[") and hostname.endswith("]"):
                hostname = hostname[1:-1]

            # Domain allowlist check.
            domain_result = self._check_domain_allowlist(hostname)
            if not domain_result.valid:
                return domain_result

            # IP address vs. hostname path.
            if _is_ip_address(hostname):
                return self._check_ip_address(hostname)
            else:
                return await self._check_dns_resolution(hostname)

        except Exception as exc:  # noqa: BLE001
            return SSRFResult(valid=False, errors=[f"Invalid URL: {exc}"])

    def get_allowed_domains(self) -> List[str]:
        """Return a copy of the configured allowed-domains list."""
        return list(self._config.allowed_domains)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_domain_allowlist(self, hostname: str) -> SSRFResult:
        if "*" in self._config.allowed_domains:
            return SSRFResult(valid=True)

        normalized = hostname.lower()
        for allowed in self._config.allowed_domains:
            norm_allowed = allowed.lower()
            if normalized == norm_allowed or normalized.endswith(f".{norm_allowed}"):
                return SSRFResult(valid=True)

        return SSRFResult(
            valid=False,
            errors=[
                f"Domain {hostname!r} is not in the allowlist. "
                f"Allowed: {', '.join(self._config.allowed_domains)}"
            ],
        )

    def _check_ip_address(self, ip: str) -> SSRFResult:
        is_loopback, is_private, is_link_local = _classify_ip(ip)

        if self._config.block_localhost and is_loopback:
            return SSRFResult(valid=False, errors=[f"Cannot connect to loopback/localhost address: {ip}"])

        if self._config.block_private_ips and (is_private or is_link_local):
            return SSRFResult(valid=False, errors=[f"Cannot connect to private/link-local IP address: {ip}"])

        for blocked in self._config.blocked_ips:
            if isinstance(blocked, str):
                if ip == blocked:
                    return SSRFResult(valid=False, errors=[f"IP address {ip!r} is explicitly blocked."])
            elif blocked.search(ip):
                return SSRFResult(valid=False, errors=[f"IP address {ip!r} matches a blocked pattern."])

        return SSRFResult(valid=True)

    async def _check_dns_resolution(self, hostname: str) -> SSRFResult:
        """
        Resolve *hostname* to A and AAAA records and validate every returned IP.
        This prevents DNS rebinding — where a domain initially resolves to a public IP
        but later rebinds to an internal one.
        """
        loop = asyncio.get_event_loop()

        try:
            # Run blocking getaddrinfo in a thread-pool executor so we don't block the event loop.
            # AF_UNSPEC returns both IPv4 and IPv6 results in one call.
            results = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM),
            )
        except socket.gaierror as exc:
            return SSRFResult(
                valid=False,
                errors=[f"DNS resolution failed for {hostname!r}: {exc}"],
            )
        except Exception as exc:  # noqa: BLE001
            return SSRFResult(
                valid=False,
                errors=[f"DNS resolution error for {hostname!r}: {exc}"],
            )

        if not results:
            return SSRFResult(
                valid=False,
                errors=[f"Could not resolve hostname: {hostname!r}"],
            )

        # getaddrinfo returns (family, type, proto, canonname, sockaddr)
        # sockaddr is (ip, port) for IPv4 or (ip, port, flowinfo, scope_id) for IPv6.
        ips: list[str] = []
        for _family, _type, _proto, _canonname, sockaddr in results:
            ip_str = sockaddr[0]
            if ip_str not in ips:
                ips.append(ip_str)

        for ip in ips:
            ip_result = self._check_ip_address(ip)
            if not ip_result.valid:
                return SSRFResult(
                    valid=False,
                    errors=[
                        f"DNS resolution detected forbidden IP {ip!r} for {hostname!r}.",
                        *ip_result.errors,
                    ],
                )

        return SSRFResult(valid=True)


__all__ = ["SSRFProtection", "SSRFConfig", "SSRFResult"]
