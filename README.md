# nachos-ssrf

SSRF (Server-Side Request Forgery) protection for Python — asyncio-native, zero external dependencies.

Port of the TypeScript `SSRFProtection` class from the nachos gateway, improved with Python's
`ipaddress` stdlib module for correct, exhaustive IP classification.

## Install

```
pip install nachos-ssrf
```

## Quick Start

```python
import asyncio
from nachos_ssrf import SSRFProtection, SSRFConfig

# Allow requests only to example.com and its subdomains
config = SSRFConfig(
    allowed_domains=["example.com"],
    block_private_ips=True,
    block_localhost=True,
)
ssrf = SSRFProtection(config)

async def main():
    result = await ssrf.validate_url("https://api.example.com/data")
    if result.valid:
        print("Safe to fetch.")
    else:
        print("Blocked:", result.errors)

asyncio.run(main())
```

### Wildcard — allow all domains (only IP/protocol checks apply)

```python
config = SSRFConfig(allowed_domains=["*"])
ssrf = SSRFProtection(config)
```

### Custom blocked IPs

```python
import re

config = SSRFConfig(
    allowed_domains=["*"],
    blocked_ips=["203.0.113.5", re.compile(r"^198\.51\.100\.")],
)
```

## Config Options

| Option | Type | Default | Description |
|---|---|---|---|
| `allowed_domains` | `list[str]` | `[]` | Domains/subdomains to allow. `["*"]` bypasses domain check. |
| `block_private_ips` | `bool` | `True` | Block RFC1918 + link-local ranges. |
| `block_localhost` | `bool` | `True` | Block loopback (127.x, ::1, 0.0.0.0, ::). |
| `blocked_ips` | `list[str \| re.Pattern]` | `[]` | Additional IPs/patterns to block. |

## Why This Matters

### DNS Rebinding

A naive SSRF check that only validates the hostname at request time is bypassable via DNS rebinding:
an attacker registers a domain that initially resolves to a public IP (passing validation) and then
re-resolves to an internal address for the actual connection. `nachos-ssrf` resolves DNS **before**
making the request and validates every returned A and AAAA record, closing this window.

### IPv4-Mapped IPv6 Addresses

Modern stacks may represent IPv4 addresses as IPv6 (e.g. `::ffff:127.0.0.1` for loopback). A filter
that only checks the plain `127.x.x.x` range will silently pass these. Python's `ipaddress` module
unwraps IPv4-mapped IPv6 addresses via `.ipv4_mapped` before classification, so `::ffff:10.0.0.1`
is correctly identified as private — no extra regex needed.

## Running Tests

```
pip install pytest pytest-asyncio
pytest tests/
```
