"""
image_loader.py — Two implementations of load_image():

  vulnerable_load_image()  — fetches any URL with no validation (simulates
                              the pre-patch lmdeploy behaviour from
                              GHSA-6w67-hwm5-92mq / CVE-2026-33626).

  safe_load_image()        — resolves the hostname, rejects any IP that is
                              not globally routable, then fetches.

The server switches between them via the LAB_MODE env var / config flag.
"""

import ipaddress
import io
import socket
from urllib.parse import urlparse, urlunparse

import requests
from PIL import Image

FETCH_TIMEOUT = 8
HEADERS = {"User-Agent": "ssrf-lab/1.0 (internal-testing-only)"}

# ---------------------------------------------------------------------------
# Vulnerable implementation (intentionally unsafe — lab use only)
# ---------------------------------------------------------------------------

def vulnerable_load_image(image_url: str) -> tuple[str, dict]:
    """
    Fetches image_url with requests.get() and NO destination validation.

    THIS IS DELIBERATELY UNSAFE.  It exists solely so that detection
    rules (WAF signatures, network monitors, SIEM alerts) can be tested
    against a real SSRF trigger in a controlled lab environment.
    """
    resp = requests.get(image_url, headers=HEADERS, timeout=FETCH_TIMEOUT)
    resp.raise_for_status()

    content_type = resp.headers.get("Content-Type", "application/octet-stream")
    size_bytes    = len(resp.content)

    # Attempt to open as image; fall back gracefully so metadata probes
    # (e.g. http://169.254.169.254/latest/meta-data/) still return a response
    # the caller can inspect — that response IS the detection signal.
    image_info: dict = {
        "content_type": content_type,
        "size_bytes": size_bytes,
        "resolved_url": resp.url,
        "status_code": resp.status_code,
    }
    try:
        img = Image.open(io.BytesIO(resp.content))
        image_info.update({"width": img.width, "height": img.height, "format": img.format})
    except Exception:
        # Non-image response body (e.g. metadata JSON) — keep raw preview
        image_info["body_preview"] = resp.text[:512]

    return "vulnerable", image_info


# ---------------------------------------------------------------------------
# Safe implementation
# ---------------------------------------------------------------------------

# Every CIDR that must never be a fetch destination
_BLOCKED: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # Shared address space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),   # Benchmark testing (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"), # Documentation (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),  # Documentation (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),     # Multicast
    ipaddress.ip_network("240.0.0.0/4"),     # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),        # Unique local
    ipaddress.ip_network("fe80::/10"),       # Link-local
]

_ALLOWED_SCHEMES = {"http", "https"}


class SSRFBlockedError(ValueError):
    """Raised when a URL resolves to a blocked (private/internal) address."""


def _resolve_and_check(url: str) -> str:
    """
    Parse url, resolve its hostname via DNS, and raise SSRFBlockedError if
    the resolved IP is not a globally routable unicast address.

    Returns the resolved IP string on success.
    """
    parsed = urlparse(url)

    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"Disallowed URL scheme: {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("URL has no hostname")

    # Resolve ALL addresses the hostname might map to; block if ANY is private
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"DNS resolution failed for {hostname!r}: {exc}") from exc

    if not addr_infos:
        raise SSRFBlockedError(f"No DNS records found for {hostname!r}")

    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        raw_ip = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise SSRFBlockedError(f"Cannot parse resolved address {raw_ip!r}") from exc

        # is_global check (primary gate)
        if not ip.is_global:
            raise SSRFBlockedError(
                f"Hostname {hostname!r} resolves to non-global address {ip} — blocked"
            )

        # Belt-and-suspenders: explicit CIDR blocklist catches edge cases
        # (e.g. is_global is True for some shared-space addresses in older Pythons)
        for net in _BLOCKED:
            if ip in net:
                raise SSRFBlockedError(
                    f"Hostname {hostname!r} resolves to blocked range {net} — blocked"
                )

    return addr_infos[0][4][0]   # return first resolved IP for logging


def _safe_get(url: str, max_hops: int = 5, **kwargs) -> "requests.Response":
    """
    Drop-in for requests.get() that re-validates every redirect hop.

    Fixes Bypass 1 (HTTP redirect TOCTOU): instead of validating the initial
    URL and then blindly following 302s, we disable automatic redirect following
    and validate each Location header before continuing.
    """
    for _ in range(max_hops):
        _resolve_and_check(url)
        resp = requests.get(url, allow_redirects=False, **kwargs)
        if resp.status_code not in (301, 302, 303, 307, 308):
            return resp
        location = resp.headers.get("Location", "")
        if not location.startswith(("http://", "https://")):
            raise SSRFBlockedError(f"Redirect to non-HTTP(S) scheme: {location!r}")
        url = location
    raise SSRFBlockedError("Too many redirects")


def _safe_pinned_get(url: str, **kwargs) -> "requests.Response":
    """
    Validates url, then replaces its hostname with the resolved IP so the OS
    never performs a second DNS lookup.

    Fixes Bypass 2 (DNS rebinding TOCTOU): after validation we pin the IP
    directly into the URL, preventing an attacker from flipping the DNS
    record between our check and the actual TCP connect.
    """
    resolved_ip = _resolve_and_check(url)
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    pinned_url = urlunparse(parsed._replace(netloc=f"{resolved_ip}:{port}"))
    extra_headers = {**HEADERS, "Host": parsed.hostname}
    extra_headers.update(kwargs.pop("headers", {}))
    return requests.get(
        pinned_url,
        headers=extra_headers,
        allow_redirects=False,
        **kwargs,
    )


def hardened_load_image(image_url: str) -> tuple[str, dict]:
    """
    Fully hardened fetch: redirect-aware validation + IP pinning.

    Combines both countermeasures:
      - _safe_get()        re-validates every redirect hop (blocks redirect bypass)
      - _safe_pinned_get() pins the IP for the final hop (blocks DNS rebinding)

    The flow is: validate initial URL → follow redirects one-at-a-time with
    per-hop validation → on the last non-redirect response, pin the final URL's
    IP for the actual content fetch.
    """
    # Walk redirect chain with per-hop validation; collect final URL
    current_url = image_url
    for _ in range(5):
        _resolve_and_check(current_url)
        resp = requests.get(
            current_url,
            allow_redirects=False,
            headers=HEADERS,
            timeout=FETCH_TIMEOUT,
        )
        if resp.status_code not in (301, 302, 303, 307, 308):
            break
        location = resp.headers.get("Location", "")
        if not location.startswith(("http://", "https://")):
            raise SSRFBlockedError(f"Redirect to non-HTTP(S) scheme: {location!r}")
        current_url = location
    else:
        raise SSRFBlockedError("Too many redirects")

    # Final content fetch: pin the validated IP to defeat DNS rebinding
    resp = _safe_pinned_get(current_url, timeout=FETCH_TIMEOUT)
    resp.raise_for_status()

    content_type = resp.headers.get("Content-Type", "application/octet-stream")
    image_info: dict = {
        "content_type": content_type,
        "size_bytes": len(resp.content),
        "resolved_url": current_url,
        "status_code": resp.status_code,
        "redirect_hops": current_url != image_url,
    }
    try:
        img = Image.open(io.BytesIO(resp.content))
        image_info.update({"width": img.width, "height": img.height, "format": img.format})
    except Exception:
        image_info["body_preview"] = resp.text[:512]

    return "hardened", image_info


def safe_load_image(image_url: str) -> tuple[str, dict]:
    """Validates image_url before fetching; raises SSRFBlockedError if blocked."""
    resolved_ip = _resolve_and_check(image_url)

    resp = requests.get(image_url, headers=HEADERS, timeout=FETCH_TIMEOUT)
    resp.raise_for_status()

    content_type = resp.headers.get("Content-Type", "application/octet-stream")
    image_info: dict = {
        "content_type": content_type,
        "size_bytes": len(resp.content),
        "resolved_ip": resolved_ip,
        "resolved_url": resp.url,
        "status_code": resp.status_code,
    }
    try:
        img = Image.open(io.BytesIO(resp.content))
        image_info.update({"width": img.width, "height": img.height, "format": img.format})
    except Exception:
        image_info["body_preview"] = resp.text[:512]

    return "safe", image_info
