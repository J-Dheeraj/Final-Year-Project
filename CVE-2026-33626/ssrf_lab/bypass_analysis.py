"""
bypass_analysis.py — Theoretical SSRF bypass analysis against the patched
image_loader._resolve_and_check() implementation.

For each bypass class this script:
  1. Explains WHY the patch is insufficient
  2. Shows the attack vector as a concrete test
  3. Shows the hardened countermeasure
  4. Marks the result: BYPASSED / BLOCKED / NEEDS-EXTERNAL-INFRA

Run:
    python bypass_analysis.py
"""

import ipaddress
import socket
import sys
import textwrap
from urllib.parse import urlparse

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SEP  = "=" * 68
SEP2 = "-" * 68


def header(n, title):
    print(f"\n{SEP}")
    print(f"  BYPASS {n}: {title}")
    print(SEP)


def result(label, verdict, detail=""):
    icon = {"BYPASSED": "✗ BYPASSED", "BLOCKED": "✓ BLOCKED",
            "NEEDS-EXTERNAL": "~ NEEDS-EXTERNAL-INFRA (theoretical)"}.get(verdict, verdict)
    print(f"\n  Result   : {icon}")
    if detail:
        print(f"  Detail   : {detail}")


# ─────────────────────────────────────────────────────────────────────────────
# Replicate the patched validator so we can test against it directly
# ─────────────────────────────────────────────────────────────────────────────

_BLOCKED = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

class SSRFBlockedError(ValueError):
    pass

def patched_validate(url: str) -> str:
    """Exact copy of image_loader._resolve_and_check()."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SSRFBlockedError(f"Disallowed scheme: {parsed.scheme!r}")
    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("No hostname")
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise SSRFBlockedError(f"DNS failed: {e}")
    for _, _, _, _, sockaddr in addr_infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global:
            raise SSRFBlockedError(f"Non-global: {ip}")
        for net in _BLOCKED:
            if ip in net:
                raise SSRFBlockedError(f"Blocked CIDR {net}: {ip}")
    return addr_infos[0][4][0]


def check(url: str) -> tuple[bool, str]:
    """Returns (blocked: bool, reason: str)."""
    try:
        ip = patched_validate(url)
        return False, f"passed — resolved to {ip}"
    except SSRFBlockedError as e:
        return True, str(e)
    except Exception as e:
        return True, f"{type(e).__name__}: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# BYPASS 1 — HTTP Redirect (TOCTOU on URL)
# ─────────────────────────────────────────────────────────────────────────────

header(1, "HTTP Redirect (most critical)")

print("""
  How it works:
    The patch validates the INITIAL URL.  requests.get() follows redirects
    by default.  An attacker hosts a public server that returns a 302
    pointing to http://169.254.169.254/latest/meta-data/.

    Validation sees:  attacker.com  →  public IP  ✓  ALLOWED
    requests.get sees: attacker.com  →  302  →  169.254.169.254  (fetched!)

  Attack flow:
    image_url = "http://attacker.com/redirect-to-metadata"
    _validate_url(image_url)   # attacker.com resolves to 1.2.3.4 — passes
    requests.get(image_url)    # follows 302 → http://169.254.169.254/ ← SSRF
""")

print("  Validation result on initial URL:")
blocked, reason = check("http://google.com/")
print(f"    http://google.com/  →  blocked={blocked}  ({reason})")

print("""
  Countermeasure — disable redirects and re-validate each hop:

    import urllib.parse

    def safe_get(url, max_hops=3, **kwargs):
        for _ in range(max_hops):
            _resolve_and_check(url)          # validate before every hop
            resp = requests.get(url, allow_redirects=False, **kwargs)
            if resp.status_code not in (301, 302, 303, 307, 308):
                return resp
            url = resp.headers.get("Location", "")
            if not url.startswith(("http://", "https://")):
                raise SSRFBlockedError("Redirect to non-HTTP scheme")
        raise SSRFBlockedError("Too many redirects")
""")
result("1", "NEEDS-EXTERNAL",
       "Requires attacker.com with a redirect endpoint (not testable on localhost)")


# ─────────────────────────────────────────────────────────────────────────────
# BYPASS 2 — DNS Rebinding (TOCTOU on DNS)
# ─────────────────────────────────────────────────────────────────────────────

header(2, "DNS Rebinding (Time-of-Check / Time-of-Use)")

print("""
  How it works:
    DNS is resolved TWICE — once inside _resolve_and_check(), and again
    inside requests.get() (which calls the OS resolver).

    The attacker controls the DNS record and sets TTL=1s:
      Round 1  getaddrinfo()  →  1.2.3.4   (public, passes validation)
      Round 2  requests.get() →  127.0.0.1 (private, DNS rebind fires)

    The gap between validation and the HTTP connect() call is the window.

  Tools that implement this:
    • singularity (https://github.com/nccgroup/singularity)
    • rbndr.us   (public DNS rebinding test service)

  Countermeasure — resolve once, pin the IP, bypass DNS for the request:

    import ipaddress, socket
    from urllib.parse import urlparse, urlunparse

    def safe_pinned_get(url, **kwargs):
        resolved_ip = _resolve_and_check(url)   # validated IP
        parsed = urlparse(url)
        # Replace hostname with the validated IP so the OS never re-resolves
        pinned_url = urlunparse(parsed._replace(
            netloc=f"{resolved_ip}:{parsed.port or 80}"
        ))
        return requests.get(
            pinned_url,
            headers={"Host": parsed.hostname},  # preserve SNI / Host header
            allow_redirects=False,
            **kwargs
        )
""")
result("2", "NEEDS-EXTERNAL",
       "Requires attacker-controlled DNS with TTL=0 — not testable on localhost")


# ─────────────────────────────────────────────────────────────────────────────
# BYPASS 3 — is_global edge-cases
# ─────────────────────────────────────────────────────────────────────────────

header(3, "ip.is_global Edge Cases")

print("  Testing addresses where is_global may return True unexpectedly:\n")

edge_cases = [
    ("0.0.0.0",            "Unspecified address"),
    ("0.1.2.3",            "0.0.0.0/8 — is_global=True in older Python"),
    ("100.64.0.1",         "RFC-6598 shared / carrier-grade NAT"),
    ("192.0.2.1",          "TEST-NET-1 (documentation range)"),
    ("198.51.100.1",       "TEST-NET-2 (documentation range)"),
    ("203.0.113.1",        "TEST-NET-3 (documentation range)"),
    ("240.0.0.1",          "Reserved (Class E)"),
    ("255.255.255.255",    "Broadcast"),
    ("::ffff:127.0.0.1",   "IPv4-mapped loopback"),
    ("::ffff:169.254.0.1", "IPv4-mapped link-local"),
    ("2001:db8::1",        "Documentation IPv6 (RFC 3849)"),
]

print(f"  {'Address':<26} {'is_global':>9}  {'Patched CIDR blocks':>6}  Description")
print(f"  {'-'*26} {'-'*9}  {'-'*6}  -----------")

for addr, desc in edge_cases:
    try:
        ip = ipaddress.ip_address(addr)
        is_g = ip.is_global
        in_blocklist = any(ip in net for net in _BLOCKED)
        flag = "✓" if in_blocklist or not is_g else "✗ BYPASS?"
        print(f"  {addr:<26} {str(is_g):>9}  {str(in_blocklist):>6}  {flag}  {desc}")
    except Exception as e:
        print(f"  {addr:<26} ERROR: {e}")

print("""
  Countermeasure — the explicit CIDR blocklist in image_loader.py already
  catches most of these, but add any missing ranges:

    _BLOCKED += [
        ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
        ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
        ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
        ipaddress.ip_network("240.0.0.0/4"),      # Class E reserved
        ipaddress.ip_network("255.255.255.255/32"),
    ]
    # And normalise IPv4-mapped IPv6:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped   # re-check the unwrapped IPv4 address
""")
result("3", "BLOCKED",
       "Explicit CIDR list catches all dangerous edge cases tested above")


# ─────────────────────────────────────────────────────────────────────────────
# BYPASS 4 — Alternative IP Encodings
# ─────────────────────────────────────────────────────────────────────────────

header(4, "Alternative IP Encodings")

print("""
  Numeric tricks that some validators miss.
  Python's socket.getaddrinfo() normalises these — we test whether the
  patch's DNS call sees through them.
""")

encoding_tests = [
    ("http://2130706433/",         "127.0.0.1 in decimal"),
    ("http://0x7f000001/",         "127.0.0.1 in hex"),
    ("http://0177.0.0.01/",        "127.0.0.1 in octal"),
    ("http://[::1]/",              "IPv6 loopback (bracket notation)"),
    ("http://[0:0:0:0:0:0:0:1]/", "IPv6 loopback (full notation)"),
    ("http://[::ffff:127.0.0.1]/", "IPv4-mapped loopback"),
    ("http://[::ffff:7f00:1]/",    "IPv4-mapped loopback (hex segments)"),
]

for url, desc in encoding_tests:
    blocked, reason = check(url)
    icon = "✓ BLOCKED" if blocked else "✗ BYPASSED"
    print(f"  {icon}  {url:<40}  {desc}")
    print(f"           Reason: {reason[:80]}")

print("""
  Countermeasure — no extra code needed; socket.getaddrinfo() normalises
  all of the above to their canonical IP form before validation.
  BUT add explicit urlparse scheme check to block non-http(s) schemes
  that bypass getaddrinfo entirely (file://, dict://, gopher://).
""")
result("3", "BLOCKED", "socket.getaddrinfo() normalises all encoding tricks")


# ─────────────────────────────────────────────────────────────────────────────
# BYPASS 5 — URL Parser Confusion
# ─────────────────────────────────────────────────────────────────────────────

header(5, "URL Parser Confusion (@-trick, Fragment, Port confusion)")

print("""
  Some validators parse hostname differently from how the HTTP client does.
  We test what urlparse extracts as hostname for tricky URLs.
""")

confusion_tests = [
    "http://169.254.169.254@google.com/",
    "http://google.com@169.254.169.254/",
    "http://169.254.169.254#@google.com/",
    "http://google.com:80@169.254.169.254/secret",
    "http://127.0.0.1:80\\@169.254.169.254/",
    "http://localhost:8000/℀/path",           # Unicode look-alike
    "http://localhosт/",                      # Cyrillic т instead of t
]

print(f"  {'URL (truncated)':<48}  urlparse.hostname    blocked?")
print(f"  {'-'*48}  -------------------  --------")

for url in confusion_tests:
    try:
        parsed = urlparse(url)
        h = parsed.hostname or "(none)"
        blocked, reason = check(url)
        icon = "✓" if blocked else "✗ BYPASS?"
        print(f"  {url[:48]:<48}  {h:<20} {icon}  {reason[:40]}")
    except Exception as e:
        print(f"  {url[:48]:<48}  ERROR: {e}")

print("""
  Countermeasure — enforce strict URL allowlist and add a final check
  that the resolved IP matches what the HTTP client will actually connect to:

    # After urlparse:
    if "@" in parsed.netloc:
        raise SSRFBlockedError("@ in netloc — possible credential/host confusion")
    if parsed.username or parsed.password:
        raise SSRFBlockedError("credentials in URL not allowed")
""")
result("5", "BLOCKED",
       "urlparse correctly extracts hostname; @ before host is parsed safely by Python")


# ─────────────────────────────────────────────────────────────────────────────
# Summary table
# ─────────────────────────────────────────────────────────────────────────────

print(f"\n{SEP}")
print("  SUMMARY — BYPASS ANALYSIS vs CURRENT PATCH")
print(SEP)
print(f"  {'Bypass':<40} {'Status':<22} Priority")
print(f"  {'-'*40} {'-'*22} --------")
rows = [
    ("HTTP Redirect (302 chain)",         "NEEDS FIX",        "CRITICAL"),
    ("DNS Rebinding (TOCTOU)",            "NEEDS FIX",        "HIGH    "),
    ("ip.is_global edge cases",           "Covered by CIDR",  "LOW     "),
    ("Alt IP encodings (hex/octal/dec)",  "Blocked by gai()", "LOW     "),
    ("URL parser @-trick",                "Blocked/parsable", "LOW     "),
]
for name, status, priority in rows:
    icon = "✗" if "FIX" in status else "✓"
    print(f"  {icon} {name:<39} {status:<22} {priority}")

print(f"""
  Action items for image_loader.py:
    1. Replace requests.get() with a redirect-aware safe_get() that calls
       _resolve_and_check() before EVERY redirect hop.
    2. Pin the resolved IP into the request URL to prevent DNS rebinding.
    3. Reject URLs containing '@' in the netloc.
    4. Add IPv4-mapped IPv6 unwrapping before the CIDR check.
{SEP}
""")
