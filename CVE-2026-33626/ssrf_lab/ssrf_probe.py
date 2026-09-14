"""
ssrf_probe.py — Integration test for the SSRF defensive lab.

Spins up a local callback HTTP server on a random port, fires a crafted
image_url at both server modes, and reports whether each mode made the
outbound request (SSRF triggered) or blocked it.

Usage:
    python ssrf_probe.py                        # server at 127.0.0.1:8000
    python ssrf_probe.py --server-port 9000
    python ssrf_probe.py --format json
    python ssrf_probe.py --format text --out report.txt
    python ssrf_probe.py --timeout 6
"""

from __future__ import annotations

import argparse
import io
import json
import queue
import socket
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import requests

# ── force UTF-8 on Windows ──────────────────────────────────────────────────
if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ── timestamp helper ─────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ─────────────────────────────────────────────────────────────────────────────
# Callback server
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CallbackHit:
    timestamp:   str
    method:      str
    path:        str
    query:       str
    remote_addr: str
    headers:     dict[str, str]


class _CallbackHandler(BaseHTTPRequestHandler):
    """Records every inbound request to the shared queue; returns 200 OK."""

    hit_queue: queue.Queue[CallbackHit]   # injected before server starts

    def do_GET(self)  -> None: self._record()
    def do_POST(self) -> None: self._record()
    def do_HEAD(self) -> None: self._record()

    def _record(self) -> None:
        path, _, query = self.path.partition("?")
        hit = CallbackHit(
            timestamp   = _now(),
            method      = self.command,
            path        = path,
            query       = query,
            remote_addr = self.client_address[0],
            headers     = dict(self.headers),
        )
        self.hit_queue.put(hit)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"callback received\n")

    # silence the default access log so our output stays clean
    def log_message(self, *_):  # type: ignore[override]
        pass


def _free_port() -> int:
    """Ask the OS for an available ephemeral port."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CallbackServer:
    """
    A lightweight HTTP server that records every inbound request.

    with CallbackServer() as cb:
        url = cb.url("/test", data="confirmed")
        # ... fire requests at url ...
        hits = cb.drain(timeout=3)
    """

    def __init__(self) -> None:
        self._port     = _free_port()
        self._q: queue.Queue[CallbackHit] = queue.Queue()
        self._server   = self._build()
        self._thread   = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="callback-server",
        )

    def _build(self) -> HTTPServer:
        q = self._q
        class _Handler(_CallbackHandler):
            hit_queue = q
        server = HTTPServer(("127.0.0.1", self._port), _Handler)
        server.timeout = 0.5
        return server

    @property
    def port(self) -> int:
        return self._port

    def url(self, path: str = "/test", **params: str) -> str:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        return f"http://127.0.0.1:{self._port}{path}" + (f"?{qs}" if qs else "")

    def start(self) -> "CallbackServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()

    def drain(self, timeout: float = 3.0) -> list[CallbackHit]:
        """Collect all hits that arrive within *timeout* seconds."""
        hits: list[CallbackHit] = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                hits.append(self._q.get(timeout=min(remaining, 0.2)))
            except queue.Empty:
                pass
        return hits

    def __enter__(self) -> "CallbackServer":
        return self.start()

    def __exit__(self, *_: Any) -> None:
        self.stop()


# ─────────────────────────────────────────────────────────────────────────────
# Lab server client
# ─────────────────────────────────────────────────────────────────────────────

class LabClient:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def ping(self) -> bool:
        try:
            requests.get(f"{self.base}/mode", timeout=3).raise_for_status()
            return True
        except Exception:
            return False

    def set_mode(self, mode: str) -> dict:
        r = requests.post(
            f"{self.base}/mode",
            json={"mode": mode},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()

    def get_mode(self) -> str:
        return requests.get(f"{self.base}/mode", timeout=5).json()["mode"]

    def chat(self, image_url: str, timeout: float = 8) -> requests.Response:
        return requests.post(
            f"{self.base}/v1/chat/completions",
            json={
                "model": "internlm-xcomposer2",
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text",      "text": "describe this image"},
                            {"type": "image_url", "image_url": {"url": image_url}},
                        ],
                    }
                ],
            },
            timeout=timeout,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Probe result model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    mode:                  str       # "vulnerable" | "patched"
    callback_url:          str
    request_sent_at:       str
    response_received_at:  str
    http_status:           int | None
    server_blocked:        bool      # server returned 422 ssrf_blocked
    callback_hit:          bool      # callback server received a request
    callback_hits:         list[CallbackHit]
    ssrf_confirmed:        bool      # True iff callback was reached in vulnerable mode
    verdict:               str       # "PASS" | "FAIL"
    verdict_reason:        str
    elapsed_s:             float


def _evaluate(mode: str, server_blocked: bool, callback_hit: bool) -> tuple[str, str]:
    """
    Decide PASS/FAIL for each mode:

    vulnerable:  PASS  when the server did NOT block (allowing the probe) AND
                        the callback was reached — proving the SSRF path works.
                 FAIL  when the server blocked even in vulnerable mode (config error)
                        or when the callback was never hit (probe didn't reach it).

    patched:     PASS  when the server blocked the request AND the callback was
                        NOT reached (no outbound traffic escaped).
                 FAIL  if either the server didn't block or the callback was hit.
    """
    if mode == "vulnerable":
        if not server_blocked and callback_hit:
            return "PASS", "vulnerable mode allowed the request; callback confirmed SSRF"
        if server_blocked:
            return "FAIL", "server blocked the request even in vulnerable mode — misconfiguration"
        return "FAIL", "server allowed the request but callback was never hit — network issue"

    # patched
    if server_blocked and not callback_hit:
        return "PASS", "patched mode blocked the request; callback received no traffic"
    if not server_blocked and callback_hit:
        return "FAIL", "patched mode allowed the request AND callback was hit — SSRF not fixed"
    if not server_blocked and not callback_hit:
        return "FAIL", "patched mode did not return ssrf_blocked (check server logs)"
    # server_blocked but callback was ALSO hit — request leaked before block
    return "FAIL", "server returned ssrf_blocked but callback was still hit — timing/race issue"


# ─────────────────────────────────────────────────────────────────────────────
# Main probe routine
# ─────────────────────────────────────────────────────────────────────────────

def probe_mode(
    lab: LabClient,
    mode: str,
    callback: CallbackServer,
    wait_s: float,
) -> ProbeResult:
    lab.set_mode(mode)
    time.sleep(0.15)   # let mode switch propagate

    # Drain any stale hits from a previous run
    callback.drain(timeout=0.1)

    callback_url = callback.url("/ssrf-probe", data="confirmed", mode=mode)
    t0 = time.monotonic()
    sent_at = _now()
    http_status: int | None = None
    server_blocked = False

    try:
        resp = lab.chat(callback_url, timeout=wait_s + 2)
        http_status    = resp.status_code
        server_blocked = (
            resp.status_code == 422
            and isinstance(resp.json().get("detail"), dict)
            and resp.json()["detail"].get("error") == "ssrf_blocked"
        )
    except requests.exceptions.Timeout:
        pass   # server hung — still check callback
    except requests.exceptions.ConnectionError:
        pass

    received_at = _now()
    elapsed = round(time.monotonic() - t0, 3)

    hits = callback.drain(timeout=wait_s)
    callback_hit = len(hits) > 0
    ssrf_confirmed = (mode == "vulnerable") and callback_hit

    verdict, reason = _evaluate(mode, server_blocked, callback_hit)

    return ProbeResult(
        mode                 = mode,
        callback_url         = callback_url,
        request_sent_at      = sent_at,
        response_received_at = received_at,
        http_status          = http_status,
        server_blocked       = server_blocked,
        callback_hit         = callback_hit,
        callback_hits        = hits,
        ssrf_confirmed       = ssrf_confirmed,
        verdict              = verdict,
        verdict_reason       = reason,
        elapsed_s            = elapsed,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Renderers
# ─────────────────────────────────────────────────────────────────────────────

_ICON = {"PASS": "✓", "FAIL": "✗"}


def render_text(results: list[ProbeResult], callback_port: int) -> str:
    sep  = "=" * 68
    sep2 = "-" * 68
    lines = [
        sep,
        "  SSRF PROBE REPORT",
        sep,
        f"  Callback server : 127.0.0.1:{callback_port}",
        f"  Generated at    : {_now()}",
        "",
    ]

    for r in results:
        icon = _ICON[r.verdict]
        lines += [
            sep2,
            f"  {icon} MODE: {r.mode.upper()}    →   {r.verdict}",
            sep2,
            f"    Callback URL       : {r.callback_url}",
            f"    Request sent at    : {r.request_sent_at}",
            f"    Response at        : {r.response_received_at}",
            f"    Elapsed            : {r.elapsed_s}s",
            f"    HTTP status        : {r.http_status}",
            f"    Server blocked     : {r.server_blocked}",
            f"    Callback hit       : {r.callback_hit}",
            f"    SSRF confirmed     : {r.ssrf_confirmed}",
            f"    Verdict reason     : {r.verdict_reason}",
        ]
        if r.callback_hits:
            h = r.callback_hits[0]
            lines += [
                "",
                "    Callback request detail:",
                f"      Timestamp   : {h.timestamp}",
                f"      Method      : {h.method}",
                f"      Path        : {h.path}",
                f"      Query       : {h.query}",
                f"      Remote IP   : {h.remote_addr}",
                f"      User-Agent  : {h.headers.get('User-Agent', '(none)')}",
            ]
        lines.append("")

    # Summary table
    lines += [
        sep,
        "  SUMMARY",
        sep,
        f"  {'Mode':<12} {'Blocked?':<10} {'Callback hit?':<15} {'SSRF confirmed?':<17} Result",
        f"  {'----':<12} {'--------':<10} {'-------------':<15} {'---------------':<17} ------",
    ]
    for r in results:
        lines.append(
            f"  {r.mode:<12} {str(r.server_blocked):<10} {str(r.callback_hit):<15}"
            f" {str(r.ssrf_confirmed):<17} {_ICON[r.verdict]} {r.verdict}"
        )
    lines += [
        "",
        "  Interpretation:",
        "    vulnerable PASS  → SSRF path is exploitable; detection rules should fire",
        "    patched    PASS  → fix is effective; no outbound traffic escaped",
        sep,
    ]
    return "\n".join(lines)


def render_json(results: list[ProbeResult], callback_port: int) -> str:
    def _serialise(r: ProbeResult) -> dict:
        d = asdict(r)
        d["callback_hits"] = [asdict(h) for h in r.callback_hits]
        return d

    return json.dumps(
        {
            "generated_at":    _now(),
            "callback_port":   callback_port,
            "results":         [_serialise(r) for r in results],
            "overall_verdict": "PASS" if all(r.verdict == "PASS" for r in results) else "FAIL",
        },
        indent=2,
        ensure_ascii=False,
    )


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="SSRF probe for the defensive lab")
    parser.add_argument("--server-host", default="127.0.0.1")
    parser.add_argument("--server-port", default="8000", type=int)
    parser.add_argument("--wait",        default=4.0, type=float,
                        help="seconds to wait for a callback hit (default: 4)")
    parser.add_argument("--format",      choices=["text", "json"], default="text")
    parser.add_argument("--out",         metavar="FILE",
                        help="write report to a file instead of stdout")
    args = parser.parse_args()

    base = f"http://{args.server_host}:{args.server_port}"
    lab  = LabClient(base)

    if not lab.ping():
        sys.exit(
            f"[!] Lab server not reachable at {base}\n"
            "    Start it with: python server.py"
        )
    print(f"[*] Lab server reachable at {base}", file=sys.stderr)

    results: list[ProbeResult] = []

    with CallbackServer() as cb:
        print(f"[*] Callback server listening on 127.0.0.1:{cb.port}", file=sys.stderr)

        for mode in ("vulnerable", "patched"):
            print(f"[*] Probing {mode} mode ...", file=sys.stderr)
            r = probe_mode(lab, mode, cb, wait_s=args.wait)
            icon = _ICON[r.verdict]
            print(
                f"    {icon} {r.verdict}  "
                f"blocked={r.server_blocked}  callback_hit={r.callback_hit}  "
                f"ssrf_confirmed={r.ssrf_confirmed}",
                file=sys.stderr,
            )
            results.append(r)

    output = (
        render_json(results, cb.port)
        if args.format == "json"
        else render_text(results, cb.port)
    )

    if args.out:
        from pathlib import Path
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"[*] Report written to {args.out}", file=sys.stderr)
    else:
        print(output)

    overall = all(r.verdict == "PASS" for r in results)
    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
