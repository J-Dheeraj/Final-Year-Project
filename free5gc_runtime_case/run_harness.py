"""free5GC UDR runtime validation harness: CVE-2026-40246
(HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete,
missing `return` after a 404 write -> the delete runs regardless).

Uses NO LLM backend at all - the "patch" here is the real upstream
maintainers' own fix commit, checked out directly, not generated.
NO_PAID_BACKEND=1 is set defensively even though this script never
imports cve_pipeline.

Requires: a real free5gc/udr clone at .udr_clone/ (see docs/
FREE5GC_RUNTIME_VALIDATION_PLAN.md for how it was produced), Go on
PATH, and a real MongoDB reachable at mongodb://localhost:27017.

Run: python free5gc_runtime_case/run_harness.py
"""
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

os.environ["NO_PAID_BACKEND"] = "1"

import requests  # noqa: E402

HERE = Path(__file__).parent.resolve()

# Stub NRF: satisfies exactly the one call this case needs (PUT
# .../nf-instances/{id}, i.e. RegisterNFInstance) so UDR's blocking
# registration retry loop (internal/sbi/consumer/nrf_service.go's
# SendRegisterNFInstance - found live to retry forever, not give up
# after logging an error as first assumed) can succeed and let UDR
# proceed to its own HTTP server startup. This is NOT a real NRF and
# makes no claim to be: it does not perform discovery, does not track
# other NFs, and has no bearing on the vulnerability under test (the
# data-repository DELETE handler's own missing `return`), which is
# entirely independent of NRF's behaviour.
#
# Implemented as a real Go binary (stub_nrf/main.go), not a Python
# http.server: free5gc's NRF client (github.com/free5gc/openapi's
# innerHTTP2CleartextClient) uses golang.org/x/net/http2 with
# AllowHTTP: true and dials with prior knowledge of HTTP/2 framing. A
# plain HTTP/1.1 server cannot answer this client - it fails client-side
# with "http2: frame too large" because the client parses the HTTP/1.1
# response bytes as if they were HTTP/2 frames. This was confirmed live:
# an earlier Python http.server-based stub produced exactly that error.
STUB_NRF_EXE = HERE / "stub_nrf.exe"


def start_stub_nrf():
    proc = subprocess.Popen(
        [str(STUB_NRF_EXE)], cwd=HERE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)
    return proc


def stop_stub_nrf(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)

CLONE_DIR = HERE / ".udr_clone"
CONFIG = HERE / "udrcfg.yaml"
FIX_COMMIT = "86686276a7e226183ee786e3dd6714ec56c78fda"
VULN_COMMIT = f"{FIX_COMMIT}^"
BASE_URL = "http://127.0.0.1:8000/nudr-dr/v2"
SUB_ID = "runtimecase-sub-001"
CORRECT_INFLUENCE_ID = "subs-to-notify"
WRONG_INFLUENCE_ID = "attacker-controlled-id"


def git(*args):
    return subprocess.run(["git", *args], cwd=CLONE_DIR, capture_output=True,
                           text=True, check=True)


def resolved_commit():
    return git("rev-parse", "HEAD").stdout.strip()


def build(label):
    exe = HERE / f"udr_{label}.exe"
    proc = subprocess.run(["go", "build", "-o", str(exe), "./cmd/..."],
                           cwd=CLONE_DIR, capture_output=True, text=True)
    return exe, proc


def seed_subscription():
    body = {"dnns": ["internet"], "notificationUri": "http://127.0.0.1:9/callback"}
    return requests.put(
        f"{BASE_URL}/application-data/influenceData/{CORRECT_INFLUENCE_ID}/{SUB_ID}",
        json=body, timeout=5,
    )


def check_exists():
    return requests.get(
        f"{BASE_URL}/application-data/influenceData/{CORRECT_INFLUENCE_ID}/{SUB_ID}",
        timeout=5,
    )


def malicious_delete():
    return requests.delete(
        f"{BASE_URL}/application-data/influenceData/{WRONG_INFLUENCE_ID}/{SUB_ID}",
        timeout=5,
    )


def benign_delete():
    return requests.delete(
        f"{BASE_URL}/application-data/influenceData/{CORRECT_INFLUENCE_ID}/{SUB_ID}",
        timeout=5,
    )


def wait_for_server(retries=30, delay=1.0):
    for _ in range(retries):
        try:
            check_exists()
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(delay)
    return False


def run_case(label, commit):
    git("checkout", "--quiet", commit)
    real_commit = resolved_commit()
    exe, build_proc = build(label)
    build_log = build_proc.stdout + build_proc.stderr
    (HERE / f"build_{label}.log").write_text(
        f"go build ./cmd/... @ {real_commit}\nexit_code={build_proc.returncode}\n\n{build_log}",
        encoding="utf-8",
    )
    if build_proc.returncode != 0 or not exe.exists():
        return {"label": label, "commit": real_commit, "verdict": "inconclusive_crash",
                "reason": "build failed", "build_log": build_log}

    log_path = HERE / f"{label}_process.log"
    logf = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen([str(exe), "-c", str(CONFIG)], cwd=HERE,
                            stdout=logf, stderr=subprocess.STDOUT)
    result = {"label": label, "commit": real_commit}
    try:
        if not wait_for_server():
            result["verdict"] = "inconclusive_crash"
            result["reason"] = "server never became reachable on :8000"
            return result

        seed_r = seed_subscription()
        result["seed_status"] = seed_r.status_code
        pre_r = check_exists()
        result["pre_check_status"] = pre_r.status_code

        mal_r = malicious_delete()
        result["malicious_status"] = mal_r.status_code
        result["malicious_body"] = mal_r.text
        post_mal_r = check_exists()
        result["post_malicious_check_status"] = post_mal_r.status_code

        # Reseed before the benign test - the malicious attempt may have
        # already deleted the record on the vulnerable version.
        reseed_r = seed_subscription()
        result["reseed_status"] = reseed_r.status_code
        benign_r = benign_delete()
        result["benign_status"] = benign_r.status_code
        post_benign_r = check_exists()
        result["post_benign_check_status"] = post_benign_r.status_code

        exploit_blocked = (result["post_malicious_check_status"] == 200)
        function_preserved = (
            result["benign_status"] == 204
            and result["post_benign_check_status"] == 404
        )
        if not function_preserved and result["benign_status"] not in (200, 204):
            result["verdict"] = "inconclusive_crash"
        elif exploit_blocked and function_preserved:
            result["verdict"] = "confirmed_fix"
        elif exploit_blocked and not function_preserved:
            result["verdict"] = "regression_broke_route"
        else:
            result["verdict"] = "not_blocked"
        result["patch_exploit_blocked"] = exploit_blocked
        result["patch_function_preserved"] = function_preserved
    except Exception as exc:
        result["verdict"] = "inconclusive_crash"
        result["reason"] = f"{type(exc).__name__}: {exc}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        logf.close()
    return result


def main():
    print("Vulnerable commit:", VULN_COMMIT)
    print("Fixed commit:", FIX_COMMIT)
    (HERE / "vulnerable_commit.txt").write_text(VULN_COMMIT + "\n", encoding="utf-8")

    stub_nrf = start_stub_nrf()
    try:
        vuln_result = run_case("vulnerable", VULN_COMMIT)
        time.sleep(1)
        patched_result = run_case("patched", FIX_COMMIT)
    finally:
        stop_stub_nrf(stub_nrf)

    diff = git("diff", VULN_COMMIT, FIX_COMMIT, "--", "internal/sbi/api_datarepository.go").stdout
    (HERE / "patch.diff").write_text(diff, encoding="utf-8")

    for label, r in (("vulnerable", vuln_result), ("patched", patched_result)):
        (HERE / f"{label}_response.log").write_text(json.dumps(r, indent=2), encoding="utf-8")

    manifest = {
        "cve_id": "CVE-2026-40246",
        "component": "free5GC UDR (internal/sbi/api_datarepository.go)",
        "handler": "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete",
        "vulnerable_commit": VULN_COMMIT,
        "fixed_commit": FIX_COMMIT,
        "services_used": {
            "mongodb": "mongodb://localhost:27017 (real, local)",
            "nrf": "stub h2c server (stub_nrf/main.go) required to unblock UDR's blocking "
                   "registration retry loop at startup; not a real NRF (no discovery, no NF "
                   "tracking), has no bearing on the vulnerability under test",
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vulnerable_run": vuln_result,
        "patched_run": patched_result,
    }
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verdict = {
        "cve_id": "CVE-2026-40246",
        "patch_exploit_blocked": patched_result.get("patch_exploit_blocked"),
        "patch_function_preserved": patched_result.get("patch_function_preserved"),
        "patch_verdict": patched_result.get("verdict"),
        "vulnerable_run_confirmed_exploit": vuln_result.get("post_malicious_check_status") == 404,
    }
    (HERE / "verdict.json").write_text(json.dumps(verdict, indent=2), encoding="utf-8")

    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    main()
