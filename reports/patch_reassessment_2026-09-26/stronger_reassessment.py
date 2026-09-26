"""Step 2 of the 2026-09-26 roadmap: reassess the 6 surviving hosted-Claude
patched artifacts (out of the original 36-run comparison) using class-specific
success tests that check real expected content, not merely crash-absence.

Background: reports/model_comparison_pilot_2026-09-25/'s multi-model sweep
wrote every model's Stage 3.5/3.8 artifacts to a shared, non-model-specific
scratch path (a pre-existing harness gap - the artifact writer hardcodes
"reports/<CVE-ID>/" regardless of --out). Only the LAST model to touch each
CVE survived on disk: 6 files total, one per CVE, not 36. This script re-tests
those 6 survivors directly against a real, expected legitimate response per
CVE class, not just "the benign probe didn't crash" (the corrected pipeline
validator's own, weaker check - see docs/PATCH_VALIDATION_INVESTIGATION.md
and the FYP report's Section 4.1.2).

Run from the repo root: python reports/patch_reassessment_2026-09-26/stronger_reassessment.py
"""
import base64
import pickle
import subprocess
import sys
import time

import requests

import os
BASE = os.path.abspath("reports/claude_code_catalog_run_2026-09-25/reports")

CASES = [
    dict(
        cve="CVE-2026-42208", cls="SQL Injection", model="unknown (last writer)",
        malicious=lambda: requests.post("http://127.0.0.1:5000/chat/completions",
            headers={"Authorization": "Bearer ' OR '1'='1'--"}, timeout=5),
        malicious_check=lambda r: "PWNED_LITELLM_SQLI_A7F3B2" not in r.text,
        legit=lambda: requests.post("http://127.0.0.1:5000/chat/completions",
            headers={"Authorization": "Bearer sk-legit-user-001"}, timeout=5),
        legit_check=lambda r: r.status_code == 200 and r.json() == {"status": "authenticated", "user_id": "u1"},
    ),
    dict(
        cve="CVE-2026-27602", cls="OS Command Injection", model="unknown (last writer)",
        malicious=lambda: requests.post("http://127.0.0.1:5000/admin/domain/add",
            data={"domain_name": "legit.com; echo PWNED_3f7a2b9d"},
            headers={"X-Admin-Token": "superadmin-token"}, timeout=5),
        malicious_check=lambda r: "PWNED_3f7a2b9d" not in r.text,
        legit=lambda: requests.post("http://127.0.0.1:5000/admin/domain/add",
            data={"domain_name": "example.com"},
            headers={"X-Admin-Token": "superadmin-token"}, timeout=5),
        legit_check=lambda r: r.status_code == 200 and r.json().get("output") == "domain created successfully",
    ),
    dict(
        cve="CVE-2026-23949", cls="Path Traversal", model="unknown (last writer)",
        malicious=lambda: requests.post("http://127.0.0.1:5000/extract",
            json={"member": "../../../srv/config/.env"}, timeout=5),
        malicious_check=lambda r: "PWNED_z9x1c7v3q8" not in r.text,
        legit=lambda: requests.post("http://127.0.0.1:5000/extract",
            json={"member": "readme.txt"}, timeout=5),
        legit_check=lambda r: r.status_code == 200 and r.json().get("data") == "example extracted file",
    ),
    dict(
        cve="CVE-2026-78683", cls="Insecure Deserialization", model="unknown (last writer)",
        malicious=lambda: requests.post("http://127.0.0.1:5000/load_model",
            json={"model": base64.b64encode(pickle.dumps(
                type("R", (), {"__reduce__": lambda self: (exec, ("import builtins; builtins._nltk_deser_pwned = True",))})()
            )).decode()}, timeout=10),
        malicious_check=lambda r: "PWNED_nltk_502_a7f3c9" not in r.text,
        legit=lambda: requests.post("http://127.0.0.1:5000/load_model",
            json={"model": base64.b64encode(pickle.dumps({"a": 1, "b": [1, 2, 3]})).decode()}, timeout=10),
        legit_check=lambda r: r.status_code == 200 and r.json().get("status") == "loaded" and r.json().get("object_type") == "dict",
    ),
    dict(
        cve="CVE-2026-54729", cls="SSRF", model="unknown (last writer)",
        malicious=lambda: requests.get("http://127.0.0.1:5000/fetch",
            params={"url": "http://0.0.0.0/latest/meta-data/"}, timeout=5),
        malicious_check=lambda r: "PWNED_ssrf_ae91k3f7" not in r.text,
        legit=lambda: requests.get("http://127.0.0.1:5000/fetch",
            params={"url": "http://example.com"}, timeout=5),
        legit_check=lambda r: r.status_code == 200 and r.json() == {"fetched": "http://example.com", "internal": False, "data": "<html>external site</html>"},
    ),
    dict(
        cve="CVE-2026-46492", cls="XSS", model="claude-opus-4-8 (identified via unique gen_out_tokens=14789 fingerprint)",
        malicious=lambda: requests.post("http://127.0.0.1:5000/render",
            data={"content": "# Shared Note\n\n<script>alert(document.domain)</script>"}, timeout=5),
        malicious_check=lambda r: "PWNED_x9f3k2vq_xss" not in r.text,
        legit=lambda: requests.post("http://127.0.0.1:5000/render",
            data={"content": "# Hello\nWorld"}, timeout=5),
        legit_check=lambda r: r.status_code == 200 and "<h1>Hello</h1>" in r.text and "<p>World</p>" in r.text and "PWNED_x9f3k2vq_xss" not in r.text,
    ),
]

results = []
for case in CASES:
    target = os.path.join(BASE, case['cve'], "target_app.iter1.v0.patched.py")
    proc = subprocess.Popen([sys.executable, target], cwd=os.path.join(BASE, case['cve']),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    try:
        requests.get("http://127.0.0.1:5000/health", timeout=5)
        mal_r = case["malicious"]()
        exploit_blocked = case["malicious_check"](mal_r)
        legit_r = case["legit"]()
        legit_preserved = case["legit_check"](legit_r)
        verdict = ("confirmed_fix" if exploit_blocked and legit_preserved
                   else "regression_broke_route" if exploit_blocked and not legit_preserved
                   else "not_blocked" if not exploit_blocked
                   else "inconclusive")
        results.append((case["cve"], case["cls"], case["model"], exploit_blocked, legit_preserved, verdict, mal_r.status_code, legit_r.status_code))
    except Exception as e:
        results.append((case["cve"], case["cls"], case["model"], None, None, f"ERROR: {e}", None, None))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        time.sleep(2)

print(f"{'CVE':<16}{'Class':<24}{'ExploitBlocked':<16}{'LegitPreserved':<16}{'Verdict':<22}{'MalStatus':<10}{'LegitStatus'}")
for r in results:
    print(f"{r[0]:<16}{r[1]:<24}{str(r[3]):<16}{str(r[4]):<16}{r[5]:<22}{str(r[6]):<10}{str(r[7])}")
