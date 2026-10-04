"""free5GC full-deployment runtime validation harness, LLM-patch variant:
same real Docker deployment (real MongoDB, real free5GC NRF) and same
four-handler test sequence as run_full_deployment_harness.py, but
comparing the real vulnerable commit against the LLM-generated patch for
HandleApplicationDataInfluenceDataSubsToNotifyGet (plus the existing
rule-based patches for the other 3 handlers) instead of the real
upstream fix commit. See docs/FREE5GC_LLM_PATCH_RESULTS.md for the
compile-verification half this extends to runtime.

Requires: Docker Desktop running, udr_build/api_datarepository_llm_patched.go
already materialized (prepare_llm_patched_source.py), and the
free5gc-udr-custom:vulnerable and :llm_patched images built from
udr_build/Dockerfile and udr_build/Dockerfile.llm respectively.

Run: python free5gc_full_deployment/run_full_deployment_harness_llm.py
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

os.environ["NO_PAID_BACKEND"] = "1"

import run_full_deployment_harness as base  # noqa: E402

HERE = Path(__file__).parent.resolve()


def main():
    (HERE / "evidence").mkdir(exist_ok=True)

    print("Bringing up db + real NRF (idempotent if already up)...")
    base.compose("up", "-d", "db", "free5gc-nrf", env={"UDR_IMAGE_TAG": "vulnerable"})

    print("Vulnerable commit:", base.VULN_COMMIT)
    base.bring_up("vulnerable")
    vuln_result = base.run_case("vulnerable")
    base.save_container_log("vulnerable_llmrun")

    print("LLM-patched build (GET handler via Ollama qwen2.5-coder:7b, "
          "rule-based for the other 3):")
    base.bring_up("llm_patched")
    llm_result = base.run_case("llm_patched")
    base.save_container_log("llm_patched")

    for label, r in (("vulnerable_llmrun", vuln_result), ("llm_patched", llm_result)):
        (HERE / "evidence" / f"{label}_response.json").write_text(
            json.dumps(r, indent=2), encoding="utf-8")

    manifest = {
        "cve_id": "CVE-2026-40248",
        "component": "free5GC UDR (internal/sbi/api_datarepository.go)",
        "handlers_tested": [
            "HandleApplicationDataInfluenceDataSubsToNotifyGet (collection) - LLM-PATCHED (Ollama qwen2.5-coder:7b)",
            "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdGet - rule-based",
            "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdPut - rule-based",
            "HandleApplicationDataInfluenceDataSubsToNotifySubscriptionIdDelete - rule-based",
        ],
        "vulnerable_commit": base.VULN_COMMIT,
        "patch_source": "LLM (Ollama qwen2.5-coder:7b) for the GET handler; "
                         "deterministic rule-based patcher for the other 3 - "
                         "NOT the real upstream fix commit",
        "deployment": {
            "mongodb": "real, official mongo:4.4 image via free5gc-compose",
            "nrf": "real, official free5gc/nrf:v4.2.3 image (OAuth2 disabled - out of scope)",
            "udr": "custom-built from the vulnerable commit + LLM/rule-based patches, see udr_build/Dockerfile.llm",
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vulnerable_run": vuln_result,
        "llm_patched_run": llm_result,
    }
    (HERE / "evidence" / "manifest_llm.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verdict = {
        "cve_id": "CVE-2026-40248",
        "patch_source": "llm-ollama (GET handler) + mock-rule-based (other 3)",
        "collection_get_leak_confirmed_vulnerable": vuln_result["collection_get_leaked_data"],
        "collection_get_leak_fixed": not llm_result["collection_get_leaked_data"],
        "single_get_leak_confirmed_vulnerable": vuln_result["single_get_leaked_data"],
        "single_get_leak_fixed": not llm_result["single_get_leaked_data"],
        "single_put_unauthorized_write_confirmed_vulnerable": vuln_result["single_put_unauthorized_write"],
        "single_put_unauthorized_write_fixed": not llm_result["single_put_unauthorized_write"],
        "single_delete_confirmed_exploit_vulnerable": vuln_result["single_delete_confirmed_exploit"],
        "single_delete_fixed": not llm_result["single_delete_confirmed_exploit"],
        "benign_path_preserved_vulnerable": vuln_result["benign_path_preserved"],
        "benign_path_preserved_llm_patched": llm_result["benign_path_preserved"],
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
        and verdict["benign_path_preserved_llm_patched"]
    )
    verdict["overall_verdict"] = "confirmed_fix_all_four_handlers" if all_confirmed else "partial_or_inconclusive"
    (HERE / "evidence" / "verdict_llm.json").write_text(json.dumps(verdict, indent=2), encoding="utf-8")

    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    main()
