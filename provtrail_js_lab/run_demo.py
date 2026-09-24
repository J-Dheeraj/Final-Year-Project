#!/usr/bin/env python3
"""Dynamic demo for CVE-2024-48910 (DOMPurify, GHSA-p3vf-v8qc-cwcr) -
Prototype Pollution. Runs the exact pipeline mechanism every other CVE
in this project uses (cve_pipeline.execute_exploit_artifacts, Stage 3.6),
just pointed at a hand-authored target.js instead of an LLM-generated
target.py - proving the ONE thing this integration needed to prove:
a real, generated-by-nothing-magic JS target can be dynamically
confirmed through the pipeline's real execution path, not a parallel
one-off script.

Run: python run_demo.py
Needs: Node.js on PATH (node --version). Zero npm dependencies - the
target itself only uses Node's built-in http/url modules.
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from cve_pipeline import ExploitArtifacts, execute_exploit_artifacts  # noqa: E402


def main() -> int:
    cve_dir = HERE / "CVE-2024-48910"
    artifacts = ExploitArtifacts(
        generated=True,
        poc_path=str(cve_dir / "poc.py"),
        target_app_path=str(cve_dir / "target_app.js"),
        vuln_class="Prototype Pollution",
    )
    artifacts = execute_exploit_artifacts(artifacts)

    print(f"executed:              {artifacts.executed}")
    print(f"exit_code:             {artifacts.exit_code}")
    print(f"dynamically_confirmed: {artifacts.dynamically_confirmed}")
    if artifacts.execution_skip_reason:
        print(f"execution_skip_reason: {artifacts.execution_skip_reason}")
    print("--- execution_log ---")
    print(artifacts.execution_log)

    if not artifacts.dynamically_confirmed:
        print("\n[-] FAILED - CVE-2024-48910 was not dynamically confirmed")
        return 1
    print("\n[+] CONFIRMED - real global Object.prototype pollution via "
          "Stage 3.6's real execution path, node target + Python PoC")
    return 0


if __name__ == "__main__":
    sys.exit(main())
