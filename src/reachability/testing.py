"""Stage 5: dynamic patch verification.

A patch is only trustworthy once it's actually exercised, not just
generated - this is the step most "LLM finds a bug" demos skip. reachcrs
applies each patch to a scratch copy of the source file, tries to compile
it, and (if the caller supplies a PoC command) runs the PoC against both
the original and patched builds to confirm the crash is gone and the
binary still builds. If no compiler is available in the environment (e.g.
this prototype was scaffolded on a plain Windows machine with no cc/gcc),
the stage degrades to "compile check skipped" rather than silently
pretending success - the report always says which checks actually ran.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .patch import Patch

_MAIN_DEF_RE = re.compile(r"\bmain\s*\(")
# Comments/string literals can contain the literal text "main(" (this very
# docstring's prose does) without it being a real function - strip them
# before matching, or a source file merely *describing* a PoC harness in a
# comment would be mistaken for one that defines main().
_C_COMMENT_OR_STRING_RE = re.compile(
    r'//[^\n]*|/\*.*?\*/|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', re.DOTALL)


def _has_existing_main(source_text: str) -> bool:
    """True if `source_text` already defines its own `main()`. A file that
    already ships a working, hand-authored PoC (e.g. examples/demo_vuln.c)
    takes precedence over an auto-generated exploit harness (exploit.py) -
    appending a second `main()` would just fail to compile with
    "redefinition of main", silently discarding the human-written one."""
    code = _C_COMMENT_OR_STRING_RE.sub(" ", source_text)
    return _MAIN_DEF_RE.search(code) is not None


@dataclass
class TestOutcome:
    patch: Patch
    compiler_available: bool
    compiles: bool | None       # None = not attempted
    poc_ran: bool | None
    poc_passed: bool | None
    log: str
    original_compiles: bool | None = None
    original_poc_crashed: bool | None = None  # True = PoC reproduced the bug pre-patch

    @property
    def fix_confirmed(self) -> bool | None:
        """True only if we proved BOTH halves: the bug reproduced on the
        original build AND is gone on the patched build. Either half
        missing (no compiler, no PoC) means we can't claim this."""
        if self.poc_passed is None or self.original_poc_crashed is None:
            return None
        return bool(self.poc_passed and self.original_poc_crashed)


def _find_compiler(preferred: str | None) -> str | None:
    for candidate in filter(None, [preferred, "cc", "gcc", "clang"]):
        if shutil.which(candidate):
            return candidate
    return None


def _build_and_run(cc: str, tmp: Path, name: str, source_text: str,
                    poc_cmd: list[str] | None, timeout: float) -> dict:
    src_path = tmp / name
    src_path.write_text(source_text, encoding="utf-8")
    out_bin = tmp / f"{name}.out"
    try:
        proc = subprocess.run(
            [cc, str(src_path), "-o", str(out_bin)],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        # A pathological compile (e.g. exploit.py's LLM-generated harnesses
        # are explicitly asked to write code that crashes/misbehaves, which
        # can also mean degenerate constant-folding or huge static buffers)
        # must not kill the whole pipeline run - degrade to "does not
        # compile" for this one attempt instead of propagating.
        return {"compiles": False, "log": f"compiler timed out after {timeout:.0f}s",
                "poc_ran": None, "poc_crashed": None}
    except OSError as e:
        return {"compiles": False, "log": f"could not run compiler {cc!r}: {e}",
                "poc_ran": None, "poc_crashed": None}
    result = {"compiles": proc.returncode == 0, "log": proc.stdout + proc.stderr,
              "poc_ran": None, "poc_crashed": None}

    if result["compiles"] and poc_cmd is not None:
        try:
            poc = subprocess.run([str(out_bin)] + poc_cmd, capture_output=True,
                                  text=True, timeout=timeout)
            result["poc_ran"] = True
            # Convention: the PoC harness exits 0 when it runs to completion
            # (safe) and dies with a nonzero/signal exit when the bug fires.
            result["poc_crashed"] = poc.returncode != 0
            result["log"] += f"\n--- PoC (exit {poc.returncode}) ---\n{poc.stdout}{poc.stderr}"
        except subprocess.TimeoutExpired:
            result["poc_ran"] = True
            result["poc_crashed"] = True
            result["log"] += "\n--- PoC ---\ntimed out (possible hang)"
    return result


def verify_patch(patch: Patch, compiler: str | None = None,
                  poc_cmd: list[str] | None = None,
                  harness: str | None = None,
                  timeout: float = 15.0) -> TestOutcome:
    """`harness` is reachcrs's own generated proof-of-vulnerability code
    (see exploit.py) rather than a hand-supplied `--poc-cmd`: when given,
    it's appended to BOTH the original and patched source before building,
    so the exact same exploit that was confirmed pre-patch is re-run
    post-patch with no extra user action needed. `poc_cmd` defaults to
    running the binary with no extra args in that case, since the
    harness's own `main()` decides what to do, not command-line arguments."""
    fn = patch.finding.triage.function
    src_path = Path(fn.file)
    cc = _find_compiler(compiler)

    if not src_path.exists():
        return TestOutcome(patch=patch, compiler_available=cc is not None,
                            compiles=None, poc_ran=None, poc_passed=None,
                            log=f"source file {src_path} not found on disk")

    original_file_text = src_path.read_text(encoding="utf-8", errors="replace")
    if patch.original not in original_file_text:
        return TestOutcome(patch=patch, compiler_available=cc is not None,
                            compiles=None, poc_ran=None, poc_passed=None,
                            log="function body no longer matches source on disk "
                                "(file changed since analysis); refusing to patch blind")

    patched_file_text = original_file_text.replace(patch.original, patch.patched, 1)

    if harness is not None and not _has_existing_main(original_file_text):
        original_file_text += "\n\n" + harness
        patched_file_text += "\n\n" + harness
        if poc_cmd is None:
            poc_cmd = []

    if cc is None:
        return TestOutcome(patch=patch, compiler_available=False,
                            compiles=None, poc_ran=None, poc_passed=None,
                            log="no C compiler (cc/gcc/clang) found on PATH; "
                                "compile check skipped")

    with tempfile.TemporaryDirectory(prefix="reachcrs_") as tmp:
        tmp_path = Path(tmp)
        orig = _build_and_run(cc, tmp_path, f"orig_{src_path.name}",
                               original_file_text, poc_cmd, timeout)
        patched = _build_and_run(cc, tmp_path, f"patched_{src_path.name}",
                                  patched_file_text, poc_cmd, timeout)

        log = (f"=== original build ===\n{orig['log']}\n\n"
                f"=== patched build ===\n{patched['log']}")

        return TestOutcome(
            patch=patch, compiler_available=True,
            compiles=patched["compiles"],
            poc_ran=patched["poc_ran"],
            poc_passed=(None if patched["poc_crashed"] is None else not patched["poc_crashed"]),
            log=log,
            original_compiles=orig["compiles"],
            original_poc_crashed=orig["poc_crashed"],
        )
