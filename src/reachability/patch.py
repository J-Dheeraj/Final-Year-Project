"""Stage 4: patch generation.

Mirrors AutoPatch/Atlantis: given a confirmed vulnerability and the
function's source, produce a minimal fix rather than a rewrite (kernel
maintainers reject large diffs; RGym's own finding is that non-local,
sprawling patches are exactly what gets bounced in review). The mock
provider ships a small rule-based fixer for the same pattern classes its
mock triage detects, so the patch stage also works fully offline.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .heuristics import find_missing_return_after_response, find_underflow_into_copy
from .providers import MockProvider, Provider
from .verify import VerifiedFinding

if TYPE_CHECKING:
    from .exploit import ExploitOutcome

_SYSTEM_PROMPT = (
    "You are a kernel/systems C developer writing a minimal security fix. "
    "Output ONLY the complete corrected function body (same signature, same "
    "style), no markdown fences, no commentary. Keep the change as small as "
    "possible - do not refactor or rename anything not required by the fix."
)

_USER_TEMPLATE = """\
CWE: {cwe}
Vulnerability: {explanation}

Fix this function. Preserve its exact signature and behavior for valid \
inputs; only add the missing bounds/validation/sanitization needed to \
close the reported issue.

```c
{body}
```
"""

_MOCK_FIXES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bstrcpy\s*\(([^,]+),\s*([^)]+)\)"), r"strncpy(\1, \2, sizeof(\1) - 1)"),
    (re.compile(r"\bstrcat\s*\(([^,]+),\s*([^)]+)\)"), r"strncat(\1, \2, sizeof(\1) - strlen(\1) - 1)"),
    (re.compile(r"\bsprintf\s*\(([^,]+),"), r"snprintf(\1, sizeof(\1),"),
    (re.compile(r"\bgets\s*\(([^)]+)\)"), r"fgets(\1, sizeof(\1), stdin)"),
]

# CWE-191 (unsigned underflow feeding a copy length, e.g. `remaining = len -
# HEADER_SIZE - EXTRA_SIZE;`) can't be fixed by a single-token substitution
# like the ones above - it needs a bounds check inserted. Rather than try to
# parse operator precedence generically, widen to signed 64-bit arithmetic
# for the check and clamp negative results to 0. Crucially, this uses the
# SAME `find_underflow_into_copy` the mock provider's detector uses
# (heuristics.py), so it patches the exact statement that was flagged - not
# every syntactically similar `-=`/`= a - b` line in the function. An
# earlier version used a body-wide regex substitution here and, against the
# real CVE-2023-0179 source, ended up "fixing" two unrelated, non-buggy
# `-=` statements alongside the one genuine bug - see heuristics.py's
# module docstring.


def _underflow_fix_repl(var: str, first: str, rest: str) -> str:
    # Deliberately produces no second declaration: callers splice this
    # directly over the original statement, so any type prefix (e.g.
    # "unsigned int ") preceding the variable name in the source - whether
    # this is its declaration or a later reassignment - is left untouched
    # and still applies. The safe expression is written twice (bounds
    # check, then value) rather than via a helper temporary, specifically
    # to avoid introducing a second declaration on this line.
    safe_expr = f"(long long){first}{rest}"
    return f"{var} = (({safe_expr}) < 0) ? 0 : (unsigned int)({safe_expr});"


def _compound_underflow_fix_repl(var: str, expr: str) -> str:
    # Unlike the `=`-chain form above, `expr` here may freely mix `+`/`-`
    # (real CVE-2023-0179: `offset + len - VLAN_ETH_HLEN + vlan_hlen`), so
    # it isn't safe to reconstruct with the "cast just the first operand"
    # trick - instead the whole original expression is evaluated twice
    # (once cast to signed 64-bit for the check, once unchanged for the
    # value when safe), which preserves exact original semantics for every
    # currently-valid input regardless of how `expr` is shaped internally.
    check_expr = f"(long long){var} - ({expr})"
    return f"{var} = (({check_expr}) < 0) ? 0 : {var} - ({expr});"


@dataclass
class Patch:
    finding: VerifiedFinding
    original: str
    patched: str
    diff: str
    method: str
    # Carried from stage 3.5 (exploit.py) when a proof-of-vulnerability
    # harness was generated and confirmed against this exact finding BEFORE
    # this patch existed. `exploit_harness` lets stage 5 re-run the SAME
    # harness against the patched code (see testing.py's `harness` param)
    # instead of requiring a hand-supplied --poc-cmd; `exploit_confirmed`
    # records whether that pre-patch run actually reproduced the bug.
    exploit_harness: str | None = None
    exploit_method: str | None = None
    exploit_confirmed: bool | None = None


def _missing_return_fix(body: str) -> str:
    """CWE-285 (missing `return` after an early-exit HTTP response, see
    heuristics.py / CVE-2026-40248): insert `return` as a new line just
    before the offending if-block's closing brace, indented one level
    deeper than that brace - i.e. matching the statements already inside
    the block, not the brace itself."""
    finding = find_missing_return_after_response(body)
    if finding is None:
        return body
    close_brace_idx = finding.block_end - 1
    line_start = body.rfind("\n", 0, close_brace_idx) + 1
    closing_indent = body[line_start:close_brace_idx]
    return (
        body[:line_start]
        + closing_indent + "\treturn\n"
        + closing_indent
        + body[close_brace_idx:]
    )


def _mock_fix(body: str, cwe: str | None) -> str:
    if cwe == "CWE-191":
        finding = find_underflow_into_copy(body)
        if finding is None:
            return body  # nothing to target precisely; leave body untouched
        m = finding.match
        if finding.is_compound:
            replacement = _compound_underflow_fix_repl(m.group(1), m.group(2))
        else:
            replacement = _underflow_fix_repl(m.group(1), m.group(2), m.group(3))
        return body[:m.start()] + replacement + body[m.end():]

    if cwe == "CWE-285":
        return _missing_return_fix(body)

    fixed = body
    for pattern, repl in _MOCK_FIXES:
        fixed = pattern.sub(repl, fixed)
    return fixed


def generate_patch(finding: VerifiedFinding, provider: Provider,
                    exploit_outcome: ExploitOutcome | None = None) -> Patch:
    fn = finding.triage.function
    if isinstance(provider, MockProvider):
        patched_body = _mock_fix(fn.body, finding.triage.cwe)
        method = "mock-rule-based"
    else:
        user = _USER_TEMPLATE.format(
            cwe=finding.triage.cwe, explanation=finding.triage.explanation,
            body=fn.body,
        )
        if exploit_outcome is not None and exploit_outcome.crashed:
            # Ground the fix in the actual confirmed failure, not just the
            # triage/verify stages' prose description of it - this is new
            # evidence those stages never had, generated after them.
            user += (
                "\n\nA generated proof-of-vulnerability harness confirmed this "
                "exact bug crashes the original code:\n```\n"
                f"{exploit_outcome.log[-1000:]}\n```\n"
                "The fix must make this exact harness survive without crashing."
            )
        patched_body = provider.complete(_SYSTEM_PROMPT, user).strip()
        if patched_body.startswith("```"):
            patched_body = patched_body.strip("`")
            if patched_body.startswith("c\n"):
                patched_body = patched_body[2:]
        method = f"llm-{provider.name}"

    diff = "\n".join(difflib.unified_diff(
        fn.body.splitlines(), patched_body.splitlines(),
        fromfile=f"a/{fn.file}::{fn.name}", tofile=f"b/{fn.file}::{fn.name}",
        lineterm="",
    ))

    exploit_harness = exploit_outcome.exploit.harness if exploit_outcome else None
    exploit_method = exploit_outcome.exploit.method if exploit_outcome else None
    exploit_confirmed = exploit_outcome.crashed if exploit_outcome else None

    return Patch(finding=finding, original=fn.body, patched=patched_body,
                 exploit_harness=exploit_harness, exploit_method=exploit_method,
                 exploit_confirmed=exploit_confirmed,
                 diff=diff, method=method)
