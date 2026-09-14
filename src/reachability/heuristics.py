"""Shared pattern-matching for the CWE-191 (unsigned underflow feeding a
copy length) heuristic, used by BOTH the mock provider's detector
(providers.py) and the mock patcher (patch.py).

This used to be two independent copies of the same regex logic in those
two files. That's how a real bug happened during development: the patcher
matched more broadly than the detector and "fixed" statements that were
never actually flagged (e.g. against the real CVE-2023-0179 source, it
rewrote two unrelated `-=` lines alongside the one genuine bug). Having a
single source of truth for "which statement, exactly, is the finding"
means the patch stage can only ever touch what the triage stage actually
reported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# `var = a - b - c...;` - a chain of one or more subtractions on a plain
# assignment.
UNDERFLOW_ASSIGN_RE = re.compile(r"\b(\w+)\s*=\s*(\w+)((?:\s*-\s*[\w.\[\]]+)+)\s*;")

# `var -= expr;` - NOT matched by the pattern above (a `-` sits directly
# before the `=`), and `expr` may freely mix `+`/`-` rather than being a
# pure subtraction chain. This is the form real CVE-2023-0179 uses:
# `ethlen -= offset + len - VLAN_ETH_HLEN + vlan_hlen;` in
# net/netfilter/nft_payload.c - see examples/kernel_case_study/.
COMPOUND_UNDERFLOW_RE = re.compile(r"\b(\w+)\s*-=\s*([^;{}]+);")

_COPY_CALL_RE = re.compile(r"\b(?:memcpy|memmove|memset)\s*\(")


def is_guarded_by_if(code: str, pos: int) -> bool:
    """True if `pos` sits directly inside an `if (...) { ... }` block.
    Cheap proxy for "syntactically bounds-checked" - NOT a proof of
    semantic safety. Only applied to the `=`-form below; deliberately not
    applied to the `-=`-form, because real CVE-2023-0179 sits inside an
    `if` guard that looks protective but has a sign error - the guard's
    mere presence doesn't mean the arithmetic it guards is actually safe.
    """
    depth = 0
    i = pos - 1
    while i >= 0:
        c = code[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                before = code[max(0, i - 80):i].rstrip()
                return bool(re.search(r"\bif\s*\([^)]*\)\s*$", before))
            depth -= 1
        i -= 1
    return False


@dataclass
class UnderflowFinding:
    match: re.Match
    is_compound: bool
    var: str
    explanation: str


def find_underflow_into_copy(code: str) -> UnderflowFinding | None:
    """Scan `code` for a subtraction assigned to a variable that is later
    passed as an argument to memcpy/memmove/memset. Returns the exact
    regex Match for the offending statement (not just a description) so
    callers can target a patch precisely at it."""
    candidates = sorted(
        [(m, False) for m in UNDERFLOW_ASSIGN_RE.finditer(code)]
        + [(m, True) for m in COMPOUND_UNDERFLOW_RE.finditer(code)],
        key=lambda pair: pair[0].start(),
    )
    for m, is_compound in candidates:
        if not is_compound and is_guarded_by_if(code, m.start()):
            continue
        var = m.group(1)
        rest = code[m.end():]
        for call in _COPY_CALL_RE.finditer(rest):
            args_start = call.end()
            depth = 1
            i = args_start
            while i < len(rest) and depth > 0:
                if rest[i] == "(":
                    depth += 1
                elif rest[i] == ")":
                    depth -= 1
                i += 1
            args = rest[args_start:i]
            if re.search(rf"\b{re.escape(var)}\b", args):
                explanation = (
                    f"`{var}` is assigned from a subtraction and later used as a "
                    f"length/size argument to a copy call; if the operands are "
                    f"unsigned this can underflow to a huge value before reaching "
                    f"the copy (same bug class as CVE-2023-0179)."
                )
                return UnderflowFinding(match=m, is_compound=is_compound,
                                         var=var, explanation=explanation)
    return None


# --- Go: missing `return` after an early-exit HTTP response -----------------
#
# Real CVE-2026-40248 (free5GC UDR, CWE-285): a validation guard writes an
# HTTP 404/400 response but never returns, so request processing falls
# through and executes anyway - see examples/free5gc_case_study/. The fix
# (github.com/free5gc/udr@86686276) is exactly "add the missing `return`",
# repeated at several call sites in the same file/commit. This heuristic
# looks for that specific shape: an `if` block that writes a Gin response
# with no `return` inside it, while the enclosing function still has more
# statements to execute afterward (if the if-block were the function's last
# statement, the missing return would be harmless).

_IF_OPEN_RE = re.compile(r"\bif\b[^{]*\{")
_GIN_RESPONSE_CALL_RE = re.compile(r"\bc\.(?:String|JSON|XML|Data|AbortWithStatus)\s*\(")
_RETURN_RE = re.compile(r"\breturn\b")


def _block_end(code: str, open_brace_idx: int) -> int:
    """Index just past the `}` matching the `{` at open_brace_idx."""
    depth = 0
    i = open_brace_idx
    while i < len(code):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(code)


@dataclass
class MissingReturnFinding:
    match: re.Match       # the `if ... {` match
    block_end: int        # index just past the if-block's closing `}`
    explanation: str


def find_missing_return_after_response(code: str) -> MissingReturnFinding | None:
    """`code` is expected to be a single function body (Go). Returns the
    first `if` block that writes a Gin HTTP response but doesn't return,
    with more code still following it in the same function."""
    func_end = len(code.rstrip())
    for m in _IF_OPEN_RE.finditer(code):
        open_brace = m.end() - 1
        end = _block_end(code, open_brace)
        block = code[open_brace:end]
        if not _GIN_RESPONSE_CALL_RE.search(block):
            continue
        if _RETURN_RE.search(block):
            continue
        after = code[end:func_end].strip()
        # Trailing `}` characters just close enclosing blocks (e.g. this
        # `if` was itself the last statement in an outer `if`/`for`) - not
        # "more code after" in the sense that matters here.
        if after.strip("}").strip() == "":
            continue
        explanation = (
            "This `if` block writes an HTTP response (looks like an "
            "early-exit / validation-failure path) but never returns, and "
            "the function keeps executing afterward - so the response "
            "sent to the client doesn't reflect what actually happens "
            "next (same bug class as CVE-2026-40248 in free5GC's UDR)."
        )
        return MissingReturnFinding(match=m, block_end=end, explanation=explanation)
    return None
