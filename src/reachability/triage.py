"""Stage 2: LLM-based vulnerability triage over reachability-filtered units.

Two things make this materially faster than a naive "call the LLM once per
function, one at a time" loop:

1. Units are analyzed concurrently (thread pool - the work is I/O bound on
   the LLM API call, or near-instant for the mock provider), not serially.
2. Results are cached on disk keyed by a hash of the function body, so
   re-running on an unchanged codebase costs zero LLM calls on the second
   run (same idempotency principle AIxCC's own scoring-pipeline uses).
"""

from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from .providers import Provider
from .reachability import Function

_SYSTEM_PROMPT = (
    "You are a security auditor reviewing reachable C/C++ code for memory-"
    "safety and injection vulnerabilities. Answer ONLY with a compact JSON "
    "object: {\"vulnerable\": bool, \"cwe\": string|null, \"confidence\": "
    "0-1 float, \"explanation\": string}. No prose outside the JSON."
)

_USER_TEMPLATE = """\
Function `{name}` in {file}:{line}, reached from entrypoint(s) via a call \
path of depth {depth}.

Questions to answer before deciding:
1. What does this function do?
2. Where does its input ultimately originate, given it is reachable from \
an external entry point?
3. What security risk, if any, could an attacker trigger through this path?

```{lang}
{body}
```
"""


@dataclass
class TriageResult:
    function: Function
    vulnerable: bool
    cwe: str | None
    confidence: float
    explanation: str
    cached: bool = False


def _cache_path(cache_dir: Path, key: str) -> Path:
    return cache_dir / f"{key}.json"


def _hash_unit(fn: Function, depth: int, provider_id: str) -> str:
    """Cache key for one triage unit.

    `provider_id` is part of the key so results from different providers
    or models can never collide - see Provider.cache_id for what went
    wrong when it wasn't.
    """
    h = hashlib.sha256()
    h.update(fn.name.encode())
    h.update(fn.body.encode())
    h.update(str(depth).encode())
    h.update(provider_id.encode())
    return h.hexdigest()[:32]


_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def _parse_json_response(text: str) -> dict:
    text = text.strip()
    # Reasoning models (DeepSeek-R1 distills and similar) emit a <think>...
    # </think> reasoning block before the actual answer. Strip it first -
    # otherwise the brace-matching fallback below can be fooled by braces
    # appearing in the reasoning prose itself (e.g. discussing "struct {}"),
    # spanning from a brace in the thinking block to one in the real answer.
    text = _THINK_BLOCK_RE.sub("", text).strip()
    # Tolerate providers that wrap JSON in a markdown fence.
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Best-effort: find the first {...} block.
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
        return {"vulnerable": False, "cwe": None, "confidence": 0.0,
                "explanation": f"Unparseable model response: {text[:200]!r}"}


def _triage_one(fn: Function, depth: int, provider: Provider,
                 cache_dir: Path | None) -> TriageResult:
    key = _hash_unit(fn, depth, provider.cache_id)
    if cache_dir is not None:
        cp = _cache_path(cache_dir, key)
        if cp.exists():
            data = json.loads(cp.read_text(encoding="utf-8"))
            return TriageResult(function=fn, cached=True, **data)

    lang = "go" if fn.file.endswith(".go") else "c"
    user = _USER_TEMPLATE.format(name=fn.name, file=fn.file, line=fn.start_line,
                                  depth=depth, body=fn.body, lang=lang)
    raw = provider.complete(_SYSTEM_PROMPT, user)
    parsed = _parse_json_response(raw)

    result = TriageResult(
        function=fn,
        vulnerable=bool(parsed.get("vulnerable", False)),
        cwe=parsed.get("cwe"),
        confidence=float(parsed.get("confidence", 0.0) or 0.0),
        explanation=str(parsed.get("explanation", "")),
    )

    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        _cache_path(cache_dir, key).write_text(json.dumps({
            "vulnerable": result.vulnerable,
            "cwe": result.cwe,
            "confidence": result.confidence,
            "explanation": result.explanation,
        }), encoding="utf-8")

    return result


def triage_units(functions: list[Function], depths: dict[str, int],
                  provider: Provider, jobs: int = 8,
                  cache_dir: Path | None = None) -> list[TriageResult]:
    results: list[TriageResult] = []
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = {
            pool.submit(_triage_one, fn, depths.get(fn.name, 0), provider, cache_dir): fn
            for fn in functions
        }
        for fut in as_completed(futures):
            results.append(fut.result())
    order = {fn.name: i for i, fn in enumerate(functions)}
    results.sort(key=lambda r: order[r.function.name])
    return results
