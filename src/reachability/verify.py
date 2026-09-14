"""Stage 3: adversarial verification.

OpenAnt's two-stage design (flag, then have a second pass argue against
its own finding as a constrained attacker) eliminated ~49.5% of initially
flagged findings in their evaluation. reachcrs reuses the same idea: a
second LLM call is asked to argue *against* exploitability given the
concrete call path from the entrypoint, and a finding only survives if it
still holds up. This is the step that keeps a fast, cheap triage pass
(stage 2) from flooding the patch stage with false positives.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .providers import Provider
from .triage import TriageResult, _parse_json_response

_SYSTEM_PROMPT = (
    "You are a skeptical security reviewer whose job is to falsify a junior "
    "analyst's vulnerability claim if it does not hold up. Assume the "
    "attacker only controls input at the stated entry point and has no "
    "other privileges. Answer ONLY with JSON: {\"exploitable\": bool, "
    "\"confidence\": 0-1 float, \"rationale\": string}."
)

_USER_TEMPLATE = """\
A prior analysis pass flagged this function as potentially vulnerable:

CWE: {cwe}
Claimed issue: {explanation}
Reached from an entry point via a call path of depth {depth}.

```{lang}
{body}
```

Given only what an external caller at the entry point can control, is this \
claim actually exploitable end-to-end, or is it a false positive (e.g. the \
value is bounds-checked elsewhere, not attacker-controlled, or dead code)?
"""


@dataclass
class VerifiedFinding:
    triage: TriageResult
    exploitable: bool
    confidence: float
    rationale: str


def _verify_one(result: TriageResult, depth: int, provider: Provider) -> VerifiedFinding:
    lang = "go" if result.function.file.endswith(".go") else "c"
    user = _USER_TEMPLATE.format(
        cwe=result.cwe, explanation=result.explanation, depth=depth,
        body=result.function.body, lang=lang,
    )
    raw = provider.complete(_SYSTEM_PROMPT, user)
    parsed = _parse_json_response(raw)
    return VerifiedFinding(
        triage=result,
        exploitable=bool(parsed.get("exploitable", False)),
        confidence=float(parsed.get("confidence", 0.0) or 0.0),
        rationale=str(parsed.get("rationale", "")),
    )


def verify_findings(flagged: list[TriageResult], depths: dict[str, int],
                     provider: Provider, jobs: int = 8,
                     min_confidence: float = 0.4) -> list[VerifiedFinding]:
    verified: list[VerifiedFinding] = []
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = {
            pool.submit(_verify_one, r, depths.get(r.function.name, 0), provider): r
            for r in flagged
        }
        for fut in as_completed(futures):
            v = fut.result()
            if v.exploitable and v.confidence >= min_confidence:
                verified.append(v)
    order = {r.function.name: i for i, r in enumerate(flagged)}
    verified.sort(key=lambda v: order[v.triage.function.name])
    return verified
