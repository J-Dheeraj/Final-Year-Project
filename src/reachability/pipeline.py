"""Orchestrates all six stages end-to-end and times each one."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .exploit import ExploitOutcome, confirm_exploit, generate_exploit
from .patch import generate_patch
from .preprocess import load_compile_commands
from .providers import Provider, get_provider
from .reachability import ReachabilityResult, build_call_graph
from .report import RunStats
from .testing import TestOutcome, verify_patch
from .triage import TriageResult, triage_units
from .verify import verify_findings


@dataclass
class PipelineConfig:
    target: Path
    entrypoints: list[str]
    provider: str = "auto"
    model: str | None = None
    jobs: int = 8
    cache_dir: Path | None = Path(".reachcrs_cache")
    min_verify_confidence: float = 0.4
    compiler: str | None = None
    poc_cmd: list[str] | None = None
    skip_verification: bool = False
    skip_testing: bool = False
    skip_exploit: bool = False
    compile_commands: Path | None = None


class Timer:
    def __init__(self):
        self.timings: dict[str, float] = {}

    def stage(self, name: str):
        return _StageTimer(self, name)


class _StageTimer:
    def __init__(self, timer: Timer, name: str):
        self._timer = timer
        self._name = name

    def __enter__(self):
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self._timer.timings[self._name] = time.perf_counter() - self._t0


def _run_exploit_stage(verified: list, provider: Provider,
                        cfg: PipelineConfig) -> dict[int, ExploitOutcome | None]:
    """Generate + dynamically confirm a proof-of-vulnerability harness for
    each verified finding, keyed by `id()` (safe here: every finding stays
    referenced by the live `verified` list for the rest of this run, so no
    id() can be reused out from under this dict - see the exploit-stage
    review notes). One bad harness (a provider error, a pathological
    compile) must not take down the whole pipeline run, so each attempt is
    isolated."""
    outcomes: dict[int, ExploitOutcome | None] = {}
    if cfg.skip_exploit:
        return outcomes
    for v in verified:
        try:
            ex = generate_exploit(v, provider)
            outcomes[id(v)] = (
                confirm_exploit(ex, compiler=cfg.compiler) if ex is not None else None)
        except Exception:
            outcomes[id(v)] = None
    return outcomes


def _select_patch_targets(verified: list, exploit_outcomes: dict[int, ExploitOutcome | None],
                           skip_exploit: bool) -> tuple[list, int]:
    """Come up with the fix only after you exploit: a finding whose
    generated exploit definitively did NOT reproduce the bug (compiled,
    ran, exited cleanly) is held back from patch generation by default -
    the confirmed absence of a crash means the earlier triage/verify
    stages' claim hasn't actually been demonstrated. Anything we could NOT
    test either way (no exploit generated, harness didn't compile, no
    compiler at all) still proceeds, since blocking on a check we are
    structurally unable to perform would make the tool useless without a
    C compiler on PATH - `skip_exploit` restores the unconditional old
    behavior outright. Returns (targets, count held back)."""
    if skip_exploit:
        return verified, 0
    targets = [v for v in verified
               if exploit_outcomes.get(id(v)) is None
               or exploit_outcomes[id(v)].crashed is not False]
    return targets, len(verified) - len(targets)


def run_pipeline(cfg: PipelineConfig):
    timer = Timer()
    provider: Provider = get_provider(cfg.provider, cfg.model)

    with timer.stage("reachability"):
        db = (load_compile_commands(cfg.compile_commands)
              if cfg.compile_commands is not None else None)
        graph = build_call_graph(cfg.target, compile_commands=db)
        reach: ReachabilityResult = graph.reachable_from(cfg.entrypoints)

    with timer.stage("triage"):
        triage_results: list[TriageResult] = triage_units(
            reach.reachable, reach.depth, provider, jobs=cfg.jobs,
            cache_dir=cfg.cache_dir,
        )
    flagged = [r for r in triage_results if r.vulnerable]

    verified = []
    with timer.stage("verify"):
        if cfg.skip_verification:
            verified = [
                type("V", (), {"triage": r, "exploitable": True,
                                "confidence": r.confidence,
                                "rationale": "verification skipped"})()
                for r in flagged
            ]
        elif flagged:
            verified = verify_findings(flagged, reach.depth, provider,
                                        jobs=cfg.jobs,
                                        min_confidence=cfg.min_verify_confidence)

    with timer.stage("exploit"):
        exploit_outcomes = _run_exploit_stage(verified, provider, cfg)

    patch_targets, exploit_unconfirmed = _select_patch_targets(
        verified, exploit_outcomes, cfg.skip_exploit)

    with timer.stage("patch"):
        patches = [generate_patch(v, provider, exploit_outcomes.get(id(v)))
                   for v in patch_targets]

    outcomes: list[TestOutcome] = []
    with timer.stage("test"):
        if not cfg.skip_testing:
            for p in patches:
                outcomes.append(verify_patch(p, compiler=cfg.compiler,
                                              poc_cmd=cfg.poc_cmd,
                                              harness=p.exploit_harness))
        else:
            outcomes = [
                TestOutcome(patch=p, compiler_available=False, compiles=None,
                            poc_ran=None, poc_passed=None, log="testing skipped")
                for p in patches
            ]

    stats = RunStats(
        reachability=reach,
        triage_count=len(triage_results),
        flagged_count=len(flagged),
        verified_count=len(verified),
        exploit_confirmed_count=sum(
            1 for oc in exploit_outcomes.values() if oc is not None and oc.crashed),
        exploit_unconfirmed_count=exploit_unconfirmed,
        timings_sec=timer.timings,
    )
    return stats, outcomes
