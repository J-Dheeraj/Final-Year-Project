"""LLM provider abstraction.

Every AIxCC finalist CRS converges on the same shape: a single internal
interface fanning out to whichever LLM provider is configured (their
"LiteLLM proxy" pattern). reachcrs mirrors that but in-process and with a
zero-cost fallback: if no API key is configured, `mock` provides an
instant, deterministic, rule-based analyzer so the whole pipeline runs
end-to-end offline (no network round-trips, no API spend) for development,
grading, and CI. This is also strictly faster than any pipeline that must
call out to a hosted LLM for every unit.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .heuristics import find_missing_return_after_response, find_underflow_into_copy


@dataclass
class LLMResponse:
    text: str
    provider: str
    cached: bool = False


class Provider(ABC):
    name: str

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return raw text completion for a system+user prompt pair."""

    @property
    def cache_id(self) -> str:
        """Identity used to key cached results.

        Must include the model, not just the provider: `llama3.2:1b` and
        `llama3.2:3b` answer differently, and a mock run must never read a
        cache entry written by a real LLM. Before this existed the cache
        was keyed on the function body alone, so `--provider mock` silently
        replayed whatever provider had last analysed that function - a
        Needle run reported 11 flagged functions instead of mock's actual 1.
        """
        model = getattr(self, "_model", None)
        return f"{self.name}:{model}" if model else self.name


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, model: str | None = None):
        try:
            import anthropic  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "anthropic package not installed. Run `pip install anthropic` "
                "or use --provider mock."
            ) from e
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set.")
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model or os.environ.get("REACHCRS_MODEL", "claude-sonnet-5")

    def complete(self, system: str, user: str) -> str:
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in resp.content if hasattr(block, "text"))


class OpenAIProvider(Provider):
    """Also works for any OpenAI-compatible chat completions API - e.g.
    Zhipu/z.ai's GLM models - by pointing OPENAI_BASE_URL at their endpoint
    and OPENAI_API_KEY at that provider's key. Nothing else changes."""

    name = "openai"

    def __init__(self, model: str | None = None):
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "openai package not installed. Run `pip install openai` "
                "or use --provider mock."
            ) from e
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not set.")
        base_url = os.environ.get("OPENAI_BASE_URL")
        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._model = model or os.environ.get("REACHCRS_MODEL", "gpt-4o")

    def complete(self, system: str, user: str) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""


# --- Mock provider: instant, offline, rule-based ---------------------------
#
# Pattern classes chosen to mirror the memory-safety bug family AIxCC's own
# "Needle" Linux kernel vulnerability (CVE-2023-0179) belongs to: unsigned
# integer underflow feeding an oversized copy. Also covers the other
# classic C-string footguns that show up constantly in kernel/driver code.

_RULES: list[tuple[re.Pattern, str, str, float]] = [
    (re.compile(r"\bstrcpy\s*\("), "CWE-120", "strcpy() with no bounds check can overflow the destination buffer.", 0.7),
    (re.compile(r"\bstrcat\s*\("), "CWE-120", "strcat() with no bounds check can overflow the destination buffer.", 0.7),
    (re.compile(r"\bsprintf\s*\("), "CWE-120", "sprintf() with no size limit can overflow the destination buffer.", 0.65),
    (re.compile(r"\bgets\s*\("), "CWE-242", "gets() has no way to bound input length; inherently unsafe.", 0.9),
    (re.compile(r"\bsystem\s*\("), "CWE-78", "system() call present; if any argument is attacker-influenced this is OS command injection.", 0.5),
    (re.compile(r'\bprintf\s*\(\s*[A-Za-z_]\w*\s*\)'), "CWE-134", "printf() called with a non-literal format string (format string vulnerability).", 0.55),
]

# CWE-191 (unsigned underflow feeding a copy length) detection lives in
# heuristics.py, shared with patch.py, so the patcher can never "fix" a
# statement other than the exact one this detector actually flagged.
def _check_underflow_into_copy(code: str) -> tuple[str, str, float] | None:
    finding = find_underflow_into_copy(code)
    if finding is None:
        return None
    return ("CWE-191", finding.explanation, 0.65)


def _check_missing_return_after_response(code: str) -> tuple[str, str, float] | None:
    finding = find_missing_return_after_response(code)
    if finding is None:
        return None
    return ("CWE-285", finding.explanation, 0.6)


class OllamaProvider(Provider):
    """Local, open-weight models via Ollama's native /api/chat endpoint.

    Deliberately does NOT go through the openai package's OpenAI-compat
    shim - talks to Ollama directly with stdlib urllib, so running an open
    model needs nothing beyond what `ollama pull <model>` already gives
    you (no pip install, no API key, no network egress at all beyond
    localhost). This is genuinely free and private, at the cost of
    whatever quality gap exists between a small local model and a hosted
    frontier one - see RGym/KGym in the README for why that gap matters
    more on kernel-class code than on typical benchmarks.
    """

    name = "ollama"

    def __init__(self, model: str | None = None):
        self._base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        self._model = model or os.environ.get("REACHCRS_MODEL", "llama3.2:3b")
        # Fail fast with a clear message rather than a raw connection-refused
        # traceback if Ollama isn't actually reachable at this URL.
        try:
            req = urllib.request.Request(f"{self._base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()
        except (urllib.error.URLError, OSError) as e:
            raise RuntimeError(
                f"Could not reach Ollama at {self._base_url} ({e}). "
                "Is `ollama serve` running? If Ollama is inside WSL and this "
                "process is on Windows, run reachcrs from inside WSL too - "
                "WSL2 does not forward that port to the Windows host here."
            ) from e

    def complete(self, system: str, user: str) -> str:
        body = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            # Hybrid-reasoning models (qwen3, deepseek-r1, ...) default to
            # emitting a long hidden chain-of-thought before the actual
            # answer - on this hardware that alone caused a run to not
            # finish a single call after 70+ minutes. think:false is a
            # no-op for models that don't support it (plain instruct models
            # like llama3.2 just ignore the field), so it's safe to always
            # send. num_predict caps runaway generation regardless.
            "think": False,
            "options": {"num_predict": 512},
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self._base_url}/api/chat", data=body,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=240) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Ollama request failed ({e.code}): {detail}") from e
        return data.get("message", {}).get("content", "")


class MockProvider(Provider):
    name = "mock"

    def complete(self, system: str, user: str) -> str:
        # `user` prompt embeds the function body between markers; extract it
        # back out so the same rule engine can be reused by both triage and
        # verify stages without re-plumbing.
        m = re.search(r"```\w*\n(.*?)\n```", user, re.DOTALL)
        code = m.group(1) if m else user

        # Two callers use this provider with two different response schemas
        # (triage wants {vulnerable,...}, verify wants {exploitable,...}) -
        # their system prompts are distinct, so key off that rather than
        # duplicating the whole rule engine per stage.
        is_verify_stage = "exploitable" in system

        findings = []
        for pattern, cwe, explanation, confidence in _RULES:
            if pattern.search(code):
                findings.append((cwe, explanation, confidence))
        underflow = _check_underflow_into_copy(code)
        if underflow:
            findings.append(underflow)
        missing_return = _check_missing_return_after_response(code)
        if missing_return:
            findings.append(missing_return)

        if not findings:
            if is_verify_stage:
                return json.dumps({
                    "exploitable": False,
                    "confidence": 0.05,
                    "rationale": "No known unsafe pattern matched by the mock heuristic ruleset.",
                })
            return json.dumps({
                "vulnerable": False,
                "cwe": None,
                "confidence": 0.05,
                "explanation": "No known unsafe pattern matched by the mock heuristic ruleset.",
            })

        cwe, explanation, confidence = max(findings, key=lambda f: f[2])
        if is_verify_stage:
            return json.dumps({
                "exploitable": True,
                "confidence": confidence,
                "rationale": explanation,
            })
        return json.dumps({
            "vulnerable": True,
            "cwe": cwe,
            "confidence": confidence,
            "explanation": explanation,
        })


def get_provider(name: str = "auto", model: str | None = None) -> Provider:
    if name == "mock":
        return MockProvider()
    if name == "anthropic":
        return AnthropicProvider(model)
    if name == "openai":
        return OpenAIProvider(model)
    if name == "ollama":
        return OllamaProvider(model)
    if name == "auto":
        if os.environ.get("ANTHROPIC_API_KEY"):
            try:
                return AnthropicProvider(model)
            except RuntimeError:
                pass
        if os.environ.get("OPENAI_API_KEY"):
            try:
                return OpenAIProvider(model)
            except RuntimeError:
                pass
        try:
            return OllamaProvider(model)
        except RuntimeError:
            pass
        return MockProvider()
    raise ValueError(f"Unknown provider: {name!r}")
