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
import subprocess
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from .heuristics import find_missing_return_after_response, find_underflow_into_copy


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader, same approach as cve_watcher.py/ghsa_extractor.py
    (no external dependency, never overwrites an already-set shell var).
    None of the 5 claude_backend.py experiment scripts loaded .env before
    this - they relied on the shell already having ANTHROPIC_API_KEY etc.
    exported, which AIxTechGatewayProvider's two new env vars would also
    need unless loaded here once, centrally, where every paid provider
    constructs from."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and val and key not in os.environ:
            os.environ[key] = val


def _load_dotenv_keys_override(path: Path, keys: set[str]) -> None:
    """Same parsing as _load_dotenv, but DOES overwrite the named keys.

    Scoped to just ANTHROPIC_AUTH_TOKEN/ANTHROPIC_BASE_URL below. Verified
    live: inside a Claude Code session's Bash tool, ANTHROPIC_BASE_URL is
    already present in the subprocess environment (pointing at the real
    api.anthropic.com), so the non-overwriting _load_dotenv() above leaves
    this project's .env value for it silently shadowed - the whole point
    of a custom gateway URL is defeated if an ambient default always wins.
    Scoped narrowly to these two new, aixtech-specific keys only; every
    other key (ANTHROPIC_API_KEY, NVD_API_KEY, ...) keeps the project's
    existing non-destructive convention from _load_dotenv() above."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key in keys and val:
            os.environ[key] = val


_DOTENV_PATH = Path(__file__).resolve().parents[2] / ".env"
_load_dotenv(_DOTENV_PATH)
_load_dotenv_keys_override(_DOTENV_PATH, {"ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"})

# Mirrors cve_pipeline.py's NO_PAID_BACKEND guard: unlike that module's
# _call_claude_metered(), nothing here previously stopped get_provider()
# from instantiating AnthropicProvider/OpenAIProvider (a metered, paid
# call) if a key happened to be present in the environment - e.g. "auto"
# mode silently preferring a paid backend over the free OllamaProvider.
# Setting NO_PAID_BACKEND=1 makes construction of either provider raise
# immediately, before any network call is attempted.
NO_PAID_BACKEND = os.environ.get("NO_PAID_BACKEND", "") not in ("", "0", "false", "False")


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
        if NO_PAID_BACKEND:
            raise RuntimeError(
                "NO_PAID_BACKEND is set - refusing to construct AnthropicProvider "
                "(a paid backend). Unset NO_PAID_BACKEND to allow this."
            )
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


class AIxTechGatewayProvider(Provider):
    """Claude models through the AI Singapore ("AIxTech") LLM gateway -
    an Anthropic-API-compatible proxy reachable at ANTHROPIC_BASE_URL and
    authenticated with a bearer token (ANTHROPIC_AUTH_TOKEN), not a raw
    ANTHROPIC_API_KEY. Same wire protocol as AnthropicProvider, so this
    only differs in which two env vars it reads and how the anthropic
    SDK is told to authenticate (auth_token -> Authorization: Bearer,
    instead of api_key -> x-api-key).

    Verified against the live gateway: claude-sonnet-5 and
    claude-haiku-4-5-20251001 are reachable with this key; claude-opus-4-8
    returned a 403 team_model_access_denied - this gateway's API keys are
    scoped to a per-team model allowlist, so not every Claude model name
    that works with ClaudeCLIProvider/AnthropicProvider will work here.
    """

    name = "aixtech"

    def __init__(self, model: str | None = None):
        if NO_PAID_BACKEND:
            raise RuntimeError(
                "NO_PAID_BACKEND is set - refusing to construct AIxTechGatewayProvider "
                "(a paid backend). Unset NO_PAID_BACKEND to allow this."
            )
        try:
            import anthropic  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "anthropic package not installed. Run `pip install anthropic` "
                "or use --provider mock."
            ) from e
        auth_token = os.environ.get("ANTHROPIC_AUTH_TOKEN")
        base_url = os.environ.get("ANTHROPIC_BASE_URL")
        if not auth_token or not base_url:
            raise RuntimeError(
                "ANTHROPIC_AUTH_TOKEN and ANTHROPIC_BASE_URL must both be set "
                "to use the aixtech gateway provider."
            )
        # This gateway is bearer-token-only. But anthropic.Anthropic() infers
        # api_key from ANTHROPIC_API_KEY whenever that env var exists AT ALL
        # (os.environ.get returns "" rather than None if it's set-but-empty),
        # and the SDK then sends an X-Api-Key header for any non-None value
        # - even "". Found live: inside a Claude Code session, ANTHROPIC_API_KEY
        # is already present in the subprocess environment as "", and the
        # gateway rejected that empty key before ever checking the valid
        # Bearer token. Constructing with a temporarily-cleared env avoids
        # sending that bogus header without touching ANTHROPIC_API_KEY for
        # any other code in this process (e.g. AnthropicProvider elsewhere).
        _stray_api_key = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            self._client = anthropic.Anthropic(auth_token=auth_token, base_url=base_url)
        finally:
            if _stray_api_key is not None:
                os.environ["ANTHROPIC_API_KEY"] = _stray_api_key
        self._model = model or os.environ.get("REACHCRS_MODEL", "claude-sonnet-5")
        # Unlike claude -p (ClaudeCLIProvider), this gateway's Messages API
        # response reports token counts but no dollar figure - last_cost_usd
        # stays None rather than a guessed value, so callers that print
        # "Total measured cost" don't report a number nobody measured.
        self.last_cost_usd: float | None = None
        self.billing_basis = "aixtech gateway (token counts only, no dollar cost reported)"
        self.last_usage: dict = {}
        self.last_duration_s: float | None = None

    def complete(self, system: str, user: str) -> str:
        started = time.perf_counter()
        try:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        finally:
            # Capture timing even on a raised error (e.g. a 403 denial) -
            # how long the gateway took to reject a call is itself a real,
            # reportable data point, not just a successful call's duration.
            self.last_duration_s = time.perf_counter() - started
        self.last_usage = {
            "input_tokens": getattr(resp.usage, "input_tokens", None),
            "output_tokens": getattr(resp.usage, "output_tokens", None),
        }
        return "".join(block.text for block in resp.content if hasattr(block, "text"))


class ClaudeCLIProvider(Provider):
    """Real Claude models via the `claude` CLI's own authenticated
    session, instead of a raw ANTHROPIC_API_KEY - mirrors
    cve_pipeline.py's `_call_claude_metered` exactly (same flags, same
    --output-format json parsing), the mechanism this project already
    uses when a raw API key isn't configured but the CLI is already
    logged in. Still a paid/metered backend - NO_PAID_BACKEND applies."""

    name = "claude-cli"

    def __init__(self, model: str | None = None):
        if NO_PAID_BACKEND:
            raise RuntimeError(
                "NO_PAID_BACKEND is set - refusing to construct ClaudeCLIProvider "
                "(a paid backend). Unset NO_PAID_BACKEND to allow this."
            )
        self._model = model
        self.last_cost_usd: float | None = None
        self.billing_basis = "claude-cli metered"

    def complete(self, system: str, user: str) -> str:
        prompt = f"{system}\n\n{user}"
        cmd = ["claude", "-p", prompt, "--output-format", "json",
               "--tools", "", "--permission-prompts", "none",
               "--no-session-persistence"]
        if self._model:
            cmd += ["--model", self._model]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=240)
        if result.returncode != 0 or not result.stdout.strip():
            raise RuntimeError(
                f"claude -p failed (exit {result.returncode}): {result.stderr[:500]}")
        data = json.loads(result.stdout)
        self.last_cost_usd = data.get("total_cost_usd")
        if data.get("is_error"):
            raise RuntimeError(
                f"claude -p API error (status {data.get('api_error_status')}): "
                f"{(data.get('result') or '')[:500]}")
        return (data.get("result") or "").strip()


class CodexCLIProvider(Provider):
    """Run the authenticated Codex CLI and retain its JSONL usage event.

    This is deliberately separate from OpenAIProvider: Codex CLI uses the
    user's ChatGPT/Codex authentication, while OpenAIProvider uses an API key.
    The CLI is constrained to a read-only, ephemeral session so a model cannot
    modify the experiment checkout while producing a patch or probe proposal.
    """

    name = "codex-cli"

    def __init__(self, model: str | None = None):
        self._model = model
        self.last_cost_usd: float | None = None
        self.billing_basis = "codex-cli ChatGPT auth"
        self.last_duration_s: float | None = None
        self.last_usage: dict = {}
        self.last_thread_id: str | None = None
        self.last_raw_events: list[dict] = []

    def complete(self, system: str, user: str) -> str:
        import time

        prompt = f"{system}\n\n{user}"
        cmd = ["codex", "exec", "--ephemeral", "--sandbox", "read-only",
               "--json", "--skip-git-repo-check", "--disable", "skill_search"]
        if self._model:
            cmd += ["--model", self._model]
        cmd.append("-")
        started = time.perf_counter()
        result = subprocess.run(cmd, input=prompt, capture_output=True,
                                text=True, encoding="utf-8", errors="replace",
                                timeout=900)
        self.last_duration_s = time.perf_counter() - started
        events: list[dict] = []
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(event)
            if event.get("type") == "thread.started":
                self.last_thread_id = event.get("thread_id")
            if event.get("type") == "turn.completed":
                self.last_usage = event.get("usage") or {}
        self.last_raw_events = events
        messages = [e.get("item", {}).get("text", "") for e in events
                    if e.get("type") == "item.completed"
                    and e.get("item", {}).get("type") == "agent_message"]
        if result.returncode != 0 or not messages:
            detail = result.stderr[-1000:] or result.stdout[-1000:]
            raise RuntimeError(f"codex exec failed (exit {result.returncode}): {detail}")
        return messages[-1].strip()


class OpenAIProvider(Provider):
    """Also works for any OpenAI-compatible chat completions API - e.g.
    Zhipu/z.ai's GLM models - by pointing OPENAI_BASE_URL at their endpoint
    and OPENAI_API_KEY at that provider's key. Nothing else changes."""

    name = "openai"

    def __init__(self, model: str | None = None):
        if NO_PAID_BACKEND:
            raise RuntimeError(
                "NO_PAID_BACKEND is set - refusing to construct OpenAIProvider "
                "(a paid backend). Unset NO_PAID_BACKEND to allow this."
            )
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
        self.last_cost_usd: float = 0.0
        self.billing_basis = "ollama-local zero-cost"
        self.last_duration_s: float | None = None
        self.last_usage: dict = {}
        self.last_raw_events: list[dict] = []
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
        started = time.perf_counter()
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
        self.last_duration_s = time.perf_counter() - started
        prompt_tokens = data.get("prompt_eval_count")
        output_tokens = data.get("eval_count")
        self.last_usage = {
            "input_tokens": prompt_tokens,
            "output_tokens": output_tokens,
            "total_tokens": ((prompt_tokens or 0) + (output_tokens or 0))
            if prompt_tokens is not None or output_tokens is not None else None,
            "total_duration_ns": data.get("total_duration"),
            "load_duration_ns": data.get("load_duration"),
            "prompt_eval_duration_ns": data.get("prompt_eval_duration"),
            "eval_duration_ns": data.get("eval_duration"),
        }
        self.last_raw_events = [data]
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
    if name == "aixtech":
        return AIxTechGatewayProvider(model)
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
        if os.environ.get("ANTHROPIC_AUTH_TOKEN") and os.environ.get("ANTHROPIC_BASE_URL"):
            try:
                return AIxTechGatewayProvider(model)
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
