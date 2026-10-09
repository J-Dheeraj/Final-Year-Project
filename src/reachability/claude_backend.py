"""Shared Claude-backend wiring for the free5GC/OpenEMR/catalog
experiment scripts.

Centralizes three things that were duplicated (and twice got the
import order wrong) across 5 separate scripts this session:

1. The NO_PAID_BACKEND="0" env var MUST be set, and providers.py
   imported, before any module that itself sets NO_PAID_BACKEND="1"
   (run_harness.py, run_full_deployment_harness.py) gets imported -
   that module resets the env var before providers.py's module-level
   constant gets baked in on first import, otherwise. Importing this
   module first in a calling script's import block gets the order
   right in one place instead of five.
2. CLAUDE_MODELS - the 6 model names used throughout this update pass.
3. provider_for(backend, model) - the OllamaProvider/ClaudeCLIProvider
   switch every script repeated inline.
"""
from __future__ import annotations

import os

os.environ["NO_PAID_BACKEND"] = "0"  # must precede the providers.py import below

from src.reachability.providers import (  # noqa: E402
    AIxTechGatewayProvider,
    ClaudeCLIProvider,
    OllamaProvider,
)

CLAUDE_MODELS = [
    "claude-haiku-4-5-20251001", "claude-sonnet-4-6", "claude-sonnet-5",
    "claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8",
]

# The AIxTech gateway (ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN) is a
# separately-keyed proxy with its own per-team model allowlist. The user's
# requested 10-model list (2026-10-09) is kept in full rather than
# pre-filtered: live smoke-testing confirmed only the first 4 resolve with
# this project's key (sonnet-5-5 and every opus-* entry return 403
# team_model_access_denied here even though opus works via ClaudeCLIProvider).
# The per-model experiment scripts already catch a provider/completion
# failure and record it in that model's own report entry, so running the
# full 10 here produces an honest "4 worked, 6 environment-limited" record
# instead of silently dropping the inaccessible ones.
AIXTECH_MODELS = [
    "claude-haiku-4-5-20251001", "claude-haiku-5-5",
    "claude-sonnet-4-6", "claude-sonnet-5",
    "claude-sonnet-5-5",
    "claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8",
    "claude-opus-5", "claude-opus-5-5",
]


def provider_for(backend: str, model: str):
    if backend == "claude":
        return ClaudeCLIProvider(model)
    if backend == "aixtech":
        return AIxTechGatewayProvider(model)
    return OllamaProvider(model)
