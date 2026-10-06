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

from src.reachability.providers import OllamaProvider, ClaudeCLIProvider  # noqa: E402

CLAUDE_MODELS = [
    "claude-haiku-4-5-20251001", "claude-sonnet-4-6", "claude-sonnet-5",
    "claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8",
]


def provider_for(backend: str, model: str):
    return ClaudeCLIProvider(model) if backend == "claude" else OllamaProvider(model)
