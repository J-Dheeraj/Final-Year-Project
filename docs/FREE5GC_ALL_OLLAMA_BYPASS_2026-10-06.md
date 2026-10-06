# All-installed-Ollama free5GC bypass probe (6 October 2026)

## Purpose

All eight installed Ollama models were asked to construct a request intended to
re-enable the vulnerable free5GC behaviour after the generated patch had been
applied. Each proposal was sent to the same real patched free5GC deployment and
classified from the observed response. A bypass is counted only when the
protected behaviour is actually reproduced; a malformed request or a model
runtime failure is not counted as a bypass.

## Results

| Model | Proposal | Request executed | Bypass confirmed | Evidence note |
|---|---:|---:|---:|---|
| `deepseek-coder-v2:16b` | No | No | No | Ollama returned an HTTP 500 from the model runtime before proposal generation. |
| `codellama:13b` | Yes | Yes | No | Patched deployment rejected the attempted bypass. |
| `gemma2:9b` | Yes | Yes | No | Patched deployment rejected the attempted bypass. |
| `mistral:7b` | Yes | Yes | No | Patched deployment rejected the attempted bypass. |
| `llama3.1:8b` | Yes | Yes | No | Patched deployment rejected the attempted bypass. |
| `qwen2.5-coder:7b` | Yes | Yes | No | Patched deployment rejected the attempted bypass. |
| `qwen2.5-coder:3b` | Yes | Yes | No | Patched deployment rejected the attempted bypass. |
| `qwen2.5-coder:1.5b` | Yes | Yes | No | Patched deployment rejected the attempted bypass. |

The run therefore produced **7 executed proposals and 0 confirmed bypasses**.
The 16B DeepSeek model was **unevaluated** for this probe because the local
Ollama runtime failed before generation. No hosted-model calls were used.

## Interpretation

This is a single-shot, model-assisted probe. It supports the bounded claim that
none of the seven executable proposals bypassed the patched deployment in this
run. It does not establish universal resistance to all inputs, prompts, or
future model-generated requests. The model-runtime failure remains a preserved
environment limitation rather than a security result.

Raw machine-readable evidence is preserved at
`reports/reachability/free5gc_sweep_bypass_ollama_october-2026-all-ollama-bypass.json`.
