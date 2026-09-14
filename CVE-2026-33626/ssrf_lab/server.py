"""
server.py — SSRF defensive testing lab server.

IMPORTANT: This server is intentionally dual-mode (vulnerable / patched).
           Bind address is 127.0.0.1 — never expose this on a public interface.

Environment variables / config:
  LAB_MODE         "vulnerable" | "patched"   (default: patched)
  LAB_HOST         bind address               (default: 127.0.0.1)
  LAB_PORT         port                       (default: 8000)
  LAB_LOG_FILE     path to NDJSON audit log   (default: lab_audit.ndjson)

Endpoint:
  POST /v1/chat/completions
    {
      "model":    "internlm-xcomposer2",
      "messages": [
        {
          "role": "user",
          "content": [
            {"type": "text",      "text": "Describe this image"},
            {"type": "image_url", "image_url": {"url": "http://..."}
          ]
        }
      ]
    }

  GET  /mode          — current mode + blocked CIDR list
  POST /mode          — {"mode": "vulnerable"|"patched"}  switch at runtime
  GET  /audit         — last 200 audit log entries
"""

import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from image_loader import (
    SSRFBlockedError,
    _BLOCKED,
    hardened_load_image,
    safe_load_image,
    vulnerable_load_image,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LAB_MODE     = os.environ.get("LAB_MODE", "patched").lower()
LAB_HOST     = os.environ.get("LAB_HOST", "127.0.0.1")
LAB_PORT     = int(os.environ.get("LAB_PORT", "8000"))
LAB_LOG_FILE = Path(os.environ.get("LAB_LOG_FILE", "lab_audit.ndjson"))

if LAB_HOST != "127.0.0.1":
    print(
        f"[WARN] LAB_HOST is set to {LAB_HOST!r}. "
        "This server contains a deliberately vulnerable mode — "
        "do not bind to a public interface.",
        file=sys.stderr,
    )

# ---------------------------------------------------------------------------
# In-memory mode state (mutable at runtime via /mode)
# ---------------------------------------------------------------------------

_state: dict[str, str] = {"mode": LAB_MODE}

# ---------------------------------------------------------------------------
# Structured audit log
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ssrf_lab")

_audit_ring: list[dict] = []   # last 200 entries, in memory


def _audit(event: str, request_id: str, data: dict) -> None:
    entry = {
        "ts":         datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "mode":       _state["mode"],
        "event":      event,
        **data,
    }
    _audit_ring.append(entry)
    if len(_audit_ring) > 200:
        _audit_ring.pop(0)
    line = json.dumps(entry, ensure_ascii=False)
    logger.info(line)
    with LAB_LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ImageURL(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("url must not be empty")
        return v.strip()


class ContentPart(BaseModel):
    type: str
    text:      str | None = None
    image_url: ImageURL | None = None


class Message(BaseModel):
    role:    str
    content: str | list[ContentPart]


class ChatRequest(BaseModel):
    model:    str = "internlm-xcomposer2"
    messages: list[Message]
    stream:   bool = False


class ModeSwitch(BaseModel):
    mode: str

    @field_validator("mode")
    @classmethod
    def must_be_valid(cls, v: str) -> str:
        if v not in ("vulnerable", "patched", "hardened"):
            raise ValueError("mode must be 'vulnerable', 'patched', or 'hardened'")
        return v


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SSRF Defensive Testing Lab",
    description=(
        "Simulates a vulnerable vision-language API (lmdeploy-style) "
        "with a runtime toggle between vulnerable and patched image-fetch modes. "
        "FOR INTERNAL SECURITY TESTING ONLY."
    ),
    version="1.0.0",
)


@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request.state.request_id = str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-Id"] = request.state.request_id
    return response


# ---------------------------------------------------------------------------
# /mode
# ---------------------------------------------------------------------------

@app.get("/mode")
def get_mode():
    return {
        "mode": _state["mode"],
        "blocked_cidrs": [str(n) for n in _BLOCKED],
        "warning": (
            "vulnerable mode disables all SSRF protection — lab use only"
            if _state["mode"] == "vulnerable" else None
        ),
        "description": {
            "vulnerable": "No validation — SSRF possible",
            "patched":    "IP validation only — redirect & DNS-rebind bypasses still possible",
            "hardened":   "Per-hop redirect validation + IP pinning — all known bypasses mitigated",
        }.get(_state["mode"]),
    }


@app.post("/mode")
def set_mode(body: ModeSwitch, request: Request):
    previous = _state["mode"]
    _state["mode"] = body.mode
    _audit("mode_switch", request.state.request_id,
           {"previous": previous, "current": body.mode})
    return {"mode": _state["mode"], "previous": previous}


# ---------------------------------------------------------------------------
# /audit
# ---------------------------------------------------------------------------

@app.get("/audit")
def get_audit(limit: int = 50):
    limit = max(1, min(limit, 200))
    return {"entries": _audit_ring[-limit:], "total_stored": len(_audit_ring)}


# ---------------------------------------------------------------------------
# /v1/chat/completions
# ---------------------------------------------------------------------------

def _extract_image_urls(messages: list[Message]) -> list[str]:
    urls: list[str] = []
    for msg in messages:
        if isinstance(msg.content, list):
            for part in msg.content:
                if part.type == "image_url" and part.image_url:
                    urls.append(part.image_url.url)
    return urls


def _fetch_image(url: str) -> dict[str, Any]:
    """Dispatch to the appropriate loader based on current mode."""
    if _state["mode"] == "vulnerable":
        return {"loader": "vulnerable", **_run_loader(vulnerable_load_image, url)}
    if _state["mode"] == "hardened":
        return {"loader": "hardened",   **_run_loader(hardened_load_image, url)}
    return {"loader": "safe",           **_run_loader(safe_load_image, url)}


def _run_loader(fn, url: str) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        _mode, info = fn(url)
        return {
            "ok":      True,
            "url":     url,
            "elapsed": round(time.perf_counter() - t0, 3),
            **info,
        }
    except SSRFBlockedError as exc:
        return {
            "ok":      False,
            "url":     url,
            "error":   "ssrf_blocked",
            "detail":  str(exc),
            "elapsed": round(time.perf_counter() - t0, 3),
        }
    except Exception as exc:
        return {
            "ok":      False,
            "url":     url,
            "error":   type(exc).__name__,
            "detail":  str(exc),
            "elapsed": round(time.perf_counter() - t0, 3),
        }


@app.post("/v1/chat/completions")
async def chat_completions(body: ChatRequest, request: Request):
    rid = request.state.request_id
    image_urls = _extract_image_urls(body.messages)

    _audit("request_received", rid, {
        "model":      body.model,
        "image_urls": image_urls,
        "client_ip":  request.client.host if request.client else "unknown",
    })

    fetch_results: list[dict] = []
    for url in image_urls:
        result = _fetch_image(url)
        fetch_results.append(result)

        event = "ssrf_blocked" if result.get("error") == "ssrf_blocked" else \
                "fetch_failed"  if not result["ok"]                      else \
                "fetch_success"

        _audit(event, rid, {
            "url":    url,
            "result": result,
        })

        if event == "ssrf_blocked":
            # Return 422 so detection rules can key on HTTP status + body shape
            raise HTTPException(
                status_code=422,
                detail={
                    "error":   "ssrf_blocked",
                    "message": result["detail"],
                    "url":     url,
                },
            )

    # Simulate a minimal vision-language response
    mock_response = {
        "id":      f"chatcmpl-{rid[:8]}",
        "object":  "chat.completion",
        "created": int(time.time()),
        "model":   body.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role":    "assistant",
                    "content": _mock_description(fetch_results),
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 42, "completion_tokens": 24, "total_tokens": 66},
        "_lab_meta": {
            "mode":          _state["mode"],
            "request_id":    rid,
            "fetch_results": fetch_results,
        },
    }

    return JSONResponse(content=mock_response)


def _mock_description(fetch_results: list[dict]) -> str:
    if not fetch_results:
        return "No image provided."
    parts = []
    for r in fetch_results:
        if not r["ok"]:
            parts.append(f"[fetch error: {r.get('detail', r.get('error'))}]")
        elif "width" in r:
            parts.append(
                f"[lab] Image {r['width']}x{r['height']} ({r.get('format','?')}) "
                f"fetched in {r['elapsed']}s via {r['loader']} loader."
            )
        else:
            body = r.get("body_preview", "")
            parts.append(
                f"[lab] Non-image response ({r.get('content_type','?')}, "
                f"{r.get('size_bytes',0)} bytes) via {r['loader']} loader. "
                f"Preview: {body[:120]!r}"
            )
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(
        f"\n{'='*60}\n"
        f"  SSRF DEFENSIVE TESTING LAB\n"
        f"  Bind  : {LAB_HOST}:{LAB_PORT}\n"
        f"  Mode  : {_state['mode'].upper()}\n"
        f"  Log   : {LAB_LOG_FILE.resolve()}\n"
        f"  Docs  : http://{LAB_HOST}:{LAB_PORT}/docs\n"
        f"{'='*60}\n",
        file=sys.stderr,
    )
    uvicorn.run(
        "server:app",
        host=LAB_HOST,
        port=LAB_PORT,
        log_level="warning",   # suppress uvicorn noise; audit log has everything
    )
