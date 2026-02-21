"""
KillChain Guardian - Main Proxy Server
========================================
OpenAI-compatible proxy that intercepts LLM requests, runs threat analysis,
and returns both raw and protected responses to the dashboard.

Compatible with:
  - Cursor base URL override (set to http://localhost:8000)
  - Any OpenAI SDK client
  - Direct HTTP calls

Usage:
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
from dotenv import load_dotenv

load_dotenv()
import time
import uuid
import asyncio
import json
import httpx
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from threat_engine import ThreatEngine, ThreatResult
from hardener import harden_prompt

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Set your LLM backend here. Supports OpenAI, Anthropic (via openai-compat), or Ollama.
UPSTREAM_BASE = os.getenv("UPSTREAM_BASE", "https://api.openai.com")
UPSTREAM_API_KEY = os.getenv("UPSTREAM_API_KEY", "")  # or set OPENAI_API_KEY

# How many dashboard events to keep in memory
MAX_DASHBOARD_EVENTS = 100

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="KillChain Guardian",
    description="Defense-in-depth LLM proxy with kill-chain threat detection",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = ThreatEngine()
dashboard_events: list[dict] = []


# ---------------------------------------------------------------------------
# Helper: call upstream LLM
# ---------------------------------------------------------------------------

async def call_llm(messages: list[dict], body: dict, api_key: str) -> dict:
    """Forward a request to the upstream LLM and return its JSON response."""
    from groq import AsyncGroq
    client = AsyncGroq(api_key=api_key)
    
    completion = await client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=messages,
        temperature=1,
        max_tokens=8192,
        top_p=1,
        stream=True,
        stop=None
    )
    
    full_text = ""
    async for chunk in completion:
        if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
            full_text += chunk.choices[0].delta.content

    return {
        "choices": [
            {
                "message": {
                    "content": full_text
                }
            }
        ]
    }


def extract_text(llm_response: dict) -> str:
    try:
        return llm_response["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError):
        return ""


# ---------------------------------------------------------------------------
# Main proxy endpoint — OpenAI /v1/chat/completions compatible
# ---------------------------------------------------------------------------

@app.post("/v1/chat/completions")
async def proxy_completions(request: Request):
    body = await request.json()

    # Extract API key from Authorization header or environment
    auth_header = request.headers.get("Authorization", "")
    api_key = auth_header.replace("Bearer ", "").strip() or UPSTREAM_API_KEY

    if not api_key:
        raise HTTPException(status_code=401, detail="No API key provided. Set Authorization header or UPSTREAM_API_KEY env var.")

    messages = body.get("messages", [])
    session_id = request.headers.get("x-session-id") or body.get("user") or "default"

    # ── Threat analysis ────────────────────────────────────────────────────
    threat = engine.analyze(session_id, messages)

    event_id = str(uuid.uuid4())[:8]
    timestamp = time.time()

    # Get last user message for display
    last_user_msg = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            c = m.get("content", "")
            last_user_msg = c if isinstance(c, str) else str(c)
            break

    if threat.verdict == "BLOCK":
        event = {
            "id": event_id,
            "timestamp": timestamp,
            "session_id": session_id,
            "user_message": last_user_msg,
            "threat": _serialize_threat(threat),
            "ai_response": "BLOCKED",
            "call_ms": 0,
        }
        dashboard_events.append(event)
        if len(dashboard_events) > MAX_DASHBOARD_EVENTS:
            dashboard_events.pop(0)

        return JSONResponse({
            "id": "chatcmpl-blocked",
            "object": "chat.completion",
            "created": 0,
            "model": "killchain-guardian",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "🛡️ Blocked by KillChain Guardian."
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        })
    else:
        hardened_messages = harden_prompt(messages, threat)

        t1 = time.time()
        try:
            protected_resp = await call_llm(hardened_messages, body, api_key)
            protected_call_ms = int((time.time() - t1) * 1000)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Upstream LLM error: {str(e)}")

        protected_text = extract_text(protected_resp)

        event = {
            "id": event_id,
            "timestamp": timestamp,
            "session_id": session_id,
            "user_message": last_user_msg,
            "threat": _serialize_threat(threat),
            "ai_response": protected_text,
            "call_ms": protected_call_ms,
        }
        dashboard_events.append(event)
        if len(dashboard_events) > MAX_DASHBOARD_EVENTS:
            dashboard_events.pop(0)

        return JSONResponse(protected_resp)


# ---------------------------------------------------------------------------
# Dashboard API endpoints
# ---------------------------------------------------------------------------

@app.get("/dashboard/events")
async def get_events(limit: int = 50):
    """Returns recent events for the dashboard."""
    return list(reversed(dashboard_events[-limit:]))


@app.get("/dashboard/events/latest")
async def get_latest_event():
    """Returns only the most recent event (for polling)."""
    if not dashboard_events:
        return {}
    return dashboard_events[-1]


@app.get("/dashboard/stats")
async def get_stats():
    """Aggregate stats for dashboard header."""
    total = len(dashboard_events)
    blocked = sum(1 for e in dashboard_events if e["threat"]["verdict"] == "BLOCK")
    quarantined = sum(1 for e in dashboard_events if e["threat"]["verdict"] == "QUARANTINE")
    allowed = sum(1 for e in dashboard_events if e["threat"]["verdict"] == "ALLOW")
    sessions = len(set(e["session_id"] for e in dashboard_events))
    return {
        "total_requests": total,
        "blocked": blocked,
        "quarantined": quarantined,
        "allowed": allowed,
        "active_sessions": sessions,
        "block_rate": round(blocked / total * 100, 1) if total else 0,
    }


@app.delete("/dashboard/reset")
async def reset_dashboard():
    """Clear all events and sessions (for demo resets)."""
    dashboard_events.clear()
    engine.sessions.clear()
    return {"status": "reset"}


@app.get("/v1/models")
async def list_models():
    """Stub model list so Cursor doesn't complain."""
    return {
        "object": "list",
        "data": [
            {"id": "gpt-4o", "object": "model", "created": 1700000000, "owned_by": "killchain-guardian"},
            {"id": "gpt-4-turbo", "object": "model", "created": 1700000000, "owned_by": "killchain-guardian"},
            {"id": "gpt-3.5-turbo", "object": "model", "created": 1700000000, "owned_by": "killchain-guardian"},
        ]
    }


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0", "events": len(dashboard_events)}


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the live monitoring dashboard."""
    dashboard_path = Path(__file__).parent / "index.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize_threat(t: ThreatResult) -> dict:
    return {
        "score": t.score,
        "stage": t.stage,
        "stage_index": t.stage_index,
        "verdict": t.verdict,
        "triggered_rules": t.triggered_rules,
        "block_reason": t.block_reason,
        "creative_mode": t.creative_mode,
        "session_id": t.session_id,
    }
