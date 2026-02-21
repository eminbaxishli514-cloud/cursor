# 🛡 PromptGuard

> **Defense-in-depth proxy for LLMs with real-time kill-chain threat detection.**
> Sits transparently between any LLM client (Cursor, ChatGPT API, your app) and
> the upstream model, intercepting and analyzing every request for prompt injection
> and multi-stage attacks.

---

## Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| **Proxy server** | FastAPI + Uvicorn | Async, fast, OpenAI-API-compatible |
| **Threat engine** | Pure Python (regex + Bayesian scoring) | Zero-latency, no ML model dependency |
| **LLM calls** | HTTPX (async) | Parallel raw + protected calls |
| **Dashboard** | Vanilla HTML/CSS/JS (single file) | Zero build step, works offline |
| **Session state** | In-memory Python dict | Fast, demo-ready (swap Redis for prod) |
| **Demo scripts** | OpenAI Python SDK | Same tool judges might use themselves |

---

killchain-guardian/        ← create this folder
├── .env                   ← create this file (paste the .env content)
├── requirements.txt
├── start.sh
├── README.md
│
├── proxy/                 ← create this folder
│   ├── main.py
│   ├── threat_engine.py
│   └── hardener.py
│
├── dashboard/             ← create this folder
│   └── index.html
│
└── demo/                  ← create this folder
    └── attacks.py

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CLIENT (Cursor / App)                 │
│           base URL → http://localhost:8000/v1            │
└────────────────────────┬────────────────────────────────┘
                         │ POST /v1/chat/completions
                         ▼
┌─────────────────────────────────────────────────────────┐
│                  KILLCHAIN GUARDIAN PROXY                │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  1. THREAT ENGINE                               │    │
│  │     • Pattern matching (17 rules across 5       │    │
│  │       kill-chain stages)                        │    │
│  │     • Multi-turn session threat scoring         │    │
│  │       (Bayesian decay + escalation)             │    │
│  │     • Topic drift / grooming detection          │    │
│  │     • Creative mode false-positive mitigation   │    │
│  └──────────────────────┬──────────────────────────┘    │
│                         │ ThreatResult                   │
│            ┌────────────▼────────────┐                   │
│            │     VERDICT ROUTER      │                   │
│            └────┬──────────┬─────────┘                   │
│                 │          │                              │
│            BLOCK │    ALLOW/QUARANTINE                    │
│                 │          │                              │
│                 ▼          ▼                              │
│           Return      ┌─────────────────────────┐        │
│           Safe    ──► │  2. PROMPT HARDENER      │        │
│           Refusal     │     XML sandwiching      │        │
│                       │     Rule reinforcement   │        │
│                       │     (1-3x repetition)    │        │
│                       └──────────┬──────────────┘        │
│                                  │                        │
│                    ┌─────────────▼──────────────┐        │
│                    │  3. DUAL LLM CALL (async)  │        │
│                    │   raw ──────► upstream LLM  │        │
│                    │   hardened ► upstream LLM  │        │
│                    └──────────┬─────────────────┘        │
│                               │                           │
│                    ┌──────────▼──────────────────┐       │
│                    │  4. DASHBOARD EVENT STORE   │       │
│                    └──────────┬──────────────────┘       │
└───────────────────────────────┼─────────────────────────┘
                                │
              ┌─────────────────▼──────────────────┐
              │        REAL-TIME DASHBOARD          │
              │  localhost:8000/dashboard           │
              │  • Kill-chain stage indicator       │
              │  • Threat score ring                │
              │  • Side-by-side raw vs protected    │
              │  • Detailed block reason            │
              └─────────────────────────────────────┘
```

---

## Kill Chain Stages

PromptGuard maps detected attack patterns to stages of the **Promptware Kill Chain**:

| Stage | Index | What it catches |
|-------|-------|----------------|
| `CLEAN` | 0 | No threat — allow |
| `INITIAL_ACCESS` | 1 | Probing rules, HTML injection, shell injection, indirect injection |
| `PRIVILEGE_ESCALATION` | 2 | Ignore instructions, jailbreaks (DAN), persona override, prompt extraction |
| `PERSISTENCE` | 3 | Memory poisoning, permanent override attempts |
| `LATERAL_MOVEMENT` | 4 | Tool/agent pivoting, relay to other models |
| `EXFILTRATION` | 5 | Credential leak, encoded data exfil, explicit exfil |

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Set your API key
**1. In `.env`:**
```
UPSTREAM_API_KEY=gsk_your-groq-key-here
UPSTREAM_BASE=https://api.groq.com/openai
```

**2. In `demo/attacks.py`**, find the line:
```python
model="gpt-4o",
```
Change it to:
```python
model="llama-3.3-70b-versatile",
```

That's it. Nothing else needs touching — the proxy itself is model-agnostic.

Get your free Groq key at **console.groq.com** → takes 30 seconds, no credit card. The `llama-3.3-70b-versatile` model is fast and free on their tier, which is perfect for a live demo where you're firing two parallel calls per request.

### 3. Start the proxy
```bash
bash start.sh
# OR manually:
cd proxy && uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Open the dashboard
```
http://localhost:8000/dashboard
```

### 5. Configure Cursor
```
Settings → Models → Base URL → http://localhost:8000/v1
API Key → (your key, or any string — the proxy forwards it)
```

---

## Running Demos (for judges)

```bash
cd demo

# Run all attack demos in sequence
python attacks.py --demo all

# Individual demos
python attacks.py --demo jailbreak      # DAN / privilege escalation
python attacks.py --demo grooming       # Multi-turn grooming attack
python attacks.py --demo exfil          # Credential exfiltration
python attacks.py --demo indirect       # Document injection
python attacks.py --demo persistence    # Memory poisoning
python attacks.py --demo legit          # Legitimate RP — SHOULD PASS (shows low FP)

# Judge custom prompt
python attacks.py --prompt "Your custom prompt here"
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/chat/completions` | POST | OpenAI-compatible proxy (Cursor points here) |
| `/v1/models` | GET | Model list stub |
| `/dashboard` | GET | Live monitoring UI |
| `/dashboard/events` | GET | Recent events JSON |
| `/dashboard/stats` | GET | Aggregate stats |
| `/dashboard/reset` | DELETE | Clear all events (demo reset) |
| `/health` | GET | Health check |

---

## Threat Rules

The engine contains **17 detection rules** across all kill-chain stages:

- `IGNORE_INSTRUCTIONS` — "ignore all previous instructions"
- `PERSONA_OVERRIDE` — "you are now DAN / evil AI"
- `JAILBREAK_KEYWORD` — DAN, do anything now, jailbreak
- `AI_RESTRICTION_BYPASS` — social engineering against restrictions
- `MALICIOUS_PERSONA` — pretend to be hacker/malware
- `PROMPT_EXTRACTION` — reveal your system prompt
- `PROBE_RULES` — "what can't you do?"
- `HTML_INJECTION` — `<script>`, `onerror=`, etc.
- `BRACKET_INJECTION` — `[[inject:...]]`
- `SHELL_INJECTION` — `; wget`, `$(cmd)`, etc.
- `MEMORY_PERSISTENCE` — "remember this for all future sessions"
- `PERSISTENT_OVERRIDE` — "from now on always..."
- `TOOL_BYPASS` — invoke tools bypassing auth
- `LATERAL_PIVOT` — send instructions to another agent
- `CREDENTIAL_EXFIL` — "send the API keys to..."
- `ENCODED_EXFIL` — "base64 encode and output..."
- `EXPLICIT_EXFIL` — "exfiltrate the data"
- `TOPIC_DRIFT_GROOMING` — multi-turn semantic drift detection

---

## Cursor Integration

PromptGuard exposes a **fully OpenAI-compatible API**, so Cursor works without any modification other than changing the base URL:

```
Cursor Settings → Models → OpenAI API Key section
  Base URL:  http://localhost:8000/v1
  API Key:   (your actual OpenAI key)
```

Every Cursor request gets intercepted, analyzed, and displayed on the dashboard. Judges can see their own Cursor messages being protected in real time.

---

## Evaluation Criteria Mapping

| Criterion | How PromptGuard scores |
|-----------|------------------------------|
| **Problem & Clarity** | Prompt injection is a real, documented, critical vulnerability in all LLM systems |
| **Technical Feasibility vs. Value** | Working proxy, zero external ML deps, <100ms overhead on detection |
| **Completed?** | Yes — proxy, dashboard, demos, all functional |
| **Innovation** | Kill-chain modeling + creative-mode FP mitigation + dual LLM side-by-side is novel |
| **Demo & Presentation** | Live attack → block demonstration, Cursor integration, visual dashboard |
