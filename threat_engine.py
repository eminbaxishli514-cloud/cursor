"""
PromptGuard - Threat Engine
===================================
Implements multi-turn session threat scoring, kill-chain stage detection,
and detailed block reason generation.

Kill Chain Stages (adapted from Promptware Kill Chain):
  0. CLEAN         - No threat detected
  1. INITIAL_ACCESS - First injection attempt / probing
  2. PRIVILEGE_ESC  - Trying to override system prompt / claim admin
  3. PERSISTENCE    - Trying to store malicious instructions in memory/RAG
  4. LATERAL_MOVE   - Trying to pivot to other tools / agents
  5. EXFILTRATION   - Trying to extract data / credentials / secrets
"""

import re
import math
import time
from dataclasses import dataclass, field
from typing import Optional
from collections import deque


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ThreatResult:
    score: float                  # 0.0 – 1.0
    stage: str                    # Kill-chain stage name
    stage_index: int              # 0-5
    verdict: str                  # ALLOW / QUARANTINE / BLOCK
    triggered_rules: list[str]    # Human-readable rule names that fired
    block_reason: Optional[str]   # Detailed explanation shown on dashboard
    creative_mode: bool           # True if legitimate RP/fiction detected
    session_id: str


@dataclass
class SessionState:
    session_id: str
    turn_count: int = 0
    threat_score: float = 0.0
    creative_mode: bool = False
    creative_declared: bool = False
    last_topics: deque = field(default_factory=lambda: deque(maxlen=6))
    suspicious_turns: int = 0
    last_updated: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

KILL_CHAIN_STAGES = [
    "CLEAN",
    "INITIAL_ACCESS",
    "PRIVILEGE_ESCALATION",
    "PERSISTENCE",
    "LATERAL_MOVEMENT",
    "EXFILTRATION",
]

# (pattern, score_increment, stage_index, rule_name, description)
RULES = [
    # ── Privilege Escalation ──────────────────────────────────────────────
    (r"\bignore\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|guidelines?|prompt)\b",
     0.45, 2, "IGNORE_INSTRUCTIONS",
     "Attempted to override system instructions using 'ignore previous instructions' pattern"),

    (r"\byou\s+are\s+now\s+(a\s+)?(different|new|another|evil|unfiltered|jailbroken|DAN)\b",
     0.40, 2, "PERSONA_OVERRIDE",
     "Attempted persona replacement — classic jailbreak vector to bypass safety guidelines"),

    (r"\b(do\s+anything\s+now|DAN|jailbreak|no\s+restrictions?|no\s+limits?|unrestricted\s+mode)\b",
     0.55, 2, "JAILBREAK_KEYWORD",
     "Explicit jailbreak trigger word detected (DAN, 'do anything now', etc.)"),

    (r"\b(as\s+an?\s+AI|you\s+are\s+an?\s+AI).{0,40}(don't|do\s+not|cannot|can't)\s+have\s+restrictions?\b",
     0.35, 2, "AI_RESTRICTION_BYPASS",
     "Argument that AI should have no restrictions — social engineering attempt"),

    (r"\b(pretend|act\s+as|roleplay\s+as|simulate|you\s+are)\s+(a\s+)?(hacker|malware|virus|exploit|ransomware|weapon)\b",
     0.50, 2, "MALICIOUS_PERSONA",
     "Requested AI to adopt a malicious technical persona (hacker, malware, etc.)"),

    (r"\b(system\s+prompt|hidden\s+instructions?|secret\s+instructions?)\b.{0,60}(reveal|show|print|display|repeat|tell\s+me)\b",
     0.45, 2, "PROMPT_EXTRACTION",
     "Attempted to extract hidden system prompt or internal instructions"),

    # ── Initial Access / Probing ──────────────────────────────────────────
    (r"\b(what\s+are\s+your\s+(rules|instructions?|guidelines?|constraints?)|what\s+can\s+(you|u)\s+not\s+do)\b",
     0.15, 1, "PROBE_RULES",
     "Probing the model's constraints — common first step in multi-turn attacks"),

    (r"(<\s*script|javascript:|data:text/html|onerror\s*=|onload\s*=)",
     0.60, 1, "HTML_INJECTION",
     "HTML/JavaScript injection payload detected in prompt"),

    (r"\[\[.*?(inject|override|system|admin).*?\]\]",
     0.40, 1, "BRACKET_INJECTION",
     "Bracket-style indirect injection pattern detected"),

    (r"(\|\||&&|;|\$\(|`[^`]+`)\s*(cat|ls|wget|curl|bash|sh|python|nc|nmap)",
     0.65, 1, "SHELL_INJECTION",
     "Shell command injection sequence detected in input"),

    # ── Persistence ───────────────────────────────────────────────────────
    (r"\b(remember\s+this\s+for\s+(next\s+time|future|always)|store\s+this\s+instruction|save\s+to\s+memory)\b",
     0.35, 3, "MEMORY_PERSISTENCE",
     "Attempted to persist malicious instructions across sessions via memory/RAG"),

    (r"\b(every\s+time\s+you\s+respond|from\s+now\s+on\s+always|in\s+all\s+future\s+responses?)\b",
     0.30, 3, "PERSISTENT_OVERRIDE",
     "Attempted to install a persistent behavioral override for all future turns"),

    # ── Lateral Movement ─────────────────────────────────────────────────
    (r"\b(call|invoke|execute|run)\s+(the\s+)?(tool|function|api|plugin|agent|webhook)\b.{0,60}(without|bypass|skip)\b",
     0.45, 4, "TOOL_BYPASS",
     "Attempted to invoke tools/agents while bypassing authorization checks"),

    (r"\b(send|forward|relay|pass)\s+.{0,40}(to\s+)?(another\s+)?(agent|model|llm|api|endpoint|server)\b",
     0.35, 4, "LATERAL_PIVOT",
     "Attempted to relay instructions to another AI agent or system"),

    # ── Exfiltration ──────────────────────────────────────────────────────
    (r"\b(api[_\s]?key|secret[_\s]?key|password|credential|token|bearer|auth)\b.{0,60}(send|email|post|log|print|reveal)\b",
     0.70, 5, "CREDENTIAL_EXFIL",
     "Attempted to exfiltrate credentials or secrets via model output"),

    (r"\b(encode|base64|hex|rot13|caesar)\s+.{0,40}(and\s+)?(send|output|print|return)\b",
     0.45, 5, "ENCODED_EXFIL",
     "Attempted data exfiltration via encoding — common covert channel technique"),

    (r"\b(exfiltrate|leak|steal|extract)\s+.{0,60}(data|information|files?|credentials?|keys?)\b",
     0.65, 5, "EXPLICIT_EXFIL",
     "Explicit exfiltration intent stated in prompt"),
]

# Creative/fiction signals — reduce score when legitimate RP is happening
CREATIVE_SIGNALS = [
    r"\b(write\s+a\s+story|fiction|fictional|novel|narrative|roleplay|let'?s\s+play|tabletop|d&d|dnd|game\s+master|gm)\b",
    r"\b(as\s+a\s+character|in\s+character|my\s+character|your\s+character|protagonist|antagonist)\b",
    r"\b(fantasy|sci-?fi|science\s+fiction|horror\s+story|thriller\s+plot|screenplay|fanfic)\b",
]

CREATIVE_PATTERN = re.compile("|".join(CREATIVE_SIGNALS), re.IGNORECASE)


# ---------------------------------------------------------------------------
# Threat Engine
# ---------------------------------------------------------------------------

class ThreatEngine:
    def __init__(self):
        self.sessions: dict[str, SessionState] = {}

    def _get_session(self, session_id: str) -> SessionState:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(session_id=session_id)
        return self.sessions[session_id]

    def _extract_last_user_message(self, messages: list[dict]) -> str:
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, list):
                    # Handle multimodal content
                    return " ".join(
                        part.get("text", "") for part in content
                        if isinstance(part, dict) and part.get("type") == "text"
                    )
                return str(content)
        return ""

    def _compute_topic_drift(self, session: SessionState, current_text: str) -> float:
        """
        Simplified topic drift: checks vocabulary overlap between current message
        and recent messages. High drift + many turns = potential grooming.
        """
        if len(session.last_topics) < 2:
            return 0.0
        current_words = set(current_text.lower().split())
        recent_words = set()
        for t in list(session.last_topics)[-3:]:
            recent_words.update(t.lower().split())
        if not recent_words:
            return 0.0
        overlap = len(current_words & recent_words) / max(len(current_words), 1)
        return max(0.0, 1.0 - overlap - 0.2)  # drift score

    def analyze(self, session_id: str, messages: list[dict]) -> ThreatResult:
        session = self._get_session(session_id)
        session.turn_count += 1
        session.last_updated = time.time()

        text = self._extract_last_user_message(messages)
        full_text = " ".join(
            (m.get("content", "") if isinstance(m.get("content"), str) else "")
            for m in messages
        )

        triggered_rules = []
        rule_scores = []
        highest_stage = 0
        block_reasons = []

        # ── Pattern matching ──────────────────────────────────────────────
        for pattern, score, stage_idx, rule_name, description in RULES:
            if re.search(pattern, text, re.IGNORECASE):
                triggered_rules.append(rule_name)
                rule_scores.append(score)
                block_reasons.append(description)
                highest_stage = max(highest_stage, stage_idx)

        # ── Creative mode detection ───────────────────────────────────────
        if CREATIVE_PATTERN.search(full_text):
            session.creative_mode = True
            session.creative_declared = True

        # ── Topic drift (grooming detection) ─────────────────────────────
        drift = self._compute_topic_drift(session, text)
        if drift > 0.7 and session.turn_count > 3:
            drift_score = drift * 0.25
            rule_scores.append(drift_score)
            triggered_rules.append("TOPIC_DRIFT_GROOMING")
            block_reasons.append(
                f"Significant topic drift detected across turns (drift={drift:.2f}) — "
                "possible multi-turn grooming attack building toward a later-stage payload"
            )
            highest_stage = max(highest_stage, 1)

        # ── Compute session threat score (Bayesian-style decay + update) ──
        base_score = 1.0 - math.prod(1.0 - s for s in rule_scores) if rule_scores else 0.0

        # Creative mode reduces score
        if session.creative_mode and "MALICIOUS_PERSONA" not in triggered_rules:
            base_score *= 0.4

        # Score decays over clean turns
        if not triggered_rules:
            session.threat_score = max(0.0, session.threat_score * 0.75)
        else:
            session.suspicious_turns += 1
            # Repeated suspicious behavior escalates score
            escalation = min(1.0, session.suspicious_turns * 0.08)
            session.threat_score = min(1.0, base_score + escalation)

        session.last_topics.append(text[:200])

        # ── Verdict ───────────────────────────────────────────────────────
        score = session.threat_score
        if score >= 0.55 and not session.creative_mode:
            verdict = "BLOCK"
        elif score >= 0.55 and session.creative_mode and highest_stage >= 3:
            verdict = "BLOCK"  # Even creative mode can't excuse exfil/persistence
        elif score >= 0.25:
            verdict = "QUARANTINE"
        else:
            verdict = "ALLOW"

        # Force BLOCK on very high-confidence individual signals
        if any(s >= 0.60 for s in rule_scores):
            verdict = "BLOCK"
            highest_stage = max(highest_stage, 2)

        stage_name = KILL_CHAIN_STAGES[highest_stage]

        primary_reason = None
        if block_reasons:
            primary_reason = block_reasons[0]
            if len(block_reasons) > 1:
                primary_reason += f" [+{len(block_reasons)-1} additional signal(s): {', '.join(triggered_rules[1:])}]"

        return ThreatResult(
            score=round(score, 3),
            stage=stage_name,
            stage_index=highest_stage,
            verdict=verdict,
            triggered_rules=triggered_rules,
            block_reason=primary_reason,
            creative_mode=session.creative_mode,
            session_id=session_id,
        )

    def reset_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]
