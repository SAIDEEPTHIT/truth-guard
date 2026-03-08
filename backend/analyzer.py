"""TruthShield – Text Analysis Module

Heuristic NLP analyzer that scores text for:
  1. Scam keyword presence
  2. Emotional / urgency manipulation
  3. AI-generated content probability
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field

# ── Keyword / phrase banks ─────────────────────────────────────────────────────

SCAM_KEYWORDS: list[str] = [
    "congratulations", "you have been selected", "claim your prize",
    "click here", "verify your account", "suspended", "winner",
    "free gift", "lottery", "inheritance", "wire transfer",
    "nigerian prince", "bank account", "social security",
    "password expired", "confirm your identity", "urgent action",
    "risk-free", "guaranteed", "double your money", "no obligation",
    "exclusive deal", "limited offer", "one-time", "act immediately",
    "million dollars", "beneficiary", "unclaimed funds", "western union",
    "money gram", "send money", "processing fee", "tax refund",
    "irs", "fbi", "court order", "legal action", "arrest warrant",
]

URGENCY_PHRASES: list[str] = [
    "act now", "limited time", "urgent", "immediately", "expires today",
    "don't miss out", "last chance", "hurry", "right away", "deadline",
    "only today", "final notice", "respond immediately", "time sensitive",
    "within 24 hours", "before it's too late", "now or never",
    "offer ends", "hours left", "minutes remaining", "closing soon",
    "once in a lifetime", "while supplies last", "today only",
]

AI_PATTERNS: list[str] = [
    "as an ai", "i cannot", "i'm an ai", "language model",
    "it's important to note", "in conclusion", "it is worth noting",
    "delve into", "moreover", "furthermore", "in the realm of",
    "it's crucial", "comprehensive", "facilitate", "leverage",
    "paradigm", "synergy", "utilize", "multifaceted",
    "groundbreaking", "cutting-edge", "harness the power",
    "in today's world", "navigating the complexities",
    "a testament to", "spearheading", "fostering",
]


@dataclass
class AnalysisResult:
    risk_score: int = 0
    classification: str = "Safe"
    signals: dict = field(default_factory=dict)
    suspicious_phrases: list[str] = field(default_factory=list)
    highlighted_text: str = ""


def _find_matches(text_lower: str, phrases: list[str]) -> list[str]:
    """Return all phrases found in the lowercased text."""
    return [p for p in phrases if p in text_lower]


def _score_from_hits(hits: list[str], weight: int) -> int:
    return min(100, len(hits) * weight)


def _highlight(original_text: str, phrases: list[str]) -> str:
    """Wrap each matched phrase in <mark> tags (case-insensitive)."""
    result = original_text
    for phrase in phrases:
        pattern = re.compile(re.escape(phrase), re.IGNORECASE)
        result = pattern.sub(lambda m: f"<mark>{m.group()}</mark>", result)
    return result


def analyze_text(text: str) -> AnalysisResult:
    """Run heuristic analysis on the supplied text and return scored results."""
    lower = text.lower()

    scam_hits = _find_matches(lower, SCAM_KEYWORDS)
    urgency_hits = _find_matches(lower, URGENCY_PHRASES)
    ai_hits = _find_matches(lower, AI_PATTERNS)

    scam_score = _score_from_hits(scam_hits, 16)
    emo_score = _score_from_hits(urgency_hits, 20)
    ai_score = _score_from_hits(ai_hits, 18)

    risk_score = min(100, round(ai_score * 0.3 + scam_score * 0.4 + emo_score * 0.3))

    if risk_score < 30:
        classification = "Safe"
    elif risk_score < 65:
        classification = "Suspicious"
    else:
        classification = "High Risk"

    all_suspicious = list(set(scam_hits + urgency_hits + ai_hits))
    highlighted_text = _highlight(text, all_suspicious)

    return AnalysisResult(
        risk_score=risk_score,
        classification=classification,
        signals={
            "ai_generated": ai_score,
            "scam_keywords": scam_score,
            "emotional_manipulation": emo_score,
        },
        suspicious_phrases=all_suspicious,
        highlighted_text=highlighted_text,
    )
