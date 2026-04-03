"""TruthShield – OpenAI-Powered Analysis Module v4.0

Primary engine: OpenAI GPT-4o-mini (structured JSON classification)
Fallback engine: Rule-based keyword heuristics (offline / quota-exceeded)

Environment variables:
  OPENAI_API_KEY – API key from https://platform.openai.com/api-keys
"""

from __future__ import annotations
import re
import os
import json
import math
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

# ── OpenAI client (lazy init) ────────────────────────────────────────────────

_openai_client = None


def _get_openai_client():
    global _openai_client
    if _openai_client is not None:
        return _openai_client
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        logger.warning("OPENAI_API_KEY not set – falling back to heuristic engine.")
        return None
    try:
        from openai import OpenAI
        _openai_client = OpenAI(api_key=api_key)
        return _openai_client
    except Exception as exc:
        logger.error("Failed to init OpenAI client: %s", exc)
        return None


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    risk_score: int = 0
    classification: str = "Safe"
    scam_type: str = "Safe"
    emotional_manipulation: bool = False
    signals: dict = field(default_factory=dict)
    suspicious_phrases: list[str] = field(default_factory=list)
    highlighted_text: str = ""
    explanations: list[dict] = field(default_factory=list)
    summary: str = ""
    tips: list[str] = field(default_factory=list)


@dataclass
class ImageAnalysisResult:
    ai_generated_probability: float = 0.0
    classification: str = "Likely Authentic"
    explanation: list[dict] = field(default_factory=list)
    risk_score: int = 0
    metadata: dict = field(default_factory=dict)
    tips: list[str] = field(default_factory=list)


# ── OpenAI prompt ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an advanced cybersecurity AI specialized in detecting scams, phishing, fraud, and manipulation, especially for Indian users.

STRICT RULES:
- Any job offer asking for payment = HIGH RISK (score > 80)
- Any bank verification link = HIGH RISK
- Any urgent message threatening loss = HIGH RISK
- Messages asking for OTP/payment/personal info = HIGH RISK
- Lottery/prize/inheritance scams = HIGH RISK (score > 85)
- Safe professional/business content = LOW RISK (score < 25)
- Mildly promotional but legitimate content = score 20-40

Analyze the text and return STRICT JSON (no markdown, no explanation outside JSON):
{
  "risk_score": <number 0-100>,
  "classification": "Safe" | "Suspicious" | "High Risk",
  "scam_type": "Phishing" | "Job Scam" | "Financial Fraud" | "Misinformation" | "AI Generated" | "Safe",
  "emotional_manipulation": <boolean>,
  "ai_generated_probability": <number 0-100>,
  "suspicious_phrases": [<list of exact suspicious phrases found>],
  "explanation": "<clear short explanation of why this is safe or dangerous>",
  "tips": [<1-3 actionable safety tips>]
}"""


def _call_openai(text: str) -> Optional[dict]:
    """Call OpenAI GPT-4o-mini and return parsed JSON, or None on failure."""
    client = _get_openai_client()
    if client is None:
        return None
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this text:\n\n{text[:8000]}"},
            ],
            temperature=0.1,
            max_tokens=1000,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        if content:
            return json.loads(content)
        return None
    except Exception as exc:
        logger.error("OpenAI API error: %s", exc)
        return None


# ── Rule-based overrides ─────────────────────────────────────────────────────

def _apply_rule_overrides(text: str, result: dict) -> dict:
    """Apply deterministic rule overrides to ensure obvious scams score high."""
    lower = text.lower()

    rules = [
        # Job scam: payment + job
        (["pay", "fee", "₹", "rs."] , ["job", "offer", "hiring", "vacancy", "salary"], "Job Scam", 82),
        # Bank phishing: bank + verify + click/link
        (["bank", "sbi", "hdfc", "icici"], ["verify", "click", "link", "update"], "Phishing", 85),
        # OTP/KYC theft
        (["otp", "share otp", "kyc update"], ["aadhaar", "pan card", "blocked", "deactivate"], "Phishing", 88),
        # Lottery/prize
        (["lottery", "winner", "prize", "congratulations"], ["claim", "selected", "million"], "Financial Fraud", 87),
        # Wire/payment demand
        (["wire transfer", "processing fee", "send money", "western union"], [], "Financial Fraud", 80),
        # Urgency + financial
        (["immediately", "urgent", "within 24 hours", "act now"], ["pay", "transfer", "send", "₹", "bank"], "Financial Fraud", 78),
    ]

    for group_a, group_b, scam_type, min_score in rules:
        has_a = any(kw in lower for kw in group_a)
        has_b = not group_b or any(kw in lower for kw in group_b)
        if has_a and has_b:
            if result.get("risk_score", 0) < min_score:
                result["risk_score"] = min_score
                result["classification"] = "High Risk"
                result["scam_type"] = scam_type
            break

    return result


# ── Highlight helper ─────────────────────────────────────────────────────────

def _highlight(text: str, phrases: list[str]) -> str:
    result = text
    for phrase in phrases:
        pattern = re.compile(re.escape(phrase), re.IGNORECASE)
        result = pattern.sub(lambda m: f"<mark>{m.group()}</mark>", result)
    return result


# ── Fallback heuristic engine ────────────────────────────────────────────────

SCAM_KEYWORDS = [
    "congratulations", "you have been selected", "claim your prize", "click here",
    "verify your account", "suspended", "winner", "lottery", "inheritance",
    "wire transfer", "bank account", "processing fee", "send money",
    "million dollars", "beneficiary", "unclaimed funds", "western union",
    "arrest warrant", "legal action", "double your money", "guaranteed",
    "gift card", "bitcoin", "cryptocurrency",
]

URGENCY_PHRASES = [
    "act now", "limited time", "urgent", "immediately", "expires today",
    "last chance", "final notice", "within 24 hours", "hurry",
    "before it's too late", "now or never", "today only",
]

INDIA_SCAM = [
    "kyc update", "aadhaar", "pan card", "upi", "otp", "share otp",
    "sbi", "hdfc", "icici", "rbi", "debit card blocked",
    "income tax", "paytm", "phonepe", "google pay", "electricity bill",
    "customs duty", "job offer", "work from home",
]

FINANCIAL_PHRASES = [
    "bank account", "wire transfer", "send money", "processing fee",
    "credit card", "debit card", "western union", "bitcoin",
    "upi", "paytm", "otp", "aadhaar", "pan card", "kyc update",
]


def _heuristic_analyze(text: str) -> dict:
    """Keyword-based fallback when OpenAI is unavailable."""
    lower = text.lower()

    def find(bank, cat):
        return [(kw, cat) for kw in bank if kw in lower]

    scam_hits = find(SCAM_KEYWORDS, "scam")
    urgency_hits = find(URGENCY_PHRASES, "urgency")
    india_hits = find(INDIA_SCAM, "india_scam")

    all_phrases = [h[0] for h in scam_hits + urgency_hits + india_hits]
    financial_hits = [p for p in all_phrases if p in FINANCIAL_PHRASES]

    score = len(scam_hits) * 15 + len(urgency_hits) * 10 + len(india_hits) * 18 + len(financial_hits) * 5
    score = max(0, min(100, score))

    classification = "Safe" if score <= 30 else "Suspicious" if score <= 60 else "High Risk"

    scam_type = "Safe"
    if india_hits:
        scam_type = "Phishing"
    elif scam_hits:
        scam_type = "Financial Fraud"

    return {
        "risk_score": score,
        "classification": classification,
        "scam_type": scam_type,
        "emotional_manipulation": len(urgency_hits) >= 2,
        "ai_generated_probability": 0,
        "suspicious_phrases": list(set(all_phrases)),
        "explanation": f"Heuristic analysis found {len(all_phrases)} suspicious indicators.",
        "tips": [
            "Never share personal info via messages.",
            "Verify sender through official channels.",
        ] if score > 30 else ["Stay vigilant."],
    }


# ── Main analysis function ───────────────────────────────────────────────────

def analyze_text(text: str) -> AnalysisResult:
    """Analyze text using OpenAI with heuristic fallback."""
    # Try OpenAI first
    ai_result = _call_openai(text)

    if ai_result is None:
        ai_result = _heuristic_analyze(text)

    # Apply rule-based overrides for accuracy
    ai_result = _apply_rule_overrides(text, ai_result)

    # Build highlighted text
    phrases = ai_result.get("suspicious_phrases", [])
    highlighted = _highlight(text, phrases)

    # Map to signals format (for extension compatibility)
    risk = ai_result.get("risk_score", 0)
    scam_signal = min(100, risk) if ai_result.get("scam_type", "Safe") != "Safe" else max(0, risk - 20)
    emo_signal = 70 if ai_result.get("emotional_manipulation", False) else max(0, risk - 40)
    ai_signal = ai_result.get("ai_generated_probability", 0)

    # Build explanations list (for extension compatibility)
    explanations = []
    for phrase in phrases:
        explanations.append({
            "category": "scam" if ai_result.get("scam_type", "Safe") != "Safe" else "ai",
            "phrase": phrase,
            "reason": f"Flagged by AI analysis as suspicious.",
            "severity": "high" if risk > 60 else "medium" if risk > 30 else "low",
        })

    explanation_text = ai_result.get("explanation", "")
    tips = ai_result.get("tips", [])
    if not tips:
        tips = ["Stay vigilant and verify sources."]

    return AnalysisResult(
        risk_score=ai_result.get("risk_score", 0),
        classification=ai_result.get("classification", "Safe"),
        scam_type=ai_result.get("scam_type", "Safe"),
        emotional_manipulation=ai_result.get("emotional_manipulation", False),
        signals={
            "ai_generated": ai_signal,
            "scam_keywords": scam_signal,
            "emotional_manipulation": emo_signal,
        },
        suspicious_phrases=phrases,
        highlighted_text=highlighted,
        explanations=explanations,
        summary=explanation_text,
        tips=tips,
    )


# ── Image analysis (kept as heuristic) ───────────────────────────────────────

def analyze_image(image_data: bytes, filename: str = "", content_type: str = "") -> ImageAnalysisResult:
    """Heuristic image analysis for AI-generation detection."""
    indicators = []
    score = 0
    metadata = {"filename": filename, "content_type": content_type, "size_bytes": len(image_data)}

    # Check for EXIF data
    has_exif = b"Exif" in image_data[:100]
    if not has_exif:
        score += 20
        indicators.append({"signal": "No EXIF metadata found", "weight": 20, "type": "suspicious"})
    else:
        indicators.append({"signal": "EXIF metadata present", "weight": -10, "type": "authentic"})
        score -= 10

    # Check dimensions (multiples of 64 common in AI)
    if content_type == "image/png" and len(image_data) > 24:
        try:
            w = struct.unpack(">I", image_data[16:20])[0]
            h = struct.unpack(">I", image_data[20:24])[0]
            metadata["width"] = w
            metadata["height"] = h
            if w % 64 == 0 and h % 64 == 0:
                score += 15
                indicators.append({"signal": f"Dimensions {w}×{h} are multiples of 64", "weight": 15, "type": "suspicious"})
        except Exception:
            pass

    # Byte distribution analysis
    if len(image_data) > 1000:
        sample = image_data[:5000]
        unique_bytes = len(set(sample))
        if unique_bytes > 250:
            score += 10
            indicators.append({"signal": "High byte diversity suggests AI generation", "weight": 10, "type": "suspicious"})

    # File size analysis
    size_mb = len(image_data) / (1024 * 1024)
    metadata["size_mb"] = round(size_mb, 2)

    score = max(0, min(100, score))
    prob = score / 100.0

    if prob < 0.3:
        classification = "Likely Authentic"
    elif prob < 0.6:
        classification = "Possibly AI-Generated"
    else:
        classification = "Likely AI-Generated"

    tips = []
    if prob > 0.3:
        tips.append("Reverse image search to verify origin.")
        tips.append("Check for visual artifacts like extra fingers or warped text.")
    tips.append("AI detection is probabilistic — use as one signal among many.")

    return ImageAnalysisResult(
        ai_generated_probability=round(prob, 3),
        classification=classification,
        explanation=indicators,
        risk_score=score,
        metadata=metadata,
        tips=tips,
    )
