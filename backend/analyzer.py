"""TruthShield – Enhanced Text & Image Analysis Module v4.0

Primary engine: Azure OpenAI GPT-4 / GPT-4o (LLM-based zero-shot classification)
Fallback engine: Weighted keyword heuristics + stylometric analysis

Environment variables (see .env.example):
  AZURE_OPENAI_ENDPOINT       – e.g. https://<resource>.openai.azure.com/
  AZURE_OPENAI_KEY            – API key
  AZURE_OPENAI_DEPLOYMENT_NAME – deployment name (e.g. gpt-4o)
"""

from __future__ import annotations
import re
import os
import json
import math
import base64
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional

# Load .env if present (no-op when env vars are already set)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

# ── Azure OpenAI client (initialised lazily) ─────────────────────────────────

_openai_client = None
_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "gpt-4o")


def _get_client():
    """Return a cached AzureOpenAI client, or None if credentials are missing."""
    global _openai_client
    if _openai_client is not None:
        return _openai_client

    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    key = os.getenv("AZURE_OPENAI_KEY")

    if not endpoint or not key:
        logger.warning(
            "Azure OpenAI credentials not set. "
            "Set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_KEY to enable GPT-4 analysis. "
            "Falling back to keyword-based heuristics."
        )
        return None

    try:
        from openai import AzureOpenAI
        _openai_client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=key,
            api_version="2024-02-01",
        )
        return _openai_client
    except Exception as exc:
        logger.error("Failed to initialise Azure OpenAI client: %s", exc)
        return None

# ── Keyword banks ────────────────────────────────────────────────────────────

SCAM_KEYWORDS: list[dict] = [
    {"phrase": "congratulations", "reason": "Unsolicited congratulations are a classic phishing opener.", "severity": "medium"},
    {"phrase": "you have been selected", "reason": "False selection claims make victims feel special.", "severity": "high"},
    {"phrase": "claim your prize", "reason": "Prize claims from unknown sources are scams.", "severity": "high"},
    {"phrase": "click here", "reason": "Vague links often lead to phishing sites.", "severity": "medium"},
    {"phrase": "verify your account", "reason": "Legitimate services rarely ask this via messages.", "severity": "high"},
    {"phrase": "suspended", "reason": "Account suspension threats create panic.", "severity": "high"},
    {"phrase": "winner", "reason": "Unsolicited winner notifications are scam tactics.", "severity": "medium"},
    {"phrase": "free gift", "reason": "Nothing is truly free — aims to collect your data.", "severity": "medium"},
    {"phrase": "lottery", "reason": "You cannot win a lottery you never entered.", "severity": "high"},
    {"phrase": "inheritance", "reason": "Fake inheritance scams trick victims into paying fees.", "severity": "high"},
    {"phrase": "wire transfer", "reason": "Wire transfers are nearly impossible to reverse.", "severity": "high"},
    {"phrase": "nigerian prince", "reason": "Classic advance-fee fraud scheme.", "severity": "high"},
    {"phrase": "bank account", "reason": "Bank details in unsolicited messages indicate fraud.", "severity": "high"},
    {"phrase": "social security", "reason": "No legitimate organization asks for SSN via email.", "severity": "high"},
    {"phrase": "password expired", "reason": "Fake password notices steal login credentials.", "severity": "high"},
    {"phrase": "confirm your identity", "reason": "Identity requests in unsolicited messages = phishing.", "severity": "high"},
    {"phrase": "urgent action", "reason": "Artificial urgency bypasses critical thinking.", "severity": "high"},
    {"phrase": "risk-free", "reason": "No offer is truly risk-free.", "severity": "medium"},
    {"phrase": "guaranteed", "reason": "Guaranteed returns in unsolicited offers = fraud.", "severity": "medium"},
    {"phrase": "double your money", "reason": "Hallmark of Ponzi schemes.", "severity": "high"},
    {"phrase": "no obligation", "reason": "Used to lower resistance before trapping victims.", "severity": "low"},
    {"phrase": "exclusive deal", "reason": "Fake exclusivity creates pressure.", "severity": "medium"},
    {"phrase": "limited offer", "reason": "Artificial scarcity prevents rational decisions.", "severity": "medium"},
    {"phrase": "act immediately", "reason": "Pressure prevents verification.", "severity": "high"},
    {"phrase": "million dollars", "reason": "Unrealistic monetary promises = fraud.", "severity": "high"},
    {"phrase": "beneficiary", "reason": "Being named beneficiary by strangers = advance-fee scam.", "severity": "high"},
    {"phrase": "unclaimed funds", "reason": "Unclaimed fund notifications from unknowns = fraud.", "severity": "high"},
    {"phrase": "western union", "reason": "Untraceable payment method favored by scammers.", "severity": "high"},
    {"phrase": "money gram", "reason": "Similar to Western Union, untraceable.", "severity": "high"},
    {"phrase": "send money", "reason": "Requests to send money to strangers = fraud.", "severity": "high"},
    {"phrase": "processing fee", "reason": "Legitimate prizes never require upfront fees.", "severity": "high"},
    {"phrase": "tax refund", "reason": "Tax authorities use official channels only.", "severity": "high"},
    {"phrase": "irs", "reason": "The IRS never contacts via email.", "severity": "high"},
    {"phrase": "fbi", "reason": "Law enforcement doesn't email for money.", "severity": "high"},
    {"phrase": "court order", "reason": "Real court orders are served in person.", "severity": "high"},
    {"phrase": "legal action", "reason": "Legal threats via email = fear tactics.", "severity": "high"},
    {"phrase": "arrest warrant", "reason": "Law enforcement doesn't issue warrants via email.", "severity": "high"},
]

URGENCY_PHRASES: list[dict] = [
    {"phrase": "act now", "reason": "Creates false urgency.", "severity": "high"},
    {"phrase": "limited time", "reason": "Artificial time pressure.", "severity": "medium"},
    {"phrase": "urgent", "reason": "Urgency bypasses critical thinking.", "severity": "medium"},
    {"phrase": "immediately", "reason": "Demands for immediate action prevent fact-checking.", "severity": "medium"},
    {"phrase": "expires today", "reason": "Fake expiration dates create panic.", "severity": "high"},
    {"phrase": "don't miss out", "reason": "FOMO is a manipulation tactic.", "severity": "medium"},
    {"phrase": "last chance", "reason": "False finality prevents evaluation.", "severity": "high"},
    {"phrase": "hurry", "reason": "Rushing prevents consulting others.", "severity": "medium"},
    {"phrase": "right away", "reason": "Immediacy demands bypass caution.", "severity": "medium"},
    {"phrase": "deadline", "reason": "Artificial deadlines create pressure.", "severity": "medium"},
    {"phrase": "only today", "reason": "False time constraints manipulate decisions.", "severity": "high"},
    {"phrase": "final notice", "reason": "Fake final notices create fear.", "severity": "high"},
    {"phrase": "respond immediately", "reason": "Demands for immediate response prevent verification.", "severity": "high"},
    {"phrase": "time sensitive", "reason": "Labeling as time-sensitive creates urgency.", "severity": "medium"},
    {"phrase": "within 24 hours", "reason": "Short deadlines prevent verification.", "severity": "high"},
    {"phrase": "before it's too late", "reason": "Fear-based language triggers impulsive action.", "severity": "high"},
    {"phrase": "now or never", "reason": "False ultimatum to force action.", "severity": "high"},
    {"phrase": "offer ends", "reason": "Fake offer expiration.", "severity": "medium"},
    {"phrase": "hours left", "reason": "Countdown language creates panic.", "severity": "high"},
    {"phrase": "minutes remaining", "reason": "Extreme time pressure.", "severity": "high"},
    {"phrase": "today only", "reason": "False time limit prevents research.", "severity": "high"},
]

AI_PATTERNS: list[dict] = [
    {"phrase": "as an ai", "reason": "Direct AI self-identification.", "severity": "high"},
    {"phrase": "i cannot", "reason": "AI refusal pattern.", "severity": "low"},
    {"phrase": "i'm an ai", "reason": "Direct AI self-identification.", "severity": "high"},
    {"phrase": "language model", "reason": "Technical AI terminology.", "severity": "high"},
    {"phrase": "it's important to note", "reason": "Formulaic AI hedging.", "severity": "medium"},
    {"phrase": "in conclusion", "reason": "Overly structured conclusion marker.", "severity": "low"},
    {"phrase": "it is worth noting", "reason": "AI-style hedging language.", "severity": "medium"},
    {"phrase": "delve into", "reason": "Overrepresented in AI content.", "severity": "medium"},
    {"phrase": "moreover", "reason": "Formal connector overused by AI.", "severity": "low"},
    {"phrase": "furthermore", "reason": "Disproportionately used by language models.", "severity": "low"},
    {"phrase": "in the realm of", "reason": "Formulaic AI phrase.", "severity": "medium"},
    {"phrase": "it's crucial", "reason": "AI emphasis pattern.", "severity": "low"},
    {"phrase": "comprehensive", "reason": "AI models overuse this descriptor.", "severity": "low"},
    {"phrase": "facilitate", "reason": "Formal verb overrepresented in AI output.", "severity": "low"},
    {"phrase": "leverage", "reason": "Corporate/AI buzzword.", "severity": "low"},
    {"phrase": "paradigm", "reason": "Overused in AI content.", "severity": "medium"},
    {"phrase": "synergy", "reason": "Corporate buzzword favored by AI.", "severity": "low"},
    {"phrase": "utilize", "reason": "AI prefers 'utilize' over simpler 'use'.", "severity": "low"},
    {"phrase": "multifaceted", "reason": "Overrepresented in AI writing.", "severity": "medium"},
    {"phrase": "groundbreaking", "reason": "Hyperbolic adjective common in AI.", "severity": "low"},
    {"phrase": "cutting-edge", "reason": "Buzzword overused by AI.", "severity": "low"},
    {"phrase": "harness the power", "reason": "Formulaic AI phrase.", "severity": "medium"},
    {"phrase": "in today's world", "reason": "Generic AI opener.", "severity": "medium"},
    {"phrase": "navigating the complexities", "reason": "Abstract AI phrasing.", "severity": "medium"},
    {"phrase": "a testament to", "reason": "Formulaic AI praise pattern.", "severity": "medium"},
    {"phrase": "spearheading", "reason": "Corporate language overrepresented in AI.", "severity": "low"},
    {"phrase": "fostering", "reason": "Abstract verb favored by language models.", "severity": "low"},
]

INDIA_SCAM_PATTERNS: list[dict] = [
    {"phrase": "kyc update", "reason": "Fake KYC requests steal Aadhaar/PAN details.", "severity": "high"},
    {"phrase": "aadhaar", "reason": "Aadhaar requests in messages = identity theft.", "severity": "high"},
    {"phrase": "pan card", "reason": "PAN requests via messages = tax fraud.", "severity": "high"},
    {"phrase": "upi", "reason": "UPI scams trick users into unauthorized transactions.", "severity": "high"},
    {"phrase": "paytm", "reason": "Fake Paytm messages for payment fraud.", "severity": "medium"},
    {"phrase": "phonepe", "reason": "PhonePe impersonation in Indian scams.", "severity": "medium"},
    {"phrase": "google pay", "reason": "Google Pay scams trick users into sending money.", "severity": "medium"},
    {"phrase": "rbi", "reason": "RBI impersonation in banking fraud.", "severity": "high"},
    {"phrase": "income tax", "reason": "Fake income tax notices for phishing.", "severity": "high"},
    {"phrase": "crore", "reason": "Promises of crores = lottery/investment scam.", "severity": "high"},
    {"phrase": "lakh", "reason": "False promises of lakhs = common scam.", "severity": "medium"},
    {"phrase": "sbi", "reason": "SBI impersonation = common banking scam.", "severity": "high"},
    {"phrase": "hdfc", "reason": "HDFC Bank impersonation for phishing.", "severity": "high"},
    {"phrase": "icici", "reason": "ICICI Bank impersonation for credential theft.", "severity": "high"},
    {"phrase": "otp", "reason": "OTP sharing = #1 digital fraud method in India.", "severity": "high"},
    {"phrase": "share otp", "reason": "No legitimate service asks to share OTP.", "severity": "high"},
    {"phrase": "debit card blocked", "reason": "Fake card blocking alerts steal details.", "severity": "high"},
    {"phrase": "credit card blocked", "reason": "Fake card blocking alerts for credential phishing.", "severity": "high"},
    {"phrase": "job offer", "reason": "Unsolicited job offers via WhatsApp = fraud.", "severity": "medium"},
    {"phrase": "work from home", "reason": "Fake work-from-home offers are rising.", "severity": "medium"},
    {"phrase": "telegram channel", "reason": "Telegram-based task scams are widespread.", "severity": "medium"},
    {"phrase": "customs duty", "reason": "Fake customs duty = parcel delivery scam.", "severity": "high"},
    {"phrase": "electricity bill", "reason": "Fake disconnection threats = payment fraud.", "severity": "high"},
]

FINANCIAL_PHRASES = [
    "bank account", "wire transfer", "send money", "processing fee", "credit card",
    "debit card", "social security", "western union", "money gram", "bitcoin",
    "cryptocurrency", "investment opportunity", "double your money", "gift card",
    "upi", "paytm", "phonepe", "google pay", "sbi", "hdfc", "icici",
    "aadhaar", "pan card", "otp", "share otp", "kyc update",
]

SCAM_WEIGHT = 15
URGENCY_WEIGHT = 10
FINANCIAL_WEIGHT = 20
LINK_WEIGHT = 25


# ── Data classes ──

@dataclass
class Explanation:
    category: str
    phrase: str
    reason: str
    severity: str


@dataclass
class AnalysisResult:
    risk_score: int = 0
    classification: str = "Safe"
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


# ── Helper functions ──

def _find_matches(text_lower: str, bank: list[dict], category: str):
    hits = []
    explanations = []
    for item in bank:
        if item["phrase"] in text_lower:
            hits.append(item["phrase"])
            explanations.append({
                "category": category,
                "phrase": item["phrase"],
                "reason": item["reason"],
                "severity": item["severity"],
            })
    return hits, explanations


def _highlight(original_text: str, phrases: list[str]) -> str:
    result = original_text
    for phrase in phrases:
        pattern = re.compile(re.escape(phrase), re.IGNORECASE)
        result = pattern.sub(lambda m: f"<mark>{m.group()}</mark>", result)
    return result


def _stylometric_analysis(text: str) -> tuple[int, list[dict]]:
    score = 0
    indicators = []

    sentences = [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]
    if len(sentences) >= 3:
        lengths = [len(s.split()) for s in sentences]
        avg_len = sum(lengths) / len(lengths)
        variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)
        std_dev = math.sqrt(variance)

        if std_dev < 3 and len(sentences) > 4:
            score += 15
            indicators.append({"category": "ai", "phrase": "(stylometric)", "reason": "Unusually uniform sentence length.", "severity": "medium"})

        if 14 < avg_len < 26:
            score += 8
            indicators.append({"category": "ai", "phrase": "(stylometric)", "reason": "Average sentence length in AI-typical range.", "severity": "low"})

    hedges = ["however", "nevertheless", "nonetheless", "on the other hand", "that being said", "it should be noted"]
    if sum(1 for h in hedges if h in text.lower()) >= 3:
        score += 10
        indicators.append({"category": "ai", "phrase": "(stylometric)", "reason": "Excessive hedging language.", "severity": "medium"})

    words = text.split()
    contractions = len(re.findall(r"\b\w+'\w+\b", text))
    if len(words) > 50 and (contractions / len(words)) < 0.005:
        score += 8
        indicators.append({"category": "ai", "phrase": "(stylometric)", "reason": "Very few contractions — overly formal.", "severity": "low"})

    return min(40, score), indicators


def _generate_summary(classification: str, signals: dict, explanations: list[dict]) -> str:
    if classification == "Safe":
        return "This content appears safe. No significant indicators detected."

    parts = []
    if signals.get("scam_keywords", 0) > 30: parts.append("scam keywords")
    if signals.get("ai_generated", 0) > 30: parts.append("AI-generated patterns")
    if signals.get("emotional_manipulation", 0) > 30: parts.append("emotional manipulation")
    india_hits = [e for e in explanations if e.get("category") == "india_scam"]
    if india_hits: parts.append("India-specific fraud patterns")

    high_count = sum(1 for e in explanations if e.get("severity") == "high")

    if classification == "High Risk":
        return f"⚠️ HIGH RISK: Contains {', '.join(parts)}. {high_count} high-severity indicators. Do NOT share info or transfer money."
    return f"⚡ SUSPICIOUS: Shows signs of {', '.join(parts)}. Verify source before acting."


def _generate_tips(classification: str, explanations: list[dict]) -> list[str]:
    tips = []
    if classification == "Safe":
        tips.append("Always stay vigilant.")
        return tips

    categories = set(e.get("category", "") for e in explanations)
    if "scam" in categories or "india_scam" in categories:
        tips.append("Never share personal info (Aadhaar, PAN, OTP) via messages.")
        tips.append("Verify sender through official channels.")
        tips.append("Do not click links in suspicious messages.")
    if "urgency" in categories:
        tips.append("Legitimate orgs don't create artificial urgency.")
    if "ai" in categories:
        tips.append("Cross-check AI-generated claims with reliable sources.")
    tips.append("When in doubt, consult a trusted person.")
    return tips[:5]


# ── GPT-4 Text Analysis ──

_TEXT_SYSTEM_PROMPT = """You are TruthGuard, an expert cybersecurity AI specialising in detecting scams, phishing, AI-generated text, emotional manipulation, and India-specific digital fraud (UPI, KYC, Aadhaar, OTP scams, etc.).

Analyse the user-provided text and return ONLY a valid JSON object (no markdown, no prose) with exactly this structure:

{
  "risk_score": <integer 0-100>,
  "classification": "<Safe|Suspicious|High Risk>",
  "signals": {
    "ai_generated": <integer 0-100>,
    "scam_keywords": <integer 0-100>,
    "emotional_manipulation": <integer 0-100>
  },
  "suspicious_phrases": [<list of suspicious phrases found verbatim in the text>],
  "highlighted_text": "<full original text with suspicious spans wrapped in <mark>…</mark>>",
  "explanations": [
    {"category": "<scam|urgency|ai|india_scam>", "phrase": "<phrase>", "reason": "<why it is suspicious>", "severity": "<low|medium|high>"}
  ],
  "summary": "<1–2 sentence human-readable summary>",
  "tips": [<list of 2–5 actionable safety tips relevant to this text>]
}

Scoring guide:
- risk_score 0-30 → Safe, 31-60 → Suspicious, 61-100 → High Risk
- signals values are independent sub-scores (0-100 each)
- For India-specific patterns (Aadhaar, PAN, OTP, UPI, KYC, SBI, HDFC, ICICI, RBI, crore, lakh) use category "india_scam"
- Keep suspicious_phrases as exact substrings from the input text
- highlighted_text must be the FULL original text, only adding <mark> tags around suspicious parts"""


def _gpt_analyze_text(text: str) -> Optional[AnalysisResult]:
    """Call Azure OpenAI to analyse text. Returns None on any failure."""
    client = _get_client()
    if client is None:
        return None

    try:
        response = client.chat.completions.create(
            model=_DEPLOYMENT,
            messages=[
                {"role": "system", "content": _TEXT_SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            temperature=0.1,
            max_tokens=1500,
            response_format={"type": "json_object"},
        )

        raw = response.choices[0].message.content or ""
        data = json.loads(raw)

        signals = data.get("signals", {})
        if not isinstance(signals, dict):
            signals = {}
        signals.setdefault("ai_generated", 0)
        signals.setdefault("scam_keywords", 0)
        signals.setdefault("emotional_manipulation", 0)

        return AnalysisResult(
            risk_score=int(data.get("risk_score", 0)),
            classification=data.get("classification", "Safe"),
            signals=signals,
            suspicious_phrases=data.get("suspicious_phrases", []) if isinstance(data.get("suspicious_phrases"), list) else [],
            highlighted_text=data.get("highlighted_text", text) if isinstance(data.get("highlighted_text"), str) else text,
            explanations=data.get("explanations", []) if isinstance(data.get("explanations"), list) else [],
            summary=data.get("summary", "") if isinstance(data.get("summary"), str) else "",
            tips=data.get("tips", []) if isinstance(data.get("tips"), list) else [],
        )
    except Exception as exc:
        logger.error("GPT text analysis failed: %s", exc)
        return None


# ── GPT-4o Image Analysis ──

_IMAGE_SYSTEM_PROMPT = """You are TruthGuard Vision, an expert in detecting AI-generated images (DALL-E, Midjourney, Stable Diffusion, etc.) and manipulated media.

Analyse the provided image and return ONLY a valid JSON object (no markdown, no prose) with exactly this structure:

{
  "ai_generated_probability": <float 0.0-1.0>,
  "risk_score": <integer 0-100>,
  "classification": "<Likely Authentic|Possibly AI-Generated|Likely AI-Generated>",
  "explanation": [
    {"signal": "<observation>", "weight": <integer, positive=towards AI, negative=towards authentic>, "type": "<positive|negative>"}
  ],
  "metadata": {"notes": "<brief technical notes>"},
  "tips": [<list of 2–4 actionable tips for the user>]
}

Classification guide:
- ai_generated_probability 0.0–0.25 → Likely Authentic
- 0.26–0.60 → Possibly AI-Generated
- 0.61–1.0 → Likely AI-Generated

Look for: unnatural skin textures, impossible anatomy (extra fingers, distorted ears), unrealistic lighting, floating objects, garbled text, overly smooth backgrounds, watermarks from AI tools, and other tell-tale signs."""


def _gpt_analyze_image(image_data: bytes, content_type: str) -> Optional[ImageAnalysisResult]:
    """Call Azure OpenAI GPT-4o Vision to analyse an image. Returns None on any failure."""
    client = _get_client()
    if client is None:
        return None

    # GPT-4o vision requires base64 data URL
    b64 = base64.b64encode(image_data).decode("utf-8")
    mime = content_type if content_type else "image/jpeg"
    data_url = f"data:{mime};base64,{b64}"

    try:
        response = client.chat.completions.create(
            model=_DEPLOYMENT,
            messages=[
                {"role": "system", "content": _IMAGE_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {"type": "image_url", "image_url": {"url": data_url}},
                        {"type": "text", "text": "Analyse this image for AI-generation indicators."},
                    ],
                },
            ],
            temperature=0.1,
            max_tokens=800,
            response_format={"type": "json_object"},
        )

        raw = response.choices[0].message.content or ""
        data = json.loads(raw)

        prob = float(data.get("ai_generated_probability", 0.0))
        risk = int(data.get("risk_score", int(prob * 100)))

        return ImageAnalysisResult(
            ai_generated_probability=prob,
            classification=data.get("classification", "Likely Authentic"),
            explanation=data.get("explanation", []),
            risk_score=risk,
            metadata=data.get("metadata", {}),
            tips=data.get("tips", []),
        )
    except Exception as exc:
        logger.error("GPT image analysis failed: %s", exc)
        return None


# ── Main Text Analysis ──

def analyze_text(text: str) -> AnalysisResult:
    """Analyse text using Azure OpenAI GPT-4 (with keyword-heuristic fallback)."""
    # Primary: GPT-4
    result = _gpt_analyze_text(text)
    if result is not None:
        return result

    # Fallback: keyword-based heuristics
    return _heuristic_analyze_text(text)


def _heuristic_analyze_text(text: str) -> AnalysisResult:
    lower = text.lower()

    scam_hits, scam_expl = _find_matches(lower, SCAM_KEYWORDS, "scam")
    urgency_hits, urgency_expl = _find_matches(lower, URGENCY_PHRASES, "urgency")
    ai_hits, ai_expl = _find_matches(lower, AI_PATTERNS, "ai")
    india_hits, india_expl = _find_matches(lower, INDIA_SCAM_PATTERNS, "india_scam")

    # Weighted scoring
    all_scam_hits = scam_hits + india_hits
    financial_hits = [h for h in all_scam_hits if h in FINANCIAL_PHRASES]
    regular_scam_hits = [h for h in all_scam_hits if h not in FINANCIAL_PHRASES]

    scam_points = len(regular_scam_hits) * SCAM_WEIGHT + len(financial_hits) * FINANCIAL_WEIGHT
    urgency_points = len(urgency_hits) * URGENCY_WEIGHT

    stylo_score, stylo_indicators = _stylometric_analysis(text)
    ai_base = min(100, len(ai_hits) * 16)
    ai_score = min(100, ai_base + stylo_score)

    raw_score = scam_points + urgency_points + round(ai_score * 0.3)
    risk_score = max(0, min(100, raw_score))

    scam_signal = min(100, scam_points)
    emo_signal = min(100, urgency_points)

    if risk_score <= 30:
        classification = "Safe"
    elif risk_score <= 60:
        classification = "Suspicious"
    else:
        classification = "High Risk"

    all_phrases = list(set(scam_hits + urgency_hits + ai_hits + india_hits))
    all_explanations = scam_expl + urgency_expl + ai_expl + india_expl + stylo_indicators

    signals = {
        "ai_generated": ai_score,
        "scam_keywords": scam_signal,
        "emotional_manipulation": emo_signal,
    }

    return AnalysisResult(
        risk_score=risk_score,
        classification=classification,
        signals=signals,
        suspicious_phrases=all_phrases,
        highlighted_text=_highlight(text, all_phrases),
        explanations=all_explanations,
        summary=_generate_summary(classification, signals, all_explanations),
        tips=_generate_tips(classification, all_explanations),
    )


# ── Image Analysis ──

def analyze_image(image_data: bytes, filename: str = "", content_type: str = "") -> ImageAnalysisResult:
    """Analyse an image using Azure OpenAI GPT-4o Vision (with heuristic fallback)."""
    # Primary: GPT-4o Vision
    result = _gpt_analyze_image(image_data, content_type)
    if result is not None:
        # Enrich metadata with file info that GPT doesn't see
        result.metadata["file_size"] = f"{len(image_data) / 1024:.1f} KB"
        result.metadata["content_type"] = content_type or "unknown"
        width, height = _get_image_dimensions(image_data, content_type)
        if width and height:
            result.metadata["dimensions"] = f"{width} × {height}"
        return result

    # Fallback: byte-level heuristics
    return _heuristic_analyze_image(image_data, filename, content_type)


def _heuristic_analyze_image(image_data: bytes, filename: str = "", content_type: str = "") -> ImageAnalysisResult:
    """Analyze image bytes for AI-generation indicators using heuristics."""
    indicators = []
    score = 0
    metadata = {}

    metadata["file_size"] = f"{len(image_data) / 1024:.1f} KB"
    metadata["content_type"] = content_type or "unknown"

    # 1. File size heuristics
    if len(image_data) > 5 * 1024 * 1024:
        score -= 5
        indicators.append({"signal": "Large file size — uncommon for AI", "weight": -5, "type": "positive"})
    elif len(image_data) < 200 * 1024 and "jpeg" in content_type:
        score += 8
        indicators.append({"signal": "Small JPEG — AI outputs are often compressed", "weight": 8, "type": "negative"})

    if "png" in content_type:
        score += 5
        indicators.append({"signal": "PNG format — commonly used by AI generators", "weight": 5, "type": "negative"})
    if "webp" in content_type:
        score += 5
        indicators.append({"signal": "WebP format — often used in AI pipelines", "weight": 5, "type": "negative"})

    # 2. EXIF check (look for 0xFFE1 marker in JPEG)
    has_exif = False
    for i in range(min(len(image_data) - 1, 65536)):
        if image_data[i] == 0xFF and image_data[i + 1] == 0xE1:
            has_exif = True
            break

    if not has_exif:
        score += 15
        indicators.append({"signal": "No EXIF metadata — AI images lack camera data", "weight": 15, "type": "negative"})
    else:
        score -= 15
        indicators.append({"signal": "EXIF metadata present — suggests real camera", "weight": -15, "type": "positive"})

    # 3. Dimension analysis (try to read from image header)
    width, height = _get_image_dimensions(image_data, content_type)
    if width and height:
        metadata["dimensions"] = f"{width} × {height}"

        common_ai_dims = [
            (512, 512), (768, 768), (1024, 1024), (1024, 768), (768, 1024),
            (1920, 1080), (1080, 1920), (1344, 768), (768, 1344),
            (2048, 2048), (1536, 1536), (896, 1152), (1152, 896),
            (2048, 1024), (1024, 2048), (1792, 1024), (1024, 1792),
        ]
        if (width, height) in common_ai_dims:
            score += 18
            indicators.append({"signal": f"Dimensions ({width}×{height}) match AI generator sizes", "weight": 18, "type": "negative"})

        if width % 64 == 0 and height % 64 == 0 and (width, height) not in common_ai_dims:
            score += 10
            indicators.append({"signal": "Dimensions are multiples of 64 — AI model alignment", "weight": 10, "type": "negative"})

        if width == height and width >= 512:
            score += 8
            indicators.append({"signal": "Perfect square aspect ratio — common in AI images", "weight": 8, "type": "negative"})

    # 4. Filename analysis
    ai_patterns = re.compile(r'\b(dalle|dall-e|midjourney|stable.?diffusion|sd_|sdxl|comfyui|generated|ai_|ai-|deepfake|flux|leonardo|firefly|imagen)\b', re.IGNORECASE)
    if ai_patterns.search(filename):
        score += 25
        indicators.append({"signal": "Filename contains AI tool references", "weight": 25, "type": "negative"})

    if re.match(r'^(image|download|IMG)[\s_-]?\d{3,}', filename, re.IGNORECASE):
        score += 5
        indicators.append({"signal": "Generic filename — common from AI platforms", "weight": 5, "type": "negative"})

    # 5. Byte-level analysis (compression patterns)
    # Check for unusually uniform byte distribution (AI images tend to be smoother)
    if len(image_data) > 1000:
        sample = image_data[100:min(len(image_data), 10100)]
        byte_hist = [0] * 256
        for b in sample:
            byte_hist[b] += 1
        max_freq = max(byte_hist)
        min_freq = min(b for b in byte_hist if b > 0) if any(b > 0 for b in byte_hist) else 0
        if max_freq > 0 and min_freq > 0:
            uniformity = min_freq / max_freq
            if uniformity > 0.3:
                score += 8
                indicators.append({"signal": "Uniform byte distribution — may indicate AI generation", "weight": 8, "type": "negative"})

    # Clamp
    score = max(0, min(100, score))

    if score <= 25:
        classification = "Likely Authentic"
    elif score <= 50:
        classification = "Possibly AI-Generated"
    else:
        classification = "Likely AI-Generated"

    tips = []
    if score > 25:
        tips.append("Use Google Reverse Image Search to verify origin.")
        tips.append("Zoom in: check fingers, earrings, text, backgrounds.")
        tips.append("Check source credibility.")
        tips.append("Look for inconsistent lighting and shadows.")
    tips.append("AI detection is probabilistic — no tool is 100% accurate.")

    return ImageAnalysisResult(
        ai_generated_probability=score / 100.0,
        classification=classification,
        explanation=indicators,
        risk_score=score,
        metadata=metadata,
        tips=tips,
    )


def _get_image_dimensions(data: bytes, content_type: str) -> tuple[Optional[int], Optional[int]]:
    """Try to extract image dimensions from binary data."""
    try:
        # PNG: bytes 16-23 contain width and height as 4-byte big-endian
        if data[:4] == b'\x89PNG':
            width = struct.unpack('>I', data[16:20])[0]
            height = struct.unpack('>I', data[20:24])[0]
            return width, height

        # JPEG: scan for SOF markers
        if data[:2] == b'\xff\xd8':
            i = 2
            while i < len(data) - 9:
                if data[i] == 0xFF:
                    marker = data[i + 1]
                    if marker in (0xC0, 0xC1, 0xC2):
                        height = struct.unpack('>H', data[i + 5:i + 7])[0]
                        width = struct.unpack('>H', data[i + 7:i + 9])[0]
                        return width, height
                    elif marker == 0xD9:
                        break
                    else:
                        length = struct.unpack('>H', data[i + 2:i + 4])[0]
                        i += 2 + length
                else:
                    i += 1

        # WebP
        if data[:4] == b'RIFF' and data[8:12] == b'WEBP':
            if data[12:16] == b'VP8 ':
                width = struct.unpack('<H', data[26:28])[0] & 0x3FFF
                height = struct.unpack('<H', data[28:30])[0] & 0x3FFF
                return width, height

    except Exception:
        pass
    return None, None
