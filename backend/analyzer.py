"""TruthShield – Enhanced Text Analysis Module

Multi-factor NLP analyzer with explainable output:
  1. Scam keyword presence (global + India-specific)
  2. Emotional / urgency manipulation
  3. AI-generated content probability (patterns + stylometry)
  4. Per-phrase explanations
  5. Summary and safety tips
"""

from __future__ import annotations
import re
import math
from dataclasses import dataclass, field

# ── Keyword banks with explanations ────────────────────────────────────────────

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


def _score_from_hits(hits: list[str], weight: int) -> int:
    return min(100, len(hits) * weight)


def _highlight(original_text: str, phrases: list[str]) -> str:
    result = original_text
    for phrase in phrases:
        pattern = re.compile(re.escape(phrase), re.IGNORECASE)
        result = pattern.sub(lambda m: f"<mark>{m.group()}</mark>", result)
    return result


def _stylometric_analysis(text: str) -> tuple[int, list[dict]]:
    """Analyze writing style patterns typical of AI-generated content."""
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
            indicators.append({
                "category": "ai",
                "phrase": "(stylometric pattern)",
                "reason": "Unusually uniform sentence length — typical of AI-generated text.",
                "severity": "medium",
            })

        if 14 < avg_len < 26:
            score += 8
            indicators.append({
                "category": "ai",
                "phrase": "(stylometric pattern)",
                "reason": "Average sentence length falls in the AI-typical range (15-25 words).",
                "severity": "low",
            })

    # Excessive hedging
    hedges = ["however", "nevertheless", "nonetheless", "on the other hand", "that being said", "it should be noted"]
    hedge_count = sum(1 for h in hedges if h in text.lower())
    if hedge_count >= 3:
        score += 10
        indicators.append({
            "category": "ai",
            "phrase": "(stylometric pattern)",
            "reason": "Excessive hedging language — characteristic of AI writing style.",
            "severity": "medium",
        })

    # Lack of contractions
    words = text.split()
    contractions = len(re.findall(r"\b\w+'\w+\b", text))
    if len(words) > 50 and (contractions / len(words)) < 0.005:
        score += 8
        indicators.append({
            "category": "ai",
            "phrase": "(stylometric pattern)",
            "reason": "Very few contractions — overly formal style typical of AI.",
            "severity": "low",
        })

    return min(40, score), indicators


def _generate_summary(classification: str, signals: dict, explanations: list[dict]) -> str:
    if classification == "Safe":
        return "This content appears safe. No significant scam indicators, AI-generation patterns, or emotional manipulation detected."

    parts = []
    if signals.get("scam_keywords", 0) > 30:
        parts.append("scam-related keywords")
    if signals.get("ai_generated", 0) > 30:
        parts.append("AI-generated content patterns")
    if signals.get("emotional_manipulation", 0) > 30:
        parts.append("emotional manipulation tactics")
    india_hits = [e for e in explanations if e["category"] == "india_scam"]
    if india_hits:
        parts.append("India-specific fraud patterns")

    high_count = sum(1 for e in explanations if e["severity"] == "high")

    if classification == "High Risk":
        return f"⚠️ HIGH RISK: Contains {', '.join(parts)}. {high_count} high-severity indicators found. Do NOT share personal info or transfer money."
    return f"⚡ SUSPICIOUS: Shows signs of {', '.join(parts)}. Verify the source before acting."


def _generate_tips(classification: str, explanations: list[dict]) -> list[str]:
    tips = []
    if classification == "Safe":
        tips.append("Always stay vigilant — even safe-looking content can be deceptive.")
        return tips

    categories = set(e["category"] for e in explanations)
    if "scam" in categories or "india_scam" in categories:
        tips.append("Never share personal info (Aadhaar, PAN, OTP, passwords) via messages.")
        tips.append("Verify sender identity through official channels.")
        tips.append("Do not click links in suspicious messages.")
    if "urgency" in categories:
        tips.append("Legitimate organizations don't create artificial urgency — take your time.")
    if "ai" in categories:
        tips.append("Cross-check AI-generated claims with reliable sources.")
    tips.append("When in doubt, consult a trusted person before acting.")
    return tips[:5]


def analyze_text(text: str) -> AnalysisResult:
    """Run enhanced heuristic + stylometric analysis."""
    lower = text.lower()

    scam_hits, scam_expl = _find_matches(lower, SCAM_KEYWORDS, "scam")
    urgency_hits, urgency_expl = _find_matches(lower, URGENCY_PHRASES, "urgency")
    ai_hits, ai_expl = _find_matches(lower, AI_PATTERNS, "ai")
    india_hits, india_expl = _find_matches(lower, INDIA_SCAM_PATTERNS, "india_scam")

    scam_score = _score_from_hits(scam_hits + india_hits, 14)
    emo_score = _score_from_hits(urgency_hits, 18)

    # AI score includes stylometric analysis
    stylo_score, stylo_indicators = _stylometric_analysis(text)
    ai_base = _score_from_hits(ai_hits, 16)
    ai_score = min(100, ai_base + stylo_score)

    risk_score = min(100, round(ai_score * 0.3 + scam_score * 0.4 + emo_score * 0.3))

    if risk_score < 30:
        classification = "Safe"
    elif risk_score < 65:
        classification = "Suspicious"
    else:
        classification = "High Risk"

    all_phrases = list(set(scam_hits + urgency_hits + ai_hits + india_hits))
    all_explanations = scam_expl + urgency_expl + ai_expl + india_expl + stylo_indicators
    highlighted = _highlight(text, all_phrases)

    signals = {
        "ai_generated": ai_score,
        "scam_keywords": scam_score,
        "emotional_manipulation": emo_score,
    }

    summary = _generate_summary(classification, signals, all_explanations)
    tips = _generate_tips(classification, all_explanations)

    return AnalysisResult(
        risk_score=risk_score,
        classification=classification,
        signals=signals,
        suspicious_phrases=all_phrases,
        highlighted_text=highlighted,
        explanations=all_explanations,
        summary=summary,
        tips=tips,
    )
