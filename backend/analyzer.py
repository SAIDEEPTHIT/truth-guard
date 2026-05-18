"""TruthShield – Hybrid Multi-Model Text Analysis Engine v8.0

Ensemble of:
  1. OpenAI GPT-4o-mini  (semantic + contextual reasoning)
  2. Google Gemini 1.5 Flash (FREE tier — secondary reasoning + manipulation analysis)
  3. Local rule engine   (deterministic guarantees, India-specific scams)
  4. Stylometric AI-text detector (sentence-length variance, em-dash density, etc.)

Auto-detects available APIs. Gracefully degrades:
  - All available    → full ensemble (best accuracy)
  - 1-2 LLMs down    → remaining LLM + heuristics
  - All LLMs down    → pure heuristic engine (still useful)

Environment variables (any subset works):
  OPENAI_API_KEY     – https://platform.openai.com/api-keys
  GEMINI_API_KEY     – https://aistudio.google.com/apikey  (FREE)
"""

from __future__ import annotations
import re
import os
import json
import struct
import logging
import statistics
from dataclasses import dataclass, field
from typing import Optional

import requests as http_requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

# ── Lazy LLM clients ──────────────────────────────────────────────────────────

_openai_client = None

GEMINI_TEXT_MODEL = os.getenv("GEMINI_TEXT_MODEL", "gemini-1.5-flash")
GEMINI_URL_TMPL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def _gemini_text_model_candidates() -> list[str]:
    candidates = [GEMINI_TEXT_MODEL, "gemini-1.5-flash", "gemini-1.5-flash-8b", "gemini-1.5-flash-latest"]
    seen = set()
    return [m for m in candidates if m and not (m in seen or seen.add(m))]


def _get_openai_client():
    global _openai_client
    if _openai_client is not None:
        return _openai_client
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI
        _openai_client = OpenAI(api_key=api_key, timeout=15.0)
        return _openai_client
    except Exception as exc:
        logger.error("OpenAI init failed: %s", exc)
        return None


def _gemini_key() -> Optional[str]:
    return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    risk_score: int = 0
    classification: str = "Safe"
    scam_type: str = "Safe"
    emotional_manipulation: bool = False
    signals: dict = field(default_factory=dict)
    suspicious_phrases: list = field(default_factory=list)
    highlighted_text: str = ""
    explanations: list = field(default_factory=list)
    summary: str = ""
    tips: list = field(default_factory=list)


@dataclass
class ImageAnalysisResult:
    ai_generated_probability: float = 0.0
    classification: str = "Likely Authentic"
    explanation: list = field(default_factory=list)
    risk_score: int = 0
    metadata: dict = field(default_factory=dict)
    tips: list = field(default_factory=list)


# ── Heuristic keyword banks ───────────────────────────────────────────────────

SCAM_KEYWORDS = [
    "wire transfer", "western union", "bitcoin", "crypto wallet", "gift card",
    "send money", "processing fee", "registration fee", "advance fee",
    "claim your prize", "you have won", "selected as winner", "lottery winner",
    "inheritance", "bequeathed", "next of kin", "compensation fund",
    "verify your account", "verify bank account", "update kyc", "kyc expired",
    "account suspended", "account blocked", "account will be deactivated",
    "share otp", "tell otp", "your otp is", "do not share otp",
    "click this link", "click here to claim", "click below to verify",
    "remote job", "work from home", "no experience needed", "earn ₹",
    "earn rs", "earn lakhs", "limited vacancies", "limited seats",
    "investment opportunity", "guaranteed returns", "double your money",
    "100% returns", "risk free investment", "trading signals",
    "loan approved", "instant loan", "pre-approved loan",
    "tax refund", "income tax refund", "refund pending",
]

URGENCY_PHRASES = [
    "act now", "act immediately", "urgent", "urgent action required",
    "within 24 hours", "within 24 hrs", "expires today", "expires soon",
    "limited time", "last chance", "final notice", "final warning",
    "immediately", "right now", "hurry", "don't miss",
    "if you cared", "if you love", "you will lose",
]

INDIA_SCAM = [
    "aadhaar", "aadhar", "pan card", "pan number", "uidai",
    "sbi", "hdfc", "icici", "axis bank", "kotak", "yes bank",
    "upi", "phonepe", "google pay", "paytm",
    "kyc", "kyc update", "kyc pending", "kyc expired",
    "irctc", "income tax department", "gst notice",
    "courier blocked", "fedex parcel", "customs clearance",
    "narcotics", "money laundering case", "cbi", "police case",
    "bsnl", "jio recharge", "electricity bill due", "disconnection",
]

FINANCIAL_PHRASES = [
    "₹", "rs.", "rs ", "rupees", "lakhs", "crore", "dollars",
    "$", "usd", "inr", "payment", "pay now", "transfer",
]

AI_TEXT_MARKERS = [
    "in conclusion", "it is important to note", "furthermore", "moreover",
    "delve into", "tapestry", "navigate the complexities", "in today's",
    "leveraging", "synergy", "robust", "seamlessly", "comprehensive overview",
    "it's worth noting", "as an ai", "i don't have personal",
    "it is worth mentioning", "in summary", "to summarize", "additionally",
    "embark on", "realm of", "landscape of", "a testament to", "underscore",
    "pivotal", "nuanced", "multifaceted", "paramount", "intricate",
    "harness the power", "unlock the potential", "in the modern era",
    "ever-evolving", "ever-changing", "cutting-edge", "game-changer",
    "at the end of the day", "when it comes to", "with that being said",
]

# ── Contextual pattern combinations (very high confidence scams) ──────────────

CONTEXTUAL_PATTERNS = [
    {
        "name": "Lottery Scam",
        "trigger_groups": [
            ["won", "winner", "lottery", "prize", "selected"],
            ["fee", "tax", "processing", "claim", "transfer", "deposit"],
        ],
        "scam_type": "Financial Fraud",
        "min_score": 88,
        "reason": "Lottery winnings combined with upfront payment requests are classic advance-fee fraud — real lotteries never ask winners to pay.",
    },
    {
        "name": "Fake Job",
        "trigger_groups": [
            ["job", "hiring", "vacancy", "position", "offer letter", "remote work"],
            ["fee", "registration", "deposit", "security amount", "training fee", "kit fee"],
        ],
        "scam_type": "Job Scam",
        "min_score": 85,
        "reason": "Legitimate employers never charge candidates a fee. Asking for payment for registration, training kits, or 'security deposit' is a hallmark of fake job scams targeting Indian job-seekers.",
    },
    {
        "name": "Bank Phishing",
        "trigger_groups": [
            ["bank", "account", "sbi", "hdfc", "icici", "axis", "kotak"],
            ["verify", "update", "kyc", "blocked", "suspended", "deactivate"],
            ["click", "link", "http", "bit.ly", "tinyurl"],
        ],
        "scam_type": "Phishing",
        "min_score": 90,
        "reason": "Banks never send verification links via SMS or email. Clicking will likely steal your credentials. Always log in via the official app or website directly.",
    },
    {
        "name": "OTP / KYC Theft",
        "trigger_groups": [
            ["otp", "one time password", "verification code"],
            ["share", "tell", "give", "send", "provide"],
        ],
        "scam_type": "Phishing",
        "min_score": 92,
        "reason": "Anyone asking you to share an OTP is attempting fraud. RBI guidelines state no bank or legitimate service will ever request your OTP.",
    },
    {
        "name": "Aadhaar / PAN Scam",
        "trigger_groups": [
            ["aadhaar", "aadhar", "pan card", "uidai"],
            ["blocked", "suspended", "deactivate", "verify", "update", "expire"],
        ],
        "scam_type": "Phishing",
        "min_score": 87,
        "reason": "UIDAI and Income Tax Department never threaten deactivation via SMS. This pattern targets fear of identity loss to extract personal data.",
    },
    {
        "name": "Investment / Crypto Scam",
        "trigger_groups": [
            ["invest", "investment", "crypto", "bitcoin", "trading", "stocks"],
            ["guaranteed", "100%", "double", "risk free", "no risk", "assured returns"],
        ],
        "scam_type": "Financial Fraud",
        "min_score": 84,
        "reason": "No legitimate investment guarantees returns. SEBI explicitly warns that 'guaranteed' or 'risk-free' investment promises are almost always Ponzi schemes.",
    },
    {
        "name": "Courier / Customs Scam",
        "trigger_groups": [
            ["courier", "parcel", "fedex", "dhl", "package", "shipment"],
            ["customs", "narcotics", "cbi", "police", "case", "arrest", "charge"],
        ],
        "scam_type": "Phishing",
        "min_score": 89,
        "reason": "The 'FedEx/DHL parcel + narcotics' scam is widespread in India in 2024-25. CBI and Mumbai Police never call victims directly to demand payment.",
    },
    {
        "name": "Emotional Money Pressure",
        "trigger_groups": [
            ["if you", "love", "care", "trust", "family", "emergency"],
            ["money", "send", "transfer", "pay", "₹", "rs", "lakhs"],
        ],
        "scam_type": "Financial Fraud",
        "min_score": 70,
        "reason": "Combining emotional appeals ('if you cared', family emergencies) with money requests is a classic manipulation tactic — verify via a separate channel before sending anything.",
    },
]


# ── OpenAI / Gemini prompt (structured) ───────────────────────────────────────

SYSTEM_PROMPT = """You are TruthShield's senior cybersecurity analyst specialising in scams targeting Indian users.

Classify the text into ONE of these scam categories (use exact label):
  - "Phishing"               (fake login / verify-account / fake bank or govt link)
  - "Fake Banking Alert"     (impersonation of SBI/HDFC/ICICI/RBI/UPI alerts)
  - "KYC Scam"               (fake KYC update, Aadhaar/PAN block, eKYC expiry)
  - "Urgency / Fear Tactic"  (act-now, account-blocked, arrest-warrant pressure)
  - "OTP / Payment Scam"     (asks to share OTP, UPI PIN, autopay, ₹1 verify)
  - "Fake Rewards"           (you-won, lottery, cashback, free gift, prize)
  - "Impersonation Scam"     (CBI/police/FedEx/courier/customs/celeb impersonation)
  - "AI Generated"           (clearly LLM-written marketing / essay, not a scam)
  - "Safe"                   (legitimate / benign content)

Also detect suspicious URLs/domains in the text: shorteners (bit.ly, tinyurl, t.co),
look-alike banking domains (sbi-secure-xxx, hdfc-verify-xxx), non-https links to
"banks", IP-address URLs, or recently-registered look-alikes — call these out.

Calibrate scores realistically. Do NOT inflate scores for benign content.

SCORING GUIDE (0-100 risk_score):
  0-15  → Casual/normal/educational text, no red flags
  16-30 → Mildly promotional but legitimate
  31-50 → Suspicious tone, unverified claims (worth caution)
  51-69 → Likely scam — multiple manipulation signals
  70-85 → High-confidence scam (job-fee, lottery, urgent verify)
  86-100 → Textbook fraud (OTP theft, courier-narcotics, bank phishing link)

Also score `ai_generated_probability` 0-100 (corporate buzzwords, em-dashes,
"delve into", "tapestry", overuse of transitions all raise this).

Return STRICT JSON only:
{
  "risk_score": <0-100>,
  "classification": "Safe" | "Suspicious" | "High Risk",
  "scam_type": "Phishing" | "Fake Banking Alert" | "KYC Scam" | "Urgency / Fear Tactic" | "OTP / Payment Scam" | "Fake Rewards" | "Impersonation Scam" | "AI Generated" | "Safe",
  "emotional_manipulation": <bool>,
  "ai_generated_probability": <0-100>,
  "suspicious_phrases": [<exact substrings copied from input>],
  "suspicious_urls": [<exact URLs/domains from input that look risky>],
  "explanation": "<2-3 sentence WHY — describe the specific pattern detected and why it's dangerous (or safe). Be concrete.>",
  "senior_explanation": "<1-2 short sentences, plain English, no jargon, suitable for a 65+ user. Example: 'This message pretends to be your bank to scare you. Do not click the link or share any OTP.'>",
  "tips": [<2-3 actionable, India-specific safety tips>]
}"""


def _call_openai(text: str) -> Optional[dict]:
    client = _get_openai_client()
    if client is None:
        return None
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyse:\n\n{text[:8000]}"},
            ],
            temperature=0.1,
            max_tokens=900,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        return json.loads(content) if content else None
    except Exception as exc:
        logger.warning("OpenAI call failed: %s", exc)
        return None


def _call_gemini(text: str) -> Optional[dict]:
    """Call Google Gemini 1.5 Flash via REST API (free tier, no SDK needed)."""
    api_key = _gemini_key()
    if not api_key:
        return None
    try:
        for model_name in _gemini_text_model_candidates():
            url = GEMINI_URL_TMPL.format(model=model_name)
            body = {
                "contents": [{
                    "role": "user",
                    "parts": [{"text": SYSTEM_PROMPT + "\n\nTEXT TO ANALYSE:\n\n" + text[:8000]}],
                }],
                "generationConfig": {
                    "temperature": 0.1,
                    "maxOutputTokens": 2048,
                    "responseMimeType": "application/json",
                },
            }
            resp = http_requests.post(
                url, params={"key": api_key},
                headers={"Content-Type": "application/json"},
                json=body, timeout=15,
            )
            if resp.status_code != 200:
                logger.warning("Gemini text %s returned %d: %s", model_name, resp.status_code, resp.text[:200])
                continue
            data = resp.json()
            candidates = data.get("candidates") or []
            if not candidates:
                continue
            parts = candidates[0].get("content", {}).get("parts", [])
            raw = "".join(p.get("text", "") for p in parts).strip()
            if raw.startswith("```"):
                raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.IGNORECASE).strip()
            return json.loads(raw)
        return None
    except Exception as exc:
        logger.warning("Gemini text call failed: %s", exc)
        return None


# ── Stylometric AI-text detector ─────────────────────────────────────────────

def _stylometric_ai_score(text: str) -> int:
    """Detect AI-generated text via writing-style fingerprints.

    Real human text: variable sentence lengths, contractions, typos, fragments.
    AI text: uniform sentence lengths, em-dashes, no contractions, balanced clauses.
    """
    if len(text) < 80:
        return 0

    score = 0
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]
    if len(sentences) < 3:
        return 0

    # 1. Sentence-length uniformity (AI tends to be very even)
    lengths = [len(s.split()) for s in sentences]
    if len(lengths) >= 4:
        try:
            stdev = statistics.stdev(lengths)
            mean_len = statistics.mean(lengths)
            cv = stdev / mean_len if mean_len > 0 else 0
            if cv < 0.35 and mean_len > 12:
                score += 25  # very uniform = AI-like
            elif cv < 0.55:
                score += 10
        except statistics.StatisticsError:
            pass

    # 2. Em-dash density (AI loves em-dashes)
    em_dashes = text.count("—") + text.count(" - ")
    em_density = em_dashes / max(1, len(sentences))
    if em_density > 0.5:
        score += 20
    elif em_density > 0.25:
        score += 10

    # 3. Contraction ratio (humans use them, AI often doesn't)
    word_count = max(1, len(text.split()))
    contractions = len(re.findall(r"\b\w+'(?:s|t|re|ve|ll|d|m)\b", text, re.IGNORECASE))
    contraction_ratio = contractions / word_count
    if word_count > 100 and contraction_ratio < 0.005:
        score += 15

    # 4. Parallel "X, Y, and Z" enumerations (AI signature)
    triplets = len(re.findall(r"\b\w+,\s+\w+,\s+and\s+\w+", text))
    if triplets >= 2:
        score += 15

    # 5. Buzzword density
    buzz_hits = sum(1 for m in AI_TEXT_MARKERS if m in text.lower())
    score += min(30, buzz_hits * 8)

    return min(100, score)


# ── Heuristic engine ──────────────────────────────────────────────────────────

def _heuristic_analyze(text: str) -> dict:
    lower = text.lower()

    def hits(bank):
        return [kw for kw in bank if kw in lower]

    scam_hits = hits(SCAM_KEYWORDS)
    urg_hits = hits(URGENCY_PHRASES)
    india_hits = hits(INDIA_SCAM)
    fin_hits = hits(FINANCIAL_PHRASES)
    ai_hits = hits(AI_TEXT_MARKERS)

    base = (
        len(scam_hits) * 12
        + len(urg_hits) * 8
        + len(india_hits) * 14
        + len(fin_hits) * 4
    )
    score = max(0, min(100, base))

    ai_prob = max(0, min(100, len(ai_hits) * 18))

    scam_type = "Safe"
    if india_hits and (urg_hits or scam_hits):
        scam_type = "Phishing"
    elif scam_hits and fin_hits:
        scam_type = "Financial Fraud"
    elif scam_hits:
        scam_type = "Financial Fraud"

    classification = "Safe" if score <= 30 else "Suspicious" if score <= 60 else "High Risk"

    all_phrases = list(set(scam_hits + urg_hits + india_hits))

    return {
        "risk_score": score,
        "classification": classification,
        "scam_type": scam_type,
        "emotional_manipulation": len(urg_hits) >= 2,
        "ai_generated_probability": ai_prob,
        "suspicious_phrases": all_phrases,
        "explanation": f"Heuristic engine flagged {len(all_phrases)} suspicious indicators across {len([x for x in [scam_hits, urg_hits, india_hits] if x])} categories.",
        "tips": [
            "Verify the sender via a separate, official channel before acting.",
            "Never share OTP, Aadhaar, PAN, or bank credentials over messages.",
        ] if score > 30 else ["No strong red flags — but stay vigilant."],
        "_source": "heuristic",
    }


# ── Contextual pattern overrides ──────────────────────────────────────────────

def _apply_contextual_patterns(text: str, result: dict) -> dict:
    lower = text.lower()
    triggered = []

    for pattern in CONTEXTUAL_PATTERNS:
        groups_matched = sum(
            1 for group in pattern["trigger_groups"]
            if any(kw in lower for kw in group)
        )
        # Require ALL groups to match for strict patterns
        if groups_matched == len(pattern["trigger_groups"]):
            triggered.append(pattern)

    if not triggered:
        return result

    # Pick the highest-confidence trigger
    best = max(triggered, key=lambda p: p["min_score"])
    if result.get("risk_score", 0) < best["min_score"]:
        result["risk_score"] = best["min_score"]
        result["classification"] = "High Risk"
        result["scam_type"] = best["scam_type"]

    # Append the contextual reason to the explanation
    existing = result.get("explanation", "") or ""
    add = f" Context match — {best['name']}: {best['reason']}"
    if best["reason"] not in existing:
        result["explanation"] = (existing + add).strip()

    result["_pattern"] = best["name"]
    return result


# ── Ensemble fusion ───────────────────────────────────────────────────────────

def _fuse(results: list) -> dict:
    """Weight-average available LLM results with heuristic floor."""
    if not results:
        return {}

    # Average numeric fields
    def avg(field, default=0):
        vals = [r.get(field, default) for r in results if r.get(field) is not None]
        return int(sum(vals) / len(vals)) if vals else default

    risk = avg("risk_score")
    ai_prob = avg("ai_generated_probability")

    # Majority vote on booleans/categoricals
    emo_votes = sum(1 for r in results if r.get("emotional_manipulation"))
    emotional = emo_votes >= (len(results) + 1) // 2

    # scam_type: pick the most-severe non-Safe label
    severity_rank = {"Phishing": 5, "Job Scam": 4, "Financial Fraud": 3, "Misinformation": 2, "AI Generated": 1, "Safe": 0}
    scam_types = [r.get("scam_type", "Safe") for r in results]
    scam_type = max(scam_types, key=lambda s: severity_rank.get(s, 0))

    # Merge phrases (deduped, preserve order)
    seen, phrases = set(), []
    for r in results:
        for p in r.get("suspicious_phrases", []) or []:
            key = p.lower().strip()
            if key and key not in seen:
                seen.add(key)
                phrases.append(p)

    # Prefer the longest, most informative explanation
    explanations_pool = [r.get("explanation", "") for r in results if r.get("explanation")]
    explanation = max(explanations_pool, key=len) if explanations_pool else ""

    # Merge tips (deduped)
    seen_t, tips = set(), []
    for r in results:
        for t in r.get("tips", []) or []:
            if t and t not in seen_t:
                seen_t.add(t)
                tips.append(t)

    if risk <= 30:
        classification = "Safe"
    elif risk <= 60:
        classification = "Suspicious"
    else:
        classification = "High Risk"

    return {
        "risk_score": risk,
        "classification": classification,
        "scam_type": scam_type,
        "emotional_manipulation": emotional,
        "ai_generated_probability": ai_prob,
        "suspicious_phrases": phrases,
        "explanation": explanation,
        "tips": tips,
        "_sources": [r.get("_source", "llm") for r in results],
    }


# ── Highlight helper ──────────────────────────────────────────────────────────

def _highlight(text: str, phrases: list) -> str:
    out = text
    for phrase in sorted(set(phrases), key=len, reverse=True):
        if not phrase or len(phrase) < 2:
            continue
        try:
            pattern = re.compile(re.escape(phrase), re.IGNORECASE)
            out = pattern.sub(lambda m: f"<mark>{m.group()}</mark>", out)
        except re.error:
            continue
    return out


# ── Main entrypoint ───────────────────────────────────────────────────────────

def analyze_text(text: str) -> AnalysisResult:
    """Hybrid ensemble analysis: OpenAI + Gemini + heuristics + stylometry + contextual patterns."""
    # 1. Always compute heuristics (cheap, deterministic)
    heuristic = _heuristic_analyze(text)
    heuristic["_source"] = "heuristic"

    # 1b. Stylometric AI-text fingerprint (independent signal)
    stylo_ai = _stylometric_ai_score(text)

    # 2. Call available LLMs
    llm_results = []
    openai_result = _call_openai(text)
    if openai_result:
        openai_result["_source"] = "openai"
        llm_results.append(openai_result)

    gemini_result = _call_gemini(text)
    if gemini_result:
        gemini_result["_source"] = "gemini"
        llm_results.append(gemini_result)

    # 3. Fuse LLM results, blend with heuristic floor
    if llm_results:
        fused = _fuse(llm_results)
        if heuristic["risk_score"] > fused["risk_score"] + 15:
            fused["risk_score"] = int((fused["risk_score"] + heuristic["risk_score"]) / 2)
        seen = {p.lower() for p in fused["suspicious_phrases"]}
        for p in heuristic["suspicious_phrases"]:
            if p.lower() not in seen:
                fused["suspicious_phrases"].append(p)
        result = fused
    else:
        result = heuristic
        result["_sources"] = ["heuristic"]

    # 3b. Boost AI-generated probability with stylometric signal
    llm_ai = result.get("ai_generated_probability", 0) or 0
    # Take the max of (LLM estimate, stylometric estimate, heuristic estimate)
    fused_ai = max(int(llm_ai), int(stylo_ai), int(heuristic.get("ai_generated_probability", 0)))
    # If both LLM and stylometric agree highly, anchor a strong floor
    if llm_ai >= 50 and stylo_ai >= 50:
        fused_ai = max(fused_ai, int((llm_ai + stylo_ai) / 2) + 5)
    result["ai_generated_probability"] = min(100, fused_ai)

    # 4. Contextual pattern overrides (deterministic safety net)
    result = _apply_contextual_patterns(text, result)

    # 5. Re-classify based on final risk
    risk = result.get("risk_score", 0)
    if risk <= 30:
        result["classification"] = "Safe"
    elif risk <= 60:
        result["classification"] = "Suspicious"
    else:
        result["classification"] = "High Risk"

    # 6. Build response
    phrases = result.get("suspicious_phrases", []) or []
    highlighted = _highlight(text, phrases)

    scam_type = result.get("scam_type", "Safe")
    scam_signal = min(100, risk) if scam_type != "Safe" else max(0, risk - 20)
    emo_signal = 75 if result.get("emotional_manipulation") else max(0, risk - 40)
    ai_signal = result.get("ai_generated_probability", 0)

    # Rich per-phrase explanations
    explanations = []
    for phrase in phrases[:10]:
        category = "scam"
        reason = "Flagged by ensemble analysis as a known scam indicator."
        pl = phrase.lower()
        if any(k in pl for k in URGENCY_PHRASES):
            category = "urgency"
            reason = "Creates artificial urgency to bypass careful judgement — classic manipulation tactic."
        elif any(k in pl for k in INDIA_SCAM):
            category = "india_scam"
            reason = "Matches India-specific scam vocabulary (KYC / UPI / Aadhaar / PAN abuse)."
        elif any(k in pl for k in AI_TEXT_MARKERS):
            category = "ai"
            reason = "Stylistic marker frequently produced by large language models."

        severity = "high" if risk > 65 else "medium" if risk > 35 else "low"
        explanations.append({
            "category": category,
            "phrase": phrase,
            "reason": reason,
            "severity": severity,
        })

    summary = result.get("explanation", "") or "Analysis complete."
    sources = result.get("_sources", ["heuristic"])
    pattern = result.get("_pattern")
    if len(sources) > 1 or pattern:
        meta_parts = []
        if len(sources) > 1:
            meta_parts.append(f"Ensemble of {', '.join(sources)}")
        if pattern:
            meta_parts.append(f"contextual pattern: {pattern}")
        summary = f"{summary}\n\n[Engine: {' • '.join(meta_parts)}]"

    tips = result.get("tips") or ["Stay vigilant and verify sources."]

    return AnalysisResult(
        risk_score=risk,
        classification=result["classification"],
        scam_type=scam_type,
        emotional_manipulation=bool(result.get("emotional_manipulation")),
        signals={
            "ai_generated": int(ai_signal),
            "scam_keywords": int(scam_signal),
            "emotional_manipulation": int(emo_signal),
        },
        suspicious_phrases=phrases,
        highlighted_text=highlighted,
        explanations=explanations,
        summary=summary,
        tips=tips,
    )


# ── Legacy lightweight image heuristic (kept for /analyze-image endpoint) ────

def analyze_image(image_data: bytes, filename: str = "", content_type: str = "") -> ImageAnalysisResult:
    """Lightweight image heuristic. The richer pipeline lives in image_analyzer.py."""
    indicators = []
    score = 0
    metadata = {"filename": filename, "content_type": content_type, "size_bytes": len(image_data)}

    has_exif = b"Exif" in image_data[:200]
    if not has_exif:
        score += 20
        indicators.append({"signal": "No EXIF metadata found", "weight": 20, "type": "suspicious"})
    else:
        indicators.append({"signal": "EXIF metadata present", "weight": -10, "type": "authentic"})
        score -= 10

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

    if len(image_data) > 1000:
        sample = image_data[:5000]
        if len(set(sample)) > 250:
            score += 8
            indicators.append({"signal": "High byte diversity", "weight": 8, "type": "suspicious"})

    metadata["size_mb"] = round(len(image_data) / (1024 * 1024), 2)
    score = max(0, min(100, score))
    prob = score / 100.0

    if prob < 0.3:
        classification = "Likely Authentic"
    elif prob < 0.6:
        classification = "Possibly AI-Generated"
    else:
        classification = "Likely AI-Generated"

    tips = ["Use the full Image Analysis page for deep forensic + Vision-LLM ensemble.",
            "AI detection is probabilistic — use as one signal among many."]

    return ImageAnalysisResult(
        ai_generated_probability=round(prob, 3),
        classification=classification,
        explanation=indicators,
        risk_score=score,
        metadata=metadata,
        tips=tips,
    )
