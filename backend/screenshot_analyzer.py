"""TruthShield screenshot OCR helpers.

Uses free/low-cost vision OCR providers when keys are present:
1) Gemini Vision (recommended free tier)
2) OpenAI vision fallback
3) HuggingFace TrOCR fallback

No central storage; images are processed in-memory only.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

GEMINI_URL_TMPL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
DEFAULT_GEMINI_VISION_MODEL = os.getenv("GEMINI_VISION_MODEL", "gemini-2.0-flash")
HF_OCR_MODEL = os.getenv("HUGGINGFACE_OCR_MODEL", "microsoft/trocr-base-printed")


def _gemini_model_candidates() -> list[str]:
    candidates = [DEFAULT_GEMINI_VISION_MODEL, "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-flash-8b"]
    seen: set[str] = set()
    return [m for m in candidates if m and not (m in seen or seen.add(m))]


def extract_urls(text: str) -> list[str]:
    url_re = re.compile(r"(?:https?://|www\.)[^\s<>'\"(){}|\\^`]+", re.IGNORECASE)
    urls = []
    for raw in url_re.findall(text or ""):
        cleaned = raw.rstrip(".,;:!?)\u0964]")
        if cleaned and cleaned not in urls:
            urls.append(cleaned)
    return urls


def _json_from_text(text: str) -> dict[str, Any]:
    if not text:
        return {}
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        return json.loads(cleaned)
    except Exception:
        match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass
    return {"text": cleaned}


def _normalize_payload(payload: dict[str, Any], provider: str) -> dict[str, Any]:
    text = str(payload.get("text") or payload.get("extracted_text") or payload.get("generated_text") or "").strip()
    links = payload.get("links") or payload.get("urls") or extract_urls(text)
    if isinstance(links, str):
        links = extract_urls(links)
    if not isinstance(links, list):
        links = []
    confidence = payload.get("confidence", 0)
    try:
        confidence = int(float(confidence))
    except Exception:
        confidence = 0
    return {
        "text": text,
        "links": [str(u) for u in links if str(u).strip()],
        "confidence": max(0, min(100, confidence)),
        "provider": provider,
    }


def _call_gemini_ocr(image_data: bytes, content_type: str) -> Optional[dict[str, Any]]:
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return None

    prompt = (
        "You are TruthShield OCR for scam screenshots. Extract ALL readable visible text exactly, "
        "including SMS/WhatsApp/bank messages, OTP/KYC/UPI text, sender names, amounts, and every URL. "
        "Return ONLY JSON with keys: text (string), links (array of strings), confidence (0-100). "
        "Do not classify; only transcribe. Preserve line breaks."
    )
    b64 = base64.b64encode(image_data).decode("ascii")
    body = {
        "contents": [{
            "parts": [
                {"text": prompt},
                {"inlineData": {"mimeType": content_type or "image/jpeg", "data": b64}},
            ]
        }],
        "generationConfig": {"temperature": 0, "maxOutputTokens": 2048, "responseMimeType": "application/json"},
    }

    for model in _gemini_model_candidates():
        try:
            res = requests.post(GEMINI_URL_TMPL.format(model=model), params={"key": api_key}, json=body, timeout=25)
            if res.status_code in {404, 429, 503}:
                logger.warning("Gemini OCR model %s returned %s", model, res.status_code)
                continue
            res.raise_for_status()
            data = res.json()
            text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            return _normalize_payload(_json_from_text(text), f"gemini:{model}")
        except Exception as exc:
            logger.warning("Gemini OCR failed for %s: %s", model, exc)
    return None


def _call_openai_ocr(image_data: bytes, content_type: str) -> Optional[dict[str, Any]]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key, timeout=25.0)
        data_url = f"data:{content_type or 'image/jpeg'};base64,{base64.b64encode(image_data).decode('ascii')}"
        completion = client.chat.completions.create(
            model=os.getenv("OPENAI_VISION_MODEL", "gpt-4o-mini"),
            temperature=0,
            max_tokens=1200,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": "Extract all readable text and URLs from this screenshot. Return only JSON: {\"text\": string, \"links\": string[], \"confidence\": number}."},
                    {"type": "image_url", "image_url": {"url": data_url}},
                ],
            }],
        )
        text = completion.choices[0].message.content or ""
        return _normalize_payload(_json_from_text(text), "openai:gpt-4o-mini")
    except Exception as exc:
        logger.warning("OpenAI OCR failed: %s", exc)
        return None


def _call_huggingface_ocr(image_data: bytes, content_type: str) -> Optional[dict[str, Any]]:
    api_key = os.getenv("HUGGINGFACE_API_KEY") or os.getenv("HF_TOKEN")
    if not api_key:
        return None
    try:
        res = requests.post(
            f"https://api-inference.huggingface.co/models/{HF_OCR_MODEL}",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": content_type or "application/octet-stream"},
            data=image_data,
            timeout=30,
        )
        if res.status_code in {404, 429, 503}:
            return None
        res.raise_for_status()
        data = res.json()
        if isinstance(data, list) and data:
            text = data[0].get("generated_text", "")
        elif isinstance(data, dict):
            text = data.get("generated_text", "") or str(data)
        else:
            text = ""
        return _normalize_payload({"text": text, "confidence": 55 if text else 0}, f"huggingface:{HF_OCR_MODEL}")
    except Exception as exc:
        logger.warning("HuggingFace OCR failed: %s", exc)
        return None


def extract_text_from_image(image_data: bytes, content_type: str = "image/jpeg") -> dict[str, Any]:
    """Extract visible text from a screenshot/image using the best available free provider."""
    for provider in (_call_gemini_ocr, _call_openai_ocr, _call_huggingface_ocr):
        result = provider(image_data, content_type)
        if result and result.get("text"):
            if not result.get("links"):
                result["links"] = extract_urls(result["text"])
            return result

    return {
        "text": "",
        "links": [],
        "confidence": 0,
        "provider": "unavailable",
        "error": "No OCR provider available. Add GEMINI_API_KEY for best screenshot text extraction.",
    }
