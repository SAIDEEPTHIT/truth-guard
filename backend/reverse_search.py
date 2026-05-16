"""TruthShield – Perceptual hash + local phishing-image database.

Pure-stdlib + Pillow + numpy. Implements dHash (difference hash) — a fast,
robust perceptual hash that survives resizing/recompression. A small local
JSON DB of known phishing/scam images is shipped for demo realism.
"""
from __future__ import annotations
import io
import os
import json
import logging
from typing import Optional

import numpy as np

try:
    from PIL import Image
except ImportError:
    Image = None

logger = logging.getLogger(__name__)

# Local seed DB — extend at runtime via /api/image/reverse-search/seed
_DB_PATH = os.path.join(os.path.dirname(__file__), "phishing_hashes.json")

# Some realistic-looking demo seeds (curated). hash -> source metadata.
_DEFAULT_SEEDS: dict[str, dict] = {
    # Example seed hashes — these are placeholders matched by Hamming distance.
    "ffffffffffffffff": {
        "url": "https://known-phish.example.com/login",
        "title": "Fake SBI Banking Login Page",
        "category": "phishing",
        "first_seen": "2024-08-12",
        "reports": 42,
    },
    "0000000000000000": {
        "url": "https://catfish-profile.example.com/john-doe",
        "title": "Recycled Catfish Profile Picture",
        "category": "catfishing",
        "first_seen": "2024-03-04",
        "reports": 17,
    },
}


def _load_db() -> dict[str, dict]:
    if os.path.exists(_DB_PATH):
        try:
            with open(_DB_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("phishing DB load failed: %s", exc)
    return dict(_DEFAULT_SEEDS)


def _save_db(db: dict[str, dict]) -> None:
    try:
        with open(_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
    except Exception as exc:
        logger.warning("phishing DB save failed: %s", exc)


# ── Perceptual hash (dHash) ───────────────────────────────────────────────────

def compute_dhash(image_bytes: bytes, hash_size: int = 8) -> str:
    """Compute 64-bit difference hash. Returns 16-char hex string."""
    if not Image:
        return ""
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("L")
        img = img.resize((hash_size + 1, hash_size), Image.LANCZOS)
        arr = np.array(img, dtype=np.int16)
        diff = arr[:, 1:] > arr[:, :-1]
        bits = diff.flatten()
        n = 0
        for b in bits:
            n = (n << 1) | int(b)
        return f"{n:0{hash_size * hash_size // 4}x}"
    except Exception as exc:
        logger.warning("dHash failed: %s", exc)
        return ""


def hamming(a: str, b: str) -> int:
    """Hamming distance between two equal-length hex hashes."""
    if not a or not b or len(a) != len(b):
        return 9999
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except Exception:
        return 9999


# ── Search ────────────────────────────────────────────────────────────────────

def search_hash(image_hash: str, max_distance: int = 10) -> list[dict]:
    """Return DB entries within Hamming distance threshold, sorted by closeness."""
    if not image_hash:
        return []
    db = _load_db()
    matches: list[dict] = []
    for h, meta in db.items():
        d = hamming(image_hash, h)
        if d <= max_distance:
            confidence = round(max(0.0, 1.0 - d / 64.0), 3)
            matches.append({
                "url": meta.get("url", ""),
                "title": meta.get("title", "Known image"),
                "category": meta.get("category", "unknown"),
                "first_seen": meta.get("first_seen", ""),
                "reports": int(meta.get("reports", 1)),
                "matched_hash": h,
                "distance": d,
                "confidence": confidence,
                "isSuspicious": meta.get("category", "") in {"phishing", "catfishing", "scam"},
            })
    matches.sort(key=lambda m: m["distance"])
    return matches


def add_known_image(image_hash: str, url: str, title: str, category: str = "phishing") -> dict:
    db = _load_db()
    db[image_hash] = {
        "url": url,
        "title": title,
        "category": category,
        "first_seen": "user-submitted",
        "reports": int(db.get(image_hash, {}).get("reports", 0)) + 1,
    }
    _save_db(db)
    return db[image_hash]


def reverse_search(image_bytes: bytes) -> dict:
    """Full reverse-search pipeline. Returns response matching frontend contract."""
    h = compute_dhash(image_bytes)
    matches = search_hash(h, max_distance=10)
    found = len(matches) > 0

    risk_indicators: list[str] = []
    if found:
        cats = {m["category"] for m in matches}
        if "phishing" in cats:
            risk_indicators.append("Image hash matches known phishing campaigns in TruthShield database")
        if "catfishing" in cats:
            risk_indicators.append("Image reused across multiple unrelated profiles — catfishing indicator")
        if len(matches) >= 3:
            risk_indicators.append(f"Image found in {len(matches)} flagged sources — high-confidence reuse")
        risk_score = min(95, 55 + 10 * len(matches))
    else:
        risk_indicators.append("Image appears original — no matches in TruthShield phishing database")
        risk_score = 12

    return {
        "imageHash": h,
        "hashAlgorithm": "dHash-64",
        "found": found,
        "matchCount": len(matches),
        "sources": matches,
        "riskIndicators": risk_indicators,
        "riskScore": risk_score,
        "databaseSize": len(_load_db()),
    }
