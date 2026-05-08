"""TruthShield – Enhanced AI Image Detection Module v2.0

Combines: EXIF metadata extraction, pixel-level analysis, HuggingFace AI classifier.
Graceful fallback if HuggingFace API is unavailable.
"""

import io
import os
import json
import math
import base64
import struct
import logging
from typing import Optional

import numpy as np

try:
    import piexif
except ImportError:
    piexif = None

try:
    from PIL import Image
except ImportError:
    Image = None

import requests as http_requests

logger = logging.getLogger(__name__)


# ── Lazy Vision LLM clients ──────────────────────────────────────────────────

_openai_vision_client = None
_claude_vision_client = None


def _get_openai_vision():
    global _openai_vision_client
    if _openai_vision_client is not None:
        return _openai_vision_client
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI
        _openai_vision_client = OpenAI(api_key=api_key, timeout=20.0)
        return _openai_vision_client
    except Exception as exc:
        logger.warning("OpenAI Vision init failed: %s", exc)
        return None


def _get_claude_vision():
    global _claude_vision_client
    if _claude_vision_client is not None:
        return _claude_vision_client
    api_key = os.getenv("CLAUDE_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
        _claude_vision_client = anthropic.Anthropic(api_key=api_key, timeout=20.0)
        return _claude_vision_client
    except Exception as exc:
        logger.warning("Claude Vision init failed: %s", exc)
        return None


VISION_PROMPT = """You are a forensic image analyst. Decide if this image is AI-generated (Stable Diffusion / Midjourney / DALL-E / Flux / Sora) or a real photograph / human-made artwork.

Look for: diffusion artefacts, plastic/oversmooth skin, malformed hands or eyes, illegible text, impossible shadows, repeating textures, unnaturally symmetric faces, painterly noise, missing pores, weird jewellery/teeth, melted backgrounds.

Calibrate honestly:
  0-20  = real DSLR/phone photo
  21-40 = real photo with heavy filter / edit
  41-60 = ambiguous / can't tell
  61-80 = likely AI-generated
  81-100 = obvious AI art

Return STRICT JSON only, no prose:
{
  "ai_score": <0-100>,
  "verdict": "real" | "edited" | "ambiguous" | "likely_ai" | "obvious_ai",
  "indicators": [<3-6 short specific visual indicators you actually see>],
  "reasoning": "<2-3 sentences explaining the call>"
}"""


def _shrink_for_vision(image_bytes: bytes, max_side: int = 768) -> tuple[bytes, str]:
    """Resize image so max side <= max_side; returns (jpeg_bytes, mime)."""
    if not Image:
        return image_bytes, "image/jpeg"
    try:
        img = Image.open(io.BytesIO(image_bytes))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        if max(img.width, img.height) > max_side:
            ratio = max_side / max(img.width, img.height)
            img = img.resize((int(img.width * ratio), int(img.height * ratio)), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        return buf.getvalue(), "image/jpeg"
    except Exception:
        return image_bytes, "image/jpeg"


def call_openai_vision(image_bytes: bytes) -> dict:
    """Ask GPT-4o-mini to score AI-generation likelihood."""
    client = _get_openai_vision()
    if client is None:
        return {"available": False, "ai_score": 0, "verdict": "unknown", "indicators": [], "reasoning": "", "model": "none"}
    try:
        small, mime = _shrink_for_vision(image_bytes)
        b64 = base64.b64encode(small).decode("ascii")
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": VISION_PROMPT},
                    {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}},
                ],
            }],
            temperature=0.1,
            max_tokens=400,
            response_format={"type": "json_object"},
        )
        raw = resp.choices[0].message.content or "{}"
        data = json.loads(raw)
        return {
            "available": True,
            "model": "gpt-4o-mini",
            "ai_score": int(data.get("ai_score", 0)),
            "verdict": data.get("verdict", "unknown"),
            "indicators": data.get("indicators", []) or [],
            "reasoning": data.get("reasoning", "") or "",
        }
    except Exception as exc:
        logger.warning("OpenAI Vision error: %s", exc)
        return {"available": False, "ai_score": 0, "verdict": "unknown", "indicators": [], "reasoning": str(exc)[:200], "model": "gpt-4o-mini"}


def call_claude_vision(image_bytes: bytes) -> dict:
    """Ask Claude to score AI-generation likelihood."""
    client = _get_claude_vision()
    if client is None:
        return {"available": False, "ai_score": 0, "verdict": "unknown", "indicators": [], "reasoning": "", "model": "none"}
    try:
        small, mime = _shrink_for_vision(image_bytes)
        b64 = base64.b64encode(small).decode("ascii")
        msg = client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=500,
            system=VISION_PROMPT + "\n\nReturn raw JSON only — no markdown fences.",
            messages=[{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": mime, "data": b64}},
                    {"type": "text", "text": "Analyse this image."},
                ],
            }],
        )
        raw = "".join(b.text for b in msg.content if hasattr(b, "text")).strip()
        if raw.startswith("```"):
            import re as _re
            raw = _re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=_re.IGNORECASE).strip()
        data = json.loads(raw)
        return {
            "available": True,
            "model": "claude-3-5-haiku",
            "ai_score": int(data.get("ai_score", 0)),
            "verdict": data.get("verdict", "unknown"),
            "indicators": data.get("indicators", []) or [],
            "reasoning": data.get("reasoning", "") or "",
        }
    except Exception as exc:
        logger.warning("Claude Vision error: %s", exc)
        return {"available": False, "ai_score": 0, "verdict": "unknown", "indicators": [], "reasoning": str(exc)[:200], "model": "claude-3-5-haiku"}


# ── 1. EXIF Metadata Extraction ──────────────────────────────────────────────

def extract_exif_metadata(image_bytes: bytes, filename: str = "") -> dict:
    """Extract EXIF metadata from image bytes."""
    metadata = {
        "filename": filename,
        "fileSize": len(image_bytes),
        "fileSizeMB": round(len(image_bytes) / (1024 * 1024), 2),
        "hasMissingEXIF": True,
        "cameraMake": None,
        "cameraModel": None,
        "lensModel": None,
        "software": None,
        "creationDate": None,
        "modifyDate": None,
        "iso": None,
        "aperture": None,
        "shutterSpeed": None,
        "focalLength": None,
        "gpsLatitude": None,
        "gpsLongitude": None,
        "orientation": None,
        "colorSpace": None,
        "width": None,
        "height": None,
    }

    # Try to get dimensions from PIL
    if Image:
        try:
            img = Image.open(io.BytesIO(image_bytes))
            metadata["width"] = img.width
            metadata["height"] = img.height
            metadata["colorSpace"] = img.mode
        except Exception:
            pass

    # Try piexif
    if piexif:
        try:
            exif_dict = piexif.load(image_bytes)

            def _get(ifd, tag):
                val = exif_dict.get(ifd, {}).get(tag)
                if isinstance(val, bytes):
                    return val.decode("utf-8", errors="ignore").strip("\x00 ")
                return val

            make = _get("0th", piexif.ImageIFD.Make)
            model = _get("0th", piexif.ImageIFD.Model)
            software = _get("0th", piexif.ImageIFD.Software)
            orientation = _get("0th", piexif.ImageIFD.Orientation)
            date_orig = _get("Exif", piexif.ExifIFD.DateTimeOriginal)
            date_digit = _get("Exif", piexif.ExifIFD.DateTimeDigitized)
            iso_val = _get("Exif", piexif.ExifIFD.ISOSpeedRatings)
            lens = _get("Exif", piexif.ExifIFD.LensModel)

            # Aperture (FNumber as rational)
            fnumber = exif_dict.get("Exif", {}).get(piexif.ExifIFD.FNumber)
            aperture_str = None
            if fnumber and isinstance(fnumber, tuple) and len(fnumber) == 2 and fnumber[1] != 0:
                aperture_str = f"f/{fnumber[0] / fnumber[1]:.1f}"

            # Shutter speed (ExposureTime as rational)
            exposure = exif_dict.get("Exif", {}).get(piexif.ExifIFD.ExposureTime)
            shutter_str = None
            if exposure and isinstance(exposure, tuple) and len(exposure) == 2 and exposure[1] != 0:
                if exposure[0] < exposure[1]:
                    shutter_str = f"1/{exposure[1] // exposure[0]}s"
                else:
                    shutter_str = f"{exposure[0] / exposure[1]:.1f}s"

            # Focal length
            fl = exif_dict.get("Exif", {}).get(piexif.ExifIFD.FocalLength)
            fl_str = None
            if fl and isinstance(fl, tuple) and len(fl) == 2 and fl[1] != 0:
                fl_str = f"{fl[0] / fl[1]:.0f}mm"

            has_meaningful_exif = any([make, model, date_orig, iso_val])

            if has_meaningful_exif:
                metadata["hasMissingEXIF"] = False

            if make:
                metadata["cameraMake"] = make
            if model:
                metadata["cameraModel"] = model
            if software:
                metadata["software"] = str(software)
            if orientation:
                metadata["orientation"] = orientation
            if date_orig:
                metadata["creationDate"] = str(date_orig)
            elif date_digit:
                metadata["creationDate"] = str(date_digit)
            if iso_val:
                metadata["iso"] = iso_val if isinstance(iso_val, int) else str(iso_val)
            if lens:
                metadata["lensModel"] = str(lens)
            if aperture_str:
                metadata["aperture"] = aperture_str
            if shutter_str:
                metadata["shutterSpeed"] = shutter_str
            if fl_str:
                metadata["focalLength"] = fl_str

            # GPS
            gps_data = exif_dict.get("GPS", {})
            if gps_data:
                lat_ref = gps_data.get(piexif.GPSIFD.GPSLatitudeRef)
                lat = gps_data.get(piexif.GPSIFD.GPSLatitude)
                lon_ref = gps_data.get(piexif.GPSIFD.GPSLongitudeRef)
                lon = gps_data.get(piexif.GPSIFD.GPSLongitude)
                if lat and lon:
                    def _to_deg(vals):
                        d, m, s = vals
                        return d[0]/d[1] + m[0]/m[1]/60 + s[0]/s[1]/3600
                    try:
                        lat_val = _to_deg(lat)
                        lon_val = _to_deg(lon)
                        if lat_ref == b"S":
                            lat_val = -lat_val
                        if lon_ref == b"W":
                            lon_val = -lon_val
                        metadata["gpsLatitude"] = round(lat_val, 6)
                        metadata["gpsLongitude"] = round(lon_val, 6)
                    except Exception:
                        pass

        except Exception as e:
            logger.debug("EXIF extraction failed: %s", e)
    else:
        # Fallback: check raw bytes for Exif marker
        if b"Exif" in image_bytes[:100]:
            metadata["hasMissingEXIF"] = False

    return metadata


# ── 2. Metadata Scoring ─────────────────────────────────────────────────────

def score_metadata(metadata: dict) -> dict:
    """Score metadata for authenticity. Returns score 0-100 and indicators."""
    score = 0
    indicators = []

    if metadata.get("hasMissingEXIF"):
        score += 30
        indicators.append({
            "signal": "Missing EXIF metadata",
            "detail": "AI-generated images typically lack camera EXIF data",
            "severity": "high",
            "type": "red"
        })
    else:
        score -= 10
        indicators.append({
            "signal": "EXIF metadata present",
            "detail": "Contains camera information — suggests real photograph",
            "severity": "low",
            "type": "green"
        })

    if metadata.get("cameraMake") and metadata.get("cameraModel"):
        score -= 15
        indicators.append({
            "signal": f"Camera: {metadata['cameraMake']} {metadata['cameraModel']}",
            "detail": "Identified camera hardware — strong authenticity signal",
            "severity": "low",
            "type": "green"
        })

    software = metadata.get("software")
    if software:
        ai_software = ["stable diffusion", "midjourney", "dall-e", "comfyui", "automatic1111", "novelai", "invoke"]
        if any(s in software.lower() for s in ai_software):
            score += 35
            indicators.append({
                "signal": f"AI software detected: {software}",
                "detail": "Image was processed by known AI generation software",
                "severity": "high",
                "type": "red"
            })
        else:
            indicators.append({
                "signal": f"Software: {software}",
                "detail": "Image editing software detected",
                "severity": "low",
                "type": "yellow"
            })

    if metadata.get("creationDate"):
        indicators.append({
            "signal": f"Created: {metadata['creationDate']}",
            "detail": "Original creation date found",
            "severity": "low",
            "type": "green"
        })
    else:
        score += 10
        indicators.append({
            "signal": "No creation date",
            "detail": "Missing timestamp — common in AI-generated images",
            "severity": "medium",
            "type": "yellow"
        })

    if metadata.get("gpsLatitude"):
        score -= 10
        indicators.append({
            "signal": "GPS coordinates found",
            "detail": "Contains location data — strong authenticity signal (⚠️ privacy risk)",
            "severity": "low",
            "type": "green"
        })

    # Dimensions check
    w = metadata.get("width")
    h = metadata.get("height")
    if w and h:
        ai_dims = [(512,512),(768,768),(1024,1024),(1024,768),(768,1024),(2048,2048),(1536,1536),(896,1152),(1152,896)]
        if (w, h) in ai_dims:
            score += 15
            indicators.append({
                "signal": f"AI-typical dimensions: {w}×{h}",
                "detail": "These dimensions match common AI generator output sizes",
                "severity": "medium",
                "type": "yellow"
            })
        if w % 64 == 0 and h % 64 == 0:
            score += 5
            indicators.append({
                "signal": "Dimensions are multiples of 64",
                "detail": "AI models often output at 64-pixel aligned dimensions",
                "severity": "low",
                "type": "yellow"
            })

    return {"score": max(0, min(100, score)), "indicators": indicators}


# ── 3. Pixel Pattern Analysis ────────────────────────────────────────────────

def analyze_pixel_patterns(image_bytes: bytes) -> dict:
    """Analyze pixel-level patterns for AI generation signatures."""
    result = {
        "noiseDistribution": "unknown",
        "noiseScore": 0,
        "colorGradients": "unknown",
        "gradientScore": 0,
        "compressionArtifacts": False,
        "compressionScore": 0,
        "patternConsistency": "unknown",
        "patternScore": 0,
        "overallScore": 0,
        "indicators": [],
    }

    if not Image or not np:
        return result

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        # Resize for faster analysis
        max_dim = 256
        if img.width > max_dim or img.height > max_dim:
            ratio = min(max_dim / img.width, max_dim / img.height)
            img = img.resize((int(img.width * ratio), int(img.height * ratio)), Image.LANCZOS)

        arr = np.array(img, dtype=np.float32)

        # ── Noise analysis ──
        # Compute local noise via Laplacian-like filter
        gray = np.mean(arr, axis=2)
        if gray.shape[0] > 2 and gray.shape[1] > 2:
            laplacian = np.abs(
                gray[1:-1, 1:-1] * 4
                - gray[:-2, 1:-1] - gray[2:, 1:-1]
                - gray[1:-1, :-2] - gray[1:-1, 2:]
            )
            noise_mean = float(np.mean(laplacian))
            noise_std = float(np.std(laplacian))

            if noise_std < 3.0 and noise_mean < 5.0:
                result["noiseDistribution"] = "suspicious"
                result["noiseScore"] = 75
                result["indicators"].append({
                    "signal": "Unnaturally uniform noise distribution",
                    "detail": f"Noise σ={noise_std:.1f}, μ={noise_mean:.1f} — hallmark of AI generation",
                    "severity": "high",
                    "type": "red"
                })
            elif noise_std < 8.0:
                result["noiseDistribution"] = "suspicious"
                result["noiseScore"] = 45
                result["indicators"].append({
                    "signal": "Low noise variance",
                    "detail": f"Noise σ={noise_std:.1f} — smoother than typical photographs",
                    "severity": "medium",
                    "type": "yellow"
                })
            else:
                result["noiseDistribution"] = "normal"
                result["noiseScore"] = 15
                result["indicators"].append({
                    "signal": "Natural noise patterns",
                    "detail": "Noise distribution consistent with real camera sensors",
                    "severity": "low",
                    "type": "green"
                })

        # ── Color gradient analysis ──
        dx = np.diff(arr, axis=1)
        dy = np.diff(arr, axis=0)
        grad_mag = np.sqrt(np.mean(dx[:, :, :] ** 2) + np.mean(dy[:, :, :] ** 2))
        grad_std = float(np.std(np.sqrt(np.sum(dx ** 2, axis=2))))

        if grad_std < 8.0:
            result["colorGradients"] = "unusual"
            result["gradientScore"] = 70
            result["indicators"].append({
                "signal": "Unusually smooth color gradients",
                "detail": "Gradient uniformity suggests AI diffusion model output",
                "severity": "high",
                "type": "red"
            })
        elif grad_std < 15.0:
            result["colorGradients"] = "suspicious"
            result["gradientScore"] = 40
        else:
            result["colorGradients"] = "normal"
            result["gradientScore"] = 10
            result["indicators"].append({
                "signal": "Natural color gradients",
                "detail": "Color transitions look natural",
                "severity": "low",
                "type": "green"
            })

        # ── Compression artifacts ──
        # Check for 8x8 block artifacts (JPEG)
        if gray.shape[0] >= 16 and gray.shape[1] >= 16:
            block_size = 8
            h_blocks = gray.shape[0] // block_size
            w_blocks = gray.shape[1] // block_size
            block_vars = []
            for bi in range(min(h_blocks, 8)):
                for bj in range(min(w_blocks, 8)):
                    block = gray[bi*block_size:(bi+1)*block_size, bj*block_size:(bj+1)*block_size]
                    block_vars.append(float(np.var(block)))

            if block_vars:
                var_of_vars = float(np.var(block_vars))
                if var_of_vars < 20:
                    result["compressionArtifacts"] = True
                    result["compressionScore"] = 60
                    result["indicators"].append({
                        "signal": "Compression artifacts detected",
                        "detail": "Block-level uniformity suggests AI-generated compression patterns",
                        "severity": "medium",
                        "type": "yellow"
                    })

        # ── Pattern consistency (region uniformity) ──
        h, w = arr.shape[:2]
        if h >= 64 and w >= 64:
            regions = [
                arr[:h//2, :w//2],
                arr[:h//2, w//2:],
                arr[h//2:, :w//2],
                arr[h//2:, w//2:],
            ]
            region_stds = [float(np.std(r)) for r in regions]
            std_of_stds = float(np.std(region_stds))
            if std_of_stds < 5.0:
                result["patternConsistency"] = "repetitive"
                result["patternScore"] = 65
                result["indicators"].append({
                    "signal": "Repetitive texture patterns",
                    "detail": "All image regions have similar texture complexity — AI signature",
                    "severity": "medium",
                    "type": "yellow"
                })
            else:
                result["patternConsistency"] = "consistent"
                result["patternScore"] = 15

        # ── Color channel correlation ──
        r, g, b = arr[:,:,0].flatten(), arr[:,:,1].flatten(), arr[:,:,2].flatten()
        if len(r) > 100:
            corr_rg = float(np.corrcoef(r, g)[0, 1])
            corr_rb = float(np.corrcoef(r, b)[0, 1])
            avg_corr = (abs(corr_rg) + abs(corr_rb)) / 2
            if avg_corr > 0.92:
                result["indicators"].append({
                    "signal": "Extremely high color channel correlation",
                    "detail": f"R-G: {corr_rg:.3f}, R-B: {corr_rb:.3f} — typical of AI imagery",
                    "severity": "high",
                    "type": "red"
                })

        # Overall pixel score
        result["overallScore"] = max(0, min(100, int(
            result["noiseScore"] * 0.3 +
            result["gradientScore"] * 0.25 +
            result["compressionScore"] * 0.2 +
            result["patternScore"] * 0.25
        )))

    except Exception as e:
        logger.error("Pixel analysis error: %s", e)
        result["indicators"].append({
            "signal": "Pixel analysis incomplete",
            "detail": str(e),
            "severity": "low",
            "type": "yellow"
        })

    return result


# ── 4. HuggingFace API Call ──────────────────────────────────────────────────

HUGGINGFACE_MODELS = [
    "umm-maybe/AI-image-detector",
    "Organika/sdxl-detector",
]

def call_huggingface_api(image_bytes: bytes) -> dict:
    """Call HuggingFace Inference API for AI image detection.
    Returns: {"aiGenerationScore": 0-100, "model": str, "raw": dict, "available": bool}
    """
    api_key = os.getenv("HUGGINGFACE_API_KEY")
    if not api_key:
        logger.info("HUGGINGFACE_API_KEY not set — skipping HuggingFace analysis")
        return {"aiGenerationScore": 0, "model": "none", "raw": {}, "available": False}

    headers = {"Authorization": f"Bearer {api_key}"}

    for model_id in HUGGINGFACE_MODELS:
        try:
            url = f"https://api-inference.huggingface.co/models/{model_id}"
            response = http_requests.post(url, headers=headers, data=image_bytes, timeout=15)

            if response.status_code == 503:
                # Model loading
                logger.info("HuggingFace model %s is loading, trying next...", model_id)
                continue

            if response.status_code != 200:
                logger.warning("HuggingFace %s returned %d", model_id, response.status_code)
                continue

            data = response.json()

            # Parse classification results
            ai_score = 0
            if isinstance(data, list) and len(data) > 0:
                # Format: [{"label": "artificial", "score": 0.95}, {"label": "human", "score": 0.05}]
                if isinstance(data[0], list):
                    data = data[0]
                for item in data:
                    label = item.get("label", "").lower()
                    score = item.get("score", 0)
                    if any(k in label for k in ["artificial", "ai", "fake", "generated", "ai_generated"]):
                        ai_score = int(score * 100)
                    elif any(k in label for k in ["human", "real", "authentic", "not_ai"]):
                        ai_score = int((1 - score) * 100)

            return {
                "aiGenerationScore": ai_score,
                "model": model_id,
                "raw": data if isinstance(data, (list, dict)) else {},
                "available": True,
            }

        except Exception as e:
            logger.warning("HuggingFace API error for %s: %s", model_id, e)
            continue

    return {"aiGenerationScore": 0, "model": "none", "raw": {}, "available": False}


# ── 5. Flag Generation ───────────────────────────────────────────────────────

def generate_flags(metadata: dict, pixel_analysis: dict, hf_result: dict) -> list:
    """Generate list of red flags found."""
    flags = []

    if metadata.get("hasMissingEXIF"):
        flags.append({"flag": "missing_exif", "label": "Missing EXIF Data", "severity": "high",
                       "detail": "AI-generated images lack camera metadata"})

    if pixel_analysis.get("noiseDistribution") == "suspicious":
        flags.append({"flag": "noise_anomaly", "label": "Noise Pattern Anomaly", "severity": "high",
                       "detail": "Unnaturally uniform noise detected"})

    if pixel_analysis.get("colorGradients") in ["unusual", "suspicious"]:
        flags.append({"flag": "gradient_anomaly", "label": "Color Gradient Anomaly", "severity": "medium",
                       "detail": "Smooth gradients typical of diffusion models"})

    if pixel_analysis.get("compressionArtifacts"):
        flags.append({"flag": "compression_artifacts", "label": "Compression Artifacts", "severity": "medium",
                       "detail": "Block-level compression patterns detected"})

    if pixel_analysis.get("patternConsistency") == "repetitive":
        flags.append({"flag": "repetitive_pattern", "label": "Repetitive Patterns", "severity": "medium",
                       "detail": "Texture uniformity across regions"})

    if hf_result.get("aiGenerationScore", 0) > 60:
        flags.append({"flag": "ai_model_detection", "label": "AI Model Detection", "severity": "high",
                       "detail": f"AI classifier confidence: {hf_result['aiGenerationScore']}%"})

    w = metadata.get("width")
    h = metadata.get("height")
    if w and h:
        ai_dims = [(512,512),(768,768),(1024,1024),(2048,2048),(1536,1536)]
        if (w, h) in ai_dims:
            flags.append({"flag": "ai_dimensions", "label": "AI-Typical Dimensions", "severity": "medium",
                           "detail": f"{w}×{h} matches known AI output sizes"})

    return flags


# ── 6. Recommendation ────────────────────────────────────────────────────────

def get_recommendation(risk_score: int) -> dict:
    """Return recommendation based on final risk score."""
    if risk_score <= 30:
        return {
            "level": "low",
            "title": "Likely Authentic",
            "message": "This image appears to be an authentic photograph. Camera metadata and pixel patterns are consistent with real-world captures.",
            "icon": "✅",
            "color": "green",
        }
    elif risk_score <= 60:
        return {
            "level": "medium",
            "title": "Inconclusive",
            "message": "This image has mixed indicators. Some patterns suggest potential AI generation, but results are not definitive. Consider reverse image search for verification.",
            "icon": "⚠️",
            "color": "yellow",
        }
    else:
        return {
            "level": "high",
            "title": "Likely AI-Generated",
            "message": "Multiple AI generation indicators detected. Missing metadata, unusual pixel patterns, and/or AI classifier results suggest this image was likely created by an AI model.",
            "icon": "🔴",
            "color": "red",
        }


# ── 7. Full Analysis Pipeline ────────────────────────────────────────────────

def analyze_image_full(image_bytes: bytes, filename: str = "", content_type: str = "") -> dict:
    """Run complete multi-method ensemble image analysis pipeline.

    Sources (auto-detected):
      • EXIF metadata           — authenticity baseline
      • Pixel forensics         — noise / gradient / pattern signatures
      • HuggingFace classifier  — pretrained AI-detection model
      • OpenAI Vision           — semantic realism reasoning
      • Claude Vision           — artefact reasoning
    """

    # Step 1: Metadata
    metadata = extract_exif_metadata(image_bytes, filename)
    meta_result = score_metadata(metadata)
    metadata_score = meta_result["score"]

    # Step 2: Pixel forensics
    pixel_analysis = analyze_pixel_patterns(image_bytes)
    pixel_score = pixel_analysis["overallScore"]

    # Step 3: HuggingFace
    hf_result = call_huggingface_api(image_bytes)
    hf_score = hf_result.get("aiGenerationScore", 0)

    # Step 4: Vision LLM ensemble
    openai_vision = call_openai_vision(image_bytes)
    claude_vision = call_claude_vision(image_bytes)

    vision_results = []
    if openai_vision.get("available"):
        vision_results.append(openai_vision)
    if claude_vision.get("available"):
        vision_results.append(claude_vision)

    vision_score = (
        sum(v["ai_score"] for v in vision_results) // len(vision_results)
        if vision_results else 0
    )
    vision_available = len(vision_results) > 0

    # Step 5: Weighted ensemble — vision LLMs carry the most weight when present
    # because they understand semantic content (faces, hands, scenes), while
    # forensic signals are noisy on their own.
    weights = {"metadata": 0.0, "pixel": 0.0, "hf": 0.0, "vision": 0.0}

    if vision_available and hf_result.get("available"):
        weights = {"metadata": 0.10, "pixel": 0.20, "hf": 0.20, "vision": 0.50}
    elif vision_available:
        weights = {"metadata": 0.15, "pixel": 0.25, "hf": 0.0, "vision": 0.60}
    elif hf_result.get("available"):
        weights = {"metadata": 0.20, "pixel": 0.35, "hf": 0.45, "vision": 0.0}
    else:
        weights = {"metadata": 0.35, "pixel": 0.65, "hf": 0.0, "vision": 0.0}

    final_score = int(
        metadata_score * weights["metadata"]
        + pixel_score * weights["pixel"]
        + hf_score * weights["hf"]
        + vision_score * weights["vision"]
    )

    # Calibration: if both vision LLMs strongly agree, trust them more
    if len(vision_results) == 2:
        agree = abs(vision_results[0]["ai_score"] - vision_results[1]["ai_score"]) <= 20
        avg_v = (vision_results[0]["ai_score"] + vision_results[1]["ai_score"]) // 2
        if agree and avg_v >= 75:
            final_score = max(final_score, avg_v - 5)
        elif agree and avg_v <= 20:
            final_score = min(final_score, avg_v + 10)

    final_score = max(0, min(100, final_score))

    if final_score <= 30:
        classification = "Likely Authentic"
    elif final_score <= 60:
        classification = "Inconclusive"
    else:
        classification = "Likely AI-Generated"

    flags = generate_flags(metadata, pixel_analysis, hf_result)

    # Add Vision-LLM flags
    for v in vision_results:
        if v["ai_score"] >= 70:
            flags.append({
                "flag": f"vision_{v['model']}",
                "label": f"Vision AI ({v['model']})",
                "severity": "high",
                "detail": f"{v['model']} confidence: {v['ai_score']}% — {v.get('verdict', 'likely AI')}",
            })

    recommendation = get_recommendation(final_score)

    # Confidence: more independent sources = higher confidence
    sources_count = (
        1
        + (1 if hf_result.get("available") else 0)
        + len(vision_results)
    )
    confidence = min(98, 55 + sources_count * 10 + len(flags) * 2)

    # Combine indicators from all sources
    all_indicators = list(meta_result["indicators"]) + list(pixel_analysis.get("indicators", []))
    for v in vision_results:
        for ind in v.get("indicators", [])[:4]:
            all_indicators.append({
                "signal": str(ind),
                "detail": f"Visual indicator from {v['model']}",
                "severity": "high" if v["ai_score"] >= 70 else "medium",
                "type": "red" if v["ai_score"] >= 70 else "yellow",
            })

    # Build a unified "Why flagged?" reasoning
    reasoning_parts = []
    for v in vision_results:
        if v.get("reasoning"):
            reasoning_parts.append(f"[{v['model']}] {v['reasoning']}")
    why_flagged = " ".join(reasoning_parts) if reasoning_parts else (
        f"Forensic signals: metadata score {metadata_score}/100, pixel-pattern score {pixel_score}/100."
    )

    tips = []
    if final_score > 30:
        tips.append("Use Google Reverse Image Search to verify the origin.")
        tips.append("Zoom in on details: fingers, text, earrings, and teeth.")
        tips.append("Check for inconsistent lighting and shadow directions.")
        tips.append("Look for watermarks or creator attribution.")
    tips.append("AI detection is probabilistic — no tool is 100% accurate.")

    return {
        "riskScore": final_score,
        "classification": classification,
        "metadata": metadata,
        "metadataScore": metadata_score,
        "metadataIndicators": meta_result["indicators"],
        "pixelAnalysis": {
            "noiseDistribution": pixel_analysis["noiseDistribution"],
            "noiseScore": pixel_analysis["noiseScore"],
            "colorGradients": pixel_analysis["colorGradients"],
            "gradientScore": pixel_analysis["gradientScore"],
            "compressionArtifacts": pixel_analysis["compressionArtifacts"],
            "compressionScore": pixel_analysis["compressionScore"],
            "patternConsistency": pixel_analysis["patternConsistency"],
            "patternScore": pixel_analysis["patternScore"],
            "overallScore": pixel_analysis["overallScore"],
            "indicators": pixel_analysis.get("indicators", []),
        },
        "aiDetection": {
            "score": hf_score,
            "model": hf_result.get("model", "none"),
            "available": hf_result.get("available", False),
            "raw": hf_result.get("raw", {}),
        },
        "visionAnalysis": {
            "available": vision_available,
            "ensembleScore": vision_score,
            "openai": openai_vision,
            "claude": claude_vision,
            "reasoning": why_flagged,
        },
        "whyFlagged": why_flagged,
        "flags": flags,
        "recommendation": recommendation,
        "confidence": confidence,
        "allIndicators": all_indicators,
        "tips": tips,
        "scoreBreakdown": {
            "metadata": metadata_score,
            "pixelAnalysis": pixel_score,
            "aiModel": hf_score if hf_result.get("available") else None,
            "visionLLM": vision_score if vision_available else None,
            "weights": {
                "metadata": weights["metadata"],
                "pixelAnalysis": weights["pixel"],
                "aiModel": weights["hf"],
                "visionLLM": weights["vision"],
            },
            "sourcesUsed": sources_count,
        },
    }
