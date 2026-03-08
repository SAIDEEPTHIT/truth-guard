"""TruthShield – Enhanced FastAPI Backend v3.0

Run:  uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional

from analyzer import analyze_text, analyze_image

app = FastAPI(
    title="TruthShield API",
    version="3.0.0",
    description="Explainable AI API for detecting scams, AI-generated content, and manipulation with India-specific intelligence.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Schemas ────────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)


class SignalsResponse(BaseModel):
    ai_generated: int
    scam_keywords: int
    emotional_manipulation: int


class ExplanationResponse(BaseModel):
    category: str
    phrase: str
    reason: str
    severity: str


class AnalyzeResponse(BaseModel):
    risk_score: int
    classification: str
    signals: SignalsResponse
    suspicious_phrases: list[str]
    highlighted_text: str
    explanations: list[ExplanationResponse]
    summary: str
    tips: list[str]


class ImageExplanation(BaseModel):
    signal: str
    weight: int
    type: str


class ImageAnalyzeResponse(BaseModel):
    ai_generated_probability: float
    classification: str
    explanation: list[ImageExplanation]
    risk_score: int
    metadata: dict
    tips: list[str]


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "TruthShield API", "version": "3.0.0"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    """Analyze text for scam indicators, AI patterns, emotional manipulation, and India-specific fraud."""
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Text must not be empty")

    result = analyze_text(text)

    return AnalyzeResponse(
        risk_score=result.risk_score,
        classification=result.classification,
        signals=SignalsResponse(**result.signals),
        suspicious_phrases=result.suspicious_phrases,
        highlighted_text=result.highlighted_text,
        explanations=[ExplanationResponse(**e) for e in result.explanations],
        summary=result.summary,
        tips=result.tips,
    )


@app.post("/analyze-image", response_model=ImageAnalyzeResponse)
async def analyze_image_endpoint(file: UploadFile = File(...)):
    """Analyze an uploaded image for AI-generation indicators."""
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")

    image_data = await file.read()
    if len(image_data) > 20 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image too large (max 20MB)")

    result = analyze_image(image_data, filename=file.filename or "", content_type=file.content_type or "")

    return ImageAnalyzeResponse(
        ai_generated_probability=result.ai_generated_probability,
        classification=result.classification,
        explanation=[ImageExplanation(**e) for e in result.explanation],
        risk_score=result.risk_score,
        metadata=result.metadata,
        tips=result.tips,
    )


@app.get("/health")
def health():
    return {"status": "healthy", "version": "3.0.0"}
