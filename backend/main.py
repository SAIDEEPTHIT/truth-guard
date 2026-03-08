"""TruthShield – FastAPI Backend

Run:  uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from analyzer import analyze_text

app = FastAPI(
    title="TruthShield API",
    version="1.0.0",
    description="Explainable AI API for detecting scams, AI-generated content, and manipulation.",
)

# Allow requests from Chrome extension and local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response schemas ─────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="Text to analyze")


class SignalsResponse(BaseModel):
    ai_generated: int
    scam_keywords: int
    emotional_manipulation: int


class AnalyzeResponse(BaseModel):
    risk_score: int
    classification: str
    signals: SignalsResponse
    suspicious_phrases: list[str]
    highlighted_text: str


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "TruthShield API"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    """Analyze text for scam indicators, AI patterns, and emotional manipulation."""
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
    )


@app.get("/health")
def health():
    return {"status": "healthy"}
