"""TruthShield – FastAPI Backend v5.0 (OpenAI-Powered + Community Blocklist)

Run:  uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional

from analyzer import analyze_text, analyze_image
from blocklist import (
    add_domain,
    get_blocklist,
    get_domain_details,
    upvote_domain,
    downvote_domain,
    get_stats,
    seed_demo_data,
    THREAT_TYPES,
)

app = FastAPI(
    title="TruthShield API",
    version="5.0.0",
    description="OpenAI-powered API for detecting scams, AI-generated content, and manipulation with India-specific intelligence. Includes community domain blocklist.",
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
    scam_type: str
    emotional_manipulation: bool
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


class AddDomainRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255)
    threat_type: str = Field(default="Other")
    description: str = Field(default="", max_length=500)
    proof_link: str = Field(default="", max_length=500)


# ── Analysis Endpoints ─────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "TruthShield API", "version": "5.0.0"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    """Analyze text for scam indicators using OpenAI GPT-4o-mini with rule-based overrides."""
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Text must not be empty")

    result = analyze_text(text)

    return AnalyzeResponse(
        risk_score=result.risk_score,
        classification=result.classification,
        scam_type=result.scam_type,
        emotional_manipulation=result.emotional_manipulation,
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


# ── Blocklist Endpoints ───────────────────────────────────────────────────────

@app.get("/api/blocklist/stats")
def blocklist_stats():
    """Return overall blocklist statistics."""
    return get_stats()


@app.post("/api/blocklist/add")
def blocklist_add(req: AddDomainRequest):
    """Report a domain to the community blocklist."""
    result = add_domain(req.domain, req.threat_type, req.description, req.proof_link)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@app.get("/api/blocklist")
def blocklist_list(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    threat_type: Optional[str] = Query(default=None),
    sort: str = Query(default="recently_added"),
    search: Optional[str] = Query(default=None),
):
    """Get paginated blocklist with filtering and sorting."""
    return get_blocklist(limit, offset, threat_type, sort, search)


@app.get("/api/blocklist/check")
def blocklist_check(domain: str = Query(..., min_length=1)):
    """Quick check if a domain is in the community blocklist (used by extension auto-warn).
    IMPORTANT: This must be defined BEFORE /{domain:path} to avoid route conflicts."""
    result = get_domain_details(domain)
    if not result:
        return {"blocked": False, "domain": domain}
    return {
        "blocked": True,
        "domain": result["domain"],
        "threat_type": result["threat_type"],
        "report_count": result["report_count"],
        "upvotes": result["upvotes"],
        "downvotes": result["downvotes"],
    }


@app.get("/api/blocklist/stats")
def blocklist_stats_detail():
    """Return overall blocklist statistics (alternate path)."""
    return get_stats()


@app.post("/api/blocklist/seed")
def blocklist_seed():
    """Seed demo data for presentation."""
    seed_demo_data()
    return {"success": True, "message": "Demo data seeded"}


@app.get("/api/blocklist/{domain:path}")
def blocklist_domain_details(domain: str):
    """Get detailed info for a specific domain.
    NOTE: This catch-all route MUST be defined AFTER /check, /stats, /seed."""
    result = get_domain_details(domain)
    if not result:
        raise HTTPException(status_code=404, detail="Domain not found")
    return result


@app.post("/api/blocklist/{domain:path}/upvote")
def blocklist_upvote(domain: str):
    """Upvote a blocked domain."""
    result = upvote_domain(domain)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@app.post("/api/blocklist/{domain:path}/downvote")
def blocklist_downvote(domain: str):
    """Downvote a blocked domain."""
    result = downvote_domain(domain)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@app.get("/health")
def health():
    return {"status": "healthy", "version": "5.0.0"}
