# TruthShield — System Documentation

## Table of Contents

1. [System Overview](#1-system-overview)
2. [System Architecture](#2-system-architecture)
3. [Extension Workflow](#3-extension-workflow)
4. [Backend API Documentation](#4-backend-api-documentation)
5. [Detection Modules](#5-detection-modules)
6. [Frontend Web Application](#6-frontend-web-application)
7. [Deployment Instructions](#7-deployment-instructions)

---

## 1. System Overview

**TruthShield** is an explainable AI system for detecting scams, AI-generated content, and emotional manipulation in text and images. It provides:

- **Chrome Extension** (Manifest V3) — right-click analysis on any webpage
- **React Web Dashboard** — full-featured analysis UI with evaluation metrics
- **FastAPI Backend** — server-side NLP analysis engine
- **Local Fallback Engine** — browser-side heuristic analysis when the server is unreachable

The system is designed with India-specific fraud intelligence (KYC scams, UPI fraud, OTP theft, bank impersonation) and a Senior-Friendly accessibility mode.

---

## 2. System Architecture

### 2.1 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                          USER LAYER                                 │
│                                                                     │
│   ┌──────────────────┐         ┌──────────────────────────────┐    │
│   │  Chrome Extension │         │  React Web Dashboard         │    │
│   │  (Manifest V3)    │         │  (Vite + React + TypeScript) │    │
│   │                   │         │                              │    │
│   │  • Context Menus  │         │  • Text Analyzer Page        │    │
│   │  • Popup UI       │         │  • Image Analyzer Page       │    │
│   │  • Local Fallback │         │  • Evaluation Dashboard      │    │
│   │  • Senior Mode    │         │  • Analysis History          │    │
│   └────────┬─────────┘         │  • Senior Mode Toggle        │    │
│            │                    └──────────────┬───────────────┘    │
└────────────┼───────────────────────────────────┼────────────────────┘
             │ POST /analyze                     │ POST /analyze
             │ POST /analyze-image               │ POST /analyze-image
             ▼                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       BACKEND LAYER                                 │
│                                                                     │
│   ┌──────────────────────────────────────────────────────────┐     │
│   │  FastAPI Server (Python)                                  │     │
│   │  Hosted on Render: https://truth-guard-1.onrender.com     │     │
│   │                                                           │     │
│   │  ┌────────────┐  ┌────────────────┐  ┌───────────────┐  │     │
│   │  │ Text       │  │ Image          │  │ Health/Root   │  │     │
│   │  │ Analyzer   │  │ Analyzer       │  │ Endpoints     │  │     │
│   │  │            │  │                │  │               │  │     │
│   │  │ • Scam KWs │  │ • EXIF Check   │  │ GET /         │  │     │
│   │  │ • Urgency  │  │ • Dimensions   │  │ GET /health   │  │     │
│   │  │ • AI Patt. │  │ • Filename     │  │               │  │     │
│   │  │ • India    │  │ • Byte Analysis│  └───────────────┘  │     │
│   │  │ • Stylom.  │  │ • Format Check │                      │     │
│   │  └────────────┘  └────────────────┘                      │     │
│   └──────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Summary

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Chrome Extension | Manifest V3, Vanilla JS | Browser integration, right-click analysis |
| Web Dashboard | React 18, Vite, TypeScript, Tailwind CSS, Recharts | Full analysis UI, evaluation metrics |
| Backend API | Python, FastAPI, Pydantic | Server-side NLP and image analysis |
| Local Fallback | JavaScript (in extension) | Offline analysis when backend is unreachable |

### 2.3 Data Flow

```
User Input (Text/Image)
    │
    ├──► Extension: Right-click context menu
    │       │
    │       ├──► Try: POST to FastAPI backend
    │       │       └──► Return server result
    │       │
    │       └──► Catch: Run local heuristic fallback
    │               └──► Return local result
    │
    └──► Web App: Paste/upload in UI
            │
            ├──► Try: POST to FastAPI backend
            │       └──► Display result + save to analysisStore
            │
            └──► Catch: Run client-side analyzer.ts
                    └──► Display result + save to analysisStore
```

---

## 3. Extension Workflow

### 3.1 Installation

1. Open `chrome://extensions`
2. Enable **Developer Mode**
3. Click **Load Unpacked** → select the `extension/` folder

### 3.2 Usage Workflow

#### Text Analysis
1. User highlights text on any webpage
2. Right-click → **"🛡️ Analyze Text with TruthShield"**
3. `background.js` sends `POST /analyze` to the FastAPI backend
4. On failure, falls back to `analyzeTextLocally()` (built-in heuristic engine)
5. Result stored in `chrome.storage.local`
6. Popup displays: risk score, classification, signals, explanations, tips

#### Image Analysis
1. User right-clicks any image → **"🖼️ Check if Image is AI-Generated"**
2. `background.js` fetches the image and sends it as `FormData` to `POST /analyze-image`
3. On failure, runs local image analysis (dimension heuristics, filename patterns)
4. Popup displays: AI probability, classification, explanation signals

#### Link Safety Check
1. User right-clicks any hyperlink → **"🔗 Check Link Safety"**
2. `background.js` runs `analyzeURLDetailed()` locally
3. Checks: suspicious TLDs, URL length, IP addresses, homograph attacks, shortener usage
4. Result displayed in popup

### 3.3 Senior Mode (Extension)

- Toggle stored in `chrome.storage.local` as `truthshield_senior_mode`
- Activates: larger text, high-contrast theme, simplified risk indicators
- Persists across popup sessions

### 3.4 File Structure

| File | Purpose |
|------|---------|
| `manifest.json` | Extension configuration (Manifest V3) |
| `background.js` | Service worker: context menus, API calls, local analysis engines |
| `content.js` | Content script: captures selected text |
| `popup.html` | Popup UI with results display and Senior Mode toggle |
| `popup.js` | Popup logic: reads `chrome.storage.local`, renders results |

---

## 4. Backend API Documentation

**Base URL:** `https://truth-guard-1.onrender.com`

### 4.1 `GET /`

Health check and service info.

**Response:**
```json
{
  "status": "ok",
  "service": "TruthShield API",
  "version": "3.0.0"
}
```

### 4.2 `GET /health`

Simple health check.

**Response:**
```json
{
  "status": "healthy",
  "version": "3.0.0"
}
```

### 4.3 `POST /analyze`

Analyze text for scam indicators, AI patterns, and emotional manipulation.

**Request Body:**
```json
{
  "text": "string (1–10000 chars, required)"
}
```

**Response (`AnalyzeResponse`):**

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | `int` (0–100) | Overall risk index |
| `classification` | `string` | `"Safe"` / `"Suspicious"` / `"High Risk"` |
| `signals.ai_generated` | `int` (0–100) | AI-generation signal strength |
| `signals.scam_keywords` | `int` (0–100) | Scam keyword signal strength |
| `signals.emotional_manipulation` | `int` (0–100) | Emotional/urgency manipulation signal |
| `suspicious_phrases` | `string[]` | All flagged phrases |
| `highlighted_text` | `string` | Original text with `<mark>` tags around flagged phrases |
| `explanations` | `Explanation[]` | Per-phrase explanations with category, reason, severity |
| `summary` | `string` | Human-readable risk summary |
| `tips` | `string[]` | Actionable safety tips |

**Explanation Object:**
```json
{
  "category": "scam | urgency | ai | india_scam",
  "phrase": "click here",
  "reason": "Vague links often lead to phishing sites.",
  "severity": "low | medium | high"
}
```

**Example:**
```bash
curl -X POST https://truth-guard-1.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Congratulations! You won a free gift. Share your OTP to claim."}'
```

### 4.4 `POST /analyze-image`

Analyze an uploaded image for AI-generation indicators.

**Request:** `multipart/form-data` with field `file` (image, max 20MB)

**Response (`ImageAnalyzeResponse`):**

| Field | Type | Description |
|-------|------|-------------|
| `ai_generated_probability` | `float` (0.0–1.0) | Probability of AI generation |
| `classification` | `string` | `"Likely Authentic"` / `"Possibly AI-Generated"` / `"Likely AI-Generated"` |
| `explanation` | `ImageExplanation[]` | Individual signal analysis |
| `risk_score` | `int` (0–100) | Overall risk score |
| `metadata` | `dict` | File size, content type, dimensions |
| `tips` | `string[]` | Verification tips |

**ImageExplanation Object:**
```json
{
  "signal": "No EXIF metadata — AI images lack camera data",
  "weight": 15,
  "type": "negative | positive"
}
```

### 4.5 Error Responses

| Status | Meaning |
|--------|---------|
| `400` | Empty text / Invalid file type / File too large |
| `422` | Validation error (Pydantic) |
| `500` | Internal server error |

---

## 5. Detection Modules

### 5.1 Text Analysis Engine

The text analyzer uses a **multi-factor weighted scoring** approach with four detection modules plus stylometric analysis:

#### Module 1: Scam Keyword Detection
- **38 patterns** covering phishing openers, prize claims, financial fraud, identity theft
- **Weight:** 15 points per regular scam hit, 20 points per financial phrase
- Examples: `"congratulations"`, `"verify your account"`, `"wire transfer"`, `"processing fee"`

#### Module 2: Urgency/Emotional Manipulation Detection
- **20 patterns** for time pressure, FOMO, threats, and fear tactics
- **Weight:** 10 points per hit
- Examples: `"act now"`, `"expires today"`, `"final notice"`, `"within 24 hours"`

#### Module 3: AI-Generated Content Detection
- **27 patterns** for AI self-identification, formulaic phrases, and overused buzzwords
- **Weight:** 16 points per hit (capped at 100)
- Examples: `"as an ai"`, `"delve into"`, `"it's important to note"`, `"multifaceted"`

#### Module 4: India-Specific Fraud Patterns
- **23 patterns** targeting region-specific scams
- Covers: KYC fraud, UPI/Paytm/PhonePe scams, OTP theft, bank impersonation (SBI, HDFC, ICICI), fake government notices (RBI, Income Tax)
- Examples: `"kyc update"`, `"share otp"`, `"debit card blocked"`, `"customs duty"`

#### Module 5: Stylometric Analysis
- Sentence length uniformity (std dev < 3 across 4+ sentences → +15)
- Average sentence length in AI-typical range (14–26 words → +8)
- Excessive hedging language (3+ hedging phrases → +10)
- Contraction frequency (< 0.5% in 50+ word texts → +8)
- **Capped at 40 points**

#### Scoring Formula
```
scam_points = regular_scam_hits × 15 + financial_hits × 20
urgency_points = urgency_hits × 10
ai_score = min(100, ai_hits × 16 + stylometric_score)
risk_score = clamp(0, 100, scam_points + urgency_points + ai_score × 0.3)
```

#### Classification Thresholds
| Risk Score | Classification |
|-----------|----------------|
| 0–30 | Safe |
| 31–60 | Suspicious |
| 61–100 | High Risk |

### 5.2 Image Analysis Engine

The image analyzer uses **heuristic binary analysis** without ML models:

| Check | Weight | Description |
|-------|--------|-------------|
| EXIF Metadata Absent | +15 | AI images lack camera EXIF data |
| EXIF Metadata Present | −15 | Real camera photos contain EXIF |
| Common AI Dimensions | +18 | 512×512, 1024×1024, 1920×1080, etc. |
| Multiples of 64 | +10 | AI model alignment dimensions |
| Square Aspect Ratio | +8 | Perfect squares common in AI |
| AI Tool in Filename | +25 | References to DALL-E, Midjourney, Stable Diffusion |
| Generic Filename | +5 | `image_001`, `download_123` patterns |
| Small JPEG | +8 | AI outputs often compressed |
| PNG Format | +5 | Common AI output format |
| WebP Format | +5 | Common in AI pipelines |
| Large File (>5MB) | −5 | Uncommon for AI outputs |
| Uniform Byte Distribution | +8 | AI images tend to be smoother |

#### Classification Thresholds
| Score | Classification |
|-------|----------------|
| 0–25 | Likely Authentic |
| 26–50 | Possibly AI-Generated |
| 51–100 | Likely AI-Generated |

### 5.3 URL Safety Analysis (Extension Only)

Local heuristic checks for suspicious URLs:
- Suspicious TLDs (`.xyz`, `.top`, `.buzz`, `.click`, etc.)
- Excessive URL length (>100 chars)
- IP-based URLs
- Homograph attacks (mixed scripts in domain)
- URL shortener detection
- Suspicious subdomains
- Special character abuse (`@` symbol in URL)

### 5.4 Readability Analysis

Flesch-Kincaid scoring applied to analyzed text:
- Word count, sentence count, syllable estimation
- Grade level mapping
- Readability classification (Easy / Moderate / Difficult)

### 5.5 Language Detection

Heuristic language detection for Hindi, Spanish, French, German, Chinese, Japanese, Korean, Arabic, and English (default).

---

## 6. Frontend Web Application

### 6.1 Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Landing | Hero, features, how-it-works |
| `/analyze` | Text Analyzer | Paste text, view analysis results |
| `/image-analysis` | Image Analyzer | Upload image, view AI detection results |
| `/dashboard` | Evaluation Dashboard | KPIs, charts, confusion matrix, model metrics |
| `/history` | Analysis History | Past analysis records |

### 6.2 Key Components

- **Navbar** — Navigation with Senior Mode toggle
- **RiskGauge** — Circular gauge visualization for risk scores
- **SignalBars** — Bar chart for signal strengths (AI, Scam, Manipulation)
- **ExplanationPanel** — Collapsible per-phrase explanations
- **AnalysisHistory** — Timestamped list of past analyses

### 6.3 Design System

- **Framework:** Tailwind CSS with HSL semantic tokens
- **UI Library:** shadcn/ui (Radix primitives)
- **Animations:** Framer Motion
- **Charts:** Recharts
- **Theme:** Dark-first cybersecurity aesthetic with `--primary`, `--accent`, `--muted` tokens

### 6.4 Senior Mode

Toggle switches the entire UI to:
- High-contrast white background with black text
- Larger font sizes (18px+ base)
- Simplified language ("Check a Message" vs "Analyze Text")
- Reduced visual complexity

---

## 7. Deployment Instructions

### 7.1 Backend (FastAPI on Render)

1. Push the `backend/` folder to a GitHub repository
2. Create a **Web Service** on [render.com](https://render.com)
3. Configure:

| Setting | Value |
|---------|-------|
| Name | `truthshield-api` |
| Root Directory | `backend` |
| Runtime | Python 3 |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| Plan | Free |

4. After deployment, your API is at: `https://truthshield-api.onrender.com`

> **Note:** Free Render tier spins down after inactivity. First request after idle takes ~30 seconds.

### 7.2 Frontend (Lovable / Vite)

The React web app is hosted via Lovable's preview infrastructure. To deploy independently:

```bash
npm install
npm run build
# Deploy the `dist/` folder to any static hosting (Netlify, Vercel, GitHub Pages)
```

### 7.3 Chrome Extension

1. Update `API_URL` in `extension/background.js` to your deployed backend URL
2. Open `chrome://extensions` → Enable Developer Mode
3. Click **Load Unpacked** → select the `extension/` folder
4. (Optional) Add icons to `extension/icons/` (16px, 48px, 128px PNGs)

### 7.4 Local Development

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend
npm install
npm run dev
```

---

## Appendix: Technology Stack

| Layer | Technologies |
|-------|-------------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui, Framer Motion, Recharts |
| Backend | Python 3, FastAPI, Pydantic, Uvicorn |
| Extension | Manifest V3, Chrome APIs (contextMenus, storage, activeTab) |
| Deployment | Render (backend), Lovable (frontend) |
| Analysis | Custom NLP heuristics, stylometric analysis, binary image heuristics |
