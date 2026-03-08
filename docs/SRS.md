# TruthShield — Software Requirements Specification (SRS)

**Version:** 1.0  
**Date:** March 2026  
**Project:** CSP67 Mini Project  
**Institution:** Dept. of Computer Science & Engineering, M.S. Ramaiah Institute of Technology  
**Team:** Shilpa G, Shreenanda S Naik, T Sai Deepthi  
**Guide:** Prof. Priya K

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Overall Description](#2-overall-description)
3. [Specific Requirements](#3-specific-requirements)
4. [System Features](#4-system-features)
5. [External Interface Requirements](#5-external-interface-requirements)
6. [Non-Functional Requirements](#6-non-functional-requirements)
7. [Use Cases](#7-use-cases)
8. [Data Dictionary](#8-data-dictionary)

---

## 1. Introduction

### 1.1 Purpose

This SRS defines the functional and non-functional requirements for **TruthShield**, an explainable AI system for detecting scams, AI-generated content, and emotional manipulation in online text and images. The system is designed with special focus on India-specific digital fraud patterns and accessibility for senior citizens.

### 1.2 Scope

TruthShield comprises:
- A Chrome browser extension for real-time analysis of web content
- A React-based web dashboard for manual analysis with visualization
- A FastAPI backend providing server-side NLP and image analysis
- A client-side fallback engine ensuring offline functionality

### 1.3 Definitions, Acronyms, and Abbreviations

| Term | Definition |
|------|-----------|
| NLP | Natural Language Processing |
| KYC | Know Your Customer |
| UPI | Unified Payments Interface |
| OTP | One-Time Password |
| EXIF | Exchangeable Image File Format |
| RLS | Row-Level Security |
| FOMO | Fear of Missing Out |
| Stylometry | Statistical analysis of writing style |

### 1.4 References

- IEEE 830-1998: Recommended Practice for Software Requirements Specifications
- Chrome Extensions Manifest V3 Documentation
- FastAPI Documentation (v0.100+)
- OWASP Phishing Detection Guidelines

### 1.5 Overview

Section 2 provides an overall system description. Section 3 details specific requirements. Section 4 describes system features. Sections 5–8 cover interfaces, non-functional requirements, use cases, and data dictionary.

---

## 2. Overall Description

### 2.1 Product Perspective

TruthShield is a standalone system with three deployment surfaces (extension, web app, API). It does not depend on external ML model APIs or third-party AI services — all analysis is performed using custom rule-based heuristics and stylometric algorithms.

### 2.2 Product Functions

1. **Text Risk Analysis** — Detect scam keywords, urgency manipulation, AI-generated patterns, and India-specific fraud
2. **Image AI Detection** — Heuristic analysis of image metadata, dimensions, and byte patterns
3. **URL Safety Check** — Analyze link suspiciousness via TLD, structure, and pattern analysis
4. **Explainable Output** — Every flagged indicator includes a human-readable reason
5. **Senior-Friendly Mode** — Accessibility mode with large text, high contrast, and simplified language
6. **Evaluation Dashboard** — Model performance metrics (accuracy, precision, recall, F1, confusion matrix)
7. **Analysis History** — Persistent record of past analyses with labeling support

### 2.3 User Classes and Characteristics

| User Class | Description | Technical Level |
|-----------|-------------|-----------------|
| General Users | Everyday internet users analyzing suspicious messages | Low–Medium |
| Senior Citizens | Elderly users vulnerable to online scams | Low (uses Senior Mode) |
| Researchers | Academics studying misinformation and AI content | High |
| Developers | Engineers integrating TruthShield API into other systems | High |

### 2.4 Operating Environment

- **Extension:** Google Chrome 88+ (Manifest V3 compatible)
- **Web App:** Any modern browser (Chrome, Firefox, Edge, Safari)
- **Backend:** Python 3.10+, any Linux/macOS/Windows server
- **Hosting:** Render.com (backend), Lovable (frontend)

### 2.5 Design and Implementation Constraints

- No external ML model dependencies (self-contained heuristics)
- Extension must work offline (local fallback engine)
- Backend is stateless (no database required for analysis)
- Maximum text input: 10,000 characters
- Maximum image upload: 20 MB
- Free Render tier has cold-start latency (~30 seconds)

### 2.6 Assumptions and Dependencies

- Users have Chrome browser for extension functionality
- Internet connection is available for backend API calls (graceful fallback without)
- Text input is in English or mixed English-Hindi
- Images are in JPEG, PNG, or WebP format

---

## 3. Specific Requirements

### 3.1 Functional Requirements

#### FR-01: Text Analysis
- **Input:** Text string (1–10,000 characters)
- **Output:** Risk score (0–100), classification, signal breakdown, flagged phrases with explanations, summary, tips
- **Processing:** Weighted multi-factor scoring across 4 keyword banks + stylometric analysis

#### FR-02: Image Analysis
- **Input:** Image file (JPEG/PNG/WebP, ≤20 MB)
- **Output:** AI probability, classification, signal explanations, metadata, tips
- **Processing:** EXIF check, dimension analysis, filename patterns, byte distribution

#### FR-03: URL Safety Analysis
- **Input:** URL string
- **Output:** Risk score, classification, flags
- **Processing:** TLD check, length analysis, IP detection, homograph detection, shortener detection

#### FR-04: Explainable Output
- Every flagged phrase must include: category, matched phrase, human-readable reason, severity level

#### FR-05: Senior Mode
- Toggle activates: high-contrast white theme, 18px+ font, simplified language
- State persists across sessions (localStorage for web, chrome.storage for extension)

#### FR-06: Analysis History
- All analyses are recorded with timestamp, input preview, risk score, classification
- Users can review and label past analyses

#### FR-07: Evaluation Dashboard
- Display: total analyses, high-risk rate, average risk score
- Charts: 30-day trends, risk distribution, per-class performance
- Metrics: accuracy, precision, recall, F1 score (computed from user-labeled records)
- Confusion matrix visualization

#### FR-08: Offline Fallback
- Extension must analyze text locally when backend is unreachable
- Local engine mirrors backend keyword banks and scoring logic

#### FR-09: Context Menu Integration
- Three context menu items: Analyze Text, Check Image, Check Link
- Results stored in chrome.storage.local and displayed in popup

#### FR-10: Badge Notification
- Chrome extension badge shows risk score with color coding
- Green (Safe), Yellow (Suspicious), Red (High Risk)

### 3.2 Performance Requirements

- Text analysis response: < 2 seconds (backend), < 500ms (local)
- Image analysis response: < 5 seconds
- Web app initial load: < 3 seconds
- Extension popup render: < 200ms

### 3.3 Security Requirements

- No user authentication required (stateless analysis)
- No personal data stored on server
- CORS configured for cross-origin requests
- Input validation: text length limits, file type checks, file size limits

---

## 4. System Features

### 4.1 Multi-Factor Text Analysis

**Priority:** High  
**Description:** Analyzes input text across four detection modules (scam keywords, urgency manipulation, AI patterns, India-specific fraud) plus stylometric analysis, producing a weighted risk score with explainable output.

**Stimulus:** User submits text via web app or selects text via extension context menu.  
**Response:** System returns risk score, classification, signal breakdown, flagged phrases with per-phrase explanations, summary, and actionable tips.

### 4.2 AI Image Detection

**Priority:** High  
**Description:** Analyzes uploaded images for AI-generation indicators using heuristic binary analysis (no ML model required).

**Stimulus:** User uploads image via web app or right-clicks image in browser.  
**Response:** System returns AI probability, classification, individual signal analysis, file metadata, and verification tips.

### 4.3 Evaluation Dashboard

**Priority:** Medium  
**Description:** Administrative dashboard displaying model performance metrics and analysis statistics over time.

**Stimulus:** User navigates to `/dashboard`.  
**Response:** System displays KPI cards, trend charts, risk distribution, and confusion matrix based on stored analysis records.

### 4.4 Senior-Friendly Accessibility

**Priority:** High  
**Description:** Toggle-activated accessibility mode that transforms the entire UI for elderly or non-technical users.

**Stimulus:** User activates Senior Mode toggle.  
**Response:** UI switches to high-contrast white theme with large text and simplified language.

---

## 5. External Interface Requirements

### 5.1 User Interfaces

- **Web Application:** Responsive React UI (320px–1920px viewport)
- **Extension Popup:** 380px wide HTML popup with dark theme
- **Extension Context Menu:** Three right-click options in browser

### 5.2 Hardware Interfaces

- Standard computer with Chrome browser
- No special hardware required

### 5.3 Software Interfaces

| Interface | Protocol | Format |
|-----------|----------|--------|
| Text Analysis API | HTTP POST | JSON |
| Image Analysis API | HTTP POST | multipart/form-data |
| Chrome Storage | chrome.storage.local | Key-value |
| Local Storage | Web Storage API | Key-value (JSON) |

### 5.4 Communication Interfaces

- HTTPS for API communication
- CORS-enabled for cross-origin access
- No authentication tokens required

---

## 6. Non-Functional Requirements

### 6.1 Performance

| Metric | Target |
|--------|--------|
| Text analysis latency (server) | < 2 seconds |
| Text analysis latency (local) | < 500ms |
| Image analysis latency | < 5 seconds |
| Frontend load time | < 3 seconds |
| Extension popup render | < 200ms |

### 6.2 Reliability

- Offline fallback ensures 100% availability for text analysis
- Backend cold-start handled gracefully with loading states
- No single point of failure for core analysis functionality

### 6.3 Availability

- Web app: 99%+ uptime (static hosting)
- Backend API: Subject to Render free tier availability
- Extension: 100% availability (local fallback)

### 6.4 Scalability

- Backend is stateless — horizontally scalable
- No database dependency for core analysis
- Client-side analysis offloads server load

### 6.5 Usability

- Senior Mode for accessibility
- Color-coded risk indicators (green/yellow/red)
- Per-phrase explanations (no "black box" output)
- Actionable safety tips with every analysis

### 6.6 Maintainability

- Keyword banks are declarative arrays — easy to add new patterns
- Modular analysis functions with clear separation of concerns
- TypeScript for frontend type safety
- Pydantic models for backend validation

### 6.7 Portability

- Frontend: Any modern browser
- Backend: Any Python 3.10+ environment
- Extension: Chrome 88+ (Manifest V3)

---

## 7. Use Cases

### UC-01: Analyze Suspicious Text Message

**Actor:** General User / Senior Citizen  
**Precondition:** User has received a suspicious message (SMS, WhatsApp, email)  
**Main Flow:**
1. User opens TruthShield web app or extension
2. User pastes/selects the suspicious text
3. System analyzes text across all detection modules
4. System displays risk score, classification, flagged phrases with explanations
5. User reads tips and decides whether to ignore, verify, or report the message

**Alternative Flow:** Backend unreachable → local fallback analysis runs  
**Postcondition:** User has an informed assessment of the message's risk level

### UC-02: Check if Image is AI-Generated

**Actor:** General User / Researcher  
**Precondition:** User encounters a suspicious image online  
**Main Flow:**
1. User uploads image to web app or right-clicks image in browser
2. System analyzes image metadata, dimensions, byte patterns
3. System displays AI probability, classification, and signal explanations
4. User reviews verification tips

**Postcondition:** User knows the likelihood of AI generation

### UC-03: Review Analysis History

**Actor:** Any User  
**Precondition:** User has performed previous analyses  
**Main Flow:**
1. User navigates to History page
2. System displays timestamped list of past analyses
3. User can review details of any past analysis

### UC-04: Evaluate Model Performance

**Actor:** Researcher / Developer  
**Precondition:** Multiple analyses have been performed and some labeled  
**Main Flow:**
1. User navigates to Evaluation Dashboard
2. System computes accuracy, precision, recall, F1 from labeled records
3. User reviews confusion matrix and trend charts
4. User labels additional records to improve metrics

### UC-05: Use Senior Mode

**Actor:** Senior Citizen  
**Precondition:** User finds default UI too complex  
**Main Flow:**
1. User clicks Senior Mode toggle
2. UI transforms: high contrast, large text, simple language
3. User performs analysis with simplified interface
4. Mode persists across sessions

---

## 8. Data Dictionary

### 8.1 AnalysisResult

| Field | Type | Description |
|-------|------|-------------|
| risk_score | Integer (0–100) | Weighted composite risk score |
| classification | Enum | "Safe" / "Suspicious" / "High Risk" |
| signals | Object | ai_generated, scam_keywords, emotional_manipulation (each 0–100) |
| suspicious_phrases | String[] | All matched phrases |
| highlighted_text | String | HTML with `<mark>` tags |
| explanations | Explanation[] | Per-phrase analysis |
| summary | String | Human-readable summary |
| tips | String[] | Actionable safety advice |

### 8.2 Explanation

| Field | Type | Description |
|-------|------|-------------|
| category | Enum | "scam" / "urgency" / "ai" / "india_scam" |
| phrase | String | Matched keyword or pattern |
| reason | String | Human-readable explanation |
| severity | Enum | "low" / "medium" / "high" |

### 8.3 ImageAnalysisResult

| Field | Type | Description |
|-------|------|-------------|
| ai_generated_probability | Float (0.0–1.0) | Probability estimate |
| classification | Enum | "Likely Authentic" / "Possibly AI-Generated" / "Likely AI-Generated" |
| explanation | ImageExplanation[] | Individual signal analysis |
| risk_score | Integer (0–100) | Composite score |
| metadata | Object | file_size, content_type, dimensions |
| tips | String[] | Verification advice |
