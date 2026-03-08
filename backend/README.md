# TruthShield Backend

## Setup

```bash
cd backend
pip install -r requirements.txt
```

## Run

```bash
uvicorn main:app --reload --port 8000
```

## Test

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Congratulations! You have been selected as a winner. Click here to claim your prize. Act now, this limited time offer expires today!"}'
```

Expected response:
```json
{
  "risk_score": 82,
  "classification": "High Risk",
  "signals": {
    "ai_generated": 0,
    "scam_keywords": 64,
    "emotional_manipulation": 60
  },
  "suspicious_phrases": ["congratulations", "you have been selected", "click here", "winner", "claim your prize", "act now", "limited time", "expires today"],
  "highlighted_text": "..."
}
```

## Deploy to Render

1. Create a new **Web Service** on [render.com](https://render.com)
2. Point to this repo's `backend/` directory
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
