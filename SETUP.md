# TruthShield – Full Stack Setup Guide

## Project Structure

```
truthshield/
├── extension/          # Chrome Extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── popup.js
│   └── icons/          # Add icon16.png, icon48.png, icon128.png
│
├── backend/            # FastAPI Backend
│   ├── main.py
│   ├── analyzer.py
│   ├── requirements.txt
│   └── README.md
```

---

## 1. Deploy FastAPI Backend on Render

### Step 1: Push to GitHub

Push the `backend/` folder to a GitHub repository.

### Step 2: Create Render Web Service

1. Go to [render.com](https://render.com) and sign up / log in
2. Click **New → Web Service**
3. Connect your GitHub repo
4. Configure the service:

| Setting         | Value                                          |
| --------------- | ---------------------------------------------- |
| **Name**        | `truthshield-api`                              |
| **Root Dir**    | `backend`                                      |
| **Runtime**     | `Python 3`                                     |
| **Build Cmd**   | `pip install -r requirements.txt`              |
| **Start Cmd**   | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| **Plan**        | Free                                           |

5. Click **Create Web Service**

### Step 3: Get Your API URL

After deployment, Render gives you a URL like:
```
https://truthshield-api.onrender.com
```

### Step 4: Test the API

```bash
curl -X POST https://truthshield-api.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Congratulations! You won a free gift. Act now, limited time only!"}'
```

---

## 2. Load Chrome Extension Locally

### Step 1: Update the API URL

Open `extension/background.js` and change line 3:

```js
// Before
const API_URL = "http://localhost:8000";

// After – use your Render URL
const API_URL = "https://truthshield-api.onrender.com";
```

### Step 2: Add Extension Icons (Optional)

Create an `extension/icons/` folder and add three PNG icons:
- `icon16.png` (16×16 px)
- `icon48.png` (48×48 px)
- `icon128.png` (128×128 px)

If you skip this, the extension will work but show a default icon.

### Step 3: Load in Chrome

1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `extension/` folder from your project
5. The TruthShield icon appears in your toolbar

### Step 4: Use It

1. Go to any webpage
2. **Highlight** any text you want to analyze
3. **Right-click** → select **"Analyze with TruthShield"**
4. Click the **TruthShield icon** in your toolbar to see results:
   - Risk score (0–100)
   - Classification (Safe / Suspicious / High Risk)
   - Signal breakdown (AI, Scam, Manipulation)
   - Highlighted suspicious phrases

---

## 3. Run Backend Locally (for Development)

```bash
cd backend
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

API is now at `http://localhost:8000`. Keep `API_URL` in `background.js` as `http://localhost:8000`.

---

## 4. Test Examples

### High Risk Text
```
Congratulations! You have been selected as a winner of our lottery. 
Click here to claim your prize immediately. Verify your account 
and wire transfer the processing fee. Act now — this limited time 
offer expires today! Don't miss out on this once in a lifetime opportunity.
```

### Safe Text
```
The quarterly earnings report shows a 12% increase in revenue 
compared to the previous quarter, driven by strong performance 
in the cloud services division.
```

---

## Notes

- The free Render tier may spin down after inactivity. First request after idle takes ~30 seconds.
- If the backend is unreachable, the extension falls back to **local heuristic analysis** in the browser.
- The extension works offline using the built-in fallback analyzer.
