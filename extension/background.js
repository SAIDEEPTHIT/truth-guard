// TruthShield Background Service Worker (Manifest V3)

const API_URL = "http://localhost:8000"; // Change to your deployed backend URL

// Create context menu on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "truthshield-analyze",
    title: "Analyze with TruthShield",
    contexts: ["selection"],
  });
});

// Handle context menu click
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "truthshield-analyze" && info.selectionText) {
    const text = info.selectionText.trim();
    if (!text) return;

    // Notify popup that analysis started
    chrome.runtime.sendMessage({ type: "analysis_start" });

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }

      const data = await response.json();

      // Store result and notify popup
      chrome.storage.local.set({ truthshield_result: data });
      chrome.runtime.sendMessage({ type: "analysis_result", data });
    } catch (err) {
      // If backend is unavailable, use local heuristic fallback
      const fallbackResult = analyzeLocally(text);
      chrome.storage.local.set({ truthshield_result: fallbackResult });
      chrome.runtime.sendMessage({ type: "analysis_result", data: fallbackResult });
    }
  }
});

// ── Local heuristic fallback ──────────────────────────────────────────────────

const SCAM_KEYWORDS = [
  "congratulations", "you have been selected", "claim your prize",
  "click here", "verify your account", "suspended", "winner",
  "free gift", "lottery", "inheritance", "wire transfer",
  "nigerian prince", "bank account", "social security",
  "password expired", "confirm your identity", "urgent action",
  "risk-free", "guaranteed", "double your money", "no obligation",
  "exclusive deal", "limited offer", "one-time", "act immediately",
];

const URGENCY_PHRASES = [
  "act now", "limited time", "urgent", "immediately", "expires today",
  "don't miss out", "last chance", "hurry", "right away", "deadline",
  "only today", "final notice", "respond immediately", "time sensitive",
  "within 24 hours", "before it's too late", "now or never",
];

const AI_PATTERNS = [
  "as an ai", "i cannot", "i'm an ai", "language model",
  "it's important to note", "in conclusion", "it is worth noting",
  "delve into", "moreover", "furthermore", "in the realm of",
  "it's crucial", "comprehensive", "facilitate", "leverage",
  "paradigm", "synergy", "utilize", "multifaceted",
];

function analyzeLocally(text) {
  const lower = text.toLowerCase();
  const words = lower.split(/\s+/);

  // Scam score
  const scamHits = SCAM_KEYWORDS.filter((kw) => lower.includes(kw));
  const scamScore = Math.min(100, scamHits.length * 18);

  // Urgency / emotional manipulation score
  const urgencyHits = URGENCY_PHRASES.filter((p) => lower.includes(p));
  const emoScore = Math.min(100, urgencyHits.length * 22);

  // AI-generated score
  const aiHits = AI_PATTERNS.filter((p) => lower.includes(p));
  const aiScore = Math.min(100, aiHits.length * 20);

  // Combined risk score
  const riskScore = Math.min(100, Math.round(aiScore * 0.3 + scamScore * 0.4 + emoScore * 0.3));

  const classification =
    riskScore < 30 ? "Safe" :
    riskScore < 65 ? "Suspicious" : "High Risk";

  // Build highlighted text
  const allSuspicious = [...scamHits, ...urgencyHits, ...aiHits];
  let highlightedText = text;
  allSuspicious.forEach((phrase) => {
    const regex = new RegExp(`(${phrase})`, "gi");
    highlightedText = highlightedText.replace(regex, "<mark>$1</mark>");
  });

  return {
    risk_score: riskScore,
    classification,
    signals: {
      ai_generated: aiScore,
      scam_keywords: scamScore,
      emotional_manipulation: emoScore,
    },
    highlighted_text: highlightedText,
    suspicious_phrases: allSuspicious,
  };
}