// TruthShield Background Service Worker (Manifest V3)

const API_URL = "https://truth-guard-1.onrender.com"; // Render deployed backend

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

    // Store loading state so popup can detect it
    chrome.storage.local.set({ truthshield_loading: true, truthshield_result: null });

    // Try sending message to popup (may fail if popup is closed — that's ok)
    try { chrome.runtime.sendMessage({ type: "analysis_start" }); } catch (_) {}

    let result;
    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });

      if (!response.ok) throw new Error(`Server error: ${response.status}`);
      result = await response.json();
    } catch (err) {
      // Fallback to local heuristic analysis
      result = analyzeLocally(text);
    }

    // Store result and update badge
    chrome.storage.local.set({ truthshield_result: result, truthshield_loading: false });

    // Set badge to show risk score
    const badgeColor =
      result.classification === "Safe" ? "#22c55e" :
      result.classification === "Suspicious" ? "#eab308" : "#ef4444";

    chrome.action.setBadgeText({ text: String(result.risk_score) });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor });

    // Try notifying popup
    try { chrome.runtime.sendMessage({ type: "analysis_result", data: result }); } catch (_) {}
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

  const scamHits = SCAM_KEYWORDS.filter((kw) => lower.includes(kw));
  const scamScore = Math.min(100, scamHits.length * 18);

  const urgencyHits = URGENCY_PHRASES.filter((p) => lower.includes(p));
  const emoScore = Math.min(100, urgencyHits.length * 22);

  const aiHits = AI_PATTERNS.filter((p) => lower.includes(p));
  const aiScore = Math.min(100, aiHits.length * 20);

  const riskScore = Math.min(100, Math.round(aiScore * 0.3 + scamScore * 0.4 + emoScore * 0.3));

  const classification =
    riskScore < 30 ? "Safe" :
    riskScore < 65 ? "Suspicious" : "High Risk";

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