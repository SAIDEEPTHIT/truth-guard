// TruthShield Background Service Worker (Manifest V3) — Enhanced

const API_URL = "https://truth-guard-1.onrender.com";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "truthshield-analyze",
    title: "Analyze with TruthShield",
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "truthshield-analyze" && info.selectionText) {
    const text = info.selectionText.trim();
    if (!text) return;

    chrome.storage.local.set({ truthshield_loading: true, truthshield_result: null });
    chrome.runtime.sendMessage({ type: "analysis_start" }).catch(() => {});

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
      result = analyzeLocally(text);
    }

    chrome.storage.local.set({ truthshield_result: result, truthshield_loading: false });

    const badgeColor =
      result.classification === "Safe" ? "#22c55e" :
      result.classification === "Suspicious" ? "#eab308" : "#ef4444";
    chrome.action.setBadgeText({ text: String(result.risk_score) });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor });

    try { chrome.runtime.sendMessage({ type: "analysis_result", data: result }); } catch (_) {}
  }
});

// ── Local heuristic analysis (enhanced with explanations) ──

const SCAM_KEYWORDS = [
  { phrase: "congratulations", reason: "Unsolicited congratulations are a classic phishing opener.", severity: "medium" },
  { phrase: "you have been selected", reason: "False selection claims make victims feel special.", severity: "high" },
  { phrase: "claim your prize", reason: "Prize claims from unknown sources are scams.", severity: "high" },
  { phrase: "click here", reason: "Vague links often lead to phishing sites.", severity: "medium" },
  { phrase: "verify your account", reason: "Legitimate services rarely ask this via messages.", severity: "high" },
  { phrase: "suspended", reason: "Account suspension threats create panic.", severity: "high" },
  { phrase: "winner", reason: "Unsolicited winner notifications are scam tactics.", severity: "medium" },
  { phrase: "free gift", reason: "Nothing is truly free — aims to collect your data.", severity: "medium" },
  { phrase: "lottery", reason: "You cannot win a lottery you never entered.", severity: "high" },
  { phrase: "inheritance", reason: "Fake inheritance scams trick victims into paying fees.", severity: "high" },
  { phrase: "wire transfer", reason: "Wire transfers are nearly impossible to reverse.", severity: "high" },
  { phrase: "bank account", reason: "Bank details in unsolicited messages = fraud.", severity: "high" },
  { phrase: "social security", reason: "No one asks for SSN via email or text.", severity: "high" },
  { phrase: "password expired", reason: "Fake password notices steal login credentials.", severity: "high" },
  { phrase: "confirm your identity", reason: "Identity requests in unsolicited messages = phishing.", severity: "high" },
  { phrase: "urgent action", reason: "Artificial urgency bypasses critical thinking.", severity: "high" },
  { phrase: "guaranteed", reason: "Guaranteed returns in unsolicited offers = fraud.", severity: "medium" },
  { phrase: "double your money", reason: "Hallmark of Ponzi schemes.", severity: "high" },
  { phrase: "limited offer", reason: "Artificial scarcity prevents rational decisions.", severity: "medium" },
  { phrase: "act immediately", reason: "Pressure prevents verification.", severity: "high" },
  { phrase: "million dollars", reason: "Unrealistic monetary promises = clear fraud.", severity: "high" },
  { phrase: "processing fee", reason: "Legitimate prizes never require upfront fees.", severity: "high" },
  { phrase: "send money", reason: "Requests to send money to strangers = fraud.", severity: "high" },
  { phrase: "western union", reason: "Untraceable payment method favored by scammers.", severity: "high" },
  { phrase: "arrest warrant", reason: "Law enforcement doesn't issue warrants via email.", severity: "high" },
];

const URGENCY_PHRASES = [
  { phrase: "act now", reason: "Creates false urgency.", severity: "high" },
  { phrase: "limited time", reason: "Artificial time pressure.", severity: "medium" },
  { phrase: "urgent", reason: "Urgency bypasses critical thinking.", severity: "medium" },
  { phrase: "immediately", reason: "Demands for immediate action prevent fact-checking.", severity: "medium" },
  { phrase: "expires today", reason: "Fake expiration dates create panic.", severity: "high" },
  { phrase: "last chance", reason: "False finality prevents evaluation.", severity: "high" },
  { phrase: "hurry", reason: "Rushing prevents consulting others.", severity: "medium" },
  { phrase: "final notice", reason: "Fake 'final notices' create fear.", severity: "high" },
  { phrase: "within 24 hours", reason: "Short deadlines prevent verification.", severity: "high" },
  { phrase: "before it's too late", reason: "Fear-based language triggers impulsive action.", severity: "high" },
  { phrase: "now or never", reason: "False ultimatum to force action.", severity: "high" },
  { phrase: "today only", reason: "False time limit prevents research.", severity: "high" },
];

const AI_PATTERNS = [
  { phrase: "as an ai", reason: "Direct AI self-identification.", severity: "high" },
  { phrase: "language model", reason: "Technical AI terminology.", severity: "high" },
  { phrase: "it's important to note", reason: "Formulaic AI hedging.", severity: "medium" },
  { phrase: "delve into", reason: "Overrepresented in AI content.", severity: "medium" },
  { phrase: "moreover", reason: "Formal connector overused by AI.", severity: "low" },
  { phrase: "furthermore", reason: "Disproportionately used by language models.", severity: "low" },
  { phrase: "in the realm of", reason: "Formulaic AI phrase.", severity: "medium" },
  { phrase: "comprehensive", reason: "AI models overuse this descriptor.", severity: "low" },
  { phrase: "leverage", reason: "Corporate/AI buzzword.", severity: "low" },
  { phrase: "paradigm", reason: "Overused in AI-generated content.", severity: "medium" },
  { phrase: "multifaceted", reason: "Overrepresented in AI writing.", severity: "medium" },
  { phrase: "harness the power", reason: "Formulaic AI phrase.", severity: "medium" },
  { phrase: "in today's world", reason: "Generic AI opener.", severity: "medium" },
  { phrase: "navigating the complexities", reason: "Abstract AI phrasing.", severity: "medium" },
];

const INDIA_SCAM_PATTERNS = [
  { phrase: "kyc update", reason: "Fake KYC requests steal Aadhaar/PAN details.", severity: "high" },
  { phrase: "aadhaar", reason: "Aadhaar requests in messages = identity theft.", severity: "high" },
  { phrase: "pan card", reason: "PAN requests via messages = tax fraud.", severity: "high" },
  { phrase: "upi", reason: "UPI scams trick users into unauthorized transactions.", severity: "high" },
  { phrase: "otp", reason: "OTP sharing = #1 digital fraud method in India.", severity: "high" },
  { phrase: "share otp", reason: "No legitimate service asks to share OTP.", severity: "high" },
  { phrase: "sbi", reason: "SBI impersonation = common banking scam.", severity: "high" },
  { phrase: "rbi", reason: "RBI impersonation = banking fraud.", severity: "high" },
  { phrase: "debit card blocked", reason: "Fake card blocking alerts steal details.", severity: "high" },
  { phrase: "income tax", reason: "Fake tax notices = phishing.", severity: "high" },
  { phrase: "crore", reason: "Promises of crores = lottery/investment scam.", severity: "high" },
  { phrase: "job offer", reason: "Unsolicited job offers via WhatsApp = fraud.", severity: "medium" },
  { phrase: "work from home", reason: "Fake work-from-home offers are rising.", severity: "medium" },
  { phrase: "electricity bill", reason: "Fake disconnection threats = payment fraud.", severity: "high" },
];

function analyzeLocally(text) {
  const lower = text.toLowerCase();

  const findMatches = (bank, category) => {
    const hits = []; const explanations = [];
    bank.forEach(item => {
      if (lower.includes(item.phrase)) {
        hits.push(item.phrase);
        explanations.push({ category, phrase: item.phrase, reason: item.reason, severity: item.severity });
      }
    });
    return { hits, explanations };
  };

  const scam = findMatches(SCAM_KEYWORDS, "scam");
  const urgency = findMatches(URGENCY_PHRASES, "urgency");
  const ai = findMatches(AI_PATTERNS, "ai");
  const india = findMatches(INDIA_SCAM_PATTERNS, "india_scam");

  const scamScore = Math.min(100, [...scam.hits, ...india.hits].length * 14);
  const emoScore = Math.min(100, urgency.hits.length * 18);
  const aiScore = Math.min(100, ai.hits.length * 16);
  const riskScore = Math.min(100, Math.round(aiScore * 0.3 + scamScore * 0.4 + emoScore * 0.3));

  const classification = riskScore < 30 ? "Safe" : riskScore < 65 ? "Suspicious" : "High Risk";

  const allSuspicious = [...new Set([...scam.hits, ...urgency.hits, ...ai.hits, ...india.hits])];
  const allExplanations = [...scam.explanations, ...urgency.explanations, ...ai.explanations, ...india.explanations];

  let highlightedText = text;
  allSuspicious.forEach(phrase => {
    const regex = new RegExp(`(${phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi");
    highlightedText = highlightedText.replace(regex, "<mark>$1</mark>");
  });

  // Generate summary
  let summary;
  if (classification === "Safe") {
    summary = "This content appears safe. No significant scam or manipulation indicators detected.";
  } else {
    const parts = [];
    if (scamScore > 30) parts.push("scam keywords");
    if (aiScore > 30) parts.push("AI-generated patterns");
    if (emoScore > 30) parts.push("emotional manipulation");
    if (india.hits.length > 0) parts.push("India-specific fraud patterns");
    summary = classification === "High Risk"
      ? `⚠️ HIGH RISK: Contains ${parts.join(", ")}. Do NOT share personal info or transfer money.`
      : `⚡ SUSPICIOUS: Shows signs of ${parts.join(", ")}. Verify the source before acting.`;
  }

  // Generate tips
  const tips = [];
  if (classification !== "Safe") {
    if (scam.hits.length > 0 || india.hits.length > 0) {
      tips.push("Never share personal info (Aadhaar, PAN, OTP, passwords) via messages.");
      tips.push("Verify sender identity through official channels.");
    }
    if (urgency.hits.length > 0) {
      tips.push("Legitimate organizations don't create artificial urgency.");
    }
    if (ai.hits.length > 0) {
      tips.push("Cross-check AI-generated claims with reliable sources.");
    }
    tips.push("When in doubt, consult a trusted person before acting.");
  }

  return {
    risk_score: riskScore,
    classification,
    signals: { ai_generated: aiScore, scam_keywords: scamScore, emotional_manipulation: emoScore },
    highlighted_text: highlightedText,
    suspicious_phrases: allSuspicious,
    explanations: allExplanations,
    summary,
    tips,
  };
}
