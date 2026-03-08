// TruthShield Background Service Worker (Manifest V3) — Enhanced v2.1
// Supports: Text analysis, Image analysis, URL safety check

const API_URL = "https://truth-guard-1.onrender.com";

// ── Context Menus ──
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "truthshield-analyze-text",
    title: "🛡️ Analyze Text with TruthShield",
    contexts: ["selection"],
  });
  chrome.contextMenus.create({
    id: "truthshield-analyze-image",
    title: "🖼️ Check if Image is AI-Generated",
    contexts: ["image"],
  });
  chrome.contextMenus.create({
    id: "truthshield-check-link",
    title: "🔗 Check Link Safety",
    contexts: ["link"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  // ── Text Analysis ──
  if (info.menuItemId === "truthshield-analyze-text" && info.selectionText) {
    const text = info.selectionText.trim();
    if (!text) return;

    chrome.storage.local.set({ truthshield_loading: true, truthshield_result: null, truthshield_mode: "text" });
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
      result = analyzeTextLocally(text);
    }

    // Add URL analysis to text result
    const urls = extractURLs(text);
    if (urls.length > 0) {
      result.url_analysis = urls.map(url => analyzeURL(url));
    }

    // Add readability + language
    result.readability = analyzeReadability(text);
    result.language = detectLanguage(text);

    chrome.storage.local.set({ truthshield_result: result, truthshield_loading: false, truthshield_mode: "text" });

    const badgeColor =
      result.classification === "Safe" ? "#22c55e" :
      result.classification === "Suspicious" ? "#eab308" : "#ef4444";
    chrome.action.setBadgeText({ text: String(result.risk_score) });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor });

    chrome.runtime.sendMessage({ type: "analysis_result", data: result }).catch(() => {});
  }

  // ── Image Analysis ──
  if (info.menuItemId === "truthshield-analyze-image" && info.srcUrl) {
    chrome.storage.local.set({ truthshield_loading: true, truthshield_result: null, truthshield_mode: "image" });
    chrome.runtime.sendMessage({ type: "analysis_start" }).catch(() => {});

    const result = await analyzeImageFromURL(info.srcUrl);

    chrome.storage.local.set({ truthshield_result: result, truthshield_loading: false, truthshield_mode: "image" });

    const badgeColor =
      result.classification === "Likely Authentic" ? "#22c55e" :
      result.classification === "Possibly AI-Generated" ? "#eab308" : "#ef4444";
    chrome.action.setBadgeText({ text: String(result.risk_score) });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor });

    chrome.runtime.sendMessage({ type: "analysis_result", data: result, mode: "image" }).catch(() => {});
  }

  // ── Link Safety ──
  if (info.menuItemId === "truthshield-check-link" && info.linkUrl) {
    chrome.storage.local.set({ truthshield_loading: true, truthshield_result: null, truthshield_mode: "url" });
    chrome.runtime.sendMessage({ type: "analysis_start" }).catch(() => {});

    const result = analyzeURLDetailed(info.linkUrl);

    chrome.storage.local.set({ truthshield_result: result, truthshield_loading: false, truthshield_mode: "url" });

    const badgeColor = result.risk_score < 30 ? "#22c55e" : result.risk_score < 65 ? "#eab308" : "#ef4444";
    chrome.action.setBadgeText({ text: String(result.risk_score) });
    chrome.action.setBadgeBackgroundColor({ color: badgeColor });

    chrome.runtime.sendMessage({ type: "analysis_result", data: result, mode: "url" }).catch(() => {});
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// LOCAL ANALYSIS ENGINES
// ══════════════════════════════════════════════════════════════════════════════

// ── Scam/AI/Urgency/India keyword banks ──

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
  { phrase: "bitcoin", reason: "Cryptocurrency requests in unsolicited messages = fraud.", severity: "high" },
  { phrase: "cryptocurrency", reason: "Crypto investment scams are rising rapidly.", severity: "medium" },
  { phrase: "investment opportunity", reason: "Unsolicited investment offers are often Ponzi schemes.", severity: "high" },
  { phrase: "dear customer", reason: "Generic greetings in official-looking emails = phishing.", severity: "medium" },
  { phrase: "dear user", reason: "Impersonal address in 'urgent' messages = red flag.", severity: "medium" },
  { phrase: "whatsapp", reason: "Scams frequently impersonate WhatsApp notifications.", severity: "low" },
  { phrase: "gift card", reason: "Gift card payment requests = untraceable scam.", severity: "high" },
  { phrase: "tech support", reason: "Unsolicited tech support calls/messages = scam.", severity: "high" },
  { phrase: "remote access", reason: "Remote access requests = complete system compromise.", severity: "high" },
  { phrase: "teamviewer", reason: "TeamViewer requests from strangers = scam.", severity: "high" },
  { phrase: "anydesk", reason: "AnyDesk requests from strangers = scam.", severity: "high" },
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
  { phrase: "don't ignore", reason: "Guilt-tripping to force action.", severity: "medium" },
  { phrase: "your account will be", reason: "Threat-based urgency.", severity: "high" },
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
  { phrase: "a testament to", reason: "Formulaic AI praise pattern.", severity: "medium" },
  { phrase: "tapestry", reason: "Overused metaphor in AI writing.", severity: "medium" },
  { phrase: "landscape of", reason: "Abstract AI framing.", severity: "low" },
  { phrase: "at the forefront", reason: "AI-typical positioning phrase.", severity: "low" },
  { phrase: "plays a crucial role", reason: "Formulaic AI importance statement.", severity: "medium" },
  { phrase: "in this article", reason: "AI meta-reference to its own output.", severity: "medium" },
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
  { phrase: "paytm", reason: "Fake Paytm messages for payment fraud.", severity: "medium" },
  { phrase: "phonepe", reason: "PhonePe impersonation scam.", severity: "medium" },
  { phrase: "google pay", reason: "Google Pay scams trick users into sending money.", severity: "medium" },
  { phrase: "hdfc", reason: "HDFC Bank impersonation for phishing.", severity: "high" },
  { phrase: "icici", reason: "ICICI Bank impersonation for credential theft.", severity: "high" },
  { phrase: "customs duty", reason: "Fake customs duty = parcel delivery scam.", severity: "high" },
  { phrase: "telegram channel", reason: "Telegram-based task scams are widespread.", severity: "medium" },
  { phrase: "olx", reason: "OLX buyer/seller scams are common in India.", severity: "medium" },
  { phrase: "flipkart", reason: "Flipkart impersonation in fake offers.", severity: "medium" },
  { phrase: "amazon delivery", reason: "Fake Amazon delivery notifications.", severity: "medium" },
];

// ── Text Analysis Engine ──

function analyzeTextLocally(text) {
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

  const FINANCIAL_PHRASES = [
    "bank account", "wire transfer", "send money", "processing fee", "credit card",
    "debit card", "social security", "western union", "money gram", "bitcoin",
    "cryptocurrency", "investment opportunity", "double your money", "gift card",
    "upi", "paytm", "phonepe", "google pay", "sbi", "hdfc", "icici",
    "aadhaar", "pan card", "otp", "share otp", "kyc update",
  ];

  const allScamHits = [...scam.hits, ...india.hits];
  const financialHits = allScamHits.filter(h => FINANCIAL_PHRASES.includes(h));
  const regularScamHits = allScamHits.filter(h => !FINANCIAL_PHRASES.includes(h));

  const scamPoints = regularScamHits.length * 15 + financialHits.length * 20;
  const urgencyPoints = urgency.hits.length * 10;

  const stylo = analyzeStylometry(text);
  const aiScore = Math.min(100, ai.hits.length * 16 + stylo.score);

  const rawScore = scamPoints + urgencyPoints + Math.round(aiScore * 0.3);
  const riskScore = Math.max(0, Math.min(100, rawScore));

  const scamSignal = Math.min(100, scamPoints);
  const emoSignal = Math.min(100, urgencyPoints);

  const classification = riskScore <= 30 ? "Safe" : riskScore <= 60 ? "Suspicious" : "High Risk";

  const allSuspicious = [...new Set([...scam.hits, ...urgency.hits, ...ai.hits, ...india.hits])];
  const allExplanations = [...scam.explanations, ...urgency.explanations, ...ai.explanations, ...india.explanations];

  stylo.indicators.forEach(ind => {
    allExplanations.push({ category: "ai", phrase: "(stylometric)", reason: ind, severity: "medium" });
  });

  let highlightedText = text;
  allSuspicious.forEach(phrase => {
    const regex = new RegExp(`(${phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi");
    highlightedText = highlightedText.replace(regex, "<mark>$1</mark>");
  });

  let summary;
  if (classification === "Safe") {
    summary = "This content appears safe. No significant scam or manipulation indicators detected.";
  } else {
    const parts = [];
    if (scamSignal > 30) parts.push("scam keywords");
    if (aiScore > 30) parts.push("AI-generated patterns");
    if (emoSignal > 30) parts.push("emotional manipulation");
    if (india.hits.length > 0) parts.push("India-specific fraud patterns");
    summary = classification === "High Risk"
      ? `⚠️ HIGH RISK: Contains ${parts.join(", ")}. Do NOT share personal info or transfer money.`
      : `⚡ SUSPICIOUS: Shows signs of ${parts.join(", ")}. Verify the source before acting.`;
  }

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
    signals: { ai_generated: aiScore, scam_keywords: scamSignal, emotional_manipulation: emoSignal },
    highlighted_text: highlightedText,
    suspicious_phrases: allSuspicious,
    explanations: allExplanations,
    summary,
    tips,
  };
}

// ── Stylometric Analysis ──

function analyzeStylometry(text) {
  let score = 0;
  const indicators = [];

  const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
  if (sentences.length >= 3) {
    const lengths = sentences.map(s => s.trim().split(/\s+/).length);
    const avg = lengths.reduce((a, b) => a + b, 0) / lengths.length;
    const variance = lengths.reduce((sum, l) => sum + Math.pow(l - avg, 2), 0) / lengths.length;
    const stdDev = Math.sqrt(variance);

    if (stdDev < 3 && sentences.length > 4) {
      score += 15;
      indicators.push("Unusually uniform sentence length — typical of AI-generated text.");
    }
    if (avg > 14 && avg < 26) {
      score += 8;
      indicators.push("Average sentence length in AI-typical range (15-25 words).");
    }
  }

  const hedges = ["however", "nevertheless", "nonetheless", "on the other hand", "that being said", "it should be noted"];
  const hedgeCount = hedges.filter(h => text.toLowerCase().includes(h)).length;
  if (hedgeCount >= 3) {
    score += 10;
    indicators.push("Excessive hedging language — characteristic of AI writing.");
  }

  const words = text.split(/\s+/).length;
  const contractions = (text.match(/\b\w+'\w+\b/g) || []).length;
  if (words > 50 && contractions / words < 0.005) {
    score += 8;
    indicators.push("Very few contractions — overly formal AI writing style.");
  }

  // Vocabulary diversity (Type-Token Ratio)
  const wordList = text.toLowerCase().match(/\b[a-z]+\b/g) || [];
  if (wordList.length > 50) {
    const uniqueWords = new Set(wordList).size;
    const ttr = uniqueWords / wordList.length;
    if (ttr > 0.7) {
      score += 8;
      indicators.push("High vocabulary diversity — consistent with AI text generation.");
    }
  }

  return { score: Math.min(40, score), indicators };
}

// ── Image Analysis (from URL) ──

async function analyzeImageFromURL(imageUrl) {
  const indicators = [];
  let score = 0;
  const metadata = {};

  metadata["Source URL"] = imageUrl.length > 80 ? imageUrl.substring(0, 77) + "..." : imageUrl;

  // Try backend first
  try {
    const formData = new FormData();
    const response = await fetch(imageUrl);
    const blob = await response.blob();
    formData.append("file", blob, "image.jpg");

    const apiRes = await fetch(`${API_URL}/analyze-image`, {
      method: "POST",
      body: formData,
    });
    if (apiRes.ok) {
      const apiResult = await apiRes.json();
      return {
        risk_score: apiResult.risk_score,
        classification: apiResult.classification,
        indicators: apiResult.explanation.map(e => e.signal),
        metadata: apiResult.metadata,
        tips: apiResult.tips,
        type: "image",
      };
    }
  } catch (e) {
    // Fall through to local analysis
  }

  // Local heuristic fallback
  try {
    const response = await fetch(imageUrl);
    const blob = await response.blob();
    metadata["File Size"] = (blob.size / 1024).toFixed(1) + " KB";
    metadata["MIME Type"] = blob.type || "unknown";

    if (blob.size > 5 * 1024 * 1024) {
      score -= 5;
      indicators.push("✅ Large file size — uncommon for AI images.");
    } else if (blob.size < 200 * 1024 && blob.type.includes("jpeg")) {
      score += 8;
      indicators.push("Small JPEG — AI outputs are often compressed.");
    }

    if (blob.type.includes("png")) { score += 5; indicators.push("PNG format — commonly used by AI generators."); }
    if (blob.type.includes("webp")) { score += 5; indicators.push("WebP format — often used in AI pipelines."); }

    // EXIF check
    const buffer = await blob.slice(0, 65536).arrayBuffer();
    const view = new Uint8Array(buffer);
    let hasExif = false;
    for (let i = 0; i < view.length - 1; i++) {
      if (view[i] === 0xFF && view[i + 1] === 0xE1) { hasExif = true; break; }
    }
    if (!hasExif) {
      score += 15;
      indicators.push("No EXIF metadata — AI images lack camera data.");
    } else {
      score -= 15;
      indicators.push("✅ EXIF metadata present — suggests real camera.");
    }

    // Pixel analysis
    const imgBitmap = await createImageBitmap(blob);
    metadata["Dimensions"] = `${imgBitmap.width} × ${imgBitmap.height}`;

    const aiDims = [[512,512],[768,768],[1024,1024],[1024,768],[768,1024],[1920,1080],[1344,768],[768,1344],[2048,2048],[1536,1536],[896,1152],[1152,896]];
    if (aiDims.some(([w,h]) => imgBitmap.width === w && imgBitmap.height === h)) {
      score += 18;
      indicators.push(`Dimensions (${imgBitmap.width}×${imgBitmap.height}) match AI generator sizes.`);
    }

    if (imgBitmap.width % 64 === 0 && imgBitmap.height % 64 === 0) {
      score += 10;
      indicators.push("Dimensions are multiples of 64 — AI model alignment.");
    }

    if (imgBitmap.width === imgBitmap.height && imgBitmap.width >= 512) {
      score += 8;
      indicators.push("Perfect square — common in AI images.");
    }

    const canvas = new OffscreenCanvas(Math.min(imgBitmap.width, 256), Math.min(imgBitmap.height, 256));
    const ctx = canvas.getContext("2d");
    ctx.drawImage(imgBitmap, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const pixels = imageData.data;
    const totalPx = canvas.width * canvas.height;

    // Color histogram
    const histogram = new Array(256).fill(0);
    for (let i = 0; i < pixels.length; i += 4) {
      const gray = Math.round(0.299 * pixels[i] + 0.587 * pixels[i+1] + 0.114 * pixels[i+2]);
      histogram[gray]++;
    }
    if (Math.max(...histogram) / totalPx > 0.12) {
      score += 12;
      indicators.push("Unusual color uniformity.");
    }

    let emptyBins = 0;
    for (let i = 10; i < 245; i++) { if (histogram[i] === 0) emptyBins++; }
    if (emptyBins < 15 && totalPx > 10000) {
      score += 10;
      indicators.push("Very smooth color distribution — AI images rarely have histogram gaps.");
    }

    // Smooth transitions
    let smooth = 0, total = 0;
    for (let i = 4; i < pixels.length; i += 4) {
      const diff = Math.abs(pixels[i]-pixels[i-4]) + Math.abs(pixels[i+1]-pixels[i-3]) + Math.abs(pixels[i+2]-pixels[i-2]);
      if (diff < 8) smooth++;
      total++;
    }
    if (total > 0 && smooth/total > 0.65) {
      score += 14;
      indicators.push("High smooth transitions — characteristic of AI imagery.");
    }

    // Sharp edges
    let sharpEdges = 0;
    for (let i = 4; i < pixels.length; i += 4) {
      const diff = Math.abs(pixels[i]-pixels[i-4]) + Math.abs(pixels[i+1]-pixels[i-3]) + Math.abs(pixels[i+2]-pixels[i-2]);
      if (diff > 80) sharpEdges++;
    }
    if (total > 0 && sharpEdges/total < 0.03) {
      score += 10;
      indicators.push("Very few sharp edges — AI has smoother boundaries.");
    }

    // Channel correlation
    let meanR = 0, meanG = 0, meanB = 0;
    for (let i = 0; i < pixels.length; i += 4) { meanR += pixels[i]; meanG += pixels[i+1]; meanB += pixels[i+2]; }
    meanR /= totalPx; meanG /= totalPx; meanB /= totalPx;
    let sRG = 0, sR2 = 0, sG2 = 0;
    for (let i = 0; i < pixels.length; i += 4) {
      const dr = pixels[i]-meanR, dg = pixels[i+1]-meanG;
      sRG += dr*dg; sR2 += dr*dr; sG2 += dg*dg;
    }
    const corr = sR2 > 0 && sG2 > 0 ? Math.abs(sRG / Math.sqrt(sR2 * sG2)) : 0;
    if (corr > 0.92) {
      score += 12;
      indicators.push("Extremely high color channel correlation — typical of AI.");
    }

    // Noise uniformity
    const noiseVals = [];
    for (let i = 4; i < pixels.length; i += 4) noiseVals.push(Math.abs(pixels[i]-pixels[i-4]));
    if (noiseVals.length > 100) {
      const nm = noiseVals.reduce((a,b)=>a+b,0)/noiseVals.length;
      const nv = noiseVals.reduce((s,v)=>s+Math.pow(v-nm,2),0)/noiseVals.length;
      if (Math.sqrt(nv) < 5 && nm < 8) {
        score += 12;
        indicators.push("Unnaturally uniform noise — hallmark of AI generation.");
      }
    }

  } catch (err) {
    indicators.push("Could not fully analyze image (CORS restriction).");
    score += 10;
  }

  // URL pattern check
  const aiUrlPatterns = /\b(dalle|midjourney|stable.?diffusion|comfyui|generated|ai[_-]|artificial|deepfake|flux|leonardo)\b/i;
  if (aiUrlPatterns.test(imageUrl)) {
    score += 25;
    indicators.push("URL contains AI tool references.");
  }

  score = Math.max(0, Math.min(100, score));
  const classification = score <= 25 ? "Likely Authentic" : score <= 50 ? "Possibly AI-Generated" : "Likely AI-Generated";

  const tips = [];
  if (score > 25) {
    tips.push("Use Google Reverse Image Search to verify.");
    tips.push("Look for artifacts: irregular fingers, asymmetric details, blurred text.");
    tips.push("Check source credibility.");
  }
  tips.push("AI detection is probabilistic — no tool is 100% accurate.");

  return { risk_score: score, classification, indicators, metadata, tips, type: "image" };
}

// ── URL Safety Analysis ──

const SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".loan", ".work", ".gq", ".ml", ".cf", ".tk", ".buzz", ".monster", ".icu", ".cam", ".rest", ".surf"];
const PHISHING_KEYWORDS = ["login", "verify", "secure", "account", "update", "confirm", "banking", "paypal", "signin", "password", "credential"];
const TRUSTED_DOMAINS = ["google.com", "facebook.com", "youtube.com", "twitter.com", "github.com", "microsoft.com", "apple.com", "amazon.com", "wikipedia.org", "linkedin.com", "instagram.com", "reddit.com", "stackoverflow.com", "flipkart.com", "paytm.com"];

function extractURLs(text) {
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  return (text.match(urlRegex) || []);
}

function analyzeURL(url) {
  let score = 0;
  const flags = [];

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    // Check TLD
    if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
      score += 25;
      flags.push("Suspicious top-level domain");
    }

    // Check for IP address as hostname
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      score += 30;
      flags.push("Uses IP address instead of domain name");
    }

    // Check for excessive subdomains
    if (hostname.split(".").length > 4) {
      score += 15;
      flags.push("Excessive subdomains — may be masking real domain");
    }

    // Check for phishing keywords in URL
    const urlLower = url.toLowerCase();
    const phishingHits = PHISHING_KEYWORDS.filter(kw => urlLower.includes(kw));
    if (phishingHits.length >= 2) {
      score += 20;
      flags.push(`Contains phishing keywords: ${phishingHits.join(", ")}`);
    }

    // Check for URL shorteners
    const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "cutt.ly"];
    if (shorteners.some(s => hostname.includes(s))) {
      score += 15;
      flags.push("URL shortener detected — destination unknown");
    }

    // Check for typosquatting
    const typosquats = ["goggle", "gooogle", "faceb00k", "amaz0n", "paypall", "micr0soft", "instgram", "linkdin"];
    if (typosquats.some(t => hostname.includes(t))) {
      score += 35;
      flags.push("Possible typosquatting — mimics a trusted brand");
    }

    // Check if trusted
    if (TRUSTED_DOMAINS.some(d => hostname === d || hostname.endsWith("." + d))) {
      score -= 20;
      flags.push("✅ Recognized trusted domain");
    }

    // Check for suspicious characters (homograph attack)
    if (/[^\x00-\x7F]/.test(hostname)) {
      score += 25;
      flags.push("Non-ASCII characters in domain — possible homograph attack");
    }

    // Very long URL
    if (url.length > 200) {
      score += 10;
      flags.push("Unusually long URL");
    }

    // HTTP (not HTTPS)
    if (parsed.protocol === "http:") {
      score += 10;
      flags.push("Uses HTTP (not secure HTTPS)");
    }

  } catch {
    score += 20;
    flags.push("Invalid or malformed URL");
  }

  score = Math.max(0, Math.min(100, score));
  return { url, score, flags, safe: score < 30 };
}

function analyzeURLDetailed(url) {
  const analysis = analyzeURL(url);
  const classification = analysis.score < 30 ? "Safe" : analysis.score < 65 ? "Suspicious" : "High Risk";

  return {
    type: "url",
    risk_score: analysis.score,
    classification,
    url: analysis.url,
    flags: analysis.flags,
    tips: [
      "Always check the domain name carefully before entering credentials.",
      "Look for HTTPS and a valid certificate.",
      "When in doubt, type the URL manually instead of clicking links.",
      "Use Google Safe Browsing to verify: transparencyreport.google.com/safe-browsing",
    ],
  };
}

// ── Readability Analysis ──

function analyzeReadability(text) {
  const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
  const words = text.split(/\s+/).filter(w => w.length > 0);
  const syllables = words.reduce((sum, w) => sum + countSyllables(w), 0);

  if (sentences.length === 0 || words.length === 0) return { score: 0, grade: "N/A", level: "N/A" };

  // Flesch Reading Ease
  const avgSentLen = words.length / sentences.length;
  const avgSyllables = syllables / words.length;
  const flesch = Math.max(0, Math.min(100, 206.835 - (1.015 * avgSentLen) - (84.6 * avgSyllables)));

  let grade, level;
  if (flesch >= 90) { grade = "5th grade"; level = "Very Easy"; }
  else if (flesch >= 80) { grade = "6th grade"; level = "Easy"; }
  else if (flesch >= 70) { grade = "7th grade"; level = "Fairly Easy"; }
  else if (flesch >= 60) { grade = "8th-9th grade"; level = "Standard"; }
  else if (flesch >= 50) { grade = "10th-12th grade"; level = "Fairly Difficult"; }
  else if (flesch >= 30) { grade = "College"; level = "Difficult"; }
  else { grade = "Graduate"; level = "Very Difficult"; }

  return { score: Math.round(flesch), grade, level, wordCount: words.length, sentenceCount: sentences.length };
}

function countSyllables(word) {
  word = word.toLowerCase().replace(/[^a-z]/g, "");
  if (word.length <= 3) return 1;
  const vowelGroups = word.match(/[aeiouy]+/g);
  let count = vowelGroups ? vowelGroups.length : 1;
  if (word.endsWith("e") && count > 1) count--;
  return Math.max(1, count);
}

// ── Language Detection ──

function detectLanguage(text) {
  const patterns = {
    Hindi: /[\u0900-\u097F]/,
    Tamil: /[\u0B80-\u0BFF]/,
    Telugu: /[\u0C00-\u0C7F]/,
    Kannada: /[\u0C80-\u0CFF]/,
    Malayalam: /[\u0D00-\u0D7F]/,
    Bengali: /[\u0980-\u09FF]/,
    Gujarati: /[\u0A80-\u0AFF]/,
    Punjabi: /[\u0A00-\u0A7F]/,
    Arabic: /[\u0600-\u06FF]/,
    Chinese: /[\u4E00-\u9FFF]/,
    Japanese: /[\u3040-\u309F\u30A0-\u30FF]/,
    Korean: /[\uAC00-\uD7AF]/,
    Russian: /[\u0400-\u04FF]/,
  };

  for (const [lang, regex] of Object.entries(patterns)) {
    if (regex.test(text)) return lang;
  }
  return "English";
}