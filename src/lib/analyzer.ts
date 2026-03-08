// TruthShield Enhanced Analysis Engine
// Multi-factor risk analysis with explainable AI output

export interface AnalysisSignals {
  ai_generated: number;
  scam_keywords: number;
  emotional_manipulation: number;
}

export interface Explanation {
  category: "scam" | "urgency" | "ai" | "india_scam";
  phrase: string;
  reason: string;
  severity: "low" | "medium" | "high";
}

export interface AnalysisResult {
  risk_score: number;
  classification: "Safe" | "Suspicious" | "High Risk";
  signals: AnalysisSignals;
  suspicious_phrases: string[];
  highlighted_text: string;
  explanations: Explanation[];
  summary: string;
  tips: string[];
}

// ── Keyword banks with explanations ──

const SCAM_KEYWORDS: { phrase: string; reason: string; severity: "low" | "medium" | "high" }[] = [
  { phrase: "congratulations", reason: "Unsolicited congratulations are a classic phishing opener to create excitement and lower your guard.", severity: "medium" },
  { phrase: "you have been selected", reason: "False selection claims are used to make victims feel special and act without thinking.", severity: "high" },
  { phrase: "claim your prize", reason: "Prize claims from unknown sources are almost always scams designed to steal personal information.", severity: "high" },
  { phrase: "click here", reason: "Vague 'click here' links often lead to phishing sites or malware downloads.", severity: "medium" },
  { phrase: "verify your account", reason: "Legitimate services rarely ask you to verify accounts through unsolicited messages.", severity: "high" },
  { phrase: "suspended", reason: "Account suspension threats create panic to make you act without verifying the source.", severity: "high" },
  { phrase: "winner", reason: "Unsolicited 'winner' notifications are a common scam tactic.", severity: "medium" },
  { phrase: "free gift", reason: "Nothing is truly free — 'free gift' offers typically aim to collect your personal data.", severity: "medium" },
  { phrase: "lottery", reason: "You cannot win a lottery you never entered. This is a classic fraud scheme.", severity: "high" },
  { phrase: "inheritance", reason: "Fake inheritance scams promise large sums to trick victims into paying 'processing fees'.", severity: "high" },
  { phrase: "wire transfer", reason: "Requests for wire transfers are a red flag — wire transfers are nearly impossible to reverse.", severity: "high" },
  { phrase: "nigerian prince", reason: "The classic advance-fee fraud scheme originating from 419 scam letters.", severity: "high" },
  { phrase: "bank account", reason: "Requests involving bank account details in unsolicited messages indicate potential fraud.", severity: "high" },
  { phrase: "social security", reason: "No legitimate organization asks for your SSN via email or text message.", severity: "high" },
  { phrase: "password expired", reason: "Fake password expiry notices are used to steal login credentials.", severity: "high" },
  { phrase: "confirm your identity", reason: "Identity confirmation requests in unsolicited messages are phishing attempts.", severity: "high" },
  { phrase: "urgent action", reason: "Creating artificial urgency is a psychological manipulation tactic.", severity: "high" },
  { phrase: "risk-free", reason: "No investment or offer is truly risk-free — this is a misleading claim.", severity: "medium" },
  { phrase: "guaranteed", reason: "'Guaranteed' returns or outcomes in unsolicited offers are typically fraudulent.", severity: "medium" },
  { phrase: "double your money", reason: "Promises to double money are a hallmark of Ponzi schemes and investment fraud.", severity: "high" },
  { phrase: "no obligation", reason: "Used to lower resistance before trapping victims in commitments.", severity: "low" },
  { phrase: "exclusive deal", reason: "Fake exclusivity creates pressure to act quickly without proper evaluation.", severity: "medium" },
  { phrase: "limited offer", reason: "Artificial scarcity is used to prevent rational decision-making.", severity: "medium" },
  { phrase: "one-time", reason: "One-time offers create false urgency to prevent comparison shopping.", severity: "low" },
  { phrase: "act immediately", reason: "Pressure to act immediately prevents verification and rational thinking.", severity: "high" },
  { phrase: "million dollars", reason: "Unrealistic monetary promises are a clear indicator of fraud.", severity: "high" },
  { phrase: "beneficiary", reason: "Being named a 'beneficiary' by strangers is a common advance-fee scam opening.", severity: "high" },
  { phrase: "unclaimed funds", reason: "Unclaimed fund notifications from unknown sources are fraudulent.", severity: "high" },
  { phrase: "western union", reason: "Requests to use Western Union for payments are a major fraud indicator.", severity: "high" },
  { phrase: "money gram", reason: "Similar to Western Union, MoneyGram requests in scams are untraceable.", severity: "high" },
  { phrase: "send money", reason: "Requests to send money to strangers are almost always fraudulent.", severity: "high" },
  { phrase: "processing fee", reason: "Legitimate prizes/inheritances never require upfront processing fees.", severity: "high" },
  { phrase: "tax refund", reason: "Tax authorities communicate through official channels, never via email/text.", severity: "high" },
  { phrase: "irs", reason: "The IRS never initiates contact via email, text, or social media.", severity: "high" },
  { phrase: "fbi", reason: "Law enforcement does not contact citizens via email for money.", severity: "high" },
  { phrase: "court order", reason: "Real court orders are served in person, not via email or text.", severity: "high" },
  { phrase: "legal action", reason: "Threats of legal action via email are used to create fear and compliance.", severity: "high" },
  { phrase: "arrest warrant", reason: "Law enforcement does not issue arrest warrants via email or phone.", severity: "high" },
];

const URGENCY_PHRASES: { phrase: string; reason: string; severity: "low" | "medium" | "high" }[] = [
  { phrase: "act now", reason: "Creates false urgency to prevent rational decision-making.", severity: "high" },
  { phrase: "limited time", reason: "Artificial time pressure is a psychological manipulation technique.", severity: "medium" },
  { phrase: "urgent", reason: "Urgency language bypasses critical thinking.", severity: "medium" },
  { phrase: "immediately", reason: "Demands for immediate action prevent fact-checking.", severity: "medium" },
  { phrase: "expires today", reason: "Fake expiration dates create panic-driven decisions.", severity: "high" },
  { phrase: "don't miss out", reason: "Fear of missing out (FOMO) is a manipulation tactic.", severity: "medium" },
  { phrase: "last chance", reason: "False finality prevents rational evaluation.", severity: "high" },
  { phrase: "hurry", reason: "Rushing victims prevents them from consulting others.", severity: "medium" },
  { phrase: "right away", reason: "Immediacy demands are designed to bypass caution.", severity: "medium" },
  { phrase: "deadline", reason: "Artificial deadlines create unwarranted pressure.", severity: "medium" },
  { phrase: "only today", reason: "False time constraints manipulate decision-making.", severity: "high" },
  { phrase: "final notice", reason: "Fake 'final notices' are used to create fear and compliance.", severity: "high" },
  { phrase: "respond immediately", reason: "Demands for immediate response prevent verification.", severity: "high" },
  { phrase: "time sensitive", reason: "Labeling something 'time sensitive' creates artificial urgency.", severity: "medium" },
  { phrase: "within 24 hours", reason: "Short artificial deadlines prevent proper verification.", severity: "high" },
  { phrase: "before it's too late", reason: "Fear-based language designed to trigger impulsive action.", severity: "high" },
  { phrase: "now or never", reason: "False ultimatum to force immediate, unverified action.", severity: "high" },
  { phrase: "offer ends", reason: "Fake offer expiration creates urgency.", severity: "medium" },
  { phrase: "hours left", reason: "Countdown language creates panic.", severity: "high" },
  { phrase: "minutes remaining", reason: "Extreme time pressure prevents critical thinking.", severity: "high" },
  { phrase: "closing soon", reason: "False scarcity creates urgency.", severity: "medium" },
  { phrase: "once in a lifetime", reason: "Hyperbolic claims prevent rational evaluation.", severity: "medium" },
  { phrase: "while supplies last", reason: "Artificial scarcity creates purchase pressure.", severity: "low" },
  { phrase: "today only", reason: "False time limit prevents comparison and research.", severity: "high" },
];

const AI_PATTERNS: { phrase: string; reason: string; severity: "low" | "medium" | "high" }[] = [
  { phrase: "as an ai", reason: "Direct admission of AI origin.", severity: "high" },
  { phrase: "i cannot", reason: "AI refusal pattern — common in model outputs.", severity: "low" },
  { phrase: "i'm an ai", reason: "Direct AI self-identification.", severity: "high" },
  { phrase: "language model", reason: "Technical AI terminology rarely used in human writing.", severity: "high" },
  { phrase: "it's important to note", reason: "Formulaic hedging phrase overused by AI models.", severity: "medium" },
  { phrase: "in conclusion", reason: "Overly structured conclusion marker typical of AI-generated text.", severity: "low" },
  { phrase: "it is worth noting", reason: "AI-style hedging language.", severity: "medium" },
  { phrase: "delve into", reason: "Statistically overrepresented in AI-generated content.", severity: "medium" },
  { phrase: "moreover", reason: "Formal transitional word overused by AI.", severity: "low" },
  { phrase: "furthermore", reason: "Formal connector disproportionately used by language models.", severity: "low" },
  { phrase: "in the realm of", reason: "Formulaic phrase characteristic of AI writing.", severity: "medium" },
  { phrase: "it's crucial", reason: "AI emphasis pattern.", severity: "low" },
  { phrase: "comprehensive", reason: "AI models overuse this descriptor.", severity: "low" },
  { phrase: "facilitate", reason: "Formal verb overrepresented in AI output.", severity: "low" },
  { phrase: "leverage", reason: "Corporate/AI buzzword.", severity: "low" },
  { phrase: "paradigm", reason: "Abstract term overused in AI-generated content.", severity: "medium" },
  { phrase: "synergy", reason: "Corporate buzzword favored by AI models.", severity: "low" },
  { phrase: "utilize", reason: "AI prefers 'utilize' over simpler 'use'.", severity: "low" },
  { phrase: "multifaceted", reason: "Complex adjective overrepresented in AI writing.", severity: "medium" },
  { phrase: "groundbreaking", reason: "Hyperbolic adjective common in AI-generated content.", severity: "low" },
  { phrase: "cutting-edge", reason: "Buzzword overused by AI models.", severity: "low" },
  { phrase: "harness the power", reason: "Formulaic AI phrase.", severity: "medium" },
  { phrase: "in today's world", reason: "Generic opener characteristic of AI writing.", severity: "medium" },
  { phrase: "navigating the complexities", reason: "Abstract AI phrasing.", severity: "medium" },
  { phrase: "a testament to", reason: "Formulaic praise pattern used by AI.", severity: "medium" },
  { phrase: "spearheading", reason: "Corporate language overrepresented in AI output.", severity: "low" },
  { phrase: "fostering", reason: "Abstract verb favored by language models.", severity: "low" },
];

const INDIA_SCAM_PATTERNS: { phrase: string; reason: string; severity: "low" | "medium" | "high" }[] = [
  { phrase: "kyc update", reason: "Fake KYC update requests are rampant in India, used to steal Aadhaar/PAN details.", severity: "high" },
  { phrase: "aadhaar", reason: "Aadhaar number requests in unsolicited messages are identity theft attempts.", severity: "high" },
  { phrase: "pan card", reason: "PAN card details requested via messages indicate tax fraud attempts.", severity: "high" },
  { phrase: "upi", reason: "UPI-related scam messages trick users into authorizing fraudulent transactions.", severity: "high" },
  { phrase: "paytm", reason: "Fake Paytm messages are used for payment fraud in India.", severity: "medium" },
  { phrase: "phonepe", reason: "PhonePe impersonation is common in Indian digital payment scams.", severity: "medium" },
  { phrase: "google pay", reason: "Google Pay scams trick users into sending money instead of receiving.", severity: "medium" },
  { phrase: "rbi", reason: "RBI impersonation is used in banking fraud schemes.", severity: "high" },
  { phrase: "income tax", reason: "Fake income tax notices are used for phishing in India.", severity: "high" },
  { phrase: "crore", reason: "Promises of crores are used in Indian lottery/investment scams.", severity: "high" },
  { phrase: "lakh", reason: "False promises of lakhs are common in Indian scam messages.", severity: "medium" },
  { phrase: "sbi", reason: "SBI impersonation is one of the most common banking scams in India.", severity: "high" },
  { phrase: "hdfc", reason: "HDFC Bank impersonation used in phishing attacks.", severity: "high" },
  { phrase: "icici", reason: "ICICI Bank impersonation used for credential theft.", severity: "high" },
  { phrase: "otp", reason: "OTP sharing requests are the #1 digital fraud method in India.", severity: "high" },
  { phrase: "share otp", reason: "No legitimate service ever asks you to share your OTP.", severity: "high" },
  { phrase: "debit card blocked", reason: "Fake card blocking alerts used to steal card details.", severity: "high" },
  { phrase: "credit card blocked", reason: "Fake card blocking alerts used for credential phishing.", severity: "high" },
  { phrase: "job offer", reason: "Unsolicited job offers via WhatsApp/SMS are often fraudulent.", severity: "medium" },
  { phrase: "work from home", reason: "Fake work-from-home offers are a rising scam in India.", severity: "medium" },
  { phrase: "telegram channel", reason: "Telegram-based task scams are widespread in India.", severity: "medium" },
  { phrase: "customs duty", reason: "Fake customs duty demands are used in parcel delivery scams.", severity: "high" },
  { phrase: "electricity bill", reason: "Fake electricity disconnection threats are used for payment fraud.", severity: "high" },
];

function findMatches(
  textLower: string,
  bank: { phrase: string; reason: string; severity: "low" | "medium" | "high" }[],
  category: Explanation["category"]
): { hits: string[]; explanations: Explanation[] } {
  const hits: string[] = [];
  const explanations: Explanation[] = [];
  for (const item of bank) {
    if (textLower.includes(item.phrase)) {
      hits.push(item.phrase);
      explanations.push({
        category,
        phrase: item.phrase,
        reason: item.reason,
        severity: item.severity,
      });
    }
  }
  return { hits, explanations };
}

function scoreFromHits(hits: string[], weight: number): number {
  return Math.min(100, hits.length * weight);
}

function highlightText(original: string, phrases: string[]): string {
  let result = original;
  for (const phrase of phrases) {
    const pattern = new RegExp(`(${phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "gi");
    result = result.replace(pattern, "<mark>$1</mark>");
  }
  return result;
}

function generateSummary(classification: string, signals: AnalysisSignals, explanations: Explanation[]): string {
  if (classification === "Safe") {
    return "This content appears to be safe. No significant scam indicators, AI-generation patterns, or emotional manipulation tactics were detected.";
  }

  const parts: string[] = [];
  if (signals.scam_keywords > 30) parts.push("scam-related keywords");
  if (signals.ai_generated > 30) parts.push("AI-generated content patterns");
  if (signals.emotional_manipulation > 30) parts.push("emotional manipulation tactics");

  const indiaHits = explanations.filter(e => e.category === "india_scam");
  if (indiaHits.length > 0) parts.push("India-specific fraud patterns");

  const highSeverity = explanations.filter(e => e.severity === "high").length;

  if (classification === "High Risk") {
    return `⚠️ HIGH RISK: This content contains ${parts.join(", ")}. ${highSeverity} high-severity indicators were found. Do NOT share personal information, click links, or transfer money based on this content.`;
  }

  return `⚡ SUSPICIOUS: This content shows signs of ${parts.join(", ")}. Exercise caution and verify the source before taking any action.`;
}

function generateTips(classification: string, explanations: Explanation[]): string[] {
  const tips: string[] = [];

  if (classification === "Safe") {
    tips.push("Always stay vigilant — even safe-looking content can be deceptive.");
    return tips;
  }

  const categories = new Set(explanations.map(e => e.category));

  if (categories.has("scam") || categories.has("india_scam")) {
    tips.push("Never share personal information (Aadhaar, PAN, OTP, passwords) via messages.");
    tips.push("Verify the sender's identity through official channels before responding.");
    tips.push("Do not click on links in suspicious messages — type URLs manually.");
  }

  if (categories.has("urgency")) {
    tips.push("Legitimate organizations don't create artificial urgency — take your time to verify.");
    tips.push("If something feels urgent, it's designed to make you act without thinking.");
  }

  if (categories.has("ai")) {
    tips.push("AI-generated content may contain plausible-sounding but fabricated information.");
    tips.push("Cross-check facts from AI-generated text with reliable sources.");
  }

  tips.push("When in doubt, consult a trusted friend or family member before taking action.");

  return tips.slice(0, 5);
}

// ── Stylometric analysis for AI detection ──

function analyzeStylometry(text: string): { score: number; indicators: string[] } {
  const indicators: string[] = [];
  let score = 0;

  const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
  if (sentences.length >= 3) {
    const lengths = sentences.map(s => s.trim().split(/\s+/).length);
    const avgLen = lengths.reduce((a, b) => a + b, 0) / lengths.length;
    const variance = lengths.reduce((sum, l) => sum + Math.pow(l - avgLen, 2), 0) / lengths.length;
    const stdDev = Math.sqrt(variance);

    // AI tends to have uniform sentence lengths
    if (stdDev < 3 && sentences.length > 4) {
      score += 15;
      indicators.push("Unusually uniform sentence length (typical of AI)");
    }

    // AI tends to have moderate sentence lengths (15-25 words)
    if (avgLen > 14 && avgLen < 26) {
      score += 8;
      indicators.push("Average sentence length in AI-typical range");
    }
  }

  // Check for repetitive paragraph structure
  const paragraphs = text.split(/\n\n+/).filter(p => p.trim().length > 0);
  if (paragraphs.length >= 3) {
    const starts = paragraphs.map(p => p.trim().split(/\s+/).slice(0, 2).join(" ").toLowerCase());
    const uniqueStarts = new Set(starts).size;
    if (uniqueStarts < starts.length * 0.6) {
      score += 12;
      indicators.push("Repetitive paragraph structure");
    }
  }

  // Excessive hedging
  const hedges = ["however", "nevertheless", "nonetheless", "on the other hand", "that being said", "it should be noted"];
  const hedgeCount = hedges.filter(h => text.toLowerCase().includes(h)).length;
  if (hedgeCount >= 3) {
    score += 10;
    indicators.push("Excessive hedging language");
  }

  // Lack of contractions (AI tends to use formal language)
  const words = text.split(/\s+/).length;
  const contractions = (text.match(/\b\w+'\w+\b/g) || []).length;
  if (words > 50 && contractions / words < 0.005) {
    score += 8;
    indicators.push("Very few contractions (overly formal style)");
  }

  return { score: Math.min(40, score), indicators };
}

export function analyzeText(text: string): AnalysisResult {
  const lower = text.toLowerCase();

  const scam = findMatches(lower, SCAM_KEYWORDS, "scam");
  const urgency = findMatches(lower, URGENCY_PHRASES, "urgency");
  const ai = findMatches(lower, AI_PATTERNS, "ai");
  const india = findMatches(lower, INDIA_SCAM_PATTERNS, "india_scam");

  const scamScore = scoreFromHits([...scam.hits, ...india.hits], 14);
  const emoScore = scoreFromHits(urgency.hits, 18);

  // AI score includes stylometric analysis
  const stylometry = analyzeStylometry(text);
  const aiBaseScore = scoreFromHits(ai.hits, 16);
  const aiScore = Math.min(100, aiBaseScore + stylometry.score);

  // Add stylometry explanations
  const stylometryExplanations: Explanation[] = stylometry.indicators.map(ind => ({
    category: "ai" as const,
    phrase: "(stylometric pattern)",
    reason: ind,
    severity: "medium" as const,
  }));

  const riskScore = Math.min(100, Math.round(aiScore * 0.3 + scamScore * 0.4 + emoScore * 0.3));

  const classification: AnalysisResult["classification"] =
    riskScore < 30 ? "Safe" : riskScore < 65 ? "Suspicious" : "High Risk";

  const allPhrases = [...new Set([...scam.hits, ...urgency.hits, ...ai.hits, ...india.hits])];
  const allExplanations = [...scam.explanations, ...urgency.explanations, ...ai.explanations, ...india.explanations, ...stylometryExplanations];
  const highlightedText = highlightText(text, allPhrases);

  const signals: AnalysisSignals = {
    ai_generated: aiScore,
    scam_keywords: scamScore,
    emotional_manipulation: emoScore,
  };

  return {
    risk_score: riskScore,
    classification,
    signals,
    suspicious_phrases: allPhrases,
    highlighted_text: highlightedText,
    explanations: allExplanations,
    summary: generateSummary(classification, signals, allExplanations),
    tips: generateTips(classification, allExplanations),
  };
}

// ── Image analysis ──

export interface ImageAnalysisResult {
  risk_score: number;
  classification: "Likely Authentic" | "Possibly AI-Generated" | "Likely AI-Generated";
  indicators: string[];
  metadata: Record<string, string>;
  tips: string[];
}

export async function analyzeImage(file: File): Promise<ImageAnalysisResult> {
  const indicators: string[] = [];
  let score = 0;
  const metadata: Record<string, string> = {};

  metadata["File Name"] = file.name;
  metadata["File Size"] = `${(file.size / 1024).toFixed(1)} KB`;
  metadata["File Type"] = file.type;
  metadata["Last Modified"] = new Date(file.lastModified).toLocaleDateString();

  // Check file size patterns
  if (file.size > 5 * 1024 * 1024) {
    indicators.push("Large file size — uncommon for AI-generated images");
    score -= 5;
  }

  // Analyze image data
  const img = await loadImage(file);
  metadata["Dimensions"] = `${img.width} × ${img.height}`;
  metadata["Aspect Ratio"] = (img.width / img.height).toFixed(2);

  // Common AI image dimensions
  const commonAIDims = [
    [512, 512], [768, 768], [1024, 1024], [1024, 768], [768, 1024],
    [1920, 1080], [1080, 1920], [1344, 768], [768, 1344],
  ];
  const isCommonAIDim = commonAIDims.some(([w, h]) => img.width === w && img.height === h);
  if (isCommonAIDim) {
    score += 15;
    indicators.push(`Dimensions (${img.width}×${img.height}) match common AI generator output sizes`);
  }

  // Analyze pixel data for uniformity
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d")!;
  canvas.width = Math.min(img.width, 256);
  canvas.height = Math.min(img.height, 256);
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const pixels = imageData.data;

  // Check for unusual color distribution
  const colorHistogram = new Array(256).fill(0);
  for (let i = 0; i < pixels.length; i += 4) {
    const gray = Math.round(0.299 * pixels[i] + 0.587 * pixels[i + 1] + 0.114 * pixels[i + 2]);
    colorHistogram[gray]++;
  }

  const totalPixels = canvas.width * canvas.height;
  const maxBin = Math.max(...colorHistogram);
  const dominance = maxBin / totalPixels;
  if (dominance > 0.15) {
    score += 10;
    indicators.push("Unusual color uniformity detected — may indicate AI generation");
  }

  // Check for smooth gradients (AI images tend to have smoother gradients)
  let smoothTransitions = 0;
  let totalTransitions = 0;
  for (let i = 4; i < pixels.length; i += 4) {
    const diff = Math.abs(pixels[i] - pixels[i - 4]) + Math.abs(pixels[i + 1] - pixels[i - 3]) + Math.abs(pixels[i + 2] - pixels[i - 2]);
    if (diff < 10) smoothTransitions++;
    totalTransitions++;
  }
  const smoothRatio = smoothTransitions / totalTransitions;
  if (smoothRatio > 0.7) {
    score += 12;
    indicators.push("High proportion of smooth color transitions — characteristic of AI-generated imagery");
  }

  // Check for EXIF data absence (AI images typically lack EXIF)
  const hasExifMarker = await checkForExif(file);
  if (!hasExifMarker) {
    score += 10;
    indicators.push("No EXIF metadata found — AI-generated images typically lack camera metadata");
  } else {
    score -= 10;
    indicators.push("EXIF metadata present — suggests real camera capture");
  }

  // Check filename patterns
  const aiPatterns = /\b(dalle|midjourney|stable.?diffusion|sd_|comfyui|a1111|generated|ai_|artificial)\b/i;
  if (aiPatterns.test(file.name)) {
    score += 20;
    indicators.push("Filename contains AI tool references");
  }

  score = Math.max(0, Math.min(100, score));

  const classification: ImageAnalysisResult["classification"] =
    score < 25 ? "Likely Authentic" : score < 55 ? "Possibly AI-Generated" : "Likely AI-Generated";

  const tips: string[] = [];
  if (score >= 25) {
    tips.push("Use Google Reverse Image Search to check if this image appears elsewhere online.");
    tips.push("Look for subtle artifacts: irregular fingers, asymmetric earrings, blurred text.");
    tips.push("Check if the image source is a verified, credible publisher.");
  }
  tips.push("AI image detection is probabilistic — no tool is 100% accurate.");

  return { risk_score: score, classification, indicators, metadata, tips };
}

function loadImage(file: File): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = URL.createObjectURL(file);
  });
}

async function checkForExif(file: File): Promise<boolean> {
  const buffer = await file.slice(0, 65536).arrayBuffer();
  const view = new Uint8Array(buffer);
  // Look for EXIF marker (0xFFE1)
  for (let i = 0; i < view.length - 1; i++) {
    if (view[i] === 0xFF && view[i + 1] === 0xE1) return true;
  }
  return false;
}
