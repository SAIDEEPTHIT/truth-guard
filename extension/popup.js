// TruthShield Popup Script

const API_URL = "http://localhost:8000"; // Change to your deployed backend URL

document.addEventListener("DOMContentLoaded", () => {
  // Check if there's stored analysis result
  chrome.storage.local.get(["truthshield_result"], (data) => {
    if (data.truthshield_result) {
      renderResult(data.truthshield_result);
    }
  });

  // Listen for new results
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "analysis_start") {
      showLoading();
    }
    if (message.type === "analysis_result") {
      renderResult(message.data);
    }
    if (message.type === "analysis_error") {
      showError(message.error);
    }
  });
});

function showLoading() {
  document.getElementById("idle-msg").style.display = "none";
  document.getElementById("loading").style.display = "block";
  document.getElementById("result").style.display = "none";
  document.getElementById("error-msg").style.display = "none";
  document.getElementById("details-section").style.display = "none";
  document.getElementById("highlights-section").style.display = "none";
  document.getElementById("status").className = "status idle";
}

function showError(msg) {
  document.getElementById("loading").style.display = "none";
  document.getElementById("error-msg").textContent = msg;
  document.getElementById("error-msg").style.display = "block";
}

function renderResult(data) {
  const { risk_score, classification, signals, highlighted_text, suspicious_phrases } = data;

  document.getElementById("idle-msg").style.display = "none";
  document.getElementById("loading").style.display = "none";
  document.getElementById("result").style.display = "block";
  document.getElementById("error-msg").style.display = "none";

  // Score
  const scoreEl = document.getElementById("score-circle");
  scoreEl.textContent = risk_score;

  const classEl = document.getElementById("classification");
  const statusEl = document.getElementById("status");

  const riskClass =
    classification === "Safe" ? "safe" :
    classification === "Suspicious" ? "suspicious" : "high-risk";

  scoreEl.className = `score-circle ${riskClass}`;
  classEl.className = `classification ${riskClass}`;
  classEl.textContent = classification;
  statusEl.className = `status ${riskClass}`;

  // Signals
  const detailsEl = document.getElementById("details-section");
  detailsEl.style.display = "block";

  setBar("ai-bar", signals.ai_generated);
  setBar("scam-bar", signals.scam_keywords);
  setBar("emo-bar", signals.emotional_manipulation);

  // Highlights
  if (highlighted_text) {
    document.getElementById("highlights-section").style.display = "block";
    document.getElementById("highlighted-text").innerHTML = highlighted_text;
  }
}

function setBar(id, value) {
  const el = document.getElementById(id);
  const pct = Math.min(100, Math.max(0, value));
  el.style.width = pct + "%";
  el.className = `signal-fill ${pct < 40 ? "low" : pct < 70 ? "med" : "high"}`;
}