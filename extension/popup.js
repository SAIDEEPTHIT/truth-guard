// TruthShield Enhanced Popup Script

document.addEventListener("DOMContentLoaded", () => {
  // ── Senior Mode ──
  const seniorToggle = document.getElementById("senior-toggle");
  const savedSenior = localStorage.getItem("truthshield_senior") === "true";
  seniorToggle.checked = savedSenior;
  if (savedSenior) document.body.classList.add("senior-mode");

  seniorToggle.addEventListener("change", () => {
    document.body.classList.toggle("senior-mode", seniorToggle.checked);
    localStorage.setItem("truthshield_senior", seniorToggle.checked);
    // Re-render if we have a result
    chrome.storage.local.get(["truthshield_result"], (data) => {
      if (data.truthshield_result) renderResult(data.truthshield_result);
    });
  });

  // ── Tabs ──
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    });
  });

  // ── Load stored state ──
  chrome.storage.local.get(["truthshield_result", "truthshield_loading"], (data) => {
    if (data.truthshield_loading) showLoading();
    else if (data.truthshield_result) renderResult(data.truthshield_result);
  });

  // ── Live updates ──
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "analysis_start") showLoading();
    if (message.type === "analysis_result") renderResult(message.data);
    if (message.type === "analysis_error") showError(message.error);
  });

  // ── Clear ──
  document.getElementById("clear-btn").addEventListener("click", () => {
    chrome.storage.local.remove(["truthshield_result", "truthshield_loading"]);
    chrome.action.setBadgeText({ text: "" });
    resetUI();
  });
});

function showLoading() {
  document.getElementById("idle-msg").style.display = "none";
  document.getElementById("loading").style.display = "block";
  document.getElementById("result").style.display = "none";
  document.getElementById("error-msg").style.display = "none";
  document.getElementById("tabs-container").style.display = "none";
  document.getElementById("clear-btn").style.display = "none";
}

function showError(msg) {
  document.getElementById("loading").style.display = "none";
  document.getElementById("error-msg").textContent = msg;
  document.getElementById("error-msg").style.display = "block";
}

function resetUI() {
  document.getElementById("idle-msg").style.display = "block";
  document.getElementById("loading").style.display = "none";
  document.getElementById("result").style.display = "none";
  document.getElementById("error-msg").style.display = "none";
  document.getElementById("tabs-container").style.display = "none";
  document.getElementById("clear-btn").style.display = "none";
  document.getElementById("status").className = "card";
}

function renderResult(data) {
  const { risk_score, classification, signals, highlighted_text, explanations, summary, tips } = data;
  const isSenior = document.body.classList.contains("senior-mode");

  document.getElementById("idle-msg").style.display = "none";
  document.getElementById("loading").style.display = "none";
  document.getElementById("result").style.display = "block";
  document.getElementById("error-msg").style.display = "none";
  document.getElementById("tabs-container").style.display = "block";
  document.getElementById("clear-btn").style.display = "block";

  // Score
  const scoreEl = document.getElementById("score-circle");
  scoreEl.textContent = risk_score;
  const classEl = document.getElementById("classification");
  const statusEl = document.getElementById("status");

  const riskClass = classification === "Safe" ? "safe" : classification === "Suspicious" ? "suspicious" : "high-risk";
  scoreEl.className = `score-circle ${riskClass}`;
  classEl.className = `classification ${riskClass}`;
  classEl.textContent = classification;
  statusEl.className = `card ${riskClass}`;

  // Senior verdict
  const verdictEl = document.getElementById("senior-verdict");
  if (isSenior) {
    verdictEl.style.display = "block";
    if (classification === "Safe") {
      verdictEl.textContent = "✅ This message looks safe!";
      verdictEl.style.color = "#16a34a";
    } else if (classification === "Suspicious") {
      verdictEl.textContent = "⚠️ Be careful — this looks suspicious!";
      verdictEl.style.color = "#ca8a04";
    } else {
      verdictEl.textContent = "🚨 DANGER — This is very likely a scam!";
      verdictEl.style.color = "#dc2626";
    }
  } else {
    verdictEl.style.display = "none";
  }

  // Signal bars
  setBar("ai-bar", signals.ai_generated);
  setBar("scam-bar", signals.scam_keywords);
  setBar("emo-bar", signals.emotional_manipulation);

  // Highlighted text
  if (highlighted_text) {
    document.getElementById("highlighted-text").innerHTML = highlighted_text;
  }

  // Summary
  if (summary) {
    const summaryEl = document.getElementById("summary-container");
    summaryEl.style.display = "block";
    summaryEl.textContent = summary;
  }

  // Explanations
  const explContainer = document.getElementById("explanations-container");
  explContainer.innerHTML = "";
  if (explanations && explanations.length > 0) {
    explanations.forEach(exp => {
      const div = document.createElement("div");
      div.className = `explanation-item ${exp.category}`;
      const categoryLabels = {
        scam: "🎣 Scam",
        urgency: "🔥 Urgency",
        ai: "🤖 AI Pattern",
        india_scam: "🇮🇳 India Scam",
      };
      div.innerHTML = `
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
          <span style="font-size:11px;font-weight:600;">${categoryLabels[exp.category] || exp.category}</span>
          <span class="severity-badge ${exp.severity}">${exp.severity}</span>
          ${exp.phrase !== "(stylometric pattern)" ? `<span class="phrase">"${exp.phrase}"</span>` : ""}
        </div>
        <div class="reason">${isSenior ? "→ " : ""}${exp.reason}</div>
      `;
      explContainer.appendChild(div);
    });
  }

  // Tips
  const tipsContainer = document.getElementById("tips-container");
  tipsContainer.innerHTML = "";
  if (tips && tips.length > 0) {
    tips.forEach(tip => {
      const div = document.createElement("div");
      div.className = "tip-item";
      div.innerHTML = `<span class="tip-text">${tip}</span>`;
      tipsContainer.appendChild(div);
    });
  }
}

function setBar(id, value) {
  const el = document.getElementById(id);
  const pct = Math.min(100, Math.max(0, value));
  el.style.width = pct + "%";
  el.className = `signal-fill ${pct < 40 ? "low" : pct < 70 ? "med" : "high"}`;
}
