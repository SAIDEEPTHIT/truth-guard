// TruthShield Enhanced Popup Script v2.1
// Handles: Text, Image, and URL analysis results

document.addEventListener("DOMContentLoaded", () => {
  // ── Senior Mode (use chrome.storage.local for persistence) ──
  const seniorToggle = document.getElementById("senior-toggle");

  chrome.storage.local.get(["truthshield_senior"], (data) => {
    const isSenior = data.truthshield_senior === true;
    seniorToggle.checked = isSenior;
    if (isSenior) document.body.classList.add("senior-mode");
  });

  seniorToggle.addEventListener("change", () => {
    const isChecked = seniorToggle.checked;
    document.body.classList.toggle("senior-mode", isChecked);
    chrome.storage.local.set({ truthshield_senior: isChecked });
    chrome.storage.local.get(["truthshield_result", "truthshield_mode"], (data) => {
      if (data.truthshield_result) renderResult(data.truthshield_result, data.truthshield_mode || "text");
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
  chrome.storage.local.get(["truthshield_result", "truthshield_loading", "truthshield_mode"], (data) => {
    if (data.truthshield_loading) showLoading();
    else if (data.truthshield_result) renderResult(data.truthshield_result, data.truthshield_mode || "text");
  });

  // ── Live updates ──
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "analysis_start") showLoading();
    if (message.type === "analysis_result") renderResult(message.data, message.mode || "text");
    if (message.type === "analysis_error") showError(message.error);
  });

  // ── Clear ──
  document.getElementById("clear-btn").addEventListener("click", () => {
    chrome.storage.local.remove(["truthshield_result", "truthshield_loading", "truthshield_mode"]);
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
  document.getElementById("analysis-type-badge").style.display = "none";
}

function renderResult(data, mode = "text") {
  const isSenior = document.body.classList.contains("senior-mode");

  document.getElementById("idle-msg").style.display = "none";
  document.getElementById("loading").style.display = "none";
  document.getElementById("result").style.display = "block";
  document.getElementById("error-msg").style.display = "none";
  document.getElementById("tabs-container").style.display = "block";
  document.getElementById("clear-btn").style.display = "block";

  // Show analysis type badge
  const typeBadge = document.getElementById("analysis-type-badge");
  typeBadge.style.display = "inline-block";
  typeBadge.textContent = mode === "image" ? "🖼️ Image" : mode === "url" ? "🔗 URL" : "📝 Text";
  typeBadge.className = `type-badge ${mode}`;

  if (mode === "image") {
    renderImageResult(data, isSenior);
  } else if (mode === "url") {
    renderURLResult(data, isSenior);
  } else {
    renderTextResult(data, isSenior);
  }
}

function renderTextResult(data, isSenior) {
  const { risk_score, classification, signals, highlighted_text, explanations, summary, tips, readability, language, url_analysis } = data;

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
  renderSeniorVerdict(classification, isSenior);

  // Signal bars
  setBar("ai-bar", signals.ai_generated);
  setBar("scam-bar", signals.scam_keywords);
  setBar("emo-bar", signals.emotional_manipulation);
  document.getElementById("tab-signals-content").style.display = "block";

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
  renderExplanations(explanations, isSenior);

  // Tips
  renderTips(tips, isSenior);

  // Readability
  const readabilityEl = document.getElementById("readability-container");
  if (readability && readability.score > 0) {
    readabilityEl.style.display = "block";
    readabilityEl.innerHTML = `
      <div class="meta-item"><span>📖 Readability</span><span class="meta-value">${readability.level} (${readability.score}/100)</span></div>
      <div class="meta-item"><span>📊 Grade Level</span><span class="meta-value">${readability.grade}</span></div>
      <div class="meta-item"><span>📝 Words</span><span class="meta-value">${readability.wordCount}</span></div>
      <div class="meta-item"><span>📄 Sentences</span><span class="meta-value">${readability.sentenceCount}</span></div>
    `;
  } else {
    readabilityEl.style.display = "none";
  }

  // Language
  const langEl = document.getElementById("language-container");
  if (language) {
    langEl.style.display = "block";
    langEl.innerHTML = `<div class="meta-item"><span>🌐 Language</span><span class="meta-value">${language}</span></div>`;
  }

  // URL analysis
  const urlContainer = document.getElementById("url-analysis-container");
  if (url_analysis && url_analysis.length > 0) {
    urlContainer.style.display = "block";
    urlContainer.innerHTML = `<h4 style="font-size:11px;text-transform:uppercase;color:#71717a;margin-bottom:6px;">🔗 Links Found</h4>` +
      url_analysis.map(u => `
        <div class="url-item ${u.safe ? 'safe' : 'danger'}">
          <div class="url-text">${u.url.length > 50 ? u.url.substring(0, 47) + '...' : u.url}</div>
          <div class="url-score">${u.safe ? '✅ Safe' : '⚠️ ' + u.score + '/100'}</div>
          ${u.flags.map(f => `<div class="url-flag">${f}</div>`).join('')}
        </div>
      `).join('');
  } else {
    urlContainer.style.display = "none";
  }
}

function renderImageResult(data, isSenior) {
  const { risk_score, classification, indicators, metadata, tips } = data;

  const scoreEl = document.getElementById("score-circle");
  scoreEl.textContent = risk_score;
  const classEl = document.getElementById("classification");
  const statusEl = document.getElementById("status");

  const riskClass = classification === "Likely Authentic" ? "safe" : classification === "Possibly AI-Generated" ? "suspicious" : "high-risk";
  scoreEl.className = `score-circle ${riskClass}`;
  classEl.className = `classification ${riskClass}`;
  classEl.textContent = isSenior
    ? (classification === "Likely Authentic" ? "✅ Real Photo" : classification === "Possibly AI-Generated" ? "⚠️ Maybe Computer-Made" : "🚨 Probably Fake!")
    : classification;
  statusEl.className = `card ${riskClass}`;

  renderSeniorVerdict(classification === "Likely Authentic" ? "Safe" : classification === "Possibly AI-Generated" ? "Suspicious" : "High Risk", isSenior);

  // Hide text-specific tabs
  document.getElementById("tab-signals-content").style.display = "none";

  // Show indicators as explanations
  const explContainer = document.getElementById("explanations-container");
  explContainer.innerHTML = "";
  if (indicators && indicators.length > 0) {
    indicators.forEach(ind => {
      const div = document.createElement("div");
      const isPositive = ind.startsWith("✅");
      div.className = `explanation-item ${isPositive ? 'safe-indicator' : 'ai'}`;
      div.innerHTML = `<div class="reason">${ind}</div>`;
      explContainer.appendChild(div);
    });
  }

  // Show metadata
  const readabilityEl = document.getElementById("readability-container");
  if (metadata) {
    readabilityEl.style.display = "block";
    readabilityEl.innerHTML = Object.entries(metadata).map(([k, v]) =>
      `<div class="meta-item"><span>${k}</span><span class="meta-value">${v}</span></div>`
    ).join('');
  }

  // Summary
  const summaryEl = document.getElementById("summary-container");
  summaryEl.style.display = "block";
  summaryEl.textContent = isSenior
    ? (classification === "Likely Authentic"
      ? "This image appears to be a real photograph."
      : `This image has ${indicators.length} signs of being computer-generated. Be cautious!`)
    : `Image analysis complete: ${classification}. ${indicators.length} indicators analyzed.`;

  renderTips(tips, isSenior);

  // Clear unused sections
  document.getElementById("highlighted-text").innerHTML = "<em>N/A — Image analysis mode</em>";
  document.getElementById("language-container").style.display = "none";
  document.getElementById("url-analysis-container").style.display = "none";
}

function renderURLResult(data, isSenior) {
  const { risk_score, classification, url, flags, tips } = data;

  const scoreEl = document.getElementById("score-circle");
  scoreEl.textContent = risk_score;
  const classEl = document.getElementById("classification");
  const statusEl = document.getElementById("status");

  const riskClass = classification === "Safe" ? "safe" : classification === "Suspicious" ? "suspicious" : "high-risk";
  scoreEl.className = `score-circle ${riskClass}`;
  classEl.className = `classification ${riskClass}`;
  classEl.textContent = isSenior
    ? (classification === "Safe" ? "✅ Safe Link" : classification === "Suspicious" ? "⚠️ Be Careful!" : "🚨 Dangerous Link!")
    : classification;
  statusEl.className = `card ${riskClass}`;

  renderSeniorVerdict(classification, isSenior);

  document.getElementById("tab-signals-content").style.display = "none";

  // Show URL
  const summaryEl = document.getElementById("summary-container");
  summaryEl.style.display = "block";
  summaryEl.innerHTML = `<strong>URL:</strong> <code style="word-break:break-all;font-size:11px;">${url}</code>`;

  // Flags as explanations
  const explContainer = document.getElementById("explanations-container");
  explContainer.innerHTML = "";
  flags.forEach(flag => {
    const div = document.createElement("div");
    const isPositive = flag.startsWith("✅");
    div.className = `explanation-item ${isPositive ? 'safe-indicator' : 'scam'}`;
    div.innerHTML = `<div class="reason">${flag}</div>`;
    explContainer.appendChild(div);
  });

  renderTips(tips, isSenior);

  document.getElementById("highlighted-text").innerHTML = "<em>N/A — URL analysis mode</em>";
  document.getElementById("readability-container").style.display = "none";
  document.getElementById("language-container").style.display = "none";
  document.getElementById("url-analysis-container").style.display = "none";
}

// ── Helpers ──

function renderSeniorVerdict(classification, isSenior) {
  const verdictEl = document.getElementById("senior-verdict");
  if (isSenior) {
    verdictEl.style.display = "block";
    if (classification === "Safe") {
      verdictEl.textContent = "✅ This looks safe!";
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
}

function renderExplanations(explanations, isSenior) {
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
          ${exp.phrase !== "(stylometric pattern)" && exp.phrase !== "(stylometric)" ? `<span class="phrase">"${exp.phrase}"</span>` : ""}
        </div>
        <div class="reason">${isSenior ? "→ " : ""}${exp.reason}</div>
      `;
      explContainer.appendChild(div);
    });
  }
}

function renderTips(tips, isSenior) {
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
  if (!el) return;
  const pct = Math.min(100, Math.max(0, value));
  el.style.width = pct + "%";
  el.className = `signal-fill ${pct < 40 ? "low" : pct < 70 ? "med" : "high"}`;
}