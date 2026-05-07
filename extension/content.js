// TruthShield Content Script v3.0
// Captures selected text + injects community warning banners

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "get_selection") {
    const selectedText = window.getSelection().toString().trim();
    sendResponse({ text: selectedText });
  }

  if (message.type === "truthshield_domain_warning") {
    injectWarningBanner(message.data);
  }
});

function injectWarningBanner(data) {
  // Don't inject twice
  if (document.getElementById("truthshield-warning-banner")) return;

  const banner = document.createElement("div");
  banner.id = "truthshield-warning-banner";
  banner.innerHTML = `
    <style>
      #truthshield-warning-banner {
        position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
        background: linear-gradient(135deg, #1a0000 0%, #2d0a0a 50%, #1a0000 100%);
        border-bottom: 3px solid #ef4444;
        color: #fff; font-family: 'Segoe UI', system-ui, sans-serif;
        padding: 0; animation: tsSlideDown 0.4s ease-out;
        box-shadow: 0 4px 30px rgba(239,68,68,0.4);
      }
      @keyframes tsSlideDown { from { transform: translateY(-100%); } to { transform: translateY(0); } }
      @keyframes tsPulse { 0%,100% { opacity: 1; } 50% { opacity: 0.6; } }
      @keyframes tsGlow { 0%,100% { box-shadow: 0 0 10px #ef4444; } 50% { box-shadow: 0 0 25px #ef4444, 0 0 50px #ef444480; } }
      .ts-warn-inner {
        max-width: 900px; margin: 0 auto; padding: 16px 24px;
        display: flex; align-items: flex-start; gap: 16px;
      }
      .ts-warn-icon {
        font-size: 40px; animation: tsPulse 1.5s ease-in-out infinite;
        flex-shrink: 0; line-height: 1;
      }
      .ts-warn-content { flex: 1; min-width: 0; }
      .ts-warn-title {
        font-size: 16px; font-weight: 800; letter-spacing: 2px;
        text-transform: uppercase; color: #ef4444; margin-bottom: 6px;
        display: flex; align-items: center; gap: 8px;
      }
      .ts-warn-shield {
        display: inline-block; background: #ef4444; color: #fff;
        padding: 2px 8px; border-radius: 4px; font-size: 11px;
        font-weight: 700; letter-spacing: 1px; animation: tsGlow 2s infinite;
      }
      .ts-warn-domain {
        font-size: 13px; color: #fca5a5; margin-bottom: 8px;
        font-family: monospace; word-break: break-all;
      }
      .ts-warn-stats {
        display: flex; gap: 16px; margin-bottom: 8px; font-size: 12px;
      }
      .ts-warn-stat {
        background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.3);
        padding: 4px 10px; border-radius: 6px; color: #fca5a5;
      }
      .ts-warn-stat strong { color: #fff; }
      .ts-warn-rec {
        font-size: 12px; color: #fecaca; line-height: 1.5;
        background: rgba(239,68,68,0.1); padding: 8px 12px;
        border-radius: 6px; border-left: 3px solid #ef4444; margin-bottom: 10px;
      }
      .ts-warn-buttons { display: flex; gap: 10px; }
      .ts-btn-leave {
        background: #ef4444; color: #fff; border: none;
        padding: 8px 20px; border-radius: 6px; font-weight: 700;
        font-size: 13px; cursor: pointer; transition: all 0.2s;
      }
      .ts-btn-leave:hover { background: #dc2626; transform: scale(1.02); }
      .ts-btn-continue {
        background: transparent; color: #71717a; border: 1px solid #3f3f46;
        padding: 8px 16px; border-radius: 6px; font-size: 12px;
        cursor: pointer; transition: all 0.2s;
      }
      .ts-btn-continue:hover { border-color: #71717a; color: #a1a1aa; }
      .ts-btn-close {
        position: absolute; top: 12px; right: 16px; background: none;
        border: none; color: #71717a; font-size: 20px; cursor: pointer;
        line-height: 1;
      }
      .ts-btn-close:hover { color: #fff; }
    </style>
    <div class="ts-warn-inner" style="position:relative;">
      <div class="ts-warn-icon">⚠️</div>
      <div class="ts-warn-content">
        <div class="ts-warn-title">
          <span class="ts-warn-shield">TRUTHSHIELD</span>
          COMMUNITY WARNING
        </div>
        <div class="ts-warn-domain">🌐 ${data.domain}</div>
        <div class="ts-warn-stats">
          <div class="ts-warn-stat">🚨 Threat: <strong>${data.threat_type || "Unknown"}</strong></div>
          <div class="ts-warn-stat">👥 Reports: <strong>${data.report_count || 1}</strong></div>
          <div class="ts-warn-stat">👍 <strong>${data.upvotes || 0}</strong> 👎 <strong>${data.downvotes || 0}</strong></div>
        </div>
        <div class="ts-warn-rec">
          🛡️ <strong>Recommendation:</strong> Avoid entering passwords, OTPs, banking details, or making payments on this site.
          This domain has been flagged by the TruthShield community.
        </div>
        <div class="ts-warn-buttons">
          <button class="ts-btn-leave" id="ts-leave-btn">🚪 Leave Site</button>
          <button class="ts-btn-continue" id="ts-continue-btn">Continue Anyway →</button>
        </div>
      </div>
      <button class="ts-btn-close" id="ts-close-btn">✕</button>
    </div>
  `;

  document.documentElement.appendChild(banner);

  document.getElementById("ts-leave-btn").addEventListener("click", () => {
    window.location.href = "about:blank";
  });

  document.getElementById("ts-continue-btn").addEventListener("click", () => {
    banner.style.animation = "none";
    banner.style.transition = "transform 0.3s ease-in";
    banner.style.transform = "translateY(-100%)";
    setTimeout(() => banner.remove(), 300);
  });

  document.getElementById("ts-close-btn").addEventListener("click", () => {
    banner.style.animation = "none";
    banner.style.transition = "transform 0.3s ease-in";
    banner.style.transform = "translateY(-100%)";
    setTimeout(() => banner.remove(), 300);
  });
}
