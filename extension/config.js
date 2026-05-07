// TruthShield Extension Configuration
// =============================================
// IMPORTANT: Change this URL to your deployed backend
// This MUST point to a cloud-deployed backend (Render, Railway, etc.)
// so that ALL users share the same community blocklist.
// =============================================

const TRUTHSHIELD_CONFIG = {
  // Production API URL — shared across ALL extension users globally
  API_BASE: "https://truth-guard-1.onrender.com",

  // Cache duration for domain checks (5 minutes)
  CACHE_TTL: 5 * 60 * 1000,

  // Extension version
  VERSION: "4.0.0",
};
