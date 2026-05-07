// TruthShield – Blocklist API Client
// Connects to the FastAPI backend for domain blocklist operations

const API_BASE = import.meta.env.VITE_API_URL || "https://truth-guard-1.onrender.com";

export interface BlockedDomain {
  id: string;
  domain: string;
  threat_type: string;
  report_count: number;
  upvotes: number;
  downvotes: number;
  created_at: string;
  updated_at: string;
}

export interface DomainReport {
  id: string;
  domain_id: string;
  user_id: string;
  threat_type: string;
  description: string;
  proof_link: string;
  upvotes: number;
  downvotes: number;
  created_at: string;
}

export interface DomainDetails extends BlockedDomain {
  reports: DomainReport[];
}

export interface BlocklistStats {
  total_domains: number;
  total_reports: number;
  threat_types: Record<string, number>;
  top_10: Array<{
    domain: string;
    report_count: number;
    threat_type: string;
    upvotes: number;
    downvotes: number;
  }>;
  timeline: Array<{ date: string; count: number }>;
}

export const THREAT_TYPES = ["Phishing", "Job Scam", "Lottery", "Financial Fraud", "Other"] as const;

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Request failed" }));
    throw new Error(err.detail || "Request failed");
  }
  return res.json();
}

export async function fetchBlocklist(params: {
  limit?: number;
  offset?: number;
  threat_type?: string;
  sort?: string;
  search?: string;
}): Promise<{ total: number; domains: BlockedDomain[] }> {
  const qs = new URLSearchParams();
  if (params.limit) qs.set("limit", String(params.limit));
  if (params.offset) qs.set("offset", String(params.offset));
  if (params.threat_type) qs.set("threat_type", params.threat_type);
  if (params.sort) qs.set("sort", params.sort);
  if (params.search) qs.set("search", params.search);
  return apiFetch(`/api/blocklist?${qs.toString()}`);
}

export async function fetchDomainDetails(domain: string): Promise<DomainDetails> {
  return apiFetch(`/api/blocklist/${encodeURIComponent(domain)}`);
}

export async function reportDomain(data: {
  domain: string;
  threat_type: string;
  description?: string;
  proof_link?: string;
}): Promise<{ success: boolean; domain: string; message: string }> {
  return apiFetch("/api/blocklist/add", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function upvoteDomain(domain: string): Promise<{ success: boolean; upvotes: number }> {
  return apiFetch(`/api/blocklist/${encodeURIComponent(domain)}/upvote`, { method: "POST" });
}

export async function downvoteDomain(domain: string): Promise<{ success: boolean; downvotes: number }> {
  return apiFetch(`/api/blocklist/${encodeURIComponent(domain)}/downvote`, { method: "POST" });
}

export async function fetchBlocklistStats(): Promise<BlocklistStats> {
  return apiFetch("/api/blocklist/stats");
}

export async function seedDemoData(): Promise<{ success: boolean; message: string }> {
  return apiFetch("/api/blocklist/seed", { method: "POST" });
}

export interface DomainCheckResult {
  blocked: boolean;
  domain: string;
  threat_type?: string;
  report_count?: number;
  upvotes?: number;
  downvotes?: number;
}

export async function checkDomain(domain: string): Promise<DomainCheckResult> {
  return apiFetch(`/api/blocklist/check?domain=${encodeURIComponent(domain)}`);
}
