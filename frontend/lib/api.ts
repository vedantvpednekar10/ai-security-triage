/**
 * API client for the Security Alert Triage backend.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const error = await res.text();
    throw new Error(`API error ${res.status}: ${error}`);
  }
  return res.json();
}

// ── Alerts ──

export interface Alert {
  id: string;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  source_port: number;
  dest_port: number;
  attack_category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: number;
  is_anomaly: boolean;
  mitre_techniques: string[];
  description: string;
  case_id?: string;
}

export async function getAlerts(params?: {
  severity?: string;
  category?: string;
  limit?: number;
}): Promise<Alert[]> {
  const query = new URLSearchParams();
  if (params?.severity) query.set("severity", params.severity);
  if (params?.category) query.set("category", params.category);
  if (params?.limit) query.set("limit", String(params.limit));
  const qs = query.toString();
  return apiFetch(`/api/alerts${qs ? `?${qs}` : ""}`);
}

export async function getAlert(id: string): Promise<Alert> {
  return apiFetch(`/api/alerts/${id}`);
}

// ── Cases ──

export interface Case {
  id: string;
  title: string;
  status: "open" | "investigating" | "resolved" | "false_positive";
  severity: "critical" | "high" | "medium" | "low" | "info";
  alert_ids: string[];
  alert_count: number;
  primary_attack: string;
  mitre_techniques: string[];
  source_ips: string[];
  created_at: string;
  updated_at: string;
  summary: string;
  alerts?: Alert[];
  timeline?: { timestamp: string; alert_id: string; event: string; source_ip: string; dest_ip: string }[];
}

export async function getCases(params?: {
  status?: string;
  severity?: string;
}): Promise<Case[]> {
  const query = new URLSearchParams();
  if (params?.status) query.set("status", params.status);
  if (params?.severity) query.set("severity", params.severity);
  const qs = query.toString();
  return apiFetch(`/api/cases${qs ? `?${qs}` : ""}`);
}

export async function getCase(id: string): Promise<Case> {
  return apiFetch(`/api/cases/${id}`);
}

export async function generateCases(): Promise<{ generated: number; cases: Case[] }> {
  return apiFetch("/api/cases/generate", { method: "POST" });
}

export async function updateCaseStatus(id: string, status: string): Promise<Case> {
  return apiFetch(`/api/cases/${id}/status?status=${status}`, { method: "PATCH" });
}

// ── Investigation ──

export interface InvestigateResponse {
  answer: string;
  sources: { technique_id: string; name: string; tactics: string; url: string }[];
  mitre_techniques: { technique_id?: string; id?: string; name: string; tactics?: string; tactic?: string }[];
  suggested_actions: string[];
}

export async function investigate(params: {
  question: string;
  case_id?: string;
  alert_id?: string;
}): Promise<InvestigateResponse> {
  return apiFetch("/api/investigate", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

// ── Metrics ──

export interface DashboardMetrics {
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  open_cases: number;
  resolved_cases: number;
  false_positive_rate: number;
  avg_classification_confidence: number;
  alerts_by_category: Record<string, number>;
  alerts_by_severity: Record<string, number>;
  alerts_over_time: { time: string; count: number }[];
  top_source_ips: { ip: string; count: number }[];
  top_mitre_techniques: { technique: string; count: number }[];
}

export async function getMetrics(): Promise<DashboardMetrics> {
  return apiFetch("/api/metrics");
}

// ── Health ──

export async function getHealth(): Promise<{
  status: string;
  classifier_loaded: boolean;
  anomaly_detector_loaded: boolean;
  rag_initialized: boolean;
  alerts_count: number;
  cases_count: number;
}> {
  return apiFetch("/api/health");
}
