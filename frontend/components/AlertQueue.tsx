"use client";

import { useState } from "react";
import { AlertTriangle, ExternalLink, Filter } from "lucide-react";
import SeverityBadge, { MitreBadge } from "./SeverityBadge";
import type { Alert } from "@/lib/api";

interface AlertQueueProps {
  alerts: Alert[];
  onAlertClick?: (alert: Alert) => void;
}

export default function AlertQueue({ alerts, onAlertClick }: AlertQueueProps) {
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterCategory, setFilterCategory] = useState<string>("all");

  const categories = [...new Set(alerts.map((a) => a.attack_category))].sort();
  const severities = ["critical", "high", "medium", "low", "info"];

  const filtered = alerts.filter((a) => {
    if (filterSeverity !== "all" && a.severity !== filterSeverity) return false;
    if (filterCategory !== "all" && a.attack_category !== filterCategory) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-3">
        <Filter size={14} className="text-[var(--text-muted)]" />
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-indigo-500"
        >
          <option value="all">All severities</option>
          {severities.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select
          value={filterCategory}
          onChange={(e) => setFilterCategory(e.target.value)}
          className="bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-indigo-500"
        >
          <option value="all">All categories</option>
          {categories.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <span className="text-xs text-[var(--text-muted)] ml-auto">{filtered.length} alerts</span>
      </div>

      {/* Table */}
      <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-[var(--text-muted)] font-medium">Severity</th>
              <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-[var(--text-muted)] font-medium">Alert ID</th>
              <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-[var(--text-muted)] font-medium">Category</th>
              <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-[var(--text-muted)] font-medium">Source → Dest</th>
              <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-[var(--text-muted)] font-medium">MITRE</th>
              <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-[var(--text-muted)] font-medium">Confidence</th>
              <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-[var(--text-muted)] font-medium">Time</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((alert) => (
              <tr
                key={alert.id}
                onClick={() => onAlertClick?.(alert)}
                className="border-b border-[var(--border)] last:border-0 hover:bg-[var(--surface-2)] cursor-pointer transition-colors"
              >
                <td className="px-4 py-3">
                  <SeverityBadge severity={alert.severity} />
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs font-mono text-[var(--text-primary)]">{alert.id}</span>
                  {alert.is_anomaly && (
                    <span className="ml-2 text-[10px] text-amber-400 bg-amber-500/15 px-1.5 py-0.5 rounded">anomaly</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-[var(--text-secondary)]">{alert.attack_category}</span>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs font-mono text-[var(--text-secondary)]">
                    {alert.source_ip}:{alert.source_port} → {alert.dest_ip}:{alert.dest_port}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {alert.mitre_techniques.slice(0, 2).map((t) => (
                      <MitreBadge key={t} technique={t} />
                    ))}
                    {alert.mitre_techniques.length > 2 && (
                      <span className="text-[10px] text-[var(--text-muted)]">+{alert.mitre_techniques.length - 2}</span>
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-[var(--surface-3)] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-indigo-500"
                        style={{ width: `${alert.confidence * 100}%` }}
                      />
                    </div>
                    <span className="text-[10px] text-[var(--text-muted)]">{(alert.confidence * 100).toFixed(0)}%</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-[var(--text-muted)]">
                    {new Date(alert.timestamp).toLocaleTimeString()}
                  </span>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-sm text-[var(--text-muted)]">
                  No alerts match the current filters
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
