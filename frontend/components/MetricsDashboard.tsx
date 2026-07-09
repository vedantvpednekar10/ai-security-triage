"use client";

import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { AlertTriangle, Shield, FolderOpen, CheckCircle, TrendingUp, Zap } from "lucide-react";
import type { DashboardMetrics } from "@/lib/api";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#64748b",
};

function StatCard({ label, value, icon: Icon, color }: {
  label: string; value: string | number; icon: any; color: string;
}) {
  return (
    <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs text-[var(--text-muted)] uppercase tracking-wider">{label}</span>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center`} style={{ background: `${color}20` }}>
          <Icon size={16} style={{ color }} />
        </div>
      </div>
      <div className="text-2xl font-semibold text-[var(--text-primary)]">{value}</div>
    </div>
  );
}

export default function MetricsDashboard({ metrics }: { metrics: DashboardMetrics | null }) {
  if (!metrics) {
    return (
      <div className="grid grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-4 h-24 animate-pulse" />
        ))}
      </div>
    );
  }

  const categoryData = Object.entries(metrics.alerts_by_category)
    .filter(([k]) => k !== "Normal")
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);

  const severityData = Object.entries(metrics.alerts_by_severity).map(([name, count]) => ({
    name,
    count,
    fill: SEVERITY_COLORS[name] || "#64748b",
  }));

  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total alerts" value={metrics.total_alerts} icon={AlertTriangle} color="#6366f1" />
        <StatCard label="Critical" value={metrics.critical_alerts} icon={Zap} color="#ef4444" />
        <StatCard label="Open cases" value={metrics.open_cases} icon={FolderOpen} color="#f97316" />
        <StatCard label="Resolved" value={metrics.resolved_cases} icon={CheckCircle} color="#22c55e" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alerts by category */}
        <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-5">
          <h3 className="text-sm font-medium text-[var(--text-primary)] mb-4">Alerts by category</h3>
          {categoryData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={categoryData} layout="vertical" margin={{ left: 10, right: 20 }}>
                <XAxis type="number" tick={{ fill: "#9494a0", fontSize: 11 }} />
                <YAxis dataKey="name" type="category" width={100} tick={{ fill: "#9494a0", fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: "#1a1a24", border: "1px solid #2a2a36", borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: "#e4e4e8" }}
                />
                <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[220px] flex items-center justify-center text-sm text-[var(--text-muted)]">No attack data yet</div>
          )}
        </div>

        {/* Severity distribution */}
        <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-5">
          <h3 className="text-sm font-medium text-[var(--text-primary)] mb-4">Severity distribution</h3>
          {severityData.length > 0 ? (
            <div className="flex items-center gap-6">
              <ResponsiveContainer width="50%" height={220}>
                <PieChart>
                  <Pie data={severityData} dataKey="count" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3}>
                    {severityData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#1a1a24", border: "1px solid #2a2a36", borderRadius: 8, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2">
                {severityData.map((d) => (
                  <div key={d.name} className="flex items-center gap-2 text-xs">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ background: d.fill }} />
                    <span className="text-[var(--text-secondary)] capitalize w-16">{d.name}</span>
                    <span className="text-[var(--text-primary)] font-medium">{d.count}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-[220px] flex items-center justify-center text-sm text-[var(--text-muted)]">No data yet</div>
          )}
        </div>
      </div>

      {/* Top IPs and MITRE techniques */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-5">
          <h3 className="text-sm font-medium text-[var(--text-primary)] mb-3">Top source IPs</h3>
          <div className="space-y-2">
            {metrics.top_source_ips.slice(0, 5).map((item, i) => (
              <div key={i} className="flex items-center justify-between py-1.5 border-b border-[var(--border)] last:border-0">
                <span className="text-xs font-mono text-[var(--text-secondary)]">{item.ip}</span>
                <span className="text-xs font-medium text-[var(--text-primary)]">{item.count} alerts</span>
              </div>
            ))}
            {metrics.top_source_ips.length === 0 && (
              <span className="text-xs text-[var(--text-muted)]">No data</span>
            )}
          </div>
        </div>

        <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-5">
          <h3 className="text-sm font-medium text-[var(--text-primary)] mb-3">Top MITRE techniques</h3>
          <div className="space-y-2">
            {metrics.top_mitre_techniques.slice(0, 5).map((item, i) => (
              <div key={i} className="flex items-center justify-between py-1.5 border-b border-[var(--border)] last:border-0">
                <span className="text-xs font-mono text-indigo-300">{item.technique}</span>
                <span className="text-xs font-medium text-[var(--text-primary)]">{item.count} hits</span>
              </div>
            ))}
            {metrics.top_mitre_techniques.length === 0 && (
              <span className="text-xs text-[var(--text-muted)]">No data</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
