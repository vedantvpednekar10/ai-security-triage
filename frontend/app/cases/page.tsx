"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getCases, generateCases, type Case } from "@/lib/api";
import SeverityBadge, { StatusBadge, MitreBadge } from "@/components/SeverityBadge";
import { RefreshCw, Layers, ChevronRight, FolderOpen } from "lucide-react";

export default function CasesPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filterStatus, setFilterStatus] = useState("all");

  async function loadCases() {
    setLoading(true);
    setError(null);
    try {
      setCases(await getCases());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load cases");
    } finally {
      setLoading(false);
    }
  }

  async function handleGenerate() {
    setGenerating(true);
    try {
      const result = await generateCases();
      await loadCases();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate cases");
    } finally {
      setGenerating(false);
    }
  }

  useEffect(() => { loadCases(); }, []);

  const filtered = filterStatus === "all"
    ? cases
    : cases.filter((c) => c.status === filterStatus);

  return (
    <div className="max-w-7xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-[var(--text-primary)]">Investigation cases</h1>
          <p className="text-sm text-[var(--text-muted)] mt-0.5">{cases.length} cases total</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleGenerate}
            disabled={generating}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium bg-[var(--surface-2)] border border-[var(--border)] rounded-lg text-[var(--text-secondary)] hover:bg-[var(--surface-3)] transition-colors disabled:opacity-50"
          >
            <Layers size={14} />
            {generating ? "Clustering..." : "Auto-cluster alerts"}
          </button>
          <button
            onClick={loadCases}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 rounded-lg text-white transition-colors disabled:opacity-50"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 mb-4">
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      {/* Status filter */}
      <div className="flex gap-2 mb-4">
        {["all", "open", "investigating", "resolved", "false_positive"].map((s) => (
          <button
            key={s}
            onClick={() => setFilterStatus(s)}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors capitalize ${
              filterStatus === s
                ? "bg-indigo-500/15 border-indigo-500/40 text-indigo-300"
                : "bg-[var(--surface-1)] border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-2)]"
            }`}
          >
            {s === "all" ? "All" : s.replace("_", " ")}
          </button>
        ))}
      </div>

      {/* Cases list */}
      {filtered.length > 0 ? (
        <div className="space-y-3">
          {filtered.map((c) => (
            <Link key={c.id} href={`/cases/${c.id}`}>
              <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-4 hover:bg-[var(--surface-2)] transition-colors cursor-pointer group">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <SeverityBadge severity={c.severity} />
                    <h3 className="text-sm font-medium text-[var(--text-primary)]">{c.title}</h3>
                  </div>
                  <div className="flex items-center gap-3">
                    <StatusBadge status={c.status} />
                    <ChevronRight size={16} className="text-[var(--text-muted)] group-hover:text-[var(--text-secondary)] transition-colors" />
                  </div>
                </div>
                <div className="flex items-center gap-6 text-xs text-[var(--text-muted)]">
                  <span>{c.alert_count} alerts</span>
                  <span>{c.primary_attack}</span>
                  <span className="font-mono">{c.source_ips.slice(0, 2).join(", ")}</span>
                  <div className="flex gap-1 ml-auto">
                    {c.mitre_techniques.slice(0, 3).map((t) => (
                      <MitreBadge key={t} technique={t} />
                    ))}
                  </div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      ) : !loading ? (
        <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-12 text-center">
          <FolderOpen size={32} className="mx-auto mb-3 text-[var(--text-muted)]" />
          <p className="text-sm text-[var(--text-muted)]">
            No cases yet. Click "Auto-cluster alerts" to generate investigation cases from existing alerts.
          </p>
        </div>
      ) : null}
    </div>
  );
}
