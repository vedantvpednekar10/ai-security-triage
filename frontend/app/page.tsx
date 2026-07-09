"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getMetrics, getAlerts, generateCases, type DashboardMetrics, type Alert } from "@/lib/api";
import MetricsDashboard from "@/components/MetricsDashboard";
import AlertQueue from "@/components/AlertQueue";
import { RefreshCw, Layers } from "lucide-react";

export default function DashboardPage() {
  const router = useRouter();
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [m, a] = await Promise.all([
        getMetrics(),
        getAlerts({ limit: 5 }),
      ]);
      setMetrics(m);
      setRecentAlerts(a);
    } catch (err) {
      setError(
        `Could not connect to the backend. Make sure it's running at http://localhost:8000.\n\n${
          err instanceof Error ? err.message : "Unknown error"
        }`
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleGenerateCases() {
    setGenerating(true);
    try {
      const result = await generateCases();
      alert(`Generated ${result.generated} investigation cases.`);
      loadData();
    } catch (err) {
      alert(`Failed to generate cases: ${err instanceof Error ? err.message : "Unknown error"}`);
    } finally {
      setGenerating(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-[var(--text-primary)]">Dashboard</h1>
          <p className="text-sm text-[var(--text-muted)] mt-0.5">Security operations overview</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleGenerateCases}
            disabled={generating}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium bg-[var(--surface-2)] border border-[var(--border)] rounded-lg text-[var(--text-secondary)] hover:bg-[var(--surface-3)] transition-colors disabled:opacity-50"
          >
            <Layers size={14} />
            {generating ? "Generating..." : "Auto-cluster cases"}
          </button>
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 rounded-lg text-white transition-colors disabled:opacity-50"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
          <p className="text-sm text-red-300 whitespace-pre-wrap">{error}</p>
        </div>
      )}

      {/* Metrics */}
      <MetricsDashboard metrics={metrics} />

      {/* Recent alerts */}
      <div>
        <h2 className="text-sm font-medium text-[var(--text-primary)] mb-3">Recent alerts</h2>
        {recentAlerts.length > 0 ? (
          <AlertQueue alerts={recentAlerts} onAlertClick={() => router.push("/alerts")} />
        ) : !loading ? (
          <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-8 text-center text-sm text-[var(--text-muted)]">
            No alerts yet. Classify some alerts using the API to see them here.
          </div>
        ) : null}
      </div>
    </div>
  );
}