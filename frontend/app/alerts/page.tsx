"use client";

import { useEffect, useState } from "react";
import { getAlerts, type Alert } from "@/lib/api";
import AlertQueue from "@/components/AlertQueue";
import InvestigationChat from "@/components/InvestigationChat";
import { RefreshCw, X } from "lucide-react";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  async function loadAlerts() {
    setLoading(true);
    setError(null);
    try {
      const data = await getAlerts({ limit: 100 });
      setAlerts(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load alerts");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadAlerts(); }, []);

  return (
    <div className="max-w-7xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-[var(--text-primary)]">Alert queue</h1>
          <p className="text-sm text-[var(--text-muted)] mt-0.5">{alerts.length} alerts ingested</p>
        </div>
        <button
          onClick={loadAlerts}
          disabled={loading}
          className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium bg-indigo-600 hover:bg-indigo-500 rounded-lg text-white transition-colors disabled:opacity-50"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 mb-4">
          <p className="text-sm text-red-300">{error}</p>
        </div>
      )}

      <div className="flex gap-6">
        {/* Alert table */}
        <div className={selectedAlert ? "flex-1 min-w-0" : "w-full"}>
          <AlertQueue alerts={alerts} onAlertClick={setSelectedAlert} />
        </div>

        {/* Side panel: investigate selected alert */}
        {selectedAlert && (
          <div className="w-[380px] flex-shrink-0 h-[calc(100vh-140px)] sticky top-6">
            <div className="relative h-full">
              <button
                onClick={() => setSelectedAlert(null)}
                className="absolute top-2 right-2 z-10 p-1 rounded-md hover:bg-[var(--surface-3)] text-[var(--text-muted)]"
              >
                <X size={14} />
              </button>
              <InvestigationChat
                alertId={selectedAlert.id}
                contextLabel={`${selectedAlert.id} — ${selectedAlert.attack_category} (${selectedAlert.severity})`}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
