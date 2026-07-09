"use client";

import SeverityBadge, { StatusBadge, MitreBadge } from "./SeverityBadge";
import { Clock, MapPin, AlertTriangle, ArrowRight } from "lucide-react";
import type { Case } from "@/lib/api";

interface CaseViewProps {
  caseData: Case;
  onStatusChange?: (status: string) => void;
}

export default function CaseView({ caseData, onStatusChange }: CaseViewProps) {
  const statuses = ["open", "investigating", "resolved", "false_positive"];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-5">
        <div className="flex items-start justify-between mb-3">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h2 className="text-lg font-semibold text-[var(--text-primary)]">{caseData.title}</h2>
              <SeverityBadge severity={caseData.severity} size="md" />
            </div>
            <p className="text-xs font-mono text-[var(--text-muted)]">{caseData.id}</p>
          </div>
          <StatusBadge status={caseData.status} />
        </div>

        <p className="text-sm text-[var(--text-secondary)] mb-4">{caseData.summary}</p>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div>
            <span className="text-[var(--text-muted)] block mb-1">Alert count</span>
            <span className="text-[var(--text-primary)] font-medium">{caseData.alert_count}</span>
          </div>
          <div>
            <span className="text-[var(--text-muted)] block mb-1">Primary attack</span>
            <span className="text-[var(--text-primary)] font-medium">{caseData.primary_attack}</span>
          </div>
          <div>
            <span className="text-[var(--text-muted)] block mb-1">Source IPs</span>
            <div className="font-mono text-[var(--text-primary)]">
              {caseData.source_ips.slice(0, 2).join(", ")}
              {caseData.source_ips.length > 2 && ` +${caseData.source_ips.length - 2}`}
            </div>
          </div>
          <div>
            <span className="text-[var(--text-muted)] block mb-1">MITRE techniques</span>
            <div className="flex flex-wrap gap-1">
              {caseData.mitre_techniques.slice(0, 3).map((t) => (
                <MitreBadge key={t} technique={t} />
              ))}
            </div>
          </div>
        </div>

        {/* Status actions */}
        {onStatusChange && (
          <div className="mt-4 pt-4 border-t border-[var(--border)] flex gap-2">
            {statuses
              .filter((s) => s !== caseData.status)
              .map((s) => (
                <button
                  key={s}
                  onClick={() => onStatusChange(s)}
                  className="px-3 py-1.5 text-xs font-medium rounded-lg border border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--surface-2)] hover:text-[var(--text-primary)] transition-colors capitalize"
                >
                  Mark {s.replace("_", " ")}
                </button>
              ))}
          </div>
        )}
      </div>

      {/* Timeline */}
      {caseData.timeline && caseData.timeline.length > 0 && (
        <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-5">
          <h3 className="text-sm font-medium text-[var(--text-primary)] mb-4">Event timeline</h3>
          <div className="space-y-0">
            {caseData.timeline.map((event, i) => (
              <div key={i} className="flex gap-3 relative">
                {/* Timeline connector */}
                <div className="flex flex-col items-center">
                  <div className="w-2 h-2 rounded-full bg-indigo-500 mt-1.5 z-10" />
                  {i < caseData.timeline!.length - 1 && (
                    <div className="w-px flex-1 bg-[var(--border)]" />
                  )}
                </div>
                {/* Event content */}
                <div className="pb-4 flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-xs font-mono text-indigo-300">{event.alert_id}</span>
                    <span className="text-[10px] text-[var(--text-muted)]">
                      {new Date(event.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)]">{event.event}</p>
                  <div className="text-[10px] font-mono text-[var(--text-muted)] mt-0.5">
                    {event.source_ip} → {event.dest_ip}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Associated alerts */}
      {caseData.alerts && caseData.alerts.length > 0 && (
        <div className="bg-[var(--surface-1)] border border-[var(--border)] rounded-xl p-5">
          <h3 className="text-sm font-medium text-[var(--text-primary)] mb-3">
            Associated alerts ({caseData.alerts.length})
          </h3>
          <div className="space-y-2">
            {caseData.alerts.map((alert: any) => (
              <div
                key={alert.id}
                className="flex items-center gap-3 p-3 bg-[var(--surface-2)] rounded-lg"
              >
                <SeverityBadge severity={alert.severity} />
                <span className="text-xs font-mono text-[var(--text-primary)]">{alert.id}</span>
                <span className="text-xs text-[var(--text-secondary)] flex-1">{alert.description}</span>
                <span className="text-[10px] text-[var(--text-muted)]">
                  {(alert.confidence * 100).toFixed(0)}% conf.
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
