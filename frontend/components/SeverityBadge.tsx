"use client";

import clsx from "clsx";

interface SeverityBadgeProps {
  severity: string;
  size?: "sm" | "md";
}

const colorMap: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  info: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

const dotColorMap: Record<string, string> = {
  critical: "bg-red-400",
  high: "bg-orange-400",
  medium: "bg-yellow-400",
  low: "bg-emerald-400",
  info: "bg-slate-400",
};

export default function SeverityBadge({ severity, size = "sm" }: SeverityBadgeProps) {
  const colors = colorMap[severity] || colorMap.info;
  const dotColor = dotColorMap[severity] || dotColorMap.info;

  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 border rounded-full font-medium capitalize",
        colors,
        size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-3 py-1 text-xs"
      )}
    >
      <span className={clsx("w-1.5 h-1.5 rounded-full", dotColor)} />
      {severity}
    </span>
  );
}

export function MitreBadge({ technique }: { technique: string }) {
  return (
    <span className="inline-flex items-center px-2 py-0.5 text-[11px] font-mono font-medium bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 rounded">
      {technique}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    open: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    investigating: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    resolved: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    false_positive: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };

  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 text-[11px] font-medium border rounded-full capitalize",
        colors[status] || colors.open
      )}
    >
      {status.replace("_", " ")}
    </span>
  );
}
