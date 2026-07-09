"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, AlertTriangle, FolderOpen, BarChart3, Search, Activity } from "lucide-react";
import clsx from "clsx";

const navItems = [
  { href: "/", label: "Dashboard", icon: BarChart3 },
  { href: "/alerts", label: "Alert queue", icon: AlertTriangle },
  { href: "/cases", label: "Cases", icon: FolderOpen },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed left-0 top-0 h-screen w-56 bg-[var(--surface-1)] border-r border-[var(--border)] flex flex-col z-50">
      {/* Logo */}
      <div className="p-5 flex items-center gap-2.5 border-b border-[var(--border)]">
        <div className="w-8 h-8 rounded-lg bg-indigo-500/20 flex items-center justify-center">
          <Shield className="w-4.5 h-4.5 text-indigo-400" size={18} />
        </div>
        <div>
          <div className="text-sm font-semibold text-[var(--text-primary)] leading-tight">SecTriage</div>
          <div className="text-[10px] text-[var(--text-muted)] tracking-wider uppercase">AI · SOC · Ops</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 py-3 px-3 space-y-0.5">
        {navItems.map(({ href, label, icon: Icon }) => {
          const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={clsx(
                "flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors",
                active
                  ? "bg-indigo-500/15 text-indigo-300 font-medium"
                  : "text-[var(--text-secondary)] hover:bg-[var(--surface-2)] hover:text-[var(--text-primary)]"
              )}
            >
              <Icon size={16} strokeWidth={active ? 2 : 1.5} />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Status footer */}
      <div className="p-4 border-t border-[var(--border)]">
        <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
          <Activity size={12} className="text-emerald-400" />
          <span>System online</span>
        </div>
      </div>
    </aside>
  );
}
