"use client";

import { useState, useRef, useEffect } from "react";
import { Send, Bot, User, Loader2, ExternalLink } from "lucide-react";
import { investigate, type InvestigateResponse } from "@/lib/api";

interface Message {
  role: "user" | "assistant";
  content: string;
  sources?: InvestigateResponse["sources"];
  actions?: string[];
}

interface InvestigationChatProps {
  caseId?: string;
  alertId?: string;
  contextLabel?: string;
}

export default function InvestigationChat({ caseId, alertId, contextLabel }: InvestigationChatProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: `I'm your security investigation assistant. I can help analyze alerts and cases using MITRE ATT&CK intelligence.${contextLabel ? `\n\nCurrently looking at: ${contextLabel}` : ""}\n\nTry asking:\n• "What attack techniques could this represent?"\n• "What should I investigate next?"\n• "What are the recommended mitigations?"`,
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || loading) return;

    const question = input.trim();
    setInput("");
    setMessages((prev) => [...prev, { role: "user", content: question }]);
    setLoading(true);

    try {
      const result = await investigate({ question, case_id: caseId, alert_id: alertId });
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: result.answer,
          sources: result.sources,
          actions: result.suggested_actions,
        },
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: `Investigation error: ${err instanceof Error ? err.message : "Unknown error"}. Make sure the backend is running at http://localhost:8000.`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col h-full bg-[var(--surface-1)] border border-[var(--border)] rounded-xl overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-[var(--border)] flex items-center gap-2">
        <Bot size={16} className="text-indigo-400" />
        <span className="text-sm font-medium text-[var(--text-primary)]">Investigation assistant</span>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 min-h-0">
        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-3 ${msg.role === "user" ? "justify-end" : ""}`}>
            {msg.role === "assistant" && (
              <div className="w-7 h-7 rounded-lg bg-indigo-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                <Bot size={14} className="text-indigo-400" />
              </div>
            )}
            <div className={`max-w-[85%] space-y-2 ${msg.role === "user" ? "order-first" : ""}`}>
              <div
                className={`px-3.5 py-2.5 rounded-xl text-sm leading-relaxed whitespace-pre-wrap ${
                  msg.role === "user"
                    ? "bg-indigo-600 text-white rounded-br-md"
                    : "bg-[var(--surface-2)] text-[var(--text-primary)] rounded-bl-md"
                }`}
              >
                {msg.content}
              </div>

              {/* Sources */}
              {msg.sources && msg.sources.length > 0 && (
                <div className="space-y-1">
                  <span className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">Sources</span>
                  <div className="flex flex-wrap gap-1.5">
                    {msg.sources.map((s, j) => (
                      <a
                        key={j}
                        href={s.url || `https://attack.mitre.org/techniques/${s.technique_id}/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 px-2 py-1 text-[10px] font-mono bg-indigo-500/10 text-indigo-300 rounded border border-indigo-500/20 hover:bg-indigo-500/20 transition-colors"
                      >
                        {s.technique_id} <ExternalLink size={8} />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Suggested actions */}
              {msg.actions && msg.actions.length > 0 && (
                <div className="space-y-1">
                  <span className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">Suggested actions</span>
                  <div className="space-y-1">
                    {msg.actions.map((action, j) => (
                      <div key={j} className="flex items-start gap-2 text-xs text-[var(--text-secondary)]">
                        <span className="text-emerald-400 mt-0.5">→</span>
                        <span>{action}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
            {msg.role === "user" && (
              <div className="w-7 h-7 rounded-lg bg-[var(--surface-3)] flex items-center justify-center flex-shrink-0 mt-0.5">
                <User size={14} className="text-[var(--text-secondary)]" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="w-7 h-7 rounded-lg bg-indigo-500/20 flex items-center justify-center flex-shrink-0">
              <Bot size={14} className="text-indigo-400" />
            </div>
            <div className="px-3.5 py-2.5 rounded-xl bg-[var(--surface-2)] rounded-bl-md">
              <Loader2 size={16} className="animate-spin text-indigo-400" />
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <form onSubmit={handleSubmit} className="p-3 border-t border-[var(--border)]">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about this alert or case..."
            className="flex-1 bg-[var(--surface-2)] border border-[var(--border)] rounded-lg px-3.5 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-indigo-500 transition-colors"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:hover:bg-indigo-600 rounded-lg transition-colors"
          >
            <Send size={16} className="text-white" />
          </button>
        </div>
      </form>
    </div>
  );
}
