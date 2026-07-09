"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { getCase, updateCaseStatus, type Case } from "@/lib/api";
import CaseView from "@/components/CaseView";
import InvestigationChat from "@/components/InvestigationChat";
import { ArrowLeft, Loader2 } from "lucide-react";

export default function CaseDetailPage() {
  const params = useParams();
  const router = useRouter();
  const caseId = params.id as string;

  const [caseData, setCaseData] = useState<Case | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function loadCase() {
    setLoading(true);
    setError(null);
    try {
      setCaseData(await getCase(caseId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load case");
    } finally {
      setLoading(false);
    }
  }

  async function handleStatusChange(status: string) {
    try {
      const updated = await updateCaseStatus(caseId, status);
      setCaseData((prev) => prev ? { ...prev, status: updated.status, updated_at: updated.updated_at } : prev);
    } catch (err) {
      alert(`Failed to update status: ${err instanceof Error ? err.message : "Unknown error"}`);
    }
  }

  useEffect(() => { loadCase(); }, [caseId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 size={24} className="animate-spin text-indigo-400" />
      </div>
    );
  }

  if (error || !caseData) {
    return (
      <div className="max-w-7xl mx-auto">
        <button onClick={() => router.push("/cases")} className="flex items-center gap-2 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] mb-4">
          <ArrowLeft size={16} /> Back to cases
        </button>
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
          <p className="text-sm text-red-300">{error || "Case not found"}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto">
      <button
        onClick={() => router.push("/cases")}
        className="flex items-center gap-2 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] mb-4 transition-colors"
      >
        <ArrowLeft size={16} /> Back to cases
      </button>

      <div className="flex gap-6">
        {/* Case details */}
        <div className="flex-1 min-w-0">
          <CaseView caseData={caseData} onStatusChange={handleStatusChange} />
        </div>

        {/* Investigation chat */}
        <div className="w-[400px] flex-shrink-0 h-[calc(100vh-140px)] sticky top-6">
          <InvestigationChat
            caseId={caseId}
            contextLabel={`${caseData.id} — ${caseData.title}`}
          />
        </div>
      </div>
    </div>
  );
}
