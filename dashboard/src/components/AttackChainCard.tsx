"use client";

import { useState } from "react";

interface AttackChain {
  id: string;
  title: string;
  combined_severity: string;
  business_impact: string;
  steps: string[] | string;
  cvss_score: number | null;
  finding_ids?: string[] | string;
}

const SEVERITY_STYLE: Record<string, { card: string; badge: string; cvss: string }> = {
  critical: {
    card:  "border-red-200 bg-gradient-to-br from-red-50 to-white",
    badge: "bg-red-100 text-red-800",
    cvss:  "text-red-600",
  },
  high: {
    card:  "border-orange-200 bg-gradient-to-br from-orange-50 to-white",
    badge: "bg-orange-100 text-orange-800",
    cvss:  "text-orange-600",
  },
  medium: {
    card:  "border-yellow-200 bg-gradient-to-br from-yellow-50 to-white",
    badge: "bg-yellow-100 text-yellow-800",
    cvss:  "text-yellow-600",
  },
};

function parseSafe<T>(val: T | string | undefined): T | null {
  if (val === undefined) return null;
  if (typeof val !== "string") return val ?? null;
  try { return JSON.parse(val) as T; } catch { return null; }
}

export function AttackChainCard({ chain }: { chain: AttackChain }) {
  const [expanded, setExpanded] = useState(true);

  const steps: string[] = parseSafe<string[]>(chain.steps) ?? [];
  const findingIds: string[] = parseSafe<string[]>(chain.finding_ids) ?? [];
  const sev = chain.combined_severity ?? "medium";
  const style = SEVERITY_STYLE[sev] ?? { card: "border-slate-200 bg-white", badge: "bg-slate-100 text-slate-600", cvss: "text-slate-600" };

  return (
    <div className={`rounded-xl border p-5 shadow-sm ${style.card}`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${style.badge}`}>
              {sev}
            </span>
            {chain.cvss_score != null && (
              <span className={`text-xs font-bold ${style.cvss}`}>
                CVSS {chain.cvss_score.toFixed(1)}
              </span>
            )}
          </div>
          <h3 className="mt-1.5 font-semibold text-slate-800 text-sm leading-snug">{chain.title}</h3>
        </div>
        <button
          onClick={() => setExpanded((v) => !v)}
          className="shrink-0 text-slate-400 hover:text-slate-600 transition-colors mt-0.5"
          aria-label={expanded ? "Collapse" : "Expand"}
        >
          <svg viewBox="0 0 20 20" fill="currentColor" className={`w-4 h-4 transition-transform ${expanded ? "rotate-180" : ""}`}>
            <path fillRule="evenodd" d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z" clipRule="evenodd" />
          </svg>
        </button>
      </div>

      {/* Business impact */}
      {chain.business_impact && (
        <p className="mt-2 text-xs text-slate-600 leading-relaxed line-clamp-2">{chain.business_impact}</p>
      )}

      {/* Collapsible steps + findings */}
      {expanded && (
        <div className="mt-4 space-y-3">
          {steps.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-500 mb-2 uppercase tracking-wide">Attack steps</p>
              <ol className="space-y-1.5">
                {steps.map((step, i) => (
                  <li key={i} className="flex gap-2.5 text-xs text-slate-700">
                    <span className="shrink-0 w-5 h-5 rounded-full bg-white border border-slate-200 text-slate-500 flex items-center justify-center text-[10px] font-bold shadow-sm">
                      {i + 1}
                    </span>
                    <span className="leading-snug pt-0.5">{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {findingIds.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-500 mb-1.5 uppercase tracking-wide">Linked findings</p>
              <div className="flex flex-wrap gap-1.5">
                {findingIds.map((fid) => (
                  <span key={fid} className="rounded font-mono text-[10px] bg-white border border-slate-200 px-1.5 py-0.5 text-slate-600">
                    {fid}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
