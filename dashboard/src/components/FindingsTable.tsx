"use client";

import { useState } from "react";

interface Finding {
  id: string;
  rule_id: string;
  severity: string;
  file_path: string;
  line_start: number;
  message: string;
  source: string;
  fix_suggestion?: string;
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "bg-red-100 text-red-800",
  high:     "bg-orange-100 text-orange-800",
  medium:   "bg-yellow-100 text-yellow-800",
  low:      "bg-blue-100 text-blue-800",
  info:     "bg-slate-100 text-slate-500",
};

const SOURCE_COLOR: Record<string, string> = {
  semgrep:    "bg-indigo-50 text-indigo-700",
  joern:      "bg-purple-50 text-purple-700",
  llm_review: "bg-emerald-50 text-emerald-700",
  dependency: "bg-rose-50 text-rose-700",
};

function ExpandedRow({ finding }: { finding: Finding }) {
  return (
    <tr className="bg-slate-50 border-t border-slate-100">
      <td colSpan={6} className="px-5 py-3">
        <div className="grid gap-3 sm:grid-cols-2 text-xs">
          <div>
            <p className="font-medium text-slate-500 mb-1">Full message</p>
            <p className="text-slate-700 whitespace-pre-wrap break-words">{finding.message}</p>
          </div>
          {finding.fix_suggestion && (
            <div>
              <p className="font-medium text-slate-500 mb-1">Suggested fix</p>
              <p className="text-slate-700 whitespace-pre-wrap break-words font-mono bg-white border border-slate-200 rounded p-2">
                {finding.fix_suggestion}
              </p>
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  if (findings.length === 0) {
    return (
      <div className="rounded-xl border bg-white px-5 py-8 text-center text-sm text-slate-400 shadow-sm">
        No findings match the selected filters.
      </div>
    );
  }

  function toggle(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  return (
    <div className="rounded-xl border bg-white shadow-sm overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wide">
          <tr>
            <th className="px-5 py-2.5 text-left w-6" />
            <th className="px-5 py-2.5 text-left">Severity</th>
            <th className="px-5 py-2.5 text-left">Rule</th>
            <th className="px-5 py-2.5 text-left">File</th>
            <th className="px-5 py-2.5 text-left">Line</th>
            <th className="px-5 py-2.5 text-left">Message</th>
            <th className="px-5 py-2.5 text-left">Source</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {findings.map((f) => (
            <>
              <tr
                key={f.id}
                onClick={() => toggle(f.id)}
                className="hover:bg-slate-50 cursor-pointer transition-colors"
              >
                <td className="pl-5 py-3 text-slate-300">
                  <svg
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    className={`w-3.5 h-3.5 transition-transform ${expanded.has(f.id) ? "rotate-90" : ""}`}
                  >
                    <path fillRule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clipRule="evenodd" />
                  </svg>
                </td>
                <td className="px-5 py-3">
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                      SEVERITY_COLOR[f.severity] ?? "bg-slate-100 text-slate-600"
                    }`}
                  >
                    {f.severity}
                  </span>
                </td>
                <td className="px-5 py-3 font-mono text-xs text-slate-600 max-w-[180px] truncate">
                  {f.rule_id}
                </td>
                <td className="px-5 py-3 font-mono text-xs text-slate-400 max-w-[220px] truncate" title={f.file_path}>
                  {f.file_path.split("/").slice(-2).join("/")}
                </td>
                <td className="px-5 py-3 text-slate-400 tabular-nums">
                  {f.line_start > 0 ? f.line_start : "—"}
                </td>
                <td className="px-5 py-3 text-slate-600 max-w-sm truncate">{f.message}</td>
                <td className="px-5 py-3">
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                      SOURCE_COLOR[f.source] ?? "bg-slate-100 text-slate-500"
                    }`}
                  >
                    {f.source}
                  </span>
                </td>
              </tr>
              {expanded.has(f.id) && <ExpandedRow key={`${f.id}-expanded`} finding={f} />}
            </>
          ))}
        </tbody>
      </table>
    </div>
  );
}
