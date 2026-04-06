"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { FindingsTable } from "@/components/FindingsTable";
import { AttackChainCard } from "@/components/AttackChainCard";

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

interface AttackChain {
  id: string;
  title: string;
  combined_severity: string;
  business_impact: string;
  steps: string[] | string;
  cvss_score: number | null;
  finding_ids?: string[] | string;
}

interface ScanDetail {
  id: string;
  repo_name: string;
  repo_url: string;
  commit_sha: string;
  pr_number: number | null;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_at: string;
  findings: Finding[];
  attack_chains: AttackChain[];
}

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const STATUS_STYLE: Record<string, string> = {
  done:    "bg-green-100 text-green-800",
  running: "bg-blue-100 text-blue-800",
  pending: "bg-yellow-100 text-yellow-800",
  failed:  "bg-red-100 text-red-800",
};

const SEV_FILTER_STYLE: Record<string, string> = {
  all:      "bg-slate-100 text-slate-700",
  critical: "bg-red-100 text-red-700",
  high:     "bg-orange-100 text-orange-700",
  medium:   "bg-yellow-100 text-yellow-700",
  low:      "bg-blue-100 text-blue-700",
};

function elapsed(start: string | null, end: string | null): string {
  if (!start) return "—";
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const sec = Math.round((e - s) / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function severityCounts(findings: Finding[]) {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return counts;
}

export default function ScanPage({ params }: { params: { id: string } }) {
  const { id } = params;
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");

  const { data: scan, isLoading } = useQuery<ScanDetail>({
    queryKey: ["scan", id],
    queryFn: () =>
      fetch(`/api/scans/${id}`)
        .then((r) => r.json())
        .then((d) => ({
          ...d.scan,
          findings: d.findings ?? [],
          attack_chains: d.attack_chains ?? [],
        })),
    refetchInterval: (q) => (q.state.data?.status === "running" ? 4_000 : false),
  });

  if (isLoading)
    return (
      <div className="flex items-center gap-2 text-sm text-slate-400 py-12 justify-center">
        <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
        </svg>
        Loading scan…
      </div>
    );
  if (!scan) return <div className="text-red-500 text-sm py-12 text-center">Scan not found.</div>;

  const counts = severityCounts(scan.findings);
  const sources = Array.from(new Set(scan.findings.map((f) => f.source))).sort();

  const filtered = scan.findings
    .filter((f) => sevFilter === "all" || f.severity === sevFilter)
    .filter((f) => sourceFilter === "all" || f.source === sourceFilter)
    .sort((a, b) => (SEV_ORDER[b.severity] ?? 0) - (SEV_ORDER[a.severity] ?? 0));

  const duration = elapsed(scan.started_at, scan.completed_at);

  return (
    <div className="space-y-6">
      {/* Back link */}
      <Link href="/" className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-600">
        <svg viewBox="0 0 20 20" fill="currentColor" className="w-3 h-3"><path fillRule="evenodd" d="M17 10a.75.75 0 01-.75.75H5.56l3.22 3.22a.75.75 0 11-1.06 1.06l-4.5-4.5a.75.75 0 010-1.06l4.5-4.5a.75.75 0 011.06 1.06L5.56 9.25H16.25A.75.75 0 0117 10z" clipRule="evenodd"/></svg>
        All scans
      </Link>

      {/* Header */}
      <div className="rounded-xl border bg-white p-5 shadow-sm">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-semibold text-slate-800">{scan.repo_name}</h1>
            {scan.repo_url && (
              <a
                href={scan.repo_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-slate-400 hover:text-red-500 font-mono mt-0.5 inline-block"
              >
                {scan.repo_url}
              </a>
            )}
          </div>
          <span className={`rounded-full px-3 py-1 text-xs font-semibold ${STATUS_STYLE[scan.status] ?? "bg-slate-100 text-slate-600"}`}>
            {scan.status}
          </span>
        </div>

        <dl className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-2 text-xs">
          <MetaField label="Commit" value={scan.commit_sha?.slice(0, 12) ?? "—"} mono />
          {scan.pr_number && <MetaField label="PR" value={`#${scan.pr_number}`} />}
          <MetaField label="Duration" value={duration} />
          <MetaField label="Scan ID" value={id.slice(0, 8)} mono />
          {scan.error_message && (
            <div className="col-span-4 mt-1 rounded-md bg-red-50 border border-red-200 px-3 py-2 text-red-700">
              {scan.error_message}
            </div>
          )}
        </dl>

        {/* Severity breakdown mini-bar */}
        {scan.findings.length > 0 && (
          <div className="mt-4 flex items-center gap-3 flex-wrap">
            {(["critical", "high", "medium", "low"] as const).map((sev) =>
              counts[sev] > 0 ? (
                <button
                  key={sev}
                  onClick={() => setSevFilter(sevFilter === sev ? "all" : sev)}
                  className={`rounded-full px-2.5 py-0.5 text-xs font-medium border transition-all ${
                    sevFilter === sev
                      ? SEV_FILTER_STYLE[sev] + " ring-1 ring-offset-1 ring-current"
                      : SEV_FILTER_STYLE[sev] + " opacity-70 hover:opacity-100"
                  }`}
                >
                  {counts[sev]} {sev}
                </button>
              ) : null
            )}
          </div>
        )}
      </div>

      {/* Attack chains */}
      {scan.attack_chains.length > 0 && (
        <section>
          <SectionHeader title="Attack Chains" count={scan.attack_chains.length} />
          <div className="grid gap-4 md:grid-cols-2">
            {scan.attack_chains.map((chain) => (
              <AttackChainCard key={chain.id} chain={chain} />
            ))}
          </div>
        </section>
      )}

      {/* Findings */}
      <section>
        <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
          <SectionHeader title="Findings" count={filtered.length} total={scan.findings.length} />
          {/* Source filter */}
          {sources.length > 1 && (
            <div className="flex gap-1.5 flex-wrap">
              <FilterPill active={sourceFilter === "all"} onClick={() => setSourceFilter("all")} label="All sources" />
              {sources.map((src) => (
                <FilterPill key={src} active={sourceFilter === src} onClick={() => setSourceFilter(src)} label={src} />
              ))}
            </div>
          )}
        </div>
        <FindingsTable findings={filtered} />
      </section>
    </div>
  );
}

function MetaField({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-slate-400">{label}</dt>
      <dd className={`text-slate-700 font-medium mt-0.5 ${mono ? "font-mono" : ""}`}>{value}</dd>
    </div>
  );
}

function SectionHeader({ title, count, total }: { title: string; count: number; total?: number }) {
  return (
    <h2 className="text-sm font-semibold text-slate-700">
      {title}{" "}
      <span className="text-slate-400 font-normal">
        {total !== undefined && total !== count ? `(${count} of ${total})` : `(${count})`}
      </span>
    </h2>
  );
}

function FilterPill({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full px-2.5 py-0.5 text-xs font-medium transition-all border ${
        active
          ? "bg-slate-800 text-white border-slate-800"
          : "bg-white text-slate-600 border-slate-300 hover:border-slate-500"
      }`}
    >
      {label}
    </button>
  );
}
