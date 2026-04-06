"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { TrendChart } from "@/components/TrendChart";

interface ScanSummary {
  id: string;
  repo_name: string;
  repo_url: string;
  commit_sha: string;
  status: string;
  created_at: string;
  findings_count: number;
  critical_high_count: number;
  chain_count: number;
}

interface Stats {
  total_scans: number;
  total_findings: number;
  critical_findings: number;
  daily: { date: string; count: number }[];
}

const STATUS_STYLE: Record<string, { cls: string; dot: string }> = {
  done:    { cls: "bg-green-100 text-green-800",  dot: "bg-green-500" },
  running: { cls: "bg-blue-100 text-blue-800",    dot: "bg-blue-500 animate-pulse" },
  pending: { cls: "bg-yellow-100 text-yellow-800", dot: "bg-yellow-400" },
  failed:  { cls: "bg-red-100 text-red-800",      dot: "bg-red-500" },
};

function StatusBadge({ status }: { status: string }) {
  const s = STATUS_STYLE[status] ?? { cls: "bg-slate-100 text-slate-600", dot: "bg-slate-400" };
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${s.cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {status}
    </span>
  );
}

function ScanTriggerForm({ onSuccess }: { onSuccess: () => void }) {
  const [repoUrl, setRepoUrl] = useState("");
  const [error, setError] = useState("");

  const mutation = useMutation({
    mutationFn: (url: string) =>
      fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: url }),
      }).then((r) => r.json()),
    onSuccess: () => {
      setRepoUrl("");
      setError("");
      onSuccess();
    },
    onError: () => setError("Failed to trigger scan. Check the API is reachable."),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!repoUrl.trim()) return setError("Enter a repository URL.");
    setError("");
    mutation.mutate(repoUrl.trim());
  }

  return (
    <form onSubmit={submit} className="flex gap-2 items-start">
      <div className="flex-1">
        <input
          type="url"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          className="w-full rounded-md border border-slate-300 px-3 py-1.5 text-sm shadow-sm focus:border-red-400 focus:outline-none focus:ring-1 focus:ring-red-300"
          disabled={mutation.isPending}
        />
        {error && <p className="mt-1 text-xs text-red-500">{error}</p>}
      </div>
      <button
        type="submit"
        disabled={mutation.isPending}
        className="shrink-0 rounded-md bg-red-500 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-600 disabled:opacity-50 transition-colors shadow-sm"
      >
        {mutation.isPending ? "Starting…" : "Scan Repo"}
      </button>
    </form>
  );
}

export default function HomePage() {
  const queryClient = useQueryClient();

  const { data: scans = [], isLoading } = useQuery<ScanSummary[]>({
    queryKey: ["scans"],
    queryFn: () =>
      fetch("/api/scans")
        .then((r) => r.json())
        .then((d) => d.scans ?? d),
    refetchInterval: 10_000,
  });

  const { data: stats } = useQuery<Stats>({
    queryKey: ["stats"],
    queryFn: () => fetch("/api/stats").then((r) => r.json()),
    refetchInterval: 30_000,
  });

  const hasRunning = scans.some((s) => s.status === "running" || s.status === "pending");

  return (
    <div className="space-y-6">
      {/* Scan trigger */}
      <div className="rounded-xl border bg-white p-4 shadow-sm">
        <h2 className="text-sm font-semibold text-slate-700 mb-3">Trigger a New Scan</h2>
        <ScanTriggerForm onSuccess={() => queryClient.invalidateQueries({ queryKey: ["scans"] })} />
      </div>

      {/* KPI row */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <KpiCard label="Total Scans" value={stats.total_scans} />
          <KpiCard label="Total Findings" value={stats.total_findings} />
          <KpiCard label="Critical / High" value={stats.critical_findings} highlight />
          <KpiCard
            label="Active Scans"
            value={scans.filter((s) => s.status === "running").length}
            pulse={hasRunning}
          />
        </div>
      )}

      {stats?.daily && stats.daily.length > 0 && <TrendChart data={stats.daily} />}

      {/* Scan list */}
      <div className="rounded-xl border bg-white shadow-sm overflow-hidden">
        <div className="px-5 py-3 border-b flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-700">Recent Scans</h2>
          {isLoading && <span className="text-xs text-slate-400 animate-pulse">Loading…</span>}
        </div>
        {scans.length === 0 && !isLoading ? (
          <div className="px-5 py-10 text-center text-sm text-slate-400">
            No scans yet. Trigger one above or push to a connected repository.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wide">
              <tr>
                <th className="px-5 py-2.5 text-left">Repository</th>
                <th className="px-5 py-2.5 text-left">Commit</th>
                <th className="px-5 py-2.5 text-left">Status</th>
                <th className="px-5 py-2.5 text-right">Findings</th>
                <th className="px-5 py-2.5 text-right">Crit/High</th>
                <th className="px-5 py-2.5 text-right">Chains</th>
                <th className="px-5 py-2.5 text-left">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-5 py-3">
                    <Link
                      href={`/scan/${scan.id}`}
                      className="font-medium text-red-600 hover:text-red-700 hover:underline"
                    >
                      {scan.repo_name}
                    </Link>
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-slate-400">
                    {scan.commit_sha?.slice(0, 8) ?? "—"}
                  </td>
                  <td className="px-5 py-3">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="px-5 py-3 text-right tabular-nums">{scan.findings_count ?? 0}</td>
                  <td className="px-5 py-3 text-right tabular-nums">
                    {(scan.critical_high_count ?? 0) > 0 ? (
                      <span className="text-red-600 font-semibold">{scan.critical_high_count}</span>
                    ) : (
                      <span className="text-slate-400">0</span>
                    )}
                  </td>
                  <td className="px-5 py-3 text-right tabular-nums">{scan.chain_count ?? 0}</td>
                  <td className="px-5 py-3 text-slate-400 text-xs">
                    {new Date(scan.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function KpiCard({
  label,
  value,
  highlight = false,
  pulse = false,
}: {
  label: string;
  value: number;
  highlight?: boolean;
  pulse?: boolean;
}) {
  return (
    <div
      className={`rounded-xl border bg-white p-4 shadow-sm ${
        highlight ? "border-red-200" : ""
      }`}
    >
      <p className={`text-xs font-medium mb-1 ${highlight ? "text-red-500" : "text-slate-500"}`}>
        {label}
      </p>
      <p
        className={`text-3xl font-bold tabular-nums ${
          highlight ? "text-red-600" : pulse && value > 0 ? "text-blue-600" : "text-slate-800"
        }`}
      >
        {value}
      </p>
    </div>
  );
}
