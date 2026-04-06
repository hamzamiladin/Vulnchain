"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import Link from "next/link";

export default function NewScanPage() {
  const router = useRouter();
  const [repoUrl, setRepoUrl] = useState("");
  const [commitSha, setCommitSha] = useState("");
  const [prNumber, setPrNumber] = useState("");
  const [error, setError] = useState("");

  const mutation = useMutation({
    mutationFn: () =>
      fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_url: repoUrl.trim(),
          commit_sha: commitSha.trim() || undefined,
          pr_number: prNumber ? parseInt(prNumber) : undefined,
        }),
      }).then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      }),
    onSuccess: (data) => router.push(`/scan/${data.scan_id}`),
    onError: (e: Error) => setError(e.message || "Failed to start scan"),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!repoUrl.trim()) return setError("Repository URL is required.");
    setError("");
    mutation.mutate();
  }

  return (
    <div className="max-w-xl mx-auto space-y-6">
      <div>
        <Link href="/" className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-600 mb-4">
          <svg viewBox="0 0 20 20" fill="currentColor" className="w-3 h-3">
            <path fillRule="evenodd" d="M17 10a.75.75 0 01-.75.75H5.56l3.22 3.22a.75.75 0 11-1.06 1.06l-4.5-4.5a.75.75 0 010-1.06l4.5-4.5a.75.75 0 011.06 1.06L5.56 9.25H16.25A.75.75 0 0117 10z" clipRule="evenodd" />
          </svg>
          Back
        </Link>
        <h1 className="text-xl font-semibold text-slate-800">New Security Scan</h1>
        <p className="text-sm text-slate-500 mt-1">
          Enter a public or private repository URL. The agent will clone, analyse, and report findings.
        </p>
      </div>

      <form onSubmit={submit} className="rounded-xl border bg-white p-6 shadow-sm space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">
            Repository URL <span className="text-red-500">*</span>
          </label>
          <input
            type="url"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/owner/repo"
            className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm shadow-sm focus:border-red-400 focus:outline-none focus:ring-1 focus:ring-red-300"
            disabled={mutation.isPending}
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Commit SHA</label>
            <input
              type="text"
              value={commitSha}
              onChange={(e) => setCommitSha(e.target.value)}
              placeholder="Optional — scans HEAD if blank"
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm shadow-sm focus:border-red-400 focus:outline-none focus:ring-1 focus:ring-red-300 font-mono"
              disabled={mutation.isPending}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">PR Number</label>
            <input
              type="number"
              value={prNumber}
              onChange={(e) => setPrNumber(e.target.value)}
              placeholder="Optional"
              min={1}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm shadow-sm focus:border-red-400 focus:outline-none focus:ring-1 focus:ring-red-300"
              disabled={mutation.isPending}
            />
          </div>
        </div>

        {error && (
          <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={mutation.isPending}
          className="w-full rounded-md bg-red-500 px-4 py-2 text-sm font-semibold text-white hover:bg-red-600 disabled:opacity-50 transition-colors shadow-sm"
        >
          {mutation.isPending ? "Starting scan…" : "Start Scan"}
        </button>
      </form>

      <div className="rounded-xl border bg-slate-50 p-4 text-xs text-slate-500 space-y-1.5">
        <p className="font-semibold text-slate-600">What happens next</p>
        <ul className="space-y-1 list-disc list-inside">
          <li>Repository is cloned and source files are collected</li>
          <li>Semgrep runs local taint-mode rules (Python, JS/TS, PHP, C#, Swift)</li>
          <li>Joern builds a Code Property Graph for deep inter-procedural analysis</li>
          <li>Dependencies are checked against the OSV vulnerability database</li>
          <li>Claude reviews high-risk files directly for business-logic flaws</li>
          <li>A STRIDE threat model and attack chain report are generated</li>
        </ul>
      </div>
    </div>
  );
}
