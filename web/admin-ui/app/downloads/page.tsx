"use client";

import { useState } from "react";
import useSWR from "swr";
import { swrFetcher } from "@/lib/api";
import type { DownloadsResponse, Ecosystem, Outcome } from "@/types";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

const API = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8081";

const ECOSYSTEMS: Ecosystem[] = ["npm", "pypi", "rubygems", "homebrew", "docker"];

function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${
        outcome === "blocked"
          ? "bg-red-100 text-red-700"
          : "bg-green-100 text-green-700"
      }`}
    >
      {outcome}
    </span>
  );
}

export default function DownloadsPage() {
  const [ecosystem, setEcosystem] = useState("");
  const [packageName, setPackageName] = useState("");
  const [outcome, setOutcome] = useState("");

  const qs = new URLSearchParams(
    Object.entries({ ecosystem, package: packageName, outcome }).filter(([, v]) => v !== "")
  );
  const url = `${API}/api/v1/downloads${qs.toString() ? `?${qs}` : ""}`;

  const { data, error, isLoading } = useSWR<DownloadsResponse>(url, swrFetcher);

  function clearFilters() {
    setEcosystem("");
    setPackageName("");
    setOutcome("");
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Download History</h1>
        <p className="mt-1 text-sm text-gray-500">
          All package downloads that passed through the proxy.
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 rounded-lg border bg-white p-4 shadow-sm">
        <select
          className="rounded-md border px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-300"
          value={ecosystem}
          onChange={(e) => setEcosystem(e.target.value)}
        >
          <option value="">All ecosystems</option>
          {ECOSYSTEMS.map((e) => (
            <option key={e} value={e}>{e}</option>
          ))}
        </select>

        <Input
          className="w-56 h-8 text-sm"
          placeholder="Package name"
          value={packageName}
          onChange={(e) => setPackageName(e.target.value)}
        />

        <select
          className="rounded-md border px-3 py-1.5 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-300"
          value={outcome}
          onChange={(e) => setOutcome(e.target.value)}
        >
          <option value="">All outcomes</option>
          <option value="allowed">Allowed</option>
          <option value="blocked">Blocked</option>
        </select>

        <Button variant="outline" size="sm" onClick={clearFilters}>
          Clear
        </Button>

        {data && (
          <span className="ml-auto self-center text-sm text-gray-400">
            {data.count} result{data.count !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {error && (
        <div className="rounded border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-700">
          {String(error.message ?? error)}
        </div>
      )}

      {/* Table */}
      <div className="rounded-lg border bg-white shadow-sm overflow-x-auto">
        {isLoading ? (
          <p className="px-6 py-8 text-center text-sm text-gray-400">Loading…</p>
        ) : !data?.records?.length ? (
          <p className="px-6 py-8 text-center text-sm text-gray-400">No records found</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
              <tr>
                <th className="px-6 py-3">Package</th>
                <th className="px-6 py-3">Ecosystem</th>
                <th className="px-6 py-3">Outcome</th>
                <th className="px-6 py-3">Reason</th>
                <th className="px-6 py-3">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {data.records.map((r) => (
                <tr key={r.id} className="hover:bg-gray-50">
                  <td className="px-6 py-3 font-mono font-medium">
                    {r.packageName}@{r.version}
                  </td>
                  <td className="px-6 py-3">
                    <span className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                      {r.ecosystem}
                    </span>
                  </td>
                  <td className="px-6 py-3">
                    <OutcomeBadge outcome={r.outcome} />
                  </td>
                  <td className="px-6 py-3 max-w-xs truncate text-gray-500">
                    {r.blockReason ?? "—"}
                  </td>
                  <td className="px-6 py-3 whitespace-nowrap text-gray-400">
                    {new Date(r.occurredAt).toLocaleString()}
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
