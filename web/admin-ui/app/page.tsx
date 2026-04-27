"use client";

import useSWR from "swr";
import { swrFetcher } from "@/lib/api";
import type { DownloadsResponse } from "@/types";

const API = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8081";

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="rounded-lg border bg-white p-6 shadow-sm">
      <p className="text-sm font-medium text-gray-500">{label}</p>
      <p className="mt-1 text-3xl font-bold text-gray-900">{value}</p>
      {sub && <p className="mt-1 text-xs text-gray-400">{sub}</p>}
    </div>
  );
}

export default function DashboardPage() {
  const { data: all } = useSWR<DownloadsResponse>(
    `${API}/api/v1/downloads`,
    swrFetcher
  );
  const { data: blocked } = useSWR<DownloadsResponse>(
    `${API}/api/v1/downloads?outcome=blocked`,
    swrFetcher
  );

  const total = all?.count ?? "—";
  const blockedCount = blocked?.count ?? "—";
  const recentBlocks = blocked?.records?.slice(0, 5) ?? [];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-1 text-sm text-gray-500">Overview of downloads and policy enforcement</p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <StatCard label="Total Downloads" value={total} />
        <StatCard label="Blocked" value={blockedCount} sub="policy violations" />
        <StatCard
          label="Block Rate"
          value={
            typeof total === "number" && typeof blockedCount === "number" && total > 0
              ? `${((blockedCount / total) * 100).toFixed(1)}%`
              : "—"
          }
        />
      </div>

      <div className="rounded-lg border bg-white shadow-sm">
        <div className="border-b px-6 py-4">
          <h2 className="font-semibold text-gray-800">Recent Blocks</h2>
        </div>
        <div className="overflow-x-auto">
          {recentBlocks.length === 0 ? (
            <p className="px-6 py-8 text-center text-sm text-gray-400">No recent blocks</p>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-6 py-3">Package</th>
                  <th className="px-6 py-3">Ecosystem</th>
                  <th className="px-6 py-3">Reason</th>
                  <th className="px-6 py-3">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {recentBlocks.map((r) => (
                  <tr key={r.id} className="hover:bg-gray-50">
                    <td className="px-6 py-3 font-mono font-medium">
                      {r.packageName}@{r.version}
                    </td>
                    <td className="px-6 py-3">
                      <span className="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-600">
                        {r.ecosystem}
                      </span>
                    </td>
                    <td className="px-6 py-3 max-w-xs truncate text-gray-500">
                      {r.blockReason ?? "—"}
                    </td>
                    <td className="px-6 py-3 text-gray-400">
                      {new Date(r.occurredAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
