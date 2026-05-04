"use client";

import useSWR from "swr";
import { swrFetcher } from "@/lib/api";
import type { PolicyView } from "@/types";

const API = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8081";

export default function PoliciesPage() {
  const { data, error, isLoading } = useSWR<PolicyView>(
    `${API}/api/v1/policy`,
    swrFetcher
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Policy</h1>
        <p className="mt-1 text-sm text-gray-500">
          Read-only view of the policy loaded at server startup. Rules are
          evaluated top-to-bottom (declaration order = priority). To modify,
          edit the YAML file in your config repo and redeploy.
        </p>
      </div>

      {error && (
        <div className="rounded border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-700">
          {String(error.message ?? error)}
        </div>
      )}

      {isLoading && (
        <p className="text-sm text-gray-400">Loading…</p>
      )}

      {data && (
        <>
          <div className="rounded-lg border bg-white p-4 shadow-sm flex items-center gap-4 text-sm">
            <div>
              <span className="text-gray-500">Source:</span>{" "}
              <code className="font-mono text-gray-800">
                {data.source || "<none>"}
              </code>
            </div>
            <div>
              <span className="text-gray-500">Schema version:</span>{" "}
              <span className="font-mono text-gray-800">{data.version}</span>
            </div>
            <div className="ml-auto">
              <span className="text-gray-500">Rules:</span>{" "}
              <span className="font-semibold text-gray-800">
                {data.rules?.length ?? 0}
              </span>
            </div>
          </div>

          <div className="rounded-lg border bg-white shadow-sm overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-left text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th className="px-6 py-3">#</th>
                  <th className="px-6 py-3">Rule ID</th>
                  <th className="px-6 py-3">Ecosystems</th>
                  <th className="px-6 py-3">Packages</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {(data.rules ?? []).map((r, idx) => (
                  <tr key={r.id} className="hover:bg-gray-50">
                    <td className="px-6 py-3 text-gray-400">{idx + 1}</td>
                    <td className="px-6 py-3 font-mono font-medium">{r.id}</td>
                    <td className="px-6 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(r.ecosystems ?? []).map((eco) => (
                          <span
                            key={eco}
                            className="rounded bg-gray-100 px-2 py-0.5 text-xs font-mono text-gray-700"
                          >
                            {eco}
                          </span>
                        ))}
                        {(r.ecosystems ?? []).length === 0 && (
                          <span className="text-gray-400 text-xs">all</span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-3">
                      <div className="flex flex-wrap gap-1">
                        {[
                          ...(r.packages ?? []),
                          ...(r.packagePatterns ?? []),
                        ].map((p) => (
                          <span
                            key={p}
                            className="rounded bg-gray-100 px-2 py-0.5 text-xs font-mono text-gray-700"
                          >
                            {p}
                          </span>
                        ))}
                        {(r.excludePackagePatterns ?? []).map((p) => (
                          <span
                            key={`exclude-${p}`}
                            className="rounded bg-red-50 px-2 py-0.5 text-xs font-mono text-red-700"
                          >
                            exclude {p}
                          </span>
                        ))}
                        {(r.packages ?? []).length === 0 &&
                          (r.packagePatterns ?? []).length === 0 &&
                          (r.excludePackagePatterns ?? []).length === 0 && (
                            <span className="text-gray-400 text-xs">all</span>
                          )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(data.rules?.length ?? 0) === 0 && (
              <p className="px-6 py-8 text-center text-sm text-gray-400">
                No rules loaded. Set <code>POLICY_FILE</code> on the admin
                container and restart.
              </p>
            )}
          </div>

          <div className="rounded-lg border bg-blue-50 border-blue-200 p-4 text-sm text-blue-900">
            <p className="font-semibold mb-1">Editing the policy</p>
            <p>
              Update <code className="bg-blue-100 px-1 rounded">policy.yaml</code> in
              your config repository, then redeploy the <code>proxy</code> and
              <code> admin</code> services. See{" "}
              <code className="bg-blue-100 px-1 rounded">
                examples/policy.yaml
              </code>{" "}
              in the source tree for the full syntax.
            </p>
          </div>
        </>
      )}
    </div>
  );
}
