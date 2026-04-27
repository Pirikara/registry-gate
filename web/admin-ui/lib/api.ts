import type { DownloadsResponse, PolicyView } from "@/types";

const BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8081";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  /** Fetch the currently loaded policy (read-only — edit YAML to change). */
  getPolicy(): Promise<PolicyView> {
    return request<PolicyView>("/api/v1/policy");
  },

  /** Fetch download history with optional filters. */
  getDownloads(params?: {
    ecosystem?: string;
    package?: string;
    outcome?: string;
    from?: string;
    to?: string;
  }): Promise<DownloadsResponse> {
    const qs = new URLSearchParams(
      Object.entries(params ?? {}).filter(([, v]) => v != null) as [string, string][]
    );
    const query = qs.toString() ? `?${qs}` : "";
    return request<DownloadsResponse>(`/api/v1/downloads${query}`);
  },
};

/** SWR fetcher — pass the full URL as key. */
export async function swrFetcher<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
