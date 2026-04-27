export type Ecosystem = "npm" | "pypi" | "rubygems" | "homebrew" | "docker";
export type Outcome = "allowed" | "blocked";

export interface DownloadRecord {
  id: string;
  principalLabel?: string;
  ecosystem: Ecosystem;
  packageName: string;
  version: string;
  outcome: Outcome;
  blockReason?: string;
  occurredAt: string;
}

export interface DownloadsResponse {
  records: DownloadRecord[];
  count: number;
}

/**
 * Policy is loaded from a YAML file at server startup; the admin API exposes
 * it read-only. To change the policy, edit the YAML in your config repo and
 * redeploy the proxy.
 *
 * Rules are evaluated top-to-bottom — declaration order = priority.
 */
export interface PolicyView {
  source: string;
  version: number;
  rules: RuleSummary[];
}

export interface RuleSummary {
  id: string;
  ecosystems?: string[];
  packages?: string[];
}
