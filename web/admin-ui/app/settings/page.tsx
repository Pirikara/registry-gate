"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";

interface Snippet {
  label: string;
  filename: string;
  content: string;
}

function useSnippets(proxyBase: string): Record<string, Snippet[]> {
  const base = proxyBase.replace(/\/$/, "") || "https://rg.corp.example.com";

  return {
    npm: [
      {
        label: ".npmrc",
        filename: ".npmrc",
        content: `registry=${base}\n`,
      },
    ],
    pypi: [
      {
        label: "pip.conf (macOS/Linux)",
        filename: "~/.config/pip/pip.conf",
        content: `[global]\nindex-url = ${base}/pypi/simple/\n`,
      },
      {
        label: "pip.ini (Windows)",
        filename: "%APPDATA%\\pip\\pip.ini",
        content: `[global]\nindex-url = ${base}/pypi/simple/\n`,
      },
    ],
    rubygems: [
      {
        label: "~/.gemrc",
        filename: "~/.gemrc",
        content: `:sources:\n  - ${base}\n`,
      },
      {
        label: "Bundler mirror",
        filename: "~/.bundle/config",
        content: `---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: "${base}"\n`,
      },
    ],
    docker: [
      {
        label: "daemon.json",
        filename: "~/.docker/daemon.json",
        content: JSON.stringify({ "registry-mirrors": [base] }, null, 2) + "\n",
      },
    ],
  };
}

function SnippetBlock({ snippet }: { snippet: Snippet }) {
  const [copied, setCopied] = useState(false);

  function copy() {
    navigator.clipboard.writeText(snippet.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="rounded-lg border bg-white shadow-sm">
      <div className="flex items-center justify-between border-b px-4 py-2">
        <div>
          <span className="font-medium text-sm text-gray-800">{snippet.label}</span>
          <span className="ml-2 text-xs text-gray-400 font-mono">{snippet.filename}</span>
        </div>
        <Button variant="outline" size="sm" onClick={copy}>
          {copied ? "Copied!" : "Copy"}
        </Button>
      </div>
      <pre className="overflow-x-auto p-4 text-xs font-mono text-gray-700 bg-gray-50 rounded-b-lg whitespace-pre-wrap">
        {snippet.content}
      </pre>
    </div>
  );
}

const TABS = ["npm", "pypi", "rubygems", "docker"] as const;

export default function SettingsPage() {
  const [proxyBase, setProxyBase] = useState("");
  const [activeTab, setActiveTab] = useState<(typeof TABS)[number]>("npm");

  const snippets = useSnippets(proxyBase);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Client Setup</h1>
        <p className="mt-1 text-sm text-gray-500">
          Configuration snippets to point each package manager at the proxy.
          For fleet rollout via MDM, use the scripts in{" "}
          <code className="bg-gray-100 px-1 rounded text-xs">examples/clients/</code>.
        </p>
      </div>

      <div className="flex items-center gap-3 rounded-lg border bg-white p-4 shadow-sm">
        <label className="text-sm font-medium text-gray-700 whitespace-nowrap">
          Proxy base URL
        </label>
        <input
          type="text"
          className="flex-1 rounded-md border px-3 py-1.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-gray-300"
          placeholder="https://rg.corp.example.com"
          value={proxyBase}
          onChange={(e) => setProxyBase(e.target.value)}
        />
      </div>

      <div className="flex gap-1 rounded-lg border bg-white p-1 shadow-sm w-fit">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setActiveTab(t)}
            className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
              activeTab === t
                ? "bg-gray-900 text-white"
                : "text-gray-600 hover:text-gray-900"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      <div className="space-y-4">
        {snippets[activeTab]?.map((s) => (
          <SnippetBlock key={s.filename} snippet={s} />
        ))}
      </div>
    </div>
  );
}
