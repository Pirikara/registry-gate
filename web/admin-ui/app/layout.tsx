import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Registry Gate — Admin",
  description: "Policy management and download history",
};

const navLinks = [
  { href: "/", label: "Dashboard" },
  { href: "/policies", label: "Policies" },
  { href: "/downloads", label: "Downloads" },
  { href: "/settings", label: "Client Setup" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-50 antialiased">
        <header className="border-b bg-white shadow-sm">
          <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
            <span className="text-lg font-semibold tracking-tight text-gray-900">
              Registry Gate
            </span>
            <nav className="flex gap-6 text-sm font-medium text-gray-600">
              {navLinks.map((l) => (
                <Link
                  key={l.href}
                  href={l.href}
                  className="hover:text-gray-900 transition-colors"
                >
                  {l.label}
                </Link>
              ))}
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-7xl px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
