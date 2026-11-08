"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Suspense } from "react";
import { Logo } from "@/components/Logo";
import { useApi } from "@/lib/api";
import type { Health } from "@/lib/types";

const LINKS = [
  { href: "/investigate", label: "Investigate" },
  { href: "/history", label: "History" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/models", label: "Our AI" },
];

function aiStatus(health?: Health): { label: string; color: string } {
  if (!health) return { label: "API offline", color: "bg-risk-high" };
  if (health.system2.student_up) return { label: "AI online", color: "bg-risk-ok" };
  if (health.system2.fallback_up) return { label: "Backup AI", color: "bg-risk-warn" };
  return { label: "Rules only", color: "bg-risk-none" };
}

function NavLinks() {
  const pathname = usePathname();
  return LINKS.map(({ href, label }) => (
    <Link
      key={href}
      href={href}
      aria-current={pathname === href ? "page" : undefined}
      className={pathname === href ? "font-medium text-ink" : "text-ink-3 hover:text-ink"}
    >
      {label}
    </Link>
  ));
}

export function Nav() {
  const { data, loading } = useApi<Health>("/api/health");
  const status = aiStatus(data);

  return (
    <nav className="border-b border-line bg-surface">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 sm:px-6">
        <Link href="/" className="text-sm font-semibold tracking-tight">
          <Logo />
        </Link>
        <div className="flex gap-4 text-sm">
          <Suspense fallback={LINKS.map(({ href, label }) => <span key={href} className="text-ink-3">{label}</span>)}>
            <NavLinks />
          </Suspense>
        </div>
        {!loading && (
          <span className="ml-auto flex items-center gap-2 text-xs text-ink-2">
            <span className={`h-2 w-2 rounded-full ${status.color}`} aria-hidden />
            {status.label}
            {data && data.feeds.openphish_urls > 0 && (
              <span className="hidden text-ink-3 sm:inline">· {data.feeds.openphish_urls} phishing URLs loaded</span>
            )}
          </span>
        )}
      </div>
    </nav>
  );
}
