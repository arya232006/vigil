"use client";

import { Show, SignInButton, UserButton } from "@clerk/nextjs";
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
  return { label: "Rules only", color: "bg-risk-warn" };
}

function NavLinks() {
  const pathname = usePathname();
  return LINKS.map(({ href, label }) => (
    <Link key={href} href={href} className="tile" aria-current={pathname === href ? "page" : undefined}>
      {label}
    </Link>
  ));
}

export function Nav() {
  const { data, loading } = useApi<Health>("/api/health");
  const status = aiStatus(data);

  return (
    <nav className="sticky top-0 z-30 bg-(--l-ink)">
      <div className="flex flex-wrap items-center gap-1.5 p-1.5">
        <Link href="/" className="tile" aria-label="Vigil home">
          <Logo />
        </Link>
        <span className="mx-1 hidden h-6 w-px bg-[#6a6a6a] sm:block" aria-hidden />
        <Suspense
          fallback={LINKS.map(({ href, label }) => (
            <span key={href} className="tile">{label}</span>
          ))}
        >
          <NavLinks />
        </Suspense>
        <div className="ml-auto flex items-center gap-1.5">
          {!loading && (
            <span className="terminal flex items-center gap-2 px-2 text-lg text-(--l-paper)">
              <span className={`h-3 w-3 ${status.color}`} aria-hidden />
              {status.label}
              {data && data.feeds.openphish_urls > 0 && (
                <span className="hidden text-[#b5b5b5] md:inline">· {data.feeds.openphish_urls} phishing URLs</span>
              )}
            </span>
          )}
          <Show when="signed-out">
            <SignInButton>
              <button type="button" className="tile cursor-pointer">Sign in</button>
            </SignInButton>
          </Show>
          <Show when="signed-in">
            <span className="flex items-center px-1.5">
              <UserButton />
            </span>
          </Show>
        </div>
      </div>
    </nav>
  );
}
