"use client";

import { useState, type ReactNode } from "react";
import { RISK, SEVERITY_BG } from "@/lib/format";
import type { RiskLevel, Severity } from "@/lib/types";

export function RiskBadge({ level, large = false }: { level: RiskLevel; large?: boolean }) {
  const size = large ? "px-3 py-1.5 text-lg" : "px-2 py-0.5 text-xs";
  return <span className={`inline-block rounded font-semibold text-white ${RISK[level].bg} ${size}`}>{RISK[level].label}</span>;
}

export function SeverityPill({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-block rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-white ${SEVERITY_BG[severity]}`}>
      {severity}
    </span>
  );
}

export function Tag({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "danger" | "good" }) {
  const tones = {
    neutral: "border-line text-ink-2",
    danger: "border-risk-high text-risk-high",
    good: "border-risk-ok text-risk-ok",
  };
  return <span className={`inline-block rounded border px-1.5 py-0.5 text-xs ${tones[tone]}`}>{children}</span>;
}

export function Card({ title, children, className = "" }: { title?: string; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-line bg-surface p-5 ${className}`}>
      {title && <h2 className="mb-3 text-sm font-semibold">{title}</h2>}
      {children}
    </section>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[8.5rem_minmax(0,1fr)] gap-2 py-1 text-sm">
      <dt className="text-ink-3">{label}</dt>
      <dd className="break-words">{children}</dd>
    </div>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-[13px] break-all">{children}</span>;
}

export function Button({
  children,
  variant = "secondary",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" }) {
  const look = variant === "primary" ? "bg-ink text-bg border-ink" : "bg-surface text-ink border-line hover:bg-sunken";
  return (
    <button
      {...props}
      className={`rounded-md border px-3 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 ${look}`}
    >
      {children}
    </button>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="text-xs text-accent hover:underline"
      onClick={() =>
        navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        })
      }
    >
      {copied ? "Copied" : label}
    </button>
  );
}

export function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <p role="alert" className="rounded-md border border-risk-high px-3 py-2 text-sm text-risk-high">
      {children}
    </p>
  );
}

export function Loading({ children = "Loading…" }: { children?: ReactNode }) {
  return <p className="text-sm text-ink-3">{children}</p>;
}

export function PageTitle({ title, intro }: { title: string; intro?: string }) {
  return (
    <header className="mb-6">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      {intro && <p className="mt-1 text-sm text-ink-2">{intro}</p>}
    </header>
  );
}
