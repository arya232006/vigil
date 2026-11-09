"use client";

import { useState, type ReactNode } from "react";
import { RISK, SEVERITY_BG } from "@/lib/format";
import type { RiskLevel, Severity } from "@/lib/types";

export function RiskBadge({ level, large = false }: { level: RiskLevel; large?: boolean }) {
  const size = large ? "px-3 py-1.5 text-lg" : "px-2 py-0.5 text-xs";
  return <span className={`inline-block font-semibold text-white ${RISK[level].bg} ${size}`}>{RISK[level].label}</span>;
}

export function SeverityPill({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-block px-1.5 py-0.5 text-[11px] font-semibold tracking-wide text-white uppercase ${SEVERITY_BG[severity]}`}>
      {severity}
    </span>
  );
}

export function Tag({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "danger" | "good" }) {
  const tones = {
    neutral: "border-ink-3 text-ink-2",
    danger: "border-risk-high text-risk-high",
    good: "border-risk-ok text-risk-ok",
  };
  return <span className={`inline-block border px-1.5 py-0.5 text-xs ${tones[tone]}`}>{children}</span>;
}

export function Card({
  title,
  meta,
  flush = false,
  children,
  className = "",
}: {
  title?: string;
  meta?: string;
  flush?: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`win min-w-0 ${className}`}>
      {title && (
        <div className="win-bar terminal">
          <h2>{title}</h2>
          {meta && <span>{meta}</span>}
        </div>
      )}
      <div className={flush ? "" : "p-4"}>{children}</div>
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
  return <span className="code text-[13px] break-all">{children}</span>;
}

export function Button({
  children,
  variant = "secondary",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" }) {
  const look =
    variant === "primary"
      ? "bg-(--l-ink) text-(--l-paper) hover:bg-(--l-pink) hover:text-(--l-ink)"
      : "bg-(--l-paper) text-(--l-ink) hover:bg-(--l-ink) hover:text-(--l-paper)";
  return (
    <button
      {...props}
      className={`terminal cursor-pointer border border-(--l-ink) px-3 py-1 text-xl leading-tight disabled:cursor-not-allowed disabled:opacity-50 ${look}`}
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
      className="-my-1 inline-block cursor-pointer py-1 text-xs text-accent underline"
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
    <p role="alert" className="border border-risk-high bg-(--l-paper) px-3 py-2 text-sm text-risk-high">
      {children}
    </p>
  );
}

export function Loading({ children = "Loading ..." }: { children?: ReactNode }) {
  return <p className="terminal text-2xl">{children}</p>;
}

export function PageTitle({ eyebrow, title, intro }: { eyebrow: string; title: string; intro?: string }) {
  return (
    <header className="mb-8">
      <p className="code text-sm">{eyebrow}</p>
      <h1 className="display mt-3 text-[clamp(3rem,7vw,6rem)]">{title}</h1>
      {intro && <p className="mt-3 max-w-xl text-xl leading-snug">{intro}</p>}
    </header>
  );
}
