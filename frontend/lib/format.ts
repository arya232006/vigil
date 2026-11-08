import type { Report, RiskLevel, Severity } from "./types";

export const RISK: Record<RiskLevel, { label: string; message: string; bg: string; bar: string }> = {
  confirmed_malicious: {
    label: "Confirmed malicious",
    message: "Known malicious. Do not open it or reply.",
    bg: "bg-risk-critical",
    bar: "bg-risk-critical",
  },
  high_risk: {
    label: "High risk",
    message: "Several strong warning signs.",
    bg: "bg-risk-high",
    bar: "bg-risk-high",
  },
  suspicious: {
    label: "Suspicious",
    message: "Verify through an official channel first.",
    bg: "bg-risk-warn",
    bar: "bg-risk-warn",
  },
  low_risk: {
    label: "Low risk",
    message: "No malicious indicators found within the checks performed.",
    bg: "bg-risk-ok",
    bar: "bg-risk-ok",
  },
  inconclusive: {
    label: "Inconclusive",
    message: "Not enough evidence. Treat it with caution.",
    bg: "bg-risk-none",
    bar: "bg-risk-none",
  },
};

export const RISK_ORDER: RiskLevel[] = ["confirmed_malicious", "high_risk", "suspicious", "low_risk", "inconclusive"];

export const SEVERITY_BG: Record<Severity, string> = {
  critical: "bg-risk-critical",
  high: "bg-risk-high",
  medium: "bg-risk-warn",
  low: "bg-risk-minor",
  info: "bg-risk-none",
};

/** Reported URLs and domains are attacker-controlled: display them inert. */
export const defang = (s: string) => s.replace(/^http/i, "hxxp").replace(/\./g, "[.]");

export const formatTime = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

export const percent = (value: number, digits = 1) => `${(value * 100).toFixed(digits)}%`;

export const shortHash = (h: string) => `${h.slice(0, 10)}…${h.slice(-8)}`;

export function explainedBy(generatedBy: string): { label: string; selfHosted: boolean } {
  if (generatedBy.startsWith("s2:")) {
    return { label: "Explained by threatscope-s2, our fine-tuned self-hosted model", selfHosted: true };
  }
  if (generatedBy.startsWith("fallback:")) return { label: "Explained by a local backup model", selfHosted: true };
  return { label: "Rule-based summary (AI model offline)", selfHosted: false };
}

/** The domain the backend commits as the report's on-chain indicator (see chain.report_domain). */
export function reportDomain(report: Report): string | null {
  return report.target?.registered_domain ?? report.email?.from_domain ?? report.indicators?.domains[0] ?? null;
}
