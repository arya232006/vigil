"use client";

import { useEffect, useRef, useState } from "react";
import { Card, SeverityPill, Tag } from "@/components/ui";
import { defang } from "@/lib/format";
import type { Finding } from "@/lib/types";

function evidenceText(value: unknown): string {
  if (typeof value === "string") return /^https?:/i.test(value) ? defang(value) : value;
  return JSON.stringify(value, null, 2);
}

function FindingCard({ finding, focusNonce }: { finding: Finding; focusNonce: number | null }) {
  const ref = useRef<HTMLElement>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (focusNonce === null || !ref.current) return;
    const el = ref.current;
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.remove("finding-flash");
    void el.offsetWidth; // restart the animation
    el.classList.add("finding-flash");
  }, [focusNonce]);

  const evidence = Object.entries(finding.evidence);
  const notes = [
    { label: "Why it matters", text: finding.impact },
    { label: "What to do", text: finding.recommendation },
    { label: "Caveats", text: finding.limitations },
  ].filter((n): n is { label: string; text: string } => Boolean(n.text));

  return (
    <article ref={ref} id={finding.id} className="rounded-md border border-line p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs text-ink-3">{finding.id}</span>
        <SeverityPill severity={finding.severity} />
        <Tag>{finding.module.replace("_", " ")}</Tag>
        {finding.source.includes("independent agreement") && <Tag tone="good">independent agreement</Tag>}
      </div>
      <h3 className="mt-2 text-sm font-semibold break-words">{finding.title}</h3>
      <p className="mt-1 text-sm break-words text-ink-2">{finding.description}</p>
      <p className="mt-1 text-xs break-words text-ink-3">Source: {finding.source}</p>

      {(evidence.length > 0 || notes.length > 0) && (
        <details open={open} onToggle={(e) => setOpen(e.currentTarget.open)} className="mt-2">
          <summary className="-my-1 cursor-pointer py-1 text-xs text-accent">Evidence and details</summary>
          <div className="mt-2 space-y-2">
            {notes.map((note) => (
              <p key={note.label} className="text-sm">
                <span className="font-medium">{note.label}: </span>
                {note.text}
              </p>
            ))}
            {evidence.length > 0 && (
              <dl className="rounded bg-sunken p-2">
                {evidence.map(([key, value]) => (
                  <div key={key} className="grid gap-1 py-0.5 sm:grid-cols-[9rem_minmax(0,1fr)]">
                    <dt className="font-mono text-xs text-ink-3">{key}</dt>
                    <dd className="font-mono text-xs break-all whitespace-pre-wrap">{evidenceText(value)}</dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        </details>
      )}
    </article>
  );
}

export function Findings({ findings, focus }: { findings: Finding[]; focus: { id: string; nonce: number } | null }) {
  const [showMinorChosen, setShowMinorChosen] = useState(false);
  const isMinor = (f: Finding) => f.severity === "low" || f.severity === "info";
  const major = findings.filter((f) => !isMinor(f));
  const minor = findings.filter(isMinor);
  const showMinor = showMinorChosen || minor.some((f) => f.id === focus?.id);
  const nonceFor = (f: Finding) => (focus?.id === f.id ? focus.nonce : null);

  return (
    <Card title={`Findings (${findings.length})`}>
      {findings.length === 0 && <p className="text-sm text-ink-3">No findings were raised by the checks performed.</p>}
      <div className="space-y-3">
        {major.map((f) => (
          <FindingCard key={f.id} finding={f} focusNonce={nonceFor(f)} />
        ))}
        {minor.length > 0 && !showMinor && (
          <button type="button" className="-my-0.5 py-0.5 text-sm text-accent hover:underline" onClick={() => setShowMinorChosen(true)}>
            Show {minor.length} minor {minor.length === 1 ? "finding" : "findings"}
          </button>
        )}
        {showMinor && minor.map((f) => <FindingCard key={f.id} finding={f} focusNonce={nonceFor(f)} />)}
      </div>
    </Card>
  );
}
