"use client";

import Link from "next/link";
import { Card, Mono, RiskBadge } from "@/components/ui";
import { useApi } from "@/lib/api";
import { defang } from "@/lib/format";
import type { Finding, Report } from "@/lib/types";

interface Span {
  start: number;
  end: number;
  title: string;
}

function quoteSpans(text: string, findings: Finding[]): Span[] {
  const spans: Span[] = [];
  for (const finding of findings) {
    const quote = finding.evidence.quote;
    if (finding.module !== "message" || typeof quote !== "string" || !quote) continue;
    const pattern = new RegExp(quote.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    for (const match of text.matchAll(pattern)) {
      spans.push({ start: match.index, end: match.index + match[0].length, title: finding.title });
    }
  }
  spans.sort((a, b) => a.start - b.start);
  let cursor = 0;
  return spans.filter((span) => {
    if (span.start < cursor) return false;
    cursor = span.end;
    return true;
  });
}

function HighlightedMessage({ text, findings }: { text: string; findings: Finding[] }) {
  const nodes: React.ReactNode[] = [];
  let cursor = 0;
  for (const span of quoteSpans(text, findings)) {
    nodes.push(text.slice(cursor, span.start));
    nodes.push(
      <mark key={span.start} title={span.title} className="rounded-sm bg-highlight px-0.5 text-highlight-ink">
        {text.slice(span.start, span.end)}
      </mark>,
    );
    cursor = span.end;
  }
  nodes.push(text.slice(cursor));
  return <p className="font-mono text-[13px] leading-relaxed break-words whitespace-pre-wrap">{nodes}</p>;
}

function LinkedReport({ id }: { id: string }) {
  const { data, error } = useApi<Report>(`/api/reports/${id}`);
  if (error || !data) return null;
  const label = data.target?.registered_domain ?? data.input;
  return (
    <li className="flex flex-wrap items-center gap-2">
      <RiskBadge level={data.risk_level} />
      <Link href={`/reports/${id}`} className="-my-1 inline-block py-1 font-mono text-xs break-all text-accent hover:underline">
        {defang(label)}
      </Link>
    </li>
  );
}

function Iocs({ title, values }: { title: string; values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div>
      <h3 className="text-xs text-ink-3">{title}</h3>
      <ul className="mt-1 flex flex-wrap gap-1.5">
        {values.map((value) => (
          <li key={value} className="rounded bg-sunken px-1.5 py-0.5"><Mono>{value}</Mono></li>
        ))}
      </ul>
    </div>
  );
}

export function MessagePanel({ report }: { report: Report }) {
  const { indicators: ioc } = report;
  const hasIocs = ioc && Object.values(ioc).some((list) => list.length > 0);
  return (
    <>
      <Card title="The message">
        <HighlightedMessage text={report.input} findings={report.findings} />
        <p className="mt-3 text-xs text-ink-3">Highlighted text is what the rules matched. Hover for the reason.</p>
      </Card>
      {hasIocs && (
        <Card title="Extracted indicators">
          <div className="space-y-3">
            <Iocs title="Links" values={ioc.urls.map(defang)} />
            <Iocs title="Domains" values={ioc.domains.map(defang)} />
            <Iocs title="UPI IDs" values={ioc.upi_ids} />
            <Iocs title="Phone numbers" values={ioc.phones} />
            <Iocs title="Email addresses" values={ioc.emails.map(defang)} />
          </div>
        </Card>
      )}
      {report.linked_reports.length > 0 && (
        <Card title="Links found in the message">
          <ul className="space-y-2">
            {report.linked_reports.map((id) => (
              <LinkedReport key={id} id={id} />
            ))}
          </ul>
        </Card>
      )}
    </>
  );
}
