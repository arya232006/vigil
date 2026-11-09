"use client";

import Link from "next/link";
import { useState } from "react";
import { Card, ErrorNote, Loading, PageTitle, RiskBadge } from "@/components/ui";
import { useApi } from "@/lib/api";
import { RISK, RISK_ORDER, defang, formatTime } from "@/lib/format";
import type { ReportSummary, RiskLevel } from "@/lib/types";

const FETCH_LIMIT = 200;

export default function HistoryPage() {
  const { data, error, loading } = useApi<ReportSummary[]>(`/api/reports?limit=${FETCH_LIMIT}`);
  const [filter, setFilter] = useState<RiskLevel | "all">("all");

  const countOf = (level: RiskLevel) => data?.filter((r) => r.risk_level === level).length ?? 0;
  const present = RISK_ORDER.filter((level) => countOf(level) > 0);
  const rows = data?.filter((r) => filter === "all" || r.risk_level === filter) ?? [];

  const filterButton = (value: RiskLevel | "all", label: string, count: number) => (
    <button
      key={value}
      type="button"
      aria-pressed={filter === value}
      onClick={() => setFilter(value)}
      className={`terminal cursor-pointer border border-(--l-ink) px-3 py-0.5 text-xl ${
        filter === value ? "bg-(--l-ink) text-(--l-paper)" : "bg-(--l-paper) hover:bg-sunken"
      }`}
    >
      {label} · <span className="tabular-nums">{count}</span>
    </button>
  );

  return (
    <>
      <PageTitle eyebrow="vg.history" title="History" intro={`Your saved investigations, up to the latest ${FETCH_LIMIT}.`} />
      {loading && <Loading />}
      {error && <ErrorNote>{error}</ErrorNote>}
      {data?.length === 0 && (
        <Card title="history.empty">
          <p className="terminal text-2xl leading-tight">
            Nothing here yet. <Link href="/investigate" className="underline">Run your first investigation</Link>
          </p>
        </Card>
      )}
      {data && data.length > 0 && (
        <>
          <div className="mb-4 flex flex-wrap gap-1.5">
            {filterButton("all", "All", data.length)}
            {present.map((level) => filterButton(level, RISK[level].label, countOf(level)))}
          </div>
          <Card title="reports.log" meta={`${rows.length} shown`} flush>
            <ul className="divide-y divide-(--l-ink)">
              {rows.map((row) => {
                const isLink = row.input_type === "url" || row.input_type === "domain";
                return (
                  <li key={row.report_id}>
                    <Link href={`/reports/${row.report_id}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 hover:bg-sunken">
                      <span className="w-36 shrink-0"><RiskBadge level={row.risk_level} /></span>
                      <span className="code min-w-0 flex-1 basis-60 truncate text-[13px]">
                        {isLink ? defang(row.input_preview) : row.input_preview}
                      </span>
                      <span className="terminal text-lg whitespace-nowrap">{row.input_type} · {formatTime(row.analyzed_at)}</span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          </Card>
        </>
      )}
    </>
  );
}
