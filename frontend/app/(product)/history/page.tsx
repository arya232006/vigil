"use client";

import Link from "next/link";
import { ErrorNote, Loading, PageTitle, RiskBadge, Tag } from "@/components/ui";
import { useApi } from "@/lib/api";
import { defang, formatTime } from "@/lib/format";
import type { ReportSummary } from "@/lib/types";

export default function HistoryPage() {
  const { data, error, loading } = useApi<ReportSummary[]>("/api/reports?limit=50");

  return (
    <>
      <PageTitle title="History" intro="The 50 most recent investigations." />
      {loading && <Loading />}
      {error && <ErrorNote>{error}</ErrorNote>}
      {data?.length === 0 && (
        <p className="text-sm text-ink-2">
          Nothing here yet. <Link href="/investigate" className="text-accent hover:underline">Run your first investigation.</Link>
        </p>
      )}
      {data && data.length > 0 && (
        <ul className="divide-y divide-line rounded-lg border border-line bg-surface">
          {data.map((row) => {
            const isLink = row.input_type === "url" || row.input_type === "domain";
            return (
              <li key={row.report_id}>
                <Link href={`/reports/${row.report_id}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 p-3 hover:bg-sunken">
                  <span className="w-36 shrink-0"><RiskBadge level={row.risk_level} /></span>
                  <Tag>{row.input_type}</Tag>
                  <span className="min-w-0 flex-1 basis-60 truncate font-mono text-[13px]">
                    {isLink ? defang(row.input_preview) : row.input_preview}
                  </span>
                  <span className="text-xs text-ink-3">{formatTime(row.analyzed_at)}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </>
  );
}
