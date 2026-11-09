"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { CountUp } from "@/app/(marketing)/CountUp";
import { DitherFill } from "@/app/(marketing)/DitherFill";
import { DitherPanel } from "@/app/(marketing)/DitherPanel";
import { ErrorNote, Loading, PageTitle, RiskBadge } from "@/components/ui";
import { useApi } from "@/lib/api";
import { RISK, RISK_ORDER, defang, formatTime, shortHash } from "@/lib/format";
import type { ChainStatus, Health, ReportSummary, RiskLevel, Stats } from "@/lib/types";

// Denser texture means more severe, so the ranking still reads without colour.
const SEVERITY_DENSITY: Record<RiskLevel, number> = {
  confirmed_malicious: 1,
  high_risk: 0.78,
  suspicious: 0.5,
  low_risk: 0.22,
  inconclusive: 0.1,
};

const KIND_LABEL: Record<string, string> = {
  domain: "Domain",
  redirect: "Redirect hop",
  entity: "Impersonated",
  upi: "UPI ID",
  phone: "Phone",
  ip: "IP address",
};

function Panel({ title, meta, className = "", children }: { title: string; meta?: string; className?: string; children: ReactNode }) {
  return (
    <section className={`win min-w-0 ${className}`}>
      <div className="win-bar terminal">
        <h2>{title}</h2>
        {meta && <span>{meta}</span>}
      </div>
      {children}
    </section>
  );
}

function Kpi({ title, value, caption }: { title: string; value: ReactNode; caption: string }) {
  return (
    <Panel title={title}>
      <div className="p-4">
        <p className="display text-[56px]">{value}</p>
        <p className="mt-2 text-[15px] leading-tight text-[rgb(30_30_30/0.8)]">{caption}</p>
      </div>
    </Panel>
  );
}

function Bar({ label, count, total, max, density }: { label: ReactNode; count: number; total: number; max: number; density: number }) {
  const share = total ? Math.round((count / total) * 100) : 0;
  return (
    <li className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 sm:grid-cols-[9.5rem_minmax(0,1fr)_4.5rem]" title={`${count} of ${total} reports (${share}%)`}>
      <span>{label}</span>
      <span className="col-span-2 row-start-2 block h-6 border-b border-(--l-ink) sm:col-span-1 sm:col-start-2 sm:row-start-1">
        {count > 0 && (
          <span className="block h-full border-x border-t border-(--l-ink)" style={{ width: `${(count / max) * 100}%` }}>
            <DitherFill density={density} />
          </span>
        )}
      </span>
      <span className="terminal col-start-2 row-start-1 text-right text-xl tabular-nums sm:col-start-3">{count} · {share}%</span>
    </li>
  );
}

function StatusRow({ state, label, detail }: { state: "ok" | "warn" | "off"; label: string; detail: string }) {
  const mark = { ok: "✓", warn: "!", off: "✗" }[state];
  const tone = { ok: "bg-[#1a7a42]", warn: "bg-[#a85a06]", off: "bg-[#c0272d]" }[state];
  return (
    <li className="terminal flex items-center gap-3 text-xl leading-none">
      <span className={`grid h-6 w-6 shrink-0 place-items-center text-white ${tone}`} aria-hidden>{mark}</span>
      <span className="shrink-0">{label}</span>
      <span className="min-w-0 flex-1 truncate text-right" title={detail}>{detail}</span>
    </li>
  );
}

function SystemStatus({ health, healthFailed, chain }: { health?: Health; healthFailed: boolean; chain?: ChainStatus }) {
  const ai = !health
    ? { state: "off" as const, detail: "unknown" }
    : health.system2.student_up
      ? { state: "ok" as const, detail: "self-hosted model" }
      : health.system2.fallback_up
        ? { state: "warn" as const, detail: "backup model" }
        : { state: "warn" as const, detail: "rules-based summaries" };
  const chainRow = !chain
    ? { state: "off" as const, detail: "unknown" }
    : chain.connected
      ? { state: "ok" as const, detail: `chain ${chain.chain_id} · ${shortHash(chain.contract_address ?? "")}` }
      : { state: "warn" as const, detail: chain.enabled ? "unreachable" : "not configured" };
  const feeds = health?.feeds.openphish_urls ?? 0;

  return (
    <Panel title="system.status" className="lg:col-span-5">
      <DitherPanel variant="checks" className="h-28 bg-[#c4c4c4]" />
      <ul className="space-y-3 p-4">
        <StatusRow state={health ? "ok" : "off"} label="API" detail={health ? "online" : healthFailed ? "offline" : "checking"} />
        <StatusRow state={ai.state} label="AI" detail={ai.detail} />
        <StatusRow state={feeds > 0 ? "ok" : "warn"} label="Feeds" detail={feeds > 0 ? `${feeds.toLocaleString()} phishing URLs` : "not loaded"} />
        <StatusRow state={chainRow.state} label="Chain" detail={chainRow.detail} />
      </ul>
    </Panel>
  );
}

const HOUR_MS = 3_600_000;
const TIMELINE_HOURS = 24;

/** Reports per hour for the 24 hours up to the most recent report, so a quiet instance still shows its last activity. */
function ActivityTimeline({ reports }: { reports?: ReportSummary[] }) {
  if (!reports?.length) return null;
  const times = reports.map((r) => new Date(r.analyzed_at).getTime());
  const lastHour = Math.floor(Math.max(...times) / HOUR_MS);
  const hours = Array.from({ length: TIMELINE_HOURS }, (_, i) => lastHour - TIMELINE_HOURS + 1 + i);
  const countAt = (hour: number) => times.filter((t) => Math.floor(t / HOUR_MS) === hour).length;
  const max = Math.max(1, ...hours.map(countAt));
  const clock = (hour: number) => new Date(hour * HOUR_MS).toLocaleString(undefined, { hour: "numeric", day: "numeric", month: "short" });

  return (
    <Panel title="activity.timeline" meta="reports per hour">
      <div className="p-4">
        <ol className="flex h-24 items-end gap-0.5 border-b border-(--l-ink)">
          {hours.map((hour) => {
            const count = countAt(hour);
            return (
              <li key={hour} className="flex h-full min-w-0 flex-1 items-end" title={`${clock(hour)}: ${count} report${count === 1 ? "" : "s"}`}>
                {count > 0 && (
                  <span className="block w-full border-x border-t border-(--l-ink)" style={{ height: `${(count / max) * 100}%` }}>
                    <DitherFill density={0.6} />
                  </span>
                )}
              </li>
            );
          })}
        </ol>
        <div className="terminal mt-1 flex justify-between text-lg">
          <span>{clock(hours[0])}</span>
          <span>{clock(hours[TIMELINE_HOURS - 1])}</span>
        </div>
      </div>
    </Panel>
  );
}

function RecentReports({ reports }: { reports?: ReportSummary[] }) {
  return (
    <Panel title="recent.investigations" meta="latest 8" className="lg:col-span-7">
      <ul className="divide-y divide-(--l-ink)">
        {reports?.map((row) => {
          const isLink = row.input_type === "url" || row.input_type === "domain";
          return (
            <li key={row.report_id}>
              <Link href={`/reports/${row.report_id}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 hover:bg-[#c4c4c4]">
                <span className="w-36 shrink-0"><RiskBadge level={row.risk_level} /></span>
                <span className="code min-w-0 flex-1 basis-48 truncate text-[13px]">
                  {isLink ? defang(row.input_preview) : row.input_preview}
                </span>
                <span className="terminal text-lg whitespace-nowrap">{row.input_type} · {formatTime(row.analyzed_at)}</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

export default function DashboardPage() {
  const { data, error, loading } = useApi<Stats>("/api/stats");
  const { data: history } = useApi<ReportSummary[]>("/api/reports?limit=200");
  const recent = history?.slice(0, 8);
  const { data: health, error: healthError } = useApi<Health>("/api/health");
  const { data: chain } = useApi<ChainStatus>("/api/chain/status");

  const counts = data?.by_risk_level ?? {};
  const total = data?.total_reports ?? 0;
  const flagged = (counts.confirmed_malicious ?? 0) + (counts.high_risk ?? 0) + (counts.suspicious ?? 0);
  const riskMax = Math.max(1, ...RISK_ORDER.map((level) => counts[level] ?? 0));
  const types = Object.entries(data?.by_input_type ?? {}).sort((a, b) => b[1] - a[1]);
  const typeMax = Math.max(1, ...types.map(([, count]) => count));
  const campaigns = Object.entries(data?.recurring_indicators ?? {})
    .flatMap(([kind, items]) => items.map((item) => ({ kind, ...item })))
    .sort((a, b) => b.reports - a.reports);

  return (
    <>
      <PageTitle eyebrow="vg.dashboard" title="The Threat Desk" intro="Everything you have investigated, and which indicators keep coming back." />

        {error && <ErrorNote>{error}</ErrorNote>}
        {loading && <Loading>Loading the desk ...</Loading>}

        {data && (
          <div className="relative border border-(--l-ink) bg-[#df7b93] p-3 sm:p-5">
            <div className="dither pointer-events-none absolute inset-0 text-[#c46f84]" aria-hidden />

            {total === 0 ? (
              <div className="relative">
                <Panel title="desk.empty">
                  <p className="terminal p-5 text-2xl leading-tight">
                    No investigations yet.{" "}
                    <Link href="/investigate" className="underline">Run the first one</Link>
                  </p>
                </Panel>
              </div>
            ) : (
              <div className="relative grid gap-5 lg:grid-cols-12">
                <div className="grid gap-5 sm:grid-cols-2 lg:col-span-12 lg:grid-cols-4">
                  <Kpi title="reports.total" value={<CountUp value={total} decimals={0} suffix="" />} caption="Your saved investigations" />
                  <Kpi title="reports.flagged" value={<CountUp value={(flagged / total) * 100} decimals={0} />} caption={`${flagged} rated suspicious or worse`} />
                  <Kpi
                    title="chain.anchors"
                    value={chain?.connected ? <CountUp value={chain.total_reports ?? 0} decimals={0} suffix="" /> : "—"}
                    caption={chain?.connected ? "Report hashes in the on-chain registry" : "On-chain registry not connected"}
                  />
                  <Kpi title="campaigns.active" value={<CountUp value={campaigns.length} decimals={0} suffix="" />} caption="Indicators seen in 2+ risky reports" />
                </div>

                <div className="lg:col-span-12">
                  <ActivityTimeline reports={history} />
                </div>

                <Panel title="risk.levels" meta="denser = more severe" className="lg:col-span-7">
                  <div className="flex h-10 gap-0.5 px-4 pt-4" role="img" aria-label="Share of reports at each risk level">
                    {RISK_ORDER.filter((level) => (counts[level] ?? 0) > 0).map((level) => (
                      <span
                        key={level}
                        className="block h-full border border-(--l-ink)"
                        style={{ flexGrow: counts[level] ?? 0, flexBasis: 0 }}
                        title={`${RISK[level].label}: ${counts[level]} of ${total}`}
                      >
                        <DitherFill density={SEVERITY_DENSITY[level]} />
                      </span>
                    ))}
                  </div>
                  <ul className="space-y-3 p-4 text-[15px]">
                    {RISK_ORDER.map((level) => (
                      <Bar key={level} label={RISK[level].label} count={counts[level] ?? 0} total={total} max={riskMax} density={SEVERITY_DENSITY[level]} />
                    ))}
                  </ul>
                </Panel>

                <SystemStatus health={health} healthFailed={Boolean(healthError)} chain={chain} />

                <RecentReports reports={recent} />

                <div className="grid content-start gap-5 lg:col-span-5">
                  <Panel title="input.types">
                    <ul className="space-y-3 p-4 text-[15px]">
                      {types.map(([type, count]) => (
                        <Bar key={type} label={type === "url" ? "URL" : type[0].toUpperCase() + type.slice(1)} count={count} total={total} max={typeMax} density={0.5} />
                      ))}
                    </ul>
                  </Panel>

                  <Panel title="campaigns.recurring" meta={`${campaigns.length} active`}>
                    {campaigns.length === 0 ? (
                      <p className="terminal p-4 text-xl leading-tight">No indicator has recurred across risky reports yet.</p>
                    ) : (
                      <ul className="divide-y divide-(--l-ink)">
                        {campaigns.slice(0, 6).map((c) => (
                          <li key={`${c.kind}:${c.value}`} className="flex items-baseline gap-3 px-4 py-2">
                            <span className="terminal w-28 shrink-0 text-lg">{KIND_LABEL[c.kind] ?? c.kind}</span>
                            <span className="code min-w-0 flex-1 truncate text-[13px]" title={c.value}>{c.kind === "domain" ? defang(c.value) : c.value}</span>
                            <span className="terminal text-xl tabular-nums">{c.reports}×</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </Panel>
                </div>
              </div>
            )}
          </div>
        )}
    </>
  );
}
