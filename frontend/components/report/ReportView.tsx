"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { Button, Card, ErrorNote, RiskBadge, Tag } from "@/components/ui";
import { errorMessage, investigate } from "@/lib/api";
import { RISK, defang, explainedBy, formatTime, percent } from "@/lib/format";
import type { CheckStatus, ModelScore, Report } from "@/lib/types";
import { EmailPanel } from "./EmailPanel";
import { Findings } from "./Findings";
import { IntegrityPanel } from "./IntegrityPanel";
import { MessagePanel } from "./MessagePanel";
import { TargetPanels } from "./TargetPanels";

function Header({ report, cached }: { report: Report; cached: boolean }) {
  const router = useRouter();
  const [rerunning, setRerunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isLink = report.input_type === "url" || report.input_type === "domain";

  async function rerun() {
    setError(null);
    setRerunning(true);
    try {
      const job = await investigate(report.input, true, () => {});
      router.push(`/reports/${job.report_id}`);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setRerunning(false);
    }
  }

  return (
    <header className="rounded-lg border border-line bg-surface p-5">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
        <RiskBadge level={report.risk_level} large />
        <div>
          <p className="text-xs text-ink-3">Risk score</p>
          <p className="font-mono text-lg font-semibold">
            {report.risk_score}
            <span className="text-sm font-normal text-ink-3">/100</span>
          </p>
        </div>
        <div className="min-w-40">
          <p className="text-xs text-ink-3">Evidence coverage</p>
          <div className="mt-1.5 flex items-center gap-2">
            <div className="h-1.5 w-28 rounded-full bg-sunken">
              <div className="h-1.5 rounded-full bg-ink-2" style={{ width: `${report.confidence * 100}%` }} />
            </div>
            <span className="font-mono text-xs">{percent(report.confidence, 0)}</span>
          </div>
        </div>
        {report.input_type !== "email" && (
          <div className="ml-auto">
            <Button onClick={rerun} disabled={rerunning}>
              {rerunning ? "Re-running…" : "Re-run analysis"}
            </Button>
          </div>
        )}
      </div>
      <p className="mt-4 font-medium">{RISK[report.risk_level].message}</p>
      <p className="mt-1 line-clamp-2 font-mono text-[13px] break-all text-ink-2">
        {isLink ? defang(report.input) : report.input}
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-ink-3">
        <Tag>{report.input_type}</Tag>
        {cached && <Tag>cached</Tag>}
        <span>{formatTime(report.analyzed_at)}</span>
      </div>
      {error && <div className="mt-3"><ErrorNote>{error}</ErrorNote></div>}
    </header>
  );
}

function KeyPoint({ text, validIds, onFocus }: { text: string; validIds: Set<string>; onFocus: (id: string) => void }) {
  const parts = text.split(/(\[F\d+(?:,\s*F\d+)*\])/g);
  return (
    <li className="text-sm leading-relaxed">
      {parts.map((part, i) => {
        if (!/^\[F\d/.test(part)) return part;
        const ids = (part.match(/F\d+/g) ?? []).filter((id) => validIds.has(id));
        return ids.map((id) => (
          <button
            key={`${i}-${id}`}
            type="button"
            onClick={() => onFocus(id)}
            aria-label={`Go to finding ${id}`}
            className="mr-1 rounded bg-sunken px-1.5 py-0.5 font-mono text-xs font-medium text-accent hover:underline"
          >
            {id}
          </button>
        ));
      })}
    </li>
  );
}

function Explanation({ report, onFocus }: { report: Report; onFocus: (id: string) => void }) {
  const by = explainedBy(report.explanation.generated_by);
  const validIds = new Set(report.findings.map((f) => f.id));
  return (
    <Card title="What we found">
      <p className="leading-relaxed">{report.explanation.summary}</p>
      {report.explanation.key_points.length > 0 && (
        <ul className="mt-3 space-y-2">
          {report.explanation.key_points.map((point) => (
            <KeyPoint key={point} text={point} validIds={validIds} onFocus={onFocus} />
          ))}
        </ul>
      )}
      <p className="mt-4 text-xs text-ink-3">
        {by.label}. The AI explains the evidence; it cannot change the risk level.
      </p>
    </Card>
  );
}

const CHECK_MARK: Record<CheckStatus["status"], { mark: string; label: string; color: string }> = {
  ok: { mark: "✓", label: "completed", color: "text-risk-ok" },
  failed: { mark: "✗", label: "failed", color: "text-risk-high" },
  skipped: { mark: "–", label: "skipped", color: "text-ink-3" },
  unavailable: { mark: "?", label: "unavailable", color: "text-risk-warn" },
};

function Checks({ checks }: { checks: CheckStatus[] }) {
  const decision = checks.find((c) => c.name === "risk_engine");
  const rest = checks.filter((c) => c.name !== "risk_engine");
  const missing = rest.filter((c) => c.status === "unavailable" || c.status === "failed");
  return (
    <Card title="Checks performed">
      <ul className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
        {rest.map((check) => (
          <li key={check.name} className="flex gap-2 text-sm" title={check.detail ?? undefined}>
            <span className={`font-mono ${CHECK_MARK[check.status].color}`} aria-label={CHECK_MARK[check.status].label}>
              {CHECK_MARK[check.status].mark}
            </span>
            <span>{check.name.replaceAll("_", " ")}</span>
          </li>
        ))}
      </ul>
      {missing.length > 0 && (
        <p className="mt-3 text-sm text-risk-warn">
          Not covered by this report: {missing.map((c) => c.name.replaceAll("_", " ")).join(", ")}.
        </p>
      )}
      {decision?.detail && (
        <p className="mt-3 border-t border-line pt-3 text-sm text-ink-2">
          <span className="font-medium text-ink">How we decided: </span>
          {decision.detail}
        </p>
      )}
    </Card>
  );
}

function ModelScores({ scores }: { scores: ModelScore[] }) {
  return (
    <Card title="Model scores">
      <ul className="space-y-3">
        {scores.map((score) => {
          const tactics = score.details.tactics;
          return (
            <li key={score.model} className="text-sm">
              <div className="flex justify-between gap-3">
                <span className="font-mono text-xs break-all text-ink-2">{score.model}</span>
                <span className="shrink-0 text-xs">
                  {score.label} · <span className="font-mono">{percent(score.probability, 0)}</span>
                </span>
              </div>
              <div className="mt-1 h-1.5 rounded-full bg-sunken">
                <div className="h-1.5 rounded-full bg-ink-2" style={{ width: `${score.probability * 100}%` }} />
              </div>
              {Array.isArray(tactics) && tactics.length > 0 && (
                <p className="mt-1 text-xs text-ink-3">Tactics: {tactics.map(String).join(", ")}</p>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

function Related({ report }: { report: Report }) {
  return (
    <Card title="Related reports">
      <ul className="space-y-2">
        {report.correlations.map((c) => (
          <li key={c.report_id} className="flex flex-wrap items-center gap-2 text-sm">
            <RiskBadge level={c.risk_level} />
            <Link href={`/reports/${c.report_id}`} className="font-mono text-xs text-accent hover:underline">
              {c.report_id}
            </Link>
            <span className="text-xs break-all text-ink-2">shares {c.shared.map(defang).join(", ")}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function List({ title, items, muted = false }: { title: string; items: string[]; muted?: boolean }): ReactNode {
  return (
    <Card title={title}>
      <ul className={`list-disc space-y-1 pl-4 text-sm ${muted ? "text-ink-3" : ""}`}>
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </Card>
  );
}

export function ReportView({ report, cached }: { report: Report; cached: boolean }) {
  const [focus, setFocus] = useState<{ id: string; nonce: number } | null>(null);
  const focusFinding = (id: string) => setFocus((prev) => ({ id, nonce: (prev?.nonce ?? 0) + 1 }));

  return (
    <div className="space-y-4">
      <Header report={report} cached={cached} />
      <Explanation report={report} onFocus={focusFinding} />
      {report.recommendations.length > 0 && <List title="What to do" items={report.recommendations} />}
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <Findings findings={report.findings} focus={focus} />
        <div className="space-y-4">
          {report.input_type === "email" && report.email ? (
            <EmailPanel email={report.email} />
          ) : report.input_type === "message" ? (
            <MessagePanel report={report} />
          ) : (
            <TargetPanels report={report} />
          )}
        </div>
      </div>
      <IntegrityPanel report={report} />
      <div className="grid items-start gap-4 lg:grid-cols-2">
        <Checks checks={report.checks} />
        {report.model_scores.length > 0 && <ModelScores scores={report.model_scores} />}
      </div>
      {report.correlations.length > 0 && <Related report={report} />}
      {report.limitations.length > 0 && <List title="Limitations" items={report.limitations} muted />}
    </div>
  );
}
