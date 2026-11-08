"use client";

import { Card, ErrorNote, Loading, PageTitle } from "@/components/ui";
import { useApi } from "@/lib/api";
import { percent } from "@/lib/format";
import type { Models } from "@/lib/types";

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <p className="font-mono text-3xl font-semibold">{value}</p>
      <p className="mt-1 text-sm text-ink-2">{label}</p>
    </div>
  );
}

const PIPELINE = [
  { name: "System-1", text: "Calibrated classifiers score links and messages in under 5 ms." },
  { name: "System-2", text: "Our fine-tuned model reads intent and writes the explanation." },
  { name: "Rule engine", text: "Deterministic rules set the risk level from the evidence." },
  { name: "Explanation", text: "Every AI quote and citation is checked against the input." },
];

export default function ModelsPage() {
  const { data, error, loading } = useApi<Models>("/api/models");
  const results = data?.s2?.results ?? [];
  const fineTuned = results.find((r) => r.model.startsWith("vigil-s2"));
  const base = results.find((r) => r.model.startsWith("qwen3-1.7b base"));
  const url = data?.url;
  const legitFpr = url?.holdout_real_legit_subdomains["false_positive_rate@0.5"];

  return (
    <>
      <PageTitle title="Our AI" intro="Self-hosted models, measured on held-out data. No third-party AI service sees your input." />
      {loading && <Loading />}
      {error && <ErrorNote>{error}</ErrorNote>}
      {data && (
        <div className="space-y-4">
          <Card title="How a verdict is made">
            <ol className="grid gap-4 sm:grid-cols-4">
              {PIPELINE.map((step, i) => (
                <li key={step.name}>
                  <p className="font-mono text-xs text-ink-3">Step {i + 1}</p>
                  <p className="mt-0.5 text-sm font-semibold">{step.name}</p>
                  <p className="mt-1 text-sm text-ink-2">{step.text}</p>
                </li>
              ))}
            </ol>
          </Card>

          {fineTuned && base && (
            <Card title="System-2: vigil-s2">
              <p className="mb-5 text-lg font-medium">
                Fine-tuning cut false alarms on legitimate messages from {percent(base.legit_false_positive_rate ?? 0)} to{" "}
                {percent(fineTuned.legit_false_positive_rate ?? 0)}.
              </p>
              <div className="grid gap-6 sm:grid-cols-4">
                <Stat value={percent(fineTuned.scam_recall ?? 0)} label="Scam recall" />
                <Stat value={percent(fineTuned.json_valid_rate ?? 0, 0)} label="Valid structured output" />
                <Stat value={percent(fineTuned.evidence_grounding_rate ?? 0)} label="Quotes grounded in the input" />
                <Stat value={`${Math.round(fineTuned.avg_latency_ms ?? 0)} ms`} label="Average latency" />
              </div>
              <p className="mt-5 text-xs text-ink-3">
                {data.s2?.n} test samples. Held out: {data.s2?.held_out}.
              </p>
            </Card>
          )}

          {url && (
            <Card title="System-1: link classifier">
              <div className="grid gap-6 sm:grid-cols-4">
                <Stat value={percent(url.holdout_openphish_live["detection_rate@0.5"])} label="Live OpenPhish URLs detected" />
                <Stat value={url.test.ece.toFixed(3)} label="Calibration error (ECE)" />
                <Stat value={percent(url.test.false_positive_rate)} label="False positives on the test split" />
                {typeof legitFpr === "number" && <Stat value={percent(legitFpr)} label="False positives on real subdomains" />}
              </div>
              <p className="mt-5 text-xs text-ink-3">{url.model}</p>
            </Card>
          )}
        </div>
      )}
    </>
  );
}
