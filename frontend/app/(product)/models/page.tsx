"use client";

import type { ReactNode } from "react";
import { CountUp } from "@/app/(marketing)/CountUp";
import { DitherFill } from "@/app/(marketing)/DitherFill";
import { Card, ErrorNote, Loading, PageTitle } from "@/components/ui";
import { useApi } from "@/lib/api";
import { percent } from "@/lib/format";
import type { Models } from "@/lib/types";

const asPercent = (rate: number | undefined) => <CountUp value={(rate ?? 0) * 100} />;

function Stat({ value, label, note }: { value: ReactNode; label: string; note: string }) {
  return (
    <div className="border-l border-(--l-ink) pl-3">
      <p className="display text-[44px]">{value}</p>
      <p className="mt-2 text-sm leading-tight font-medium">{label}</p>
      <p className="mt-1 text-sm leading-snug text-ink-2">{note}</p>
    </div>
  );
}

function TextBlock({ kicker, title, children }: { kicker: string; title: string; children: ReactNode }) {
  return (
    <div className="border-l border-(--l-ink) pl-3">
      <p className="code text-xs">{kicker}</p>
      <h3 className="terminal mt-1 text-2xl leading-none">{title}</h3>
      <p className="mt-2 text-[15px] leading-snug text-ink-2">{children}</p>
    </div>
  );
}

function IntentExample({ tag, quote, reading }: { tag: string; quote: string; reading: string }) {
  return (
    <figure className="border border-(--l-ink) bg-(--l-paper) p-4">
      <figcaption className="code text-xs">{tag}</figcaption>
      <blockquote className="mt-3 text-xl leading-snug">“{quote}”</blockquote>
      <p className="mt-3 text-sm leading-snug text-ink-2">{reading}</p>
    </figure>
  );
}

function FalseAlarmBar({ label, rate, density }: { label: string; rate: number; density: number }) {
  return (
    <li className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 sm:grid-cols-[11rem_minmax(0,1fr)_4.5rem]" title={`${label}: ${percent(rate)}`}>
      <span className="text-[15px]">{label}</span>
      <span className="col-span-2 row-start-2 block h-7 border-b border-(--l-ink) sm:col-span-1 sm:col-start-2 sm:row-start-1">
        <span className="block h-full border-x border-t border-(--l-ink)" style={{ width: `${rate * 100}%` }}>
          <DitherFill density={density} />
        </span>
      </span>
      <span className="terminal col-start-2 row-start-1 text-right text-xl tabular-nums sm:col-start-3">{percent(rate)}</span>
    </li>
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
      <PageTitle eyebrow="vg.models" title="Our AI" intro="Self-hosted models, measured on held-out data. No third-party AI service sees your input." />
      {loading && <Loading />}
      {error && <ErrorNote>{error}</ErrorNote>}
      {data && (
        <div className="space-y-5">
          <Card title="why.our.own">
            <h2 className="display text-[clamp(1.9rem,3.6vw,3rem)]">The AI is a witness. The rules are the judge.</h2>
            <p className="mt-4 max-w-3xl text-lg leading-snug">
              Ask a chatbot whether a message is a scam and the answer can change with the wording. A scam can even tell
              the model to call it safe. So Vigil splits the job: checks and rules set the risk level, and our models
              add signals and explain the result in plain language.
            </p>
            <div className="mt-6 grid gap-5 md:grid-cols-3">
              <TextBlock kicker="privacy" title="Runs on our hardware">
                Every model is self-hosted. Your links, messages and reports are never sent to an AI provider.
              </TextBlock>
              <TextBlock kicker="grounding" title="Checked before you see it">
                A quote that isn’t in your input, or a citation to a finding that doesn’t exist, is removed from the
                explanation.
              </TextBlock>
              <TextBlock kicker="fallback" title="Clear when it’s offline">
                Link checks carry on without our model. Message checks lose its read on intent and catch fewer scams,
                and the status bar shows when that happens.
              </TextBlock>
            </div>
          </Card>

          <Card title="verdict.pipeline">
            <ol className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
              {PIPELINE.map((step, i) => (
                <li key={step.name} className="border-l border-(--l-ink) pl-3">
                  <p className="code text-xs">0{i + 1}</p>
                  <p className="terminal mt-1 text-2xl leading-none">{step.name}</p>
                  <p className="mt-2 text-sm leading-snug text-ink-2">{step.text}</p>
                </li>
              ))}
            </ol>
          </Card>

          <Card title="intent.example">
            <h2 className="display text-[clamp(1.9rem,3.6vw,3rem)]">Same words. Opposite meaning.</h2>
            <div className="mt-5 grid gap-4 md:grid-cols-2">
              <IntentExample
                tag="genuine bank alert"
                quote="Your OTP is 482913. Do not share this OTP with anyone."
                reading="Warns you to keep the code private."
              />
              <IntentExample
                tag="scam"
                quote="Share the OTP with our officer to keep your account active."
                reading="Asks you to hand the code over."
              />
            </div>
            <p className="mt-5 max-w-3xl text-[15px] leading-snug text-ink-2">
              Keyword filters see “OTP” and “share” in both. Telling them apart means understanding the sentence, which
              is the job we fine-tuned System-2 to do.
            </p>
          </Card>

          {fineTuned && base && (
            <Card title="system2.vigil-s2" meta={`${data.s2?.n} test samples`}>
              <h2 className="display text-[clamp(1.9rem,3.6vw,3rem)]">Fine-tuning cut false alarms on legitimate messages.</h2>
              <p className="mt-4 max-w-3xl text-[15px] leading-snug text-ink-2">
                A false alarm is a genuine message wrongly flagged. Out of the box, the small base model called most
                genuine messages scams, which would teach people to ignore every warning. Fine-tuning fixed that and
                gave up only a little scam recall.
              </p>
              <ul className="mt-5 space-y-3">
                <FalseAlarmBar label="Base model" rate={base.legit_false_positive_rate ?? 0} density={0.78} />
                <FalseAlarmBar label="Vigil, fine-tuned" rate={fineTuned.legit_false_positive_rate ?? 0} density={0.3} />
              </ul>
              <div className="mt-7 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
                <Stat value={asPercent(fineTuned.scam_recall)} label="Scam recall" note="Of the scams in the test, the share it caught." />
                <Stat value={asPercent(fineTuned.json_valid_rate)} label="Valid structured output" note="Replies in the exact format the pipeline expects." />
                <Stat value={asPercent(fineTuned.evidence_grounding_rate)} label="Quotes grounded in the input" note="Evidence it quoted that really appears in the message." />
                <Stat value={<CountUp value={Math.round(fineTuned.avg_latency_ms ?? 0)} decimals={0} suffix=" ms" />} label="Average latency" note="Time to read one message on Apple Silicon." />
              </div>
              <p className="mt-6 text-xs text-ink-3">Held out: {data.s2?.held_out}.</p>
            </Card>
          )}

          <Card title="training.notes">
            <h2 className="display text-[clamp(1.9rem,3.6vw,3rem)]">How we taught it.</h2>
            <div className="mt-5 grid gap-5 md:grid-cols-3">
              <TextBlock kicker="distillation" title="A bigger model as teacher">
                A larger local model labelled about 3,000 messages. Labels that disagreed with the dataset were dropped,
                and so were quotes not found word for word.
              </TextBlock>
              <TextBlock kicker="local data" title="Scams people here get">
                We hand-wrote 56 hard examples, from KYC, UPI, parcel, job and digital-arrest scams to urgent messages
                that are genuine, then expanded them to about 450 variants.
              </TextBlock>
              <TextBlock kicker="fair testing" title="Scams it had never met">
                Whole scam families were kept out of training, so the results show how it handles new scams, not just
                new wording.
              </TextBlock>
            </div>
          </Card>

          {url && (
            <Card title="system1.link-classifier">
              <h2 className="display text-[clamp(1.9rem,3.6vw,3rem)]">A fast first read on every link.</h2>
              <p className="mt-4 max-w-3xl text-[15px] leading-snug text-ink-2">
                This model reads only the hostname and answers in under 5 ms. Our first version flagged half of the real
                subdomains we tested, such as netbanking.hdfcbank.com, because the legitimate sites it learned from were
                all bare domains. Adding realistic subdomains fixed most of that.
              </p>
              <div className="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
                <Stat value={asPercent(url.holdout_openphish_live["detection_rate@0.5"])} label="Live OpenPhish URLs detected" note="Fresh phishing links from a live feed, collected after training." />
                <Stat value={<CountUp value={url.test.ece} decimals={3} suffix="" />} label="Calibration error (ECE)" note="How closely its confidence matches reality. Lower is better." />
                <Stat value={asPercent(url.test.false_positive_rate)} label="False positives on the test split" note="Legitimate sites wrongly flagged, on domains it never trained on." />
                {typeof legitFpr === "number" && <Stat value={asPercent(legitFpr)} label="False positives on real subdomains" note="Genuine login and service subdomains wrongly flagged." />}
              </div>
              <p className="mt-6 text-xs text-ink-3">{url.model}</p>
            </Card>
          )}

          <Card title="known.limits">
            <h2 className="display text-[clamp(1.9rem,3.6vw,3rem)]">What the numbers don’t say.</h2>
            <div className="mt-5 grid gap-5 md:grid-cols-2">
              <TextBlock kicker="verdicts" title="Low risk doesn’t mean safe">
                New or targeted attacks can slip past automated checks. A low score means nothing significant turned up
                in the checks that ran.
              </TextBlock>
              <TextBlock kicker="links" title="Hacked sites look normal">
                A compromised legitimate site can fool a hostname model. Threat feeds, page checks and certificate
                checks cover part of that gap.
              </TextBlock>
              <TextBlock kicker="language" title="Mostly English">
                Training data is mostly English with some Hinglish, so other languages are less reliable.
              </TextBlock>
              <TextBlock kicker="experiment" title="The model we didn’t ship">
                A second fine-tune nearly removed false alarms but missed real scams this one catches. For a security
                tool that’s the wrong trade, so we kept this version.
              </TextBlock>
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
