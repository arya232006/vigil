import { LogoMark } from "@/components/Logo";
import { DitherPanel } from "./DitherPanel";
import { Win } from "./Win";

const STEPS = [
  { name: "extract", text: "Links, domains, UPI IDs and phone numbers are pulled from the input.", place: "xl:top-[9%] xl:left-[3%]" },
  { name: "investigate", text: "Passive checks collect evidence. Nothing on the page is ever executed.", place: "xl:top-[5%] xl:left-[22%]" },
  { name: "decide", text: "A deterministic risk engine sets the verdict from that evidence.", place: "xl:top-[3%] xl:left-[41%]" },
  { name: "explain", text: "Our self-hosted model narrates it, citing each finding.", place: "xl:top-[5%] xl:left-[60%]" },
  { name: "anchor", text: "The report's hash is written on-chain. The report itself never is.", place: "xl:top-[9%] xl:left-[79%]" },
];

// Scores observed in our own end-to-end test runs.
const VERDICTS = [
  { name: "Certificate for the wrong host", level: "HIGH RISK", score: 100 },
  { name: "Prompt-injection message", level: "HIGH RISK", score: 87 },
  { name: "Spoofed bank email", level: "HIGH RISK", score: 100 },
  { name: "github.com", level: "LOW RISK", score: 0 },
  { name: "Genuine bank OTP", level: "LOW RISK", score: 0 },
];

function VerdictTable() {
  return (
    <div className="border border-(--l-ink) bg-(--l-paper) shadow-[0_0_0_2px_var(--l-paper),0_0_0_3px_var(--l-ink)]">
      <div className="win-bar terminal"><span>risk.engine</span><span>test runs</span></div>
      <div className="terminal p-4 text-[21px] leading-none">
        <p className="inline-block bg-(--l-ink) px-2 py-1 text-[34px] text-(--l-paper)">VERDICTS</p>
        <p className="mt-2 text-xl">set by rules, from evidence</p>
        <ul className="mt-5">
          {VERDICTS.map((verdict) => (
            <li key={verdict.name} className="relative border-b border-(--l-ink) pt-3 pb-5">
              <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
                <span className="bg-(--l-ink) px-1.5 py-0.5 text-(--l-paper)">{verdict.name}</span>
                <span className="tabular-nums">{verdict.level} · {verdict.score}/100</span>
              </div>
              <span
                className="absolute bottom-0 h-3 w-3 bg-(--l-ink)"
                style={{ left: `calc(${verdict.score}% - ${(verdict.score / 100) * 12}px)` }}
                aria-hidden
              />
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function PipelineDesktop() {
  return (
    <div className="relative overflow-hidden border border-(--l-ink) bg-[#df7b93] p-4 pt-14 xl:h-[800px] xl:p-0">
      <DitherPanel variant="terrain" frameMs={200} className="absolute inset-0 h-full" />
      <p className="terminal absolute top-0 left-0 z-10 bg-(--l-ink) px-1.5 text-xl text-(--l-pink)">vg.pipeline</p>

      <div className="relative flex flex-col gap-5 xl:static xl:block">
        {STEPS.map((step, i) => (
          <Win key={step.name} title={step.name} meta={`0${i + 1}`} className={`xl:absolute xl:w-[18%] ${step.place}`}>
            {step.text}
          </Win>
        ))}

        <div className="xl:absolute xl:top-[32%] xl:right-[21%] xl:left-[21%]">
          <VerdictTable />
        </div>

        <Win title="Vigil" className="bg-(--l-pink) xl:absolute xl:bottom-[3%] xl:left-[2%] xl:w-[18%]">
          <span className="flex items-center gap-3">
            <LogoMark className="h-9 w-9 shrink-0" />
            <span>Passive inspection only. Nothing is exploited.</span>
          </span>
        </Win>

        <div className="win hidden xl:absolute xl:right-[2%] xl:bottom-[3%] xl:block xl:w-[15%]">
          <div className="win-bar terminal"><span>scan.scope</span></div>
          <DitherPanel variant="checks" className="h-28 bg-(--l-pink)" />
        </div>
      </div>
    </div>
  );
}
