import Link from "next/link";
import { AccountControls } from "@/components/AccountControls";
import { Logo, LogoMark } from "@/components/Logo";
import { CountUp } from "./CountUp";
import { DitherPanel } from "./DitherPanel";
import type { DitherVariant } from "./ditherFields";
import { Faq } from "./Faq";
import { InjectionSection } from "./InjectionDemo";
import { PipelineDesktop } from "./PipelineDesktop";
import { FieldNotes } from "./FieldNotes";
import { Win } from "./Win";
import { WhyEvidence } from "./WhyEvidence";
import { Wireframe } from "./Wireframe";

const SAMPLE_REPORT_HASH = "0x73716238f1e6b3372e858c8b685e219fead41fbb54861b68cb936a1532640ecf";

const NAV = [
  { href: "/investigate", label: "Investigate" },
  { href: "/history", label: "History" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/models", label: "Our AI" },
];

const CHECKS: { name: string; art: DitherVariant; text: string }[] = [
  { name: "tls.inspect", art: "tls", text: "Expiry, hostname match, key size, chain, revocation, distrusted CAs." },
  { name: "url.lexical", art: "lexical", text: "Homoglyphs, punycode, brand lookalikes, suspicious hosts." },
  { name: "redirect.trace", art: "redirect", text: "Every hop recorded, with SSRF protection re-checked at each one." },
  { name: "intel.match", art: "intel", text: "Live phishing feeds. A hit is confirmed, not guessed." },
  { name: "email.auth", art: "email", text: "SPF, DKIM, DMARC, spoofed senders, deceptive links, risky attachments." },
  { name: "msg.tactics", art: "tactics", text: "Urgency, OTP requests, KYC threats, remote-access lures, quoted exactly." },
];

function Corners() {
  return (
    <span className="corners pointer-events-none absolute inset-0" aria-hidden>
      <i />
      <i />
      <i />
      <i />
    </span>
  );
}

function BrandBlock() {
  const ink = "text-[rgb(30_30_30/0.86)]";
  return (
    <div className={`mt-28 ${ink}`}>
      <div className="relative flex justify-center px-4 py-16 sm:py-24">
        <Corners />
        <div className="display flex items-center gap-[0.25em] text-[clamp(2.8rem,9.5vw,8.25rem)]">
          <LogoMark className="h-[0.95em] w-[0.95em] shrink-0" />
          <span>Vigil</span>
        </div>
      </div>
      <div className="relative flex flex-col items-center gap-x-10 gap-y-6 px-4 py-16 text-center text-[clamp(2rem,5vw,4.5rem)] sm:flex-row sm:flex-wrap sm:justify-between sm:py-20 sm:text-left">
        <Corners />
        <p className="display">Spotted Something?</p>
        <div className="flex items-center gap-6 sm:gap-10">
          <svg viewBox="0 0 54 24" fill="currentColor" className="h-[0.6em] shrink-0" aria-hidden>
            <path d="M0 0v24l18-12zM18 0v24l18-12zM36 0v24l18-12z" />
          </svg>
          <Link href="/investigate" className="display underline underline-offset-[0.12em]">Investigate</Link>
        </div>
      </div>
    </div>
  );
}

function Stat({ value, label }: { value: number; label: string }) {
  return (
    <div>
      <p className="display text-5xl"><CountUp value={value} /></p>
      <p className="mt-2 text-base">{label}</p>
    </div>
  );
}

const wrap = "mx-auto w-full max-w-[1320px] px-4 sm:px-8";

export default function LandingPage() {
  return (
    <>
      <div className="relative">
        <svg width="0" height="0" className="absolute" aria-hidden>
          <filter id="clouds" x="0" y="0" width="100%" height="100%">
            <feTurbulence type="fractalNoise" baseFrequency="0.007" numOctaves="4" seed="11" />
            <feDisplacementMap in="SourceGraphic" scale="170" xChannelSelector="R" yChannelSelector="G" />
          </filter>
        </svg>
        <div className="hero-sky" aria-hidden>
          <div className="hero-clouds" />
        </div>

        <nav className="relative flex flex-wrap items-start justify-between gap-1.5 lg:grid lg:grid-cols-[1fr_auto_1fr]">
          <Link href="/" className="tile lg:justify-self-start"><Logo /></Link>
          <div className="order-last flex w-full flex-wrap gap-1.5 sm:order-none sm:w-auto">
            {NAV.slice(1).map(({ href, label }) => (
              <Link key={href} href={href} className="tile">{label}</Link>
            ))}
          </div>
          <div className="flex items-center gap-1.5 lg:justify-self-end">
            <AccountControls />
            <Link href="/investigate" className="tile tile-dark">Investigate</Link>
          </div>
        </nav>

        <header className={`${wrap} relative pt-14 pb-24 text-center sm:pt-20`}>
          <div className="win mx-auto max-w-md">
            <div className="win-bar terminal"><span>vigil.notice</span><span>v1.0</span></div>
            <p className="terminal px-4 py-3 text-xl leading-snug">
              Got a strange link or message?
              <br />
              <Link href="/investigate" className="underline">Check it now</Link>
            </p>
          </div>
          <p className="mt-14 text-lg">Links · Domains · Messages · Emails</p>
          <h1 className="display mx-auto mt-8 max-w-[1100px] text-[clamp(3.4rem,11vw,10rem)]">
            Every Verdict Comes With Evidence
          </h1>
          <div className="mt-12 flex flex-wrap justify-center gap-x-12 gap-y-4 text-2xl font-medium tracking-tight sm:text-3xl">
            <Link href="/investigate" className="underline underline-offset-4">Start Investigating</Link>
            <Link href="/models" className="underline underline-offset-4">Meet Our AI</Link>
          </div>
        </header>
      </div>

      <section className="bg-(--l-pink) py-16 sm:py-24">
        <div className={wrap}>
          <PipelineDesktop />

          <h2 className="display mx-auto mt-20 max-w-5xl text-center text-[clamp(2.8rem,8vw,7rem)]">
            The AI Is A Witness, Not The Judge
          </h2>

          <WhyEvidence />

          <div className="grid gap-10 text-lg leading-snug md:grid-cols-3">
            <div>
              <DitherPanel variant="checks" />
              <h3 className="terminal mt-5 text-xl">Checks Decide</h3>
              <p className="mt-3">
                Deterministic checks produce the evidence and a rule engine turns it into a risk level. The result is the
                same no matter how a scam is worded.
              </p>
            </div>
            <div>
              <DitherPanel variant="explains" />
              <h3 className="terminal mt-5 text-xl">AI Explains</h3>
              <p className="mt-3">
                Our self-hosted model turns findings into plain language. Every quote and citation it produces is verified
                against the input.
              </p>
            </div>
            <div>
              <DitherPanel variant="limits" />
              <h3 className="terminal mt-5 text-xl">Limits Are Listed</h3>
              <p className="mt-3">
                Unavailable checks are always reported. When the evidence runs out, the verdict is Inconclusive rather than a
                confident guess.
              </p>
            </div>
          </div>

          <h2 className="display mt-24 text-[clamp(3rem,9vw,8rem)]"><CountUp value={85.5} /> → <CountUp value={9.7} /></h2>
          <p className="mt-4 max-w-2xl text-xl">
            False alarms on legitimate messages, before and after we fine-tuned our model on a held-out test set.
          </p>
          <div className="mt-12 grid gap-8 sm:grid-cols-3">
            <Stat value={93.3} label="Scam recall on the same held-out test set" />
            <Stat value={98.7} label="Model quotes grounded in the input" />
            <Stat value={86.3} label="Live OpenPhish URLs caught by our link classifier" />
          </div>
        </div>
      </section>

      <section className="bg-(--l-pink) pb-16 sm:pb-24">
        <div className={wrap}>
          <h2 className="display max-w-4xl text-[clamp(2.6rem,6.5vw,5.5rem)]">Six Ways We Look Before We Speak</h2>
          <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {CHECKS.map((check) => (
              <Win key={check.name} title={check.name} art={check.art}>{check.text}</Win>
            ))}
          </div>

          <InjectionSection />
          <BrandBlock />
        </div>
      </section>

      <FieldNotes />

      <section className="bg-(--l-ink) py-16 text-(--l-paper) sm:py-24">
        <div className={wrap}>
          <div className="relative py-12 text-center sm:py-14">
            <Corners />
            <h2 className="display text-[clamp(2.6rem,6vw,5rem)]">Straight Answers</h2>
          </div>

          <div className="mt-14 grid gap-12 lg:grid-cols-[minmax(0,1fr)_300px] lg:gap-24">
            <Faq />

            <aside className="hidden self-end lg:block">
              <p className="code text-xs">[sha256]</p>
              <p className="code mt-4 text-xs leading-relaxed break-all">{SAMPLE_REPORT_HASH}</p>
              <p className="mt-3 text-sm text-[#b5b5b5]">A real report hash, anchored during testing.</p>
              <div className="relative mt-8 grid place-items-center py-10">
                <Corners />
                <LogoMark className="h-20 w-20" />
              </div>
            </aside>
          </div>
        </div>
      </section>

      <footer className="bg-(--l-ink) text-(--l-paper)">
        <div className="relative mx-4 flex min-h-[80vh] items-center justify-center overflow-hidden sm:mx-8">
          <Corners />
          <Wireframe />
          <div className="display relative flex items-center gap-[0.25em] text-[clamp(2.8rem,9.5vw,9rem)]">
            <LogoMark className="h-[0.95em] w-[0.95em] shrink-0" />
            <span>Vigil</span>
          </div>
          <p className="code absolute inset-x-6 bottom-4 text-center text-xs">report_hash = sha256(canonical_json) → ThreatRegistry</p>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-x-8 gap-y-3 px-4 py-7 text-lg tracking-tight sm:px-8">
          <span>Vigil © 2026</span>
          <span className="flex flex-wrap gap-x-6 gap-y-1">
            {NAV.map(({ href, label }) => (
              <Link key={href} href={href} className="hover:underline">{label}</Link>
            ))}
            <Link href="/brand" className="hover:underline">Brand</Link>
          </span>
          <span>Passive inspection only</span>
        </div>
      </footer>
    </>
  );
}
