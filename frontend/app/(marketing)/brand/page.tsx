import type { Metadata } from "next";
import Image from "next/image";
import Link from "next/link";
import { TopBar } from "../TopBar";
import { CopyHex } from "./CopyHex";

export const metadata: Metadata = {
  title: "Brand Assets · Vigil",
  description: "Download the Vigil logo, and find its colours, typefaces and usage guidelines.",
};

const LOGOS = [
  { file: "vigil-wordmark", label: "wordmark", name: "Vigil wordmark", width: 2842, height: 1055, size: "h-16 sm:h-20" },
  { file: "vigil-mark", label: "mark", name: "Vigil mark", width: 32, height: 32, size: "h-20 sm:h-24" },
];

const VARIANTS = [
  { name: "ink", use: "for light backgrounds", background: "bg-(--l-paper)" },
  { name: "paper", use: "for dark backgrounds", background: "bg-(--l-ink)" },
  { name: "pink", use: "for dark backgrounds", background: "bg-(--l-ink)" },
];

type Colour = { name: string; hex: string; use: string; text: string };

const INK = "#1E1E1E";
const PAPER = "#FEFEFE";

const CORE: Colour[] = [
  { name: "Pink", hex: "#F386A1", use: "Main brand background", text: INK },
  { name: "Ink", hex: INK, use: "Text, title bars, dark sections", text: PAPER },
  { name: "Paper", hex: PAPER, use: "Tiles and text on ink", text: INK },
  { name: "Grey", hex: "#DEDEDE", use: "Window fill", text: INK },
  { name: "Green", hex: "#44C086", use: "Feature sections", text: INK },
];

const RISK: Colour[] = [
  { name: "Critical", hex: "#7F1416", use: "Confirmed malicious", text: PAPER },
  { name: "High", hex: "#C0272D", use: "High risk", text: PAPER },
  { name: "Warning", hex: "#A85A06", use: "Suspicious", text: PAPER },
  { name: "Minor", hex: "#7A6A06", use: "Minor findings", text: PAPER },
  { name: "OK", hex: "#1A7A42", use: "Low risk", text: PAPER },
  { name: "None", hex: "#5A6069", use: "Inconclusive", text: PAPER },
];

const DOS = [
  "Write the name as “Vigil”, with a capital V only.",
  "Keep clear space of at least half the mark’s height on every side.",
  "Use the ink logo on light backgrounds, and paper or pink on dark ones.",
  "Keep the mark at least 16 px tall and the wordmark at least 80 px wide.",
];

const DONTS = [
  "Stretch, rotate, outline or add effects to the logo.",
  "Recolour the logo outside the palette above.",
  "Place the logo on busy images where it is hard to read.",
  "Imply that Vigil endorses your product, service or findings.",
];

const wrap = "mx-auto w-full max-w-[1320px] px-4 sm:px-8";
const heading = "display text-[clamp(2.4rem,6vw,4.5rem)]";

function Section({ title, intro, children }: { title: string; intro?: string; children: React.ReactNode }) {
  return (
    <section className="mt-20 sm:mt-28">
      <h2 className={heading}>{title}</h2>
      {intro && <p className="mt-4 max-w-2xl text-xl leading-snug">{intro}</p>}
      <div className="mt-10">{children}</div>
    </section>
  );
}

function Swatch({ colour }: { colour: Colour }) {
  return (
    <div className="win flex min-w-0 flex-col">
      <div className="flex h-36 flex-col justify-between p-3" style={{ background: colour.hex, color: colour.text }}>
        <span className="text-xl font-medium tracking-tight">{colour.name}</span>
        <span><CopyHex hex={colour.hex} /></span>
      </div>
      <p className="terminal px-3 py-2 text-lg leading-tight">{colour.use}</p>
    </div>
  );
}

function Typeface({ name, role, href, children }: { name: string; role: string; href: string; children: React.ReactNode }) {
  return (
    <div className="win min-w-0">
      <div className="win-bar terminal">
        <h3>{name}</h3>
        <a href={href} target="_blank" rel="noreferrer" className="-my-0.5 inline-block py-0.5 underline">Google Fonts</a>
      </div>
      <div className="p-5">
        {children}
        <p className="mt-5 text-lg leading-snug">{role}</p>
      </div>
    </div>
  );
}

function Rules({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="win min-w-0">
      <div className="win-bar terminal"><h3>{title}</h3></div>
      <ul className="space-y-3 p-5 text-lg leading-snug">
        {items.map((item) => <li key={item}>{item}</li>)}
      </ul>
    </div>
  );
}

export default function BrandPage() {
  return (
    <div className="bg-(--l-pink)">
      <TopBar />

      <main className={`${wrap} pt-16 pb-24 sm:pt-24`}>
        <p className="terminal text-xl">vg.brand</p>
        <h1 className="display mt-4 text-[clamp(3.4rem,11vw,10rem)]">Brand Assets</h1>
        <p className="mt-8 max-w-2xl text-2xl leading-snug tracking-tight">
          The Vigil logo, colours and typefaces, for anyone writing about, presenting or linking to the project.
        </p>
        <a href="/brand/vigil-brand-kit.zip" download className="tile tile-dark mt-8 inline-block">Download all logos (ZIP)</a>

        <Section title="Logo" intro="Vector SVG for anything that can use it. Transparent PNG for everything else.">
          <div className="space-y-5">
            {LOGOS.map((logo) => (
              <div key={logo.file} className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
                {VARIANTS.map((variant) => {
                  const path = `/brand/${logo.file}-${variant.name}`;
                  return (
                    <div key={variant.name} className="win min-w-0">
                      <div className="win-bar terminal">
                        <h3>{`${logo.label}.${variant.name}`}</h3>
                        <span>{variant.use}</span>
                      </div>
                      <div className={`grid h-48 place-items-center px-6 ${variant.background}`}>
                        <Image
                          src={`${path}.svg`}
                          alt={`${logo.name}, ${variant.name}`}
                          width={logo.width}
                          height={logo.height}
                          unoptimized
                          className={`${logo.size} w-auto max-w-full`}
                        />
                      </div>
                      <div className="terminal flex gap-5 px-3 py-1.5 text-xl">
                        <a href={`${path}.svg`} download className="py-0.5 underline underline-offset-2">SVG</a>
                        <a href={`${path}.png`} download className="py-0.5 underline underline-offset-2">PNG</a>
                      </div>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </Section>

        <Section title="Colour" intro="Select a value to copy it.">
          <div className="grid grid-cols-1 gap-5 min-[420px]:grid-cols-2 md:grid-cols-3 lg:grid-cols-5">
            {CORE.map((colour) => <Swatch key={colour.hex} colour={colour} />)}
          </div>
          <h3 className="terminal mt-14 text-2xl">Risk levels</h3>
          <p className="mt-2 max-w-2xl text-lg leading-snug">These carry meaning in reports, so use them only to show a risk level.</p>
          <div className="mt-6 grid grid-cols-1 gap-5 min-[420px]:grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
            {RISK.map((colour) => <Swatch key={colour.hex} colour={colour} />)}
          </div>
        </Section>

        <Section title="Type">
          <div className="grid gap-5 lg:grid-cols-3">
            <Typeface name="Inter Tight" href="https://fonts.google.com/specimen/Inter+Tight" role="Headlines and body text. Medium weight, with headlines tightly spaced (−4.5%).">
              <p className="display text-5xl">Every Verdict Comes With Evidence</p>
            </Typeface>
            <Typeface name="VT323" href="https://fonts.google.com/specimen/VT323" role="Window titles, labels and short status text.">
              <p className="terminal text-4xl leading-none">reports.log<br />30 shown</p>
            </Typeface>
            <Typeface name="JetBrains Mono" href="https://fonts.google.com/specimen/JetBrains+Mono" role="Hashes, code and evidence.">
              <p className="code text-sm leading-relaxed break-all">report_hash = sha256(canonical_json)</p>
            </Typeface>
          </div>
        </Section>

        <Section title="Usage">
          <div className="grid gap-5 md:grid-cols-2">
            <Rules title="do" items={DOS} />
            <Rules title="don't" items={DONTS} />
          </div>
        </Section>
      </main>

      <footer className="flex flex-wrap items-center justify-between gap-x-8 gap-y-3 bg-(--l-ink) px-4 py-7 text-lg tracking-tight text-(--l-paper) sm:px-8">
        <span>Vigil © 2026</span>
        <Link href="/" className="hover:underline">Back to home</Link>
      </footer>
    </div>
  );
}
