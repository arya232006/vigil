"use client";

import { useId, useState } from "react";

const FAQ = [
  {
    q: "Does Low Risk mean a site is harmless?",
    a: "No. It means no malicious indicators were found within the checks performed. Every report lists what was checked and what could not be.",
  },
  {
    q: "Can a message talk the AI into a better score?",
    a: "Not by asking. Known injection phrasing forces High Risk at minimum, whatever the model says. A reworded attempt could still sway the model, but a harmful request the rules find keeps the message at Suspicious or above.",
  },
  {
    q: "Does a valid certificate count in a site's favour?",
    a: "Never as proof of legitimacy. A valid certificate only means the connection is encrypted.",
  },
  {
    q: "What does the blockchain record prove?",
    a: "That a report has not changed since it was anchored. It proves integrity and history, not that the conclusions are true.",
  },
  {
    q: "Where does my data go?",
    a: "The AI runs on our own infrastructure, so no third-party AI provider sees your input. Only hashes go on-chain.",
  },
  {
    q: "Do you attack or scan the sites you check?",
    a: "No. Inspection is passive: no exploitation, no intrusive scanning, no file downloads and no JavaScript execution.",
  },
];

function FaqItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();

  return (
    <div className="border-l border-dashed border-[#9a9a9a] py-5 pl-4">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((o) => !o)}
        className="code flex w-full cursor-pointer items-center justify-between gap-6 text-left text-sm sm:text-base"
      >
        {q}
        <span className="faq-sign grid h-8 w-8 shrink-0 place-items-center border border-current" data-open={open} aria-hidden>
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" className="h-4 w-4">
            <path d="m3 6 5 5 5-5" />
          </svg>
        </span>
      </button>
      <div id={panelId} className="faq-panel" data-open={open}>
        <div>
          <p className="mt-4 max-w-2xl pr-12 text-lg leading-snug text-[#cfcfcf]">{a}</p>
        </div>
      </div>
    </div>
  );
}

export function Faq() {
  return (
    <div className="max-w-3xl space-y-6">
      {FAQ.map((item) => (
        <FaqItem key={item.q} {...item} />
      ))}
    </div>
  );
}
