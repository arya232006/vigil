"use client";

import { useState } from "react";

export function CopyHex({ hex }: { hex: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={`Copy ${hex}`}
      className="terminal cursor-pointer py-1 text-xl underline underline-offset-2"
      onClick={() =>
        navigator.clipboard.writeText(hex).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        })
      }
    >
      {copied ? "Copied" : hex}
    </button>
  );
}
