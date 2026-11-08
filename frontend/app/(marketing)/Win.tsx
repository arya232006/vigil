import type { ReactNode } from "react";
import { DitherPanel } from "./DitherPanel";
import type { DitherVariant } from "./ditherFields";

export function Win({
  title,
  meta,
  art,
  children,
  className = "",
}: {
  title: string;
  meta?: string;
  art?: DitherVariant;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`win ${className}`}>
      <div className="win-bar terminal">
        <span>{title}</span>
        {meta && <span>{meta}</span>}
      </div>
      {art && <DitherPanel variant={art} className="h-32 bg-[#c4c4c4]" />}
      <div className="terminal p-3 text-lg leading-snug">{children}</div>
    </div>
  );
}
