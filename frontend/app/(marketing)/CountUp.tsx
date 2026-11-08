"use client";

import { useEffect, useRef } from "react";

const DURATION_MS = 1500;

/** Counts from zero to `value` the first time it scrolls into view. */
export function CountUp({ value, decimals = 1, suffix = "%" }: { value: number; decimals?: number; suffix?: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  const final = `${value.toFixed(decimals)}${suffix}`;

  useEffect(() => {
    const el = ref.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    let raf = 0;
    el.textContent = `${(0).toFixed(decimals)}${suffix}`;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        observer.disconnect();
        const start = performance.now();
        const step = (now: number) => {
          const progress = Math.min(1, (now - start) / DURATION_MS);
          const eased = 1 - (1 - progress) ** 3;
          el.textContent = `${(value * eased).toFixed(decimals)}${suffix}`;
          if (progress < 1) raf = requestAnimationFrame(step);
        };
        raf = requestAnimationFrame(step);
      },
      { threshold: 0.5 },
    );
    observer.observe(el);

    return () => {
      observer.disconnect();
      cancelAnimationFrame(raf);
    };
  }, [value, decimals, suffix]);

  // The transparent copy reserves the final width, so nearby text never shifts, and is what screen readers read.
  return (
    <span className="inline-grid justify-items-start tabular-nums">
      <span className="opacity-0 [grid-area:1/1]">{final}</span>
      <span ref={ref} className="[grid-area:1/1]" aria-hidden>
        {final}
      </span>
    </span>
  );
}
