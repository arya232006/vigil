"use client";

import { useEffect, useRef } from "react";
import { BAYER } from "./ditherFields";

const CSS_PX_PER_CELL = 2;

/** A flat ordered-dither texture. `density` (0-1) is how much of the area is inked. */
export function DitherFill({ density, className = "" }: { density: number; className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    const resize = new ResizeObserver(() => {
      canvas.width = Math.max(1, Math.ceil(canvas.clientWidth / CSS_PX_PER_CELL));
      canvas.height = Math.max(1, Math.ceil(canvas.clientHeight / CSS_PX_PER_CELL));
      ctx.fillStyle = "#1e1e1e";
      for (let y = 0; y < canvas.height; y++) {
        for (let x = 0; x < canvas.width; x++) {
          if (density > (BAYER[y % 8][x % 8] + 0.5) / 64) ctx.fillRect(x, y, 1, 1);
        }
      }
    });
    resize.observe(canvas);
    return () => resize.disconnect();
  }, [density]);

  return <canvas ref={ref} className={`block h-full w-full [image-rendering:pixelated] ${className}`} aria-hidden />;
}
