"use client";

import { useEffect, useRef } from "react";
import { BAYER, FIELDS, type DitherVariant } from "./ditherFields";

const CSS_PX_PER_CELL = 3;
const FRAME_MS = 66;
const INK = [30, 30, 30];

export function DitherPanel({
  variant,
  className = "h-44 bg-[#df7b93]",
  frameMs = FRAME_MS,
}: {
  variant: DitherVariant;
  className?: string;
  frameMs?: number;
}) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    const { field, stillAt } = FIELDS[variant];
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0;
    let lastDraw = 0;

    const draw = (t: number) => {
      const { width, height } = canvas;
      if (!width || !height) return;
      const image = ctx.createImageData(width, height);
      const aspect = width / height;
      for (let y = 0; y < height; y++) {
        for (let x = 0; x < width; x++) {
          const threshold = (BAYER[y % 8][x % 8] + 0.5) / 64;
          if (field(x / width, y / height, aspect, t) <= threshold) continue;
          const i = (y * width + x) * 4;
          image.data[i] = INK[0];
          image.data[i + 1] = INK[1];
          image.data[i + 2] = INK[2];
          image.data[i + 3] = 255;
        }
      }
      ctx.putImageData(image, 0, 0);
    };

    const tick = (now: number) => {
      raf = requestAnimationFrame(tick);
      if (now - lastDraw < frameMs) return;
      lastDraw = now;
      draw(now / 1000);
    };

    const resize = new ResizeObserver(() => {
      canvas.width = Math.ceil(canvas.clientWidth / CSS_PX_PER_CELL);
      canvas.height = Math.ceil(canvas.clientHeight / CSS_PX_PER_CELL);
      draw(reduceMotion ? stillAt : performance.now() / 1000);
    });
    resize.observe(canvas);

    // Animates only while on screen.
    const visibility = new IntersectionObserver(([entry]) => {
      cancelAnimationFrame(raf);
      if (entry.isIntersecting && !reduceMotion) raf = requestAnimationFrame(tick);
    });
    visibility.observe(canvas);

    return () => {
      cancelAnimationFrame(raf);
      resize.disconnect();
      visibility.disconnect();
    };
  }, [variant, frameMs]);

  return <canvas ref={ref} className={`block w-full [image-rendering:pixelated] ${className}`} aria-hidden />;
}
