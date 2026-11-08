"use client";

import { useEffect, useRef } from "react";

type Vec = [number, number, number];

const CSS_PX_PER_CELL = 3;
const FRAME_MS = 50;
const SAMPLES_PER_LOOP = 720;
const TILT = 0.38;

function loop(point: (angle: number) => Vec): Vec[] {
  return Array.from({ length: SAMPLES_PER_LOOP }, (_, i) => point((i / SAMPLES_PER_LOOP) * Math.PI * 2));
}

function segment(a: Vec, b: Vec): Vec[] {
  const steps = 120;
  return Array.from({ length: steps }, (_, i) => {
    const t = i / steps;
    return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
  });
}

/** A globe (the scope) around an octahedron (the block of evidence in the Vigil mark). */
function buildShape(): Vec[][] {
  const lines: Vec[][] = [];
  for (const degrees of [-60, -30, 0, 30, 60]) {
    const lat = (degrees * Math.PI) / 180;
    lines.push(loop((a) => [Math.cos(lat) * Math.cos(a), Math.sin(lat), Math.cos(lat) * Math.sin(a)]));
  }
  for (let k = 0; k < 6; k++) {
    const lon = (k * Math.PI) / 6;
    lines.push(loop((a) => [Math.cos(a) * Math.cos(lon), Math.sin(a), Math.cos(a) * Math.sin(lon)]));
  }
  const r = 0.42;
  const top: Vec = [0, r, 0];
  const bottom: Vec = [0, -r, 0];
  const waist: Vec[] = [[r, 0, 0], [0, 0, r], [-r, 0, 0], [0, 0, -r]];
  waist.forEach((corner, i) => {
    lines.push(segment(top, corner), segment(bottom, corner), segment(corner, waist[(i + 1) % 4]));
  });
  return lines;
}

const SHAPE = buildShape();

export function Wireframe() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let frame = 0;
    let lastDraw = 0;
    let angle = 0.6;

    const draw = () => {
      const { width, height } = canvas;
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = "#fff";
      const radius = Math.min(width, height) * 0.35;
      const [cosY, sinY, cosX, sinX] = [Math.cos(angle), Math.sin(angle), Math.cos(TILT), Math.sin(TILT)];
      for (const line of SHAPE) {
        line.forEach(([x, y, z], i) => {
          if (Math.floor(i / 14) % 3 === 0) return;
          const rx = x * cosY + z * sinY;
          const rz = -x * sinY + z * cosY;
          const ry = y * cosX - rz * sinX;
          const depth = y * sinX + rz * cosX;
          const perspective = 1 / (1 + depth * 0.22);
          ctx.globalAlpha = 0.28 + 0.6 * ((1 - depth) / 2);
          ctx.fillRect(Math.round(width / 2 + rx * radius * perspective), Math.round(height / 2 - ry * radius * perspective), 1, 1);
        });
      }
    };

    const tick = (now: number) => {
      frame = requestAnimationFrame(tick);
      if (now - lastDraw < FRAME_MS) return;
      lastDraw = now;
      angle += 0.012;
      draw();
    };

    const resize = new ResizeObserver(() => {
      canvas.width = Math.ceil(canvas.clientWidth / CSS_PX_PER_CELL);
      canvas.height = Math.ceil(canvas.clientHeight / CSS_PX_PER_CELL);
      draw();
    });
    resize.observe(canvas);

    // Animates only while on screen.
    const visibility = new IntersectionObserver(([entry]) => {
      cancelAnimationFrame(frame);
      if (entry.isIntersecting && !reduceMotion) frame = requestAnimationFrame(tick);
    });
    visibility.observe(canvas);

    return () => {
      cancelAnimationFrame(frame);
      resize.disconnect();
      visibility.disconnect();
    };
  }, []);

  return <canvas ref={ref} className="absolute inset-0 h-full w-full opacity-40 [image-rendering:pixelated] sm:opacity-100" aria-hidden />;
}
