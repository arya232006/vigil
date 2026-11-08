export type DitherVariant = "checks" | "explains" | "limits" | "tls" | "lexical" | "redirect" | "intel" | "email" | "tactics" | "ramp" | "terrain";

/** Returns how much ink a point should get (0-1). `u` and `v` are 0-1 across the panel; `aspect` is width / height. */
type Field = (u: number, v: number, aspect: number, t: number) => number;

const TAU = Math.PI * 2;

function buildBayer(size: number): number[][] {
  if (size === 1) return [[0]];
  const half = buildBayer(size / 2);
  return Array.from({ length: size }, (_, y) =>
    Array.from({ length: size }, (_, x) => {
      const cell = half[y % (size / 2)][x % (size / 2)];
      const quadrant = [[0, 2], [3, 1]][y < size / 2 ? 0 : 1][x < size / 2 ? 0 : 1];
      return 4 * cell + quadrant;
    }),
  );
}

export const BAYER = buildBayer(8);

const fract = (x: number) => x - Math.floor(x);
const hash = (x: number, y: number) => fract(Math.sin(x * 127.1 + y * 311.7) * 43758.5453);
const smoothstep = (a: number, b: number, x: number) => {
  const k = Math.min(1, Math.max(0, (x - a) / (b - a)));
  return k * k * (3 - 2 * k);
};

function noise(x: number, y: number): number {
  const [ix, iy] = [Math.floor(x), Math.floor(y)];
  const [fx, fy] = [smoothstep(0, 1, x - ix), smoothstep(0, 1, y - iy)];
  const top = hash(ix, iy) * (1 - fx) + hash(ix + 1, iy) * fx;
  const bottom = hash(ix, iy + 1) * (1 - fx) + hash(ix + 1, iy + 1) * fx;
  return top * (1 - fy) + bottom * fy;
}

/** Signed distance to a box centred on the origin. */
function boxDistance(x: number, y: number, halfWidth: number, halfHeight: number): number {
  const dx = Math.abs(x) - halfWidth;
  const dy = Math.abs(y) - halfHeight;
  return Math.hypot(Math.max(dx, 0), Math.max(dy, 0)) + Math.min(Math.max(dx, dy), 0);
}

function segmentDistance(px: number, py: number, ax: number, ay: number, bx: number, by: number): number {
  const [dx, dy] = [bx - ax, by - ay];
  const k = Math.min(1, Math.max(0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(px - ax - dx * k, py - ay - dy * k);
}

const BLIPS = [[-0.55, -0.3], [0.5, 0.38], [0.95, -0.42], [-1.1, 0.42], [0.18, -0.62]];

/** A radar sweep: every indicator is found by a systematic pass, not by a guess. */
const checks: Field = (u, v, aspect, t) => {
  const x = (u - 0.5) * aspect * 2;
  const y = (v - 0.5) * 2;
  const sweep = t * 1.1;
  const trail = (angle: number) => 1 - fract((sweep - angle) / TAU);
  const r = Math.hypot(x, y);
  let ink = trail(Math.atan2(y, x)) ** 3 * 0.62 * smoothstep(1.9, 0.2, r);
  ink += 0.42 * smoothstep(0.42, 0.47, Math.abs(fract(r * 2.2) - 0.5));
  for (const [bx, by] of BLIPS) {
    const distance = Math.hypot(x - bx, y - by);
    ink += smoothstep(0.17, 0.04, distance) * trail(Math.atan2(by, bx)) ** 2 * 1.2;
  }
  return ink;
};

/** Unstructured noise resolves into lines of text as a reading front passes across it. */
const explains: Field = (u, v, aspect, t) => {
  const cycle = fract(t / 7);
  const front = smoothstep(0.05, 0.75, cycle) * 1.3 - smoothstep(0.9, 1, cycle) * 1.3;
  const rows = v * 6.5;
  const row = Math.floor(rows);
  const onLine = smoothstep(0.62, 0.55, fract(rows)) * smoothstep(0.12, 0.2, fract(rows));
  const word = hash(row, Math.floor(u * aspect * 3.2)) > 0.26 ? 1 : 0;
  const lineEnd = 0.55 + hash(row, 9) * 0.42;
  const text = onLine * word * (u < lineEnd ? 0.95 : 0);
  const cloud = noise(u * aspect * 3 + t * 0.35, v * 3 - t * 0.25) * 0.55 + noise(u * aspect * 8, v * 8 + t * 0.6) * 0.35 - 0.12;
  const reveal = smoothstep(front + 0.1, front - 0.1, u);
  return text * reveal + cloud * (1 - reveal);
};

const BARS = [0.92, 0.74, 0.86, 0, 0.58];
const UNAVAILABLE_BAR = 3;

/** Evidence bars fill and fade out where the evidence stops; the check that could not run stays visibly empty. */
const limits: Field = (u, v, _aspect, t) => {
  const rows = v * BARS.length;
  const bar = Math.floor(rows);
  const inside = fract(rows);
  if (inside < 0.2 || inside > 0.8 || bar >= BARS.length) return 0;
  if (bar === UNAVAILABLE_BAR) {
    const stripe = fract((u * 40 + rows * 2) / 2) < 0.5 ? 1 : 0;
    return stripe * (0.42 + 0.3 * Math.sin(t * 3));
  }
  const cycle = fract(t / 7);
  const delay = bar * 0.05;
  const growth = smoothstep(delay, delay + 0.45, cycle) * (1 - smoothstep(0.92, 1, cycle));
  const end = BARS[bar] * growth;
  return 0.1 + 0.9 * smoothstep(end, end - 0.18, u);
};

/** A validation pulse travels down a certificate chain: leaf, intermediate, root. */
const tls: Field = (u, v, aspect, t) => {
  const x = (u - 0.5) * 2 * aspect;
  const y = (v - 0.5) * 2;
  const spacing = aspect * 0.62;
  const halfWidth = aspect * 0.2;
  const pulse = (fract(t / 3.2) * 2.4 - 1.2) * aspect;
  let ink = 0;
  for (const centre of [-spacing, 0, spacing]) {
    const distance = boxDistance(x - centre, y, halfWidth, 0.62);
    if (distance < 0) ink = 0.14 + 0.8 * smoothstep(aspect * 0.35, 0, Math.abs(x - pulse));
    if (Math.abs(distance) < 0.08) return 1;
  }
  if (ink === 0 && Math.abs(y) < 0.09 && Math.abs(x) < spacing + halfWidth) return 0.7;
  return ink;
};

const GLYPHS = 12;
const LOOKALIKE_GLYPH = 7;

/** A scanner reads a hostname glyph by glyph and catches the character that is not what it seems. */
const lexical: Field = (u, v, _aspect, t) => {
  const glyph = Math.floor(u * GLYPHS);
  const cu = fract(u * GLYPHS);
  const scan = fract(t / 4);
  const band = 0.34 * smoothstep(0.07, 0, Math.abs(u - scan));
  if (v < 0.18 || v > 0.82) return band * 0.5;
  const caught = glyph === LOOKALIKE_GLYPH && scan > (LOOKALIKE_GLYPH + 0.5) / GLYPHS;
  const seed = caught ? 50 + (Math.floor(t * 5) % 2) : glyph;
  const column = Math.floor(((cu - 0.14) / 0.72) * 4);
  const row = Math.floor(((v - 0.18) / 0.64) * 6);
  const on = cu > 0.14 && cu < 0.86 && hash(seed, column * 7 + row) > 0.42;
  if (caught) return on ? 0 : 1;
  return on ? 0.95 : band;
};

const HOPS = [[-0.86, 0.5], [-0.42, -0.5], [0.04, 0.5], [0.48, -0.5], [0.88, 0.2]];

/** A signal hops down a redirect path, node by node, to the final destination. */
const redirect: Field = (u, v, aspect, t) => {
  const x = (u - 0.5) * 2 * aspect;
  const y = (v - 0.5) * 2;
  const points = HOPS.map(([hx, hy]) => [hx * aspect, hy]);
  const progress = fract(t / 4.5) * (points.length - 1);
  const leg = Math.floor(progress);
  const k = progress - leg;
  const signalX = points[leg][0] + (points[leg + 1][0] - points[leg][0]) * k;
  const signalY = points[leg][1] + (points[leg + 1][1] - points[leg][1]) * k;
  let ink = smoothstep(0.42, 0, Math.hypot(x - signalX, y - signalY)) * 0.9;
  for (let i = 0; i < points.length - 1; i++) {
    const distance = segmentDistance(x, y, points[i][0], points[i][1], points[i + 1][0], points[i + 1][1]);
    if (distance < 0.06 && fract((x + y) * 2.4) < 0.62) ink = Math.max(ink, 0.85);
  }
  points.forEach(([px, py], i) => {
    const distance = Math.hypot(x - px, y - py);
    if (distance < 0.17) ink = 1;
    else if (i === points.length - 1 && Math.abs(distance - 0.34) < 0.05) ink = Math.max(ink, 0.6);
  });
  return ink;
};

const FEED_COLUMNS = 22;

/** Threat feeds stream past; a column flashes solid when an indicator matches. */
const intel: Field = (u, v, _aspect, t) => {
  const column = Math.floor(u * FEED_COLUMNS);
  if (fract(u * FEED_COLUMNS) > 0.72) return 0;
  const speed = 0.35 + hash(column, 1) * 0.5;
  const stream = fract(v * 1.4 - t * speed - hash(column, 2)) ** 3 * 0.85;
  const beat = t / 1.5;
  const hit = Math.floor(fract(Math.floor(beat) * 0.618) * FEED_COLUMNS);
  return column === hit ? Math.max(stream, 1 - fract(beat)) : stream;
};

/** An envelope is scanned while its SPF, DKIM and DMARC results fill in. */
const email: Field = (u, v, aspect, t) => {
  const x = (u - 0.5) * 2 * aspect;
  const y = (v - 0.5) * 2;
  const centre = -aspect * 0.46;
  const halfWidth = Math.min(aspect * 0.42, 1.35);
  const halfHeight = 0.72;
  const distance = boxDistance(x - centre, y, halfWidth, halfHeight);
  if (Math.abs(distance) < 0.08) return 1;
  if (distance < 0) {
    const onFlap = Math.min(
      segmentDistance(x, y, centre - halfWidth, -halfHeight, centre, 0.14),
      segmentDistance(x, y, centre + halfWidth, -halfHeight, centre, 0.14),
    );
    if (onFlap < 0.07) return 1;
    const scan = centre + (fract(t / 3.5) * 2 - 1) * halfWidth * 1.1;
    return 0.6 * smoothstep(0.55, 0, Math.abs(x - scan));
  }
  const left = aspect * 0.12;
  const right = aspect * 0.92;
  if (x < left || x > right) return 0;
  const cycle = fract(t / 5);
  for (let i = 0; i < 3; i++) {
    if (Math.abs(y - (-0.56 + i * 0.56)) < 0.17) {
      const fill = smoothstep(i * 0.22, i * 0.22 + 0.25, cycle) * (1 - smoothstep(0.92, 1, cycle));
      return x < left + (right - left) * fill ? 1 : 0.12;
    }
  }
  return 0;
};

const WAVE_BARS = 44;
const FLAGGED_PHRASES = [[6, 12], [21, 26], [34, 40]];

/** A message as a waveform: ordinary words stay low, the manipulative phrases spike. */
const tactics: Field = (u, v, _aspect, t) => {
  if (fract(u * WAVE_BARS) > 0.62) return 0;
  const bar = Math.floor(u * WAVE_BARS);
  const flagged = FLAGGED_PHRASES.some(([from, to]) => bar >= from && bar <= to);
  const height = 0.16 + 0.22 * noise(bar * 0.3, t * 0.9) + (flagged ? 0.52 * (0.6 + 0.4 * Math.sin(t * 4 + bar)) : 0);
  if (Math.abs(v - 0.5) * 2 > height) return 0;
  return flagged ? 1 : 0.48;
};

/** A plain left-to-right ramp, used behind the risk meter. */
const ramp: Field = (u) => u;

/** A slowly drifting contour map: the landscape the pipeline is surveying. */
const terrain: Field = (u, v, aspect, t) => {
  const height = noise(u * aspect * 2.1 + t * 0.05, v * 2.1 - t * 0.035) * 0.75 + noise(u * aspect * 5, v * 5 + t * 0.05) * 0.25;
  const contour = fract(height * 11) < 0.24 ? 0.85 : 0;
  return Math.max(contour, 0.07 + 0.42 * smoothstep(0.5, 0.8, height));
};

export const FIELDS: Record<DitherVariant, { field: Field; stillAt: number }> = {
  checks: { field: checks, stillAt: 1.4 },
  explains: { field: explains, stillAt: 3.2 },
  limits: { field: limits, stillAt: 3.6 },
  tls: { field: tls, stillAt: 1.6 },
  lexical: { field: lexical, stillAt: 3.2 },
  redirect: { field: redirect, stillAt: 2.2 },
  intel: { field: intel, stillAt: 3.1 },
  email: { field: email, stillAt: 2.6 },
  tactics: { field: tactics, stillAt: 1.5 },
  ramp: { field: ramp, stillAt: 0 },
  terrain: { field: terrain, stillAt: 2 },
};
