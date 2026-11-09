const frame = {
  viewBox: "0 0 400 300",
  fill: "none",
  stroke: "var(--l-ink)",
  strokeWidth: 5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  className: "absolute inset-0 m-auto h-[80%] w-full",
  "aria-hidden": true,
};

const BUBBLE = "M84 50h202a14 14 0 0 1 14 14v122a14 14 0 0 1-14 14H148l-38 34v-34H84a14 14 0 0 1-14-14V64a14 14 0 0 1 14-14Z";

/** A message holding a one-time code, examined under a lens and found to be fine. */
export function InspectedMessageArt() {
  return (
    <svg {...frame}>
      <g transform="translate(-20 0)">
        <path d={BUBBLE} fill="#fbd3dd" />
        <path d="M96 78h168M96 96h104M96 176h120" />
        {[96, 128, 160, 192, 224, 256].map((x) => (
          <g key={x}>
            <rect x={x} y="112" width="24" height="36" rx="3" />
            <circle cx={x + 12} cy="130" r="4" fill="var(--l-ink)" stroke="none" />
          </g>
        ))}
        <path d="m326 234 44 44" strokeWidth="13" />
        <circle cx="292" cy="200" r="48" fill="#fdecf1" strokeWidth="6" />
        <path d="m268 201 17 18 32-38" strokeWidth="7" />
      </g>
    </svg>
  );
}

/** A database whose contents no longer match the block recorded on a chain. */
export function TamperedRecordArt() {
  return (
    <svg {...frame}>
      <path d="M50 90v120c0 17 36 30 80 30s80-13 80-30V90" fill="#fbd3dd" />
      <path d="M50 130c0 17 36 30 80 30s80-13 80-30M50 170c0 17 36 30 80 30s80-13 80-30" />
      <ellipse cx="130" cy="90" rx="80" ry="30" fill="#fdecf1" />
      <path d="M232 138h32M232 160h32M259 124l-22 50" strokeWidth="7" />
      <path d="M325 62V96M325 180v34" />
      <rect x="295" y="22" width="60" height="40" rx="5" fill="#fbd3dd" />
      <rect x="285" y="96" width="80" height="84" rx="5" fill="#fdecf1" strokeWidth="6" />
      <path d="M300 120h50M300 138h50M300 156h28" />
      <rect x="295" y="214" width="60" height="40" rx="5" fill="#fbd3dd" />
    </svg>
  );
}

/** A message with one highlighted instruction, stopped by a shield. */
export function RefusedInstructionArt() {
  return (
    <svg {...frame}>
      <g transform="translate(-20 0)">
        <path d={BUBBLE} fill="#fbd3dd" />
        <path d="M96 78h168M96 160h90M96 178h120" />
        <rect x="96" y="100" width="160" height="38" rx="3" fill="var(--l-ink)" stroke="none" />
        <path d="M110 119h132" stroke="#fdecf1" strokeWidth="6" strokeDasharray="14 10" />
        <path d="m305 118 56 20v50c0 40-26 66-56 80-30-14-56-40-56-80v-50Z" fill="#fdecf1" strokeWidth="6" />
        <path d="m284 171 42 42m0-42-42 42" strokeWidth="8" />
      </g>
    </svg>
  );
}
