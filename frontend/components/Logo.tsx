/** Vigil mark: a folded ribbon V keeping watch over a block of evidence. */
export function LogoMark({ className = "h-5 w-5" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinejoin="miter" className={className} aria-hidden>
      {/* One path, so the crossing strokes don't double up when the colour is translucent. */}
      <path d="M3 5h8l9 24h-8ZM15.4 16.7 21 5h8L18.9 26" />
      <path d="M15.9 3.6 18.7 7l-2.8 3.4L13.1 7Z" fill="currentColor" stroke="none" />
    </svg>
  );
}

export function Logo({ className = "" }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-[0.35em] ${className}`}>
      <LogoMark className="h-[1.05em] w-[1.05em]" />
      <span>Vigil</span>
    </span>
  );
}
