/**
 * Aegis mark: a hex-shield outline with a precise crossed-lattice interior.
 * Chosen deliberately — a lattice crossed out suggests "we are NOT lattice-based"
 * (one of the core protocol claims after Vitalik's 2026-10-07 lattice warning).
 */
export default function ShieldMark({ size = 24, title = "Aegis" }: { size?: number; title?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-label={title}
      role="img"
    >
      <title>{title}</title>
      {/* outer shield */}
      <path
        d="M12 1.5 L21 5.2 V12 C21 17 17.2 20.6 12 22.5 C6.8 20.6 3 17 3 12 V5.2 L12 1.5 Z"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinejoin="round"
      />
      {/* interior lattice: 3 vertical + 3 horizontal lines, lightly */}
      <g stroke="currentColor" strokeWidth="0.6" opacity="0.45">
        <line x1="8"  y1="7.5" x2="8"  y2="17.5" />
        <line x1="12" y1="6.5" x2="12" y2="18.5" />
        <line x1="16" y1="7.5" x2="16" y2="17.5" />
        <line x1="5.5" y1="10"  x2="18.5" y2="10"  />
        <line x1="5"   y1="13"  x2="19"   y2="13"  />
        <line x1="5.5" y1="16"  x2="18.5" y2="16"  />
      </g>
      {/* diagonal strike-through — "crossed out lattice" */}
      <line
        x1="5" y1="5" x2="19" y2="19"
        stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"
      />
    </svg>
  );
}
