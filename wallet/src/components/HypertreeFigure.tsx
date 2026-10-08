// Fig. 01 — the CCHS mechanism, animated.
//
// A two-layer hypertree: one top tree whose leaves sign the roots of bottom
// subtrees; each bottom leaf signs one operation. The animation walks through
// signatures in order. The first signature of a subtree carries both layers
// (long path, top-layer nodes lit); the verifier caches that subtree's root
// (filled square); every later signature in the subtree carries only the
// bottom layer. Proportions are reduced (h = 3 instead of 10) to fit a figure.

import { useEffect, useMemo, useRef, useState } from "react";

const H = 3;                     // drawn height per layer
const LEAVES = 1 << H;           // 8 leaves per tree
const SUBTREES = 4;              // drawn bottom subtrees (of the 8 top leaves)
const W = 760, HT = 300;

type Pt = { x: number; y: number };

function treeLayout(x0: number, x1: number, yTop: number, yBottom: number): Pt[][] {
  // levels[0] = leaves (left→right), levels[H] = root
  const levels: Pt[][] = [];
  for (let k = 0; k <= H; k++) {
    const n = LEAVES >> k;
    const y = yBottom - ((yBottom - yTop) * k) / H;
    const pts: Pt[] = [];
    for (let i = 0; i < n; i++) pts.push({ x: x0 + ((x1 - x0) * (i + 0.5)) / n, y });
    levels.push(pts);
  }
  return levels;
}

export default function HypertreeFigure() {
  const reduced = typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const [sig, setSig] = useState(0);
  const raf = useRef<number | null>(null);
  const hostRef = useRef<HTMLDivElement | null>(null);

  // Advance one signature every ~900 ms while visible.
  useEffect(() => {
    if (reduced) { setSig(5); return; }
    let visible = true;
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting; }, { threshold: 0.2 });
    if (hostRef.current) io.observe(hostRef.current);
    let last = 0;
    const tick = (t: number) => {
      if (visible && t - last > 900) { last = t; setSig((s) => (s + 1) % (SUBTREES * LEAVES)); }
      raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => { if (raf.current) cancelAnimationFrame(raf.current); io.disconnect(); };
  }, [reduced]);

  const geometry = useMemo(() => {
    const top = treeLayout(W * 0.25, W * 0.75, 28, 118);
    const subW = W / SUBTREES;
    const bottoms = Array.from({ length: SUBTREES }, (_, s) => treeLayout(s * subW + 14, (s + 1) * subW - 14, 170, 272));
    return { top, bottoms };
  }, []);

  const subtree = Math.floor(sig / LEAVES);
  const leaf = sig % LEAVES;
  const firstInSubtree = leaf === 0;
  const cached = new Set<number>();
  for (let s = 0; s < subtree; s++) cached.add(s);
  if (!firstInSubtree) cached.add(subtree);

  // Auth path positions (node index per level) for the active bottom leaf and the top leaf = subtree index.
  const pathNodes = (leafIdx: number) => {
    const out: number[] = []; let p = leafIdx;
    for (let k = 0; k <= H; k++) { out.push(p); p >>= 1; }
    return out;
  };
  const bottomPath = pathNodes(leaf);
  const topPath = pathNodes(subtree);

  const edge = (a: Pt, b: Pt, lit: boolean, key: string) => (
    <line key={key} x1={a.x} y1={a.y} x2={b.x} y2={b.y} className={lit ? "ht-edge lit" : "ht-edge"} />
  );

  const drawTree = (levels: Pt[][], path: number[] | null, prefix: string, rootCached: boolean) => {
    const els: React.ReactNode[] = [];
    for (let k = 0; k < H; k++) {
      levels[k].forEach((p, i) => {
        const parent = levels[k + 1][i >> 1];
        const lit = !!path && path[k] === i;
        els.push(edge(p, parent, lit, `${prefix}e${k}-${i}`));
      });
    }
    for (let k = 0; k <= H; k++) {
      levels[k].forEach((p, i) => {
        const onPath = !!path && path[k] === i;
        const isRoot = k === H;
        const cls = ["ht-node", onPath ? "lit" : "", isRoot ? "root" : "", isRoot && rootCached ? "cached" : "", k === 0 ? "leaf" : ""].join(" ");
        const r = isRoot ? 5 : k === 0 ? 2.6 : 3.2;
        els.push(<rect key={`${prefix}n${k}-${i}`} x={p.x - r} y={p.y - r} width={2 * r} height={2 * r} className={cls} />);
      });
    }
    return els;
  };

  const topRoot = geometry.top[H][0];
  const carried = firstInSubtree ? 2 : 1;
  const bytes = firstInSubtree ? 4928 : 2464;

  return (
    <figure className="fig ht-fig" ref={hostRef}>
      <svg viewBox={`0 0 ${W} ${HT}`} role="img" aria-label="Two-layer hypertree with verifier-side cached subtree roots">
        {/* top layer */}
        <text x={W * 0.25 - 8} y={30} className="ht-label" textAnchor="end">layer 1</text>
        <text x={W * 0.25 - 8} y={172} className="ht-label" textAnchor="end">layer 0</text>
        <text x={topRoot.x + 12} y={topRoot.y + 4} className="ht-label">R₁ · on-chain root</text>
        {drawTree(geometry.top, firstInSubtree ? topPath : null, "t", false)}
        {/* links: top leaves → bottom subtree roots */}
        {geometry.bottoms.map((b, s) => {
          const tl = geometry.top[0][s];
          const br = b[H][0];
          const lit = firstInSubtree && s === subtree;
          return <path key={`l${s}`} d={`M${tl.x},${tl.y + 4} C${tl.x},${tl.y + 40} ${br.x},${br.y - 40} ${br.x},${br.y - 6}`} className={lit ? "ht-link lit" : "ht-link"} />;
        })}
        {/* bottom subtrees */}
        {geometry.bottoms.map((b, s) => (
          <g key={`b${s}`}>
            {drawTree(b, s === subtree ? bottomPath : null, `b${s}`, cached.has(s))}
            <text x={b[H][0].x} y={b[0][0].y + 18} className="ht-label" textAnchor="middle">
              {cached.has(s) ? "subtree " + s + " · cached" : "subtree " + s}
            </text>
          </g>
        ))}
        {/* active leaf marker */}
        {(() => { const p = geometry.bottoms[subtree][0][leaf]; return <circle cx={p.x} cy={p.y} r={7} className="ht-pulse" />; })()}
      </svg>
      <figcaption>
        <span className="fig-num">Fig. 01</span>
        <span className="fig-text">
          Signature <span className="mono num">#{String(sig).padStart(2, "0")}</span> · layers carried:{" "}
          <span className="mono num">{carried}</span> · calldata{" "}
          <span className="mono num">{bytes.toLocaleString("en-US")} B</span>
          {firstInSubtree ? " · verifier caches R₀ of this subtree" : " · top layer skipped, root read from cache"}
        </span>
      </figcaption>
    </figure>
  );
}
