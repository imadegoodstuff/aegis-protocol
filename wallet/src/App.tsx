import { Suspense, lazy, useEffect, useState } from "react";
import ChainDashboard from "./components/ChainDashboard";
import ChainMarquee   from "./components/ChainMarquee";
import ShieldMark     from "./components/ShieldMark";
import ThemeToggle    from "./components/ThemeToggle";
import HypertreeFigure from "./components/HypertreeFigure";
import ParamsTable    from "./components/ParamsTable";
import { useParallax } from "./hooks/useParallax";
import { applyTheme, getInitialTheme } from "./theme";

// Lazy chunks: defer heavy crypto + rarely-used UI until after first paint.
const DerivePanel    = lazy(() => import("./components/DerivePanel"));
const LabBench       = lazy(() => import("./components/LabBench"));
const ArchitectureDiagram = lazy(() => import("./components/ArchitectureDiagram"));
const CodeShowcase   = lazy(() => import("./components/CodeShowcase"));
const CommandPalette = lazy(() => import("./components/CommandPalette"));

applyTheme(getInitialTheme());

const BUILD = (((import.meta as unknown as { env?: Record<string, string> }).env?.VITE_BUILD_SHA) || "dev").slice(0, 7);
const REPO = "https://github.com/imadegoodstuff/aegis-protocol";

const NAV = [
  { href: "#protect", label: "Protect" },
  { href: "#bench",   label: "Bench" },
  { href: "#arch",    label: "Architecture" },
  { href: "#why",     label: "Threat model" },
  { href: "#verify",  label: "Verify" },
  { href: "#code",    label: "Code" },
];

function LiveTicker() {
  const [clock, setClock] = useState("--:--:--");
  useEffect(() => {
    const t = () => setClock(new Date().toISOString().slice(11, 19) + "Z");
    t();
    const i = setInterval(t, 1000);
    return () => clearInterval(i);
  }, []);
  return (
    <div className="nav-ticker" title="Protocol status">
      <span className="dot" />
      <span className="k">set</span><span className="v">CCHS-K-20</span>
      <span className="sep">·</span>
      <span className="k">gas</span><span className="v num">177 K</span>
      <span className="sep">·</span>
      <span className="v num">{clock}</span>
    </div>
  );
}

function useMouseGlow() {
  useEffect(() => {
    if (window.matchMedia("(hover: none)").matches) return;
    const h = (e: PointerEvent) => {
      const card = (e.target as HTMLElement).closest?.(".card") as HTMLElement | null;
      if (!card) return;
      const r = card.getBoundingClientRect();
      card.style.setProperty("--mx", `${e.clientX - r.left}px`);
      card.style.setProperty("--my", `${e.clientY - r.top}px`);
    };
    window.addEventListener("pointermove", h);
    return () => window.removeEventListener("pointermove", h);
  }, []);
}

function useLazyCommandPalette() {
  const [enabled, setEnabled] = useState(false);
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") setEnabled(true); };
    window.addEventListener("keydown", h, { once: true });
    return () => window.removeEventListener("keydown", h);
  }, []);
  return enabled;
}

function MobileMenu({ open, onClose }: { open: boolean; onClose: () => void }) {
  useEffect(() => {
    document.documentElement.style.overflow = open ? "hidden" : "";
    return () => { document.documentElement.style.overflow = ""; };
  }, [open]);
  if (!open) return null;
  return (
    <div className="mnav" role="dialog" aria-label="Menu">
      <div className="mnav-head">
        <div className="brand"><span className="brand-mark"><ShieldMark size={22} /></span><span>AEGIS</span></div>
        <button className="btn btn-sm" onClick={onClose} aria-label="Close menu">close</button>
      </div>
      <nav className="mnav-links">
        {NAV.map((n, i) => (
          <a key={n.href} href={n.href} onClick={onClose}>
            <span className="num mono">{String(i + 1).padStart(2, "0")}</span>{n.label}
          </a>
        ))}
        <a href={REPO} target="_blank" rel="noreferrer"><span className="num mono">↗</span>GitHub</a>
      </nav>
      <div className="mnav-foot">
        <ThemeToggle />
        <span className="mono">build {BUILD}</span>
      </div>
    </div>
  );
}

export default function App() {
  useMouseGlow();
  useParallax();
  const cpEnabled = useLazyCommandPalette();
  const [menu, setMenu] = useState(false);

  useEffect(() => {
    const els = document.querySelectorAll<HTMLElement>(".fade");
    const io = new IntersectionObserver((entries) => entries.forEach((e) => e.isIntersecting && e.target.classList.add("in")), { threshold: 0.08 });
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  useEffect(() => {
    let fired = false;
    const trigger = () => {
      if (fired) return;
      fired = true;
      window.removeEventListener("scroll", trigger);
      window.removeEventListener("pointerdown", trigger);
      void import("./components/DerivePanel");
      void import("./components/LabBench");
      void import("./components/ArchitectureDiagram");
      void import("./components/CodeShowcase");
    };
    window.addEventListener("scroll", trigger, { passive: true });
    window.addEventListener("pointerdown", trigger, { passive: true });
    return () => { window.removeEventListener("scroll", trigger); window.removeEventListener("pointerdown", trigger); };
  }, []);

  return (
    <div>
      <a className="skip-link" href="#main">Skip to content</a>
      <div className="mesh" aria-hidden="true" />
      <div className="grid" aria-hidden="true" />
      <div className="grain" aria-hidden="true" />
      {cpEnabled && <Suspense fallback={null}><CommandPalette /></Suspense>}
      <MobileMenu open={menu} onClose={() => setMenu(false)} />

      <nav className="nav">
        <div className="container nav-inner">
          <a className="brand" href="#top" aria-label="Aegis home">
            <span className="brand-mark"><ShieldMark size={22} /></span>
            <span>AEGIS</span>
            <span className="chip nav-chip">CCHS v1 · pre-audit</span>
          </a>
          <LiveTicker />
          <div className="nav-cluster">
            {NAV.map((n) => <a key={n.href} className="nav-link" href={n.href}>{n.label}</a>)}
            <span className="nav-kbd"><kbd>⌘</kbd><kbd>K</kbd></span>
            <ThemeToggle />
            <a className="btn btn-sm" href={REPO} target="_blank" rel="noreferrer">GitHub ↗</a>
          </div>
          <button className="btn btn-sm nav-burger" onClick={() => setMenu(true)} aria-label="Open menu">menu</button>
        </div>
      </nav>

      <main id="main">

      {/* HERO */}
      <header className="hero" id="top">
        <div className="container">
          <div className="hero-grid">
            <div className="hero-copy">
              <div className="hero-eyebrow fade">
                <span className="bar" />
                <span>Chain-Cached Hypertree Signatures · hash-only accounts</span>
              </div>
              <h1 className="hero-title fade d1">
                A signature scheme whose only assumption is <span className="accent">a hash function.</span>
              </h1>
              <p className="hero-sub fade d2">
                CCHS turns a smart contract's memory into part of the signature. The verifier checks
                the upper tree layer once per subtree, caches the result on chain, and the next 1 023
                signatures carry only the bottom layer: 2.5 KB, ~177 K gas end to end, no elliptic curves, no lattices,
                no trusted setup. One mnemonic, an independent key tree and account on every EVM chain.
              </p>
              <div className="hero-ctas fade d3">
                <a className="btn btn-primary" href="#protect">Protect an account →</a>
                <a className="btn" href="#bench">Run the bench</a>
                <a className="btn btn-ghost" href={`${REPO}/blob/main/CCHS.spec.md`} target="_blank" rel="noreferrer">Read the spec ↗</a>
              </div>
              <div className="hero-meta fade d3">
                <span><b>assumption</b> keccak256 / SHA-256 preimage</span>
                <span><b>curves</b> none</span>
                <span><b>lattices</b> none</span>
                <span><b>admin keys</b> none</span>
              </div>
            </div>
            <div className="hero-fig fade d2">
              <HypertreeFigure />
            </div>
          </div>

          <div className="stats fade d3 parallax-slow">
            <div className="stat">
              <div className="stat-k">gas · cached path · whole transaction</div>
              <div className="stat-v num">169<span className="stat-unit">K</span></div>
              <div className="stat-s">CCHS-K-20 · measured in an EVM · 112 K of it is execution</div>
            </div>
            <div className="stat">
              <div className="stat-k">signature</div>
              <div className="stat-v num">2 464<span className="stat-unit">B</span></div>
              <div className="stat-s">amortized · 4 928 B first in subtree</div>
            </div>
            <div className="stat">
              <div className="stat-k">signatures per key</div>
              <div className="stat-v num">2<sup>20</sup></div>
              <div className="stat-s">per chain · + 256 recoveries · one integer of client state</div>
            </div>
            <div className="stat">
              <div className="stat-k">keygen · browser</div>
              <div className="stat-v num">≈1<span className="stat-unit">s</span></div>
              <div className="stat-s">per chain tree · worker pool · WASM hash cores</div>
            </div>
          </div>

          <ChainMarquee />
        </div>
      </header>

      {/* 01 PROTECT */}
      <section id="protect" className="section">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">01</div>
            <div>
              <div className="section-eyebrow">Protect · one identity · every chain</div>
              <h2 className="section-title">Derive. Predict. Protect.</h2>
              <p className="section-sub">
                A BIP-39 phrase derives the CCHS master, and from it one key tree per chain: a one-time
                leaf never signs on two chains. The keccak set fixes each EVM account address through a
                factory that lives at the same address everywhere; the SHA-256 set serves every other
                chain. Every address exists before any transaction. Protecting a chain is one click and
                one transaction: create the account and move ETH in.
              </p>
            </div>
          </div>
          <div className="fade">
            <Suspense fallback={<CardSkeleton height={720} />}>
              <DerivePanel />
            </Suspense>
          </div>
          <div className="fade"><ChainDashboard /></div>
        </div>
      </section>

      {/* 02 BENCH */}
      <section id="bench" className="section cv">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">02</div>
            <div>
              <div className="section-eyebrow">Measurements</div>
              <h2 className="section-title">Numbers you can reproduce.</h2>
              <p className="section-sub">
                The bench runs the real protocol on your device: key generation in a worker pool, two
                signatures (first-in-subtree and cached), local verification, and two attacks that must fail.
                Table 1 lists the on-chain costs measured in an EVM with these same signatures.
              </p>
            </div>
          </div>
          <div className="bench-grid fade">
            <Suspense fallback={<CardSkeleton height={420} />}>
              <LabBench />
            </Suspense>
            <ParamsTable />
          </div>
        </div>
      </section>

      {/* 03 ARCH */}
      <section id="arch" className="section cv">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">03</div>
            <div>
              <div className="section-eyebrow">Architecture · two layers · ten adapters</div>
              <h2 className="section-title">One master key, one verifier, many chains.</h2>
              <p className="section-sub">
                <b>addr</b> is the chain's standard address derived in the browser, importable to native wallets
                today. <b>pq</b> is the CCHS account contract for that chain. The EVM contract is complete and
                tested; the other verifiers exist as source against shared test vectors and are not deployed.
              </p>
            </div>
          </div>
          <div className="fade">
            <Suspense fallback={<CardSkeleton height={420} />}>
              <ArchitectureDiagram />
            </Suspense>
          </div>
        </div>
      </section>

      {/* 04 THREAT MODEL */}
      <section id="why" className="section cv">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">04</div>
            <div>
              <div className="section-eyebrow">Threat model · stated plainly</div>
              <h2 className="section-title">What holds, and what does not.</h2>
              <p className="section-sub">
                CCHS strengthens the signature layer only. Everything else, the chain's consensus, your device,
                your seed handling, is outside it.
              </p>
            </div>
          </div>

          <div className="promise fade">
            <div className="card promise-card good">
              <h3><span className="ic">✓</span> Holds under the stated assumption</h3>
              <ul className="promise-list">
                <li><span className="mark">▶</span> Unforgeability reduces to WOTS+ (Hülsing 2013) and Merkle tree security; the only assumption is preimage / second-preimage resistance of the hash</li>
                <li><span className="mark">▶</span> A signature seen in the mempool cannot be redirected: the Winternitz checksum makes any digest change require a chain pre-image</li>
                <li><span className="mark">▶</span> Cache entries can only be written through a valid top-layer signature; recovery rotates the epoch and empties the cache</li>
                <li><span className="mark">▶</span> Replay is impossible: chain ID, account, nonce and index are inside every digest</li>
                <li><span className="mark">▶</span> No admin, proxy, upgrade, pause, fee, or treasury in the account contract</li>
                <li><span className="mark">▶</span> One-time keys are never shared: one tree per chain, one leaf per message, the chain enforces monotonic use and the client records the highest leaf it signed before signing (one integer per chain and epoch); a device without that record rotates keys before it signs again</li>
                <li><span className="mark">▶</span> Interop verified: client signatures executed against the compiled contracts for both sets</li>
              </ul>
            </div>
            <div className="card promise-card bad">
              <h3><span className="ic">!</span> Not yet, or not ours to promise</h3>
              <ul className="promise-list">
                <li><span className="mark">▶</span> The factory is not published on any chain yet. There is no deployer: the first Protect on a chain publishes it through the deterministic proxy as one extra transaction paid by that user, and the panel shows the live state</li>
                <li><span className="mark">▶</span> No external audit. The Lean proofs cover the verifier and client state machines, not the hash-level reductions in §6 of the spec</li>
                <li><span className="mark">▶</span> Solana: the C-20 program is live on mainnet-beta (AoQ7c3…jMQKr, deployed from CI) and the panel protects SOL and any SPL token there; its upgrade authority is still the deployer key, not a multisig, and no external audit covers the program. CosmWasm, NEAR, Move, Cairo and TON verifiers are source against test vectors, not deployments</li>
                <li><span className="mark">▶</span> Bitcoin: the hash-only account runs on Bitcoin Inquisition signet, where OP_CAT and OP_CHECKSIGFROMSTACK are active; mainnet has neither, and a P2TR output keeps a key path until a key-less output (BIP-360) exists. The mainnet Bitcoin address is ordinary P2WPKH and is not post-quantum (BITCOIN.md)</li>
                <li><span className="mark">▶</span> Keygen is ~1 s per chain (14 chains ≈ 8 s on a laptop), not ~100 ms; that needs the chain loop inside WASM</li>
                <li><span className="mark">▶</span> Account addresses differ per chain by design (one key tree per chain); only the factory is at one address everywhere</li>
                <li><span className="mark">▶</span> A lost mnemonic or a compromised device cannot be recovered by anyone</li>
                <li><span className="mark">▶</span> If the hash function falls, everything built on it falls, including every other post-quantum scheme</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* 05 VERIFY */}
      <section id="verify" className="section cv">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">05</div>
            <div>
              <div className="section-eyebrow">Self-verification</div>
              <h2 className="section-title">Check it yourself.</h2>
              <p className="section-sub">
                Each item below is a fact about code in the public repository or about an address on a block
                explorer. If any one fails, do not use the account.
              </p>
            </div>
          </div>

          <div className="checks">
            {[
              { h: "No owner, no upgrade",            p: "AegisCCHSBase has no setters, no proxy, no delegatecall, no selfdestruct. Storage is roots, counters and the cache." },
              { h: "Same bytecode on every chain",    p: "The factory is built with fixed compiler settings and published through the deterministic-deployment proxy. Compare runtime hashes across explorers." },
              { h: "Address is a pure function",      p: "account = CREATE2(factory, keccak(root ‖ recRoot ‖ pkSeed ‖ set), keccak(initCode ‖ roots ‖ pkSeed)). The wallet computes it offline; the factory's predict() must agree." },
              { h: "Signatures are hash chains",      p: "execute() calls only keccak256 or the SHA-256 precompile. There is no ecrecover and no pairing anywhere in the account." },
              { h: "Test vectors are shared",         p: "evm/test/fixtures/cchs-*.json drive the Solidity tests and every other port. Regenerate them from the TypeScript client and diff." },
              { h: "Attacks are tests",               p: "Front-run, replay, tampered chain value, tampered path, cache poisoning, old key after recovery: each is a Foundry test that must revert." },
              { h: "Front-end is static",             p: "Build from source, serve the dist folder. No API, no telemetry; RPC calls go to public endpoints you can change." },
              { h: "Spec states its limits",          p: "CCHS.spec.md §1 lists prior art and what the contribution is; §11 lists open problems. Read those before the claims." },
              { h: "One key tree per chain",          p: "key(chain) = HKDF(master, \"aegis/cchs/chain/v1\" ‖ tag). evm/test/fixtures/cchs-derivation.json pins the keys; check-vectors asserts that chains 1 and 8453 share no leaf secret." },
            ].map((c, i) => (
              <div key={i} className="card check fade">
                <div className="check-num mono" aria-hidden="true">{String(i + 1).padStart(2, "0")}</div>
                <h3 className="check-title">{c.h}</h3>
                <p>{c.p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 06 CODE */}
      <section id="code" className="section cv">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">06</div>
            <div>
              <div className="section-eyebrow">Source</div>
              <h2 className="section-title">Several surfaces, one state machine.</h2>
              <p className="section-sub">
                Solidity, Rust, Cairo and TypeScript implement the same verifier against the same vectors.
              </p>
            </div>
          </div>
          <div className="fade">
            <Suspense fallback={<CardSkeleton height={520} />}>
              <CodeShowcase />
            </Suspense>
          </div>
        </div>
      </section>

      </main>

      <footer className="footer">
        <div className="container">
          <div className="footer-top">
            <div className="footer-col footer-brand">
              <div className="brand" style={{ fontSize: 18, marginBottom: 8 }}>
                <span className="brand-mark"><ShieldMark size={22} /></span>
                <span>aegis</span>
              </div>
              <p>
                Chain-Cached Hypertree Signatures. Built from WOTS+ (2013), Merkle trees (1979) and hypertrees
                (XMSS^MT, 2013); the contribution is the verifier-side cache and the trade-off it reaches.
              </p>
            </div>
            <div className="footer-col">
              <h3 className="footer-col-title">Protocol</h3>
              <a href="#protect">Protect</a>
              <a href="#bench">Bench</a>
              <a href="#arch">Architecture</a>
              <a href="#why">Threat model</a>
            </div>
            <div className="footer-col">
              <h3 className="footer-col-title">Repository</h3>
              <a href={REPO} target="_blank" rel="noreferrer">GitHub</a>
              <a href={`${REPO}/blob/main/CCHS.spec.md`} target="_blank" rel="noreferrer">CCHS.spec.md</a>
              <a href={`${REPO}/blob/main/SPEC.md`} target="_blank" rel="noreferrer">SPEC.md</a>
              <a href={`${REPO}/blob/main/ADAPTERS.md`} target="_blank" rel="noreferrer">ADAPTERS.md</a>
            </div>
            <div className="footer-col">
              <h3 className="footer-col-title">References</h3>
              <a href="https://eprint.iacr.org/2017/965" target="_blank" rel="noreferrer">WOTS+ / XMSS (RFC 8391)</a>
              <a href="https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf" target="_blank" rel="noreferrer">FIPS 205 SLH-DSA</a>
              <a href="https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki" target="_blank" rel="noreferrer">BIP-347 OP_CAT</a>
            </div>
          </div>
          <div className="footer-bottom">
            <span>CCHS v1 · pre-audit · MIT (protocol, contracts) · GPL-3.0 (wallet UI)</span>
            <span>build {BUILD} · ⌘K</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

function CardSkeleton({ height }: { height: number }) {
  return (
    <div className="card" style={{ height, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-4)", fontFamily: "var(--font-mono)", fontSize: 12 }}>
      loading…
    </div>
  );
}
