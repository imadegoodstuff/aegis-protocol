import { Suspense, lazy, useEffect, useState } from "react";
import ChainDashboard from "./components/ChainDashboard";
import ChainMarquee   from "./components/ChainMarquee";
import ShieldMark     from "./components/ShieldMark";
import Terminal       from "./components/Terminal";
import ThemeToggle    from "./components/ThemeToggle";
import { useParallax } from "./hooks/useParallax";
import { applyTheme, getInitialTheme } from "./theme";

// Lazy chunks: defer heavy crypto + rarely-used UI until after first paint.
const DerivePanel    = lazy(() => import("./components/DerivePanel"));
const ArchitectureDiagram = lazy(() => import("./components/ArchitectureDiagram"));
const CodeShowcase   = lazy(() => import("./components/CodeShowcase"));
const CommandPalette = lazy(() => import("./components/CommandPalette"));

// Apply theme ASAP (before React hydrates visible content).
applyTheme(getInitialTheme());

const BUILD = (((import.meta as unknown as { env?: Record<string, string> }).env?.VITE_BUILD_SHA) || "fadba15").slice(0, 7);

function LiveTicker() {
  const [clock, setClock] = useState("--:--:--");
  useEffect(() => {
    const t = () => setClock(new Date().toISOString().slice(11, 19) + " UTC");
    t();
    const i = setInterval(t, 1000);
    return () => clearInterval(i);
  }, []);
  return (
    <div className="nav-ticker" title="Protocol status">
      <span className="dot" />
      <span className="k">CHAINS</span><span className="v">13 live</span>
      <span className="sep">·</span>
      <span className="k">BUILD</span><span className="v mono">{BUILD}</span>
      <span className="sep">·</span>
      <span className="k">SIG</span><span className="v">SPHINCS+-192s</span>
      <span className="sep">·</span>
      <span className="v mono">{clock}</span>
    </div>
  );
}

function useMouseGlow() {
  useEffect(() => {
    const h = (e: PointerEvent) => {
      const t = e.target as HTMLElement;
      const card = t.closest?.(".card") as HTMLElement | null;
      if (!card) return;
      const r = card.getBoundingClientRect();
      card.style.setProperty("--mx", `${e.clientX - r.left}px`);
      card.style.setProperty("--my", `${e.clientY - r.top}px`);
    };
    window.addEventListener("pointermove", h);
    return () => window.removeEventListener("pointermove", h);
  }, []);
}

/** Mount CommandPalette only after the first ⌘K / Ctrl+K press (saves initial JS). */
function useLazyCommandPalette() {
  const [enabled, setEnabled] = useState(false);
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") setEnabled(true);
    };
    window.addEventListener("keydown", h, { once: true });
    return () => window.removeEventListener("keydown", h);
  }, []);
  return enabled;
}

export default function App() {
  useMouseGlow();
  useParallax();
  const cpEnabled = useLazyCommandPalette();

  // IntersectionObserver reveal
  useEffect(() => {
    const els = document.querySelectorAll<HTMLElement>(".fade");
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => e.isIntersecting && e.target.classList.add("in")),
      { threshold: 0.08 }
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  // Prefetch lazy chunks only AFTER the user scrolls — never on first paint.
  // Keeps TBT / FID clean for lighthouse's cold-load measurement.
  useEffect(() => {
    let fired = false;
    const trigger = () => {
      if (fired) return;
      fired = true;
      window.removeEventListener("scroll", trigger);
      window.removeEventListener("pointerdown", trigger);
      void import("./components/DerivePanel");
      void import("./components/ArchitectureDiagram");
      void import("./components/CodeShowcase");
    };
    window.addEventListener("scroll", trigger, { passive: true, once: false });
    window.addEventListener("pointerdown", trigger, { passive: true, once: false });
    return () => {
      window.removeEventListener("scroll", trigger);
      window.removeEventListener("pointerdown", trigger);
    };
  }, []);

  return (
    <div>
      <a className="skip-link" href="#main">Skip to content</a>
      <div className="mesh" aria-hidden="true" />
      <div className="grid" aria-hidden="true" />
      {/* grain is deferred — adds visual tactility but costs 1 paint layer */}
      <div className="grain" aria-hidden="true" />
      {cpEnabled && (
        <Suspense fallback={null}>
          <CommandPalette />
        </Suspense>
      )}

      {/* NAV */}
      <nav className="nav">
        <div className="container nav-inner">
          <div className="brand">
            <span className="brand-mark"><ShieldMark size={22} /></span>
            <span>AEGIS</span>
            <span className="chip" style={{ marginLeft: 4 }}>v0.1 · pre-audit</span>
          </div>
          <LiveTicker />
          <div className="nav-cluster">
            <a className="nav-link" href="#chains">Chains</a>
            <a className="nav-link" href="#arch">Architecture</a>
            <a className="nav-link" href="#why">Threat</a>
            <a className="nav-link" href="#verify">Verify</a>
            <a className="nav-link" href="#code">Code</a>
            <span className="nav-kbd"><kbd>⌘</kbd><kbd>K</kbd></span>
            <ThemeToggle />
            <a
              className="btn btn-sm"
              href="https://github.com/imadegoodstuff/aegis-protocol"
              target="_blank" rel="noreferrer"
            >
              GitHub ↗
            </a>
          </div>
        </div>
      </nav>

      {/* MAIN */}
      <main id="main">

      {/* HERO */}
      <header className="hero">
        <div className="container">
          <div className="hero-eyebrow fade">
            <span className="bar" />
            <span className="dot" />
            <span>Post-quantum signature infrastructure · FIPS 205 SLH-DSA</span>
          </div>
          <h1 className="hero-title fade d1 parallax-med">
            Signatures that <span className="accent">outlive</span><br />
            elliptic curves.
          </h1>
          <p className="hero-sub fade d2">
            Aegis is a per-user, immutable smart account signed with
            SPHINCS+-192s. One BIP-39 mnemonic maps to the same CREATE address on
            every EVM chain plus independent accounts on Starknet, Solana, Cosmos
            and Move. No bridge, no pool, no admin, no token.
          </p>
          <div className="hero-ctas fade d3">
            <a className="btn btn-primary" href="#chains">Derive my addresses →</a>
            <a className="btn" href="#verify">Self-verify in 10 s</a>
            <a className="btn btn-ghost" href="#arch">Architecture</a>
          </div>
          <div className="hero-meta fade d3">
            <span><b>SIG</b> SLH-DSA-SHAKE-192s · live in wallet</span>
            <span><b>HASH</b> SHAKE-256 / keccak256</span>
            <span><b>LATTICE</b> none</span>
            <span><b>PAIRING</b> none</span>
          </div>

          <div className="stats fade d3 parallax-slow">
            <div className="stat">
              <div className="stat-k">chains · live</div>
              <div className="stat-v">13</div>
              <div className="stat-s">12 EVM + Starknet · same identity</div>
            </div>
            <div className="stat">
              <div className="stat-k">testnet-ready</div>
              <div className="stat-v">11</div>
              <div className="stat-s">Solana, TRON, 5 Cosmos, Aptos, Sui, NEAR, TON</div>
            </div>
            <div className="stat">
              <div className="stat-k">timelock</div>
              <div className="stat-v">7d</div>
              <div className="stat-s">PQ key can veto a stolen-ECDSA exit</div>
            </div>
            <div className="stat">
              <div className="stat-k">fee ceiling</div>
              <div className="stat-v">20%</div>
              <div className="stat-s">of gas · <code>constant</code> · ungovernable</div>
            </div>
          </div>

          <ChainMarquee />
        </div>
      </header>

      {/* 01 CHAINS */}
      <section id="chains" className="section">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">01</div>
            <div>
              <div className="section-eyebrow">Multi-chain · one identity</div>
              <h2 className="section-title">Your assets, every chain, one signature.</h2>
              <p className="section-sub">
                One seed derives a SPHINCS+ keypair. The same immutable factory address
                on every EVM chain (CREATE2) gives you a predictable account at the same
                address. Non-EVM chains derive independent accounts from the same seed.
              </p>
            </div>
          </div>

          <div className="fade"><ChainDashboard /></div>

          <div className="fade">
            <Suspense fallback={<DerivePanelSkeleton />}>
              <DerivePanel />
            </Suspense>
          </div>

          <div className="fade"><Terminal /></div>
        </div>
      </section>

      {/* 02 ARCH */}
      <section id="arch" className="section cv">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">02</div>
            <div>
              <div className="section-eyebrow">Architecture · interactive</div>
              <h2 className="section-title">One core · ten adapters.</h2>
              <p className="section-sub">
                One Rust/WASM core derives keys. Each chain adapter is a dedicated contract /
                program with the same state machine. Hover any adapter below to inspect its
                address derivation, verifier path, and status.
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

      {/* 03 THREAT MODEL */}
      <section id="why" className="section cv">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">03</div>
            <div>
              <div className="section-eyebrow">Threat model · honest version</div>
              <h2 className="section-title">What Aegis protects — and what it can't.</h2>
              <p className="section-sub">
                Aegis strengthens the signature layer only. No marketing: here is
                exactly what you get and what still depends on the underlying chain,
                your device, and the broader cryptographic community.
              </p>
            </div>
          </div>

          <div className="promise fade">
            <div className="card promise-card good">
              <h3><span className="ic">✓</span> Protected by Aegis</h3>
              <ul className="promise-list">
                <li><span className="mark">▶</span> Wallet produces real FIPS 205 SLH-DSA-SHAKE-192s signatures in-browser today (via <code>@noble/post-quantum</code>)</li>
                <li><span className="mark">▶</span> Non-custodial: funds in your per-user immutable contract</li>
                <li><span className="mark">▶</span> No admin, no upgrade, no selfdestruct, no pause</li>
                <li><span className="mark">▶</span> ECDSA fallback: 7-day timelock to your pre-committed guardian</li>
                <li><span className="mark">▶</span> PQ key can veto a stolen-ECDSA exit attempt</li>
                <li><span className="mark">▶</span> Protocol fee hard-capped at 20% in a <code>constant</code></li>
                <li><span className="mark">▶</span> Account survives on any fork that preserves state root</li>
              </ul>
            </div>
            <div className="card promise-card bad">
              <h3><span className="ic">!</span> Honestly out of scope · work-in-progress</h3>
              <ul className="promise-list">
                <li><span className="mark">▶</span> On-chain Solidity verifier for SLH-DSA-SHAKE-192s not yet deployed; vendored C13 variant (keccak-tweakable-hash, 3,688 B sigs) is in <code>evm/src/vendor/</code> but needs matching signer</li>
                <li><span className="mark">▶</span> No AegisAccount deployed to any mainnet yet · Sepolia end-to-end integration pending audit</li>
                <li><span className="mark">▶</span> We cannot save you if the underlying chain's consensus is broken</li>
                <li><span className="mark">▶</span> We cannot recover a lost mnemonic or a compromised device</li>
                <li><span className="mark">▶</span> We cannot undo a wrong guardian address committed at deploy time</li>
                <li><span className="mark">▶</span> If SPHINCS+ itself falls (i.e. hash functions fall) all systems fall</li>
                <li><span className="mark">▶</span> v0.1 does not include on-chain privacy. Note relay is on the roadmap</li>
                <li><span className="mark">▶</span> SPHINCS+ verify is ~290K gas; expensive on L1 Ethereum, cheap on L2</li>
                <li><span className="mark">▶</span> zkSync Era's CREATE2 differs; its address is independent</li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* 04 VERIFY */}
      <section id="verify" className="section cv">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">04</div>
            <div>
              <div className="section-eyebrow">10-second self-verification</div>
              <h2 className="section-title">Trust the code. Not us.</h2>
              <p className="section-sub">
                Open your Aegis address on any block explorer. Verify each of the
                following yourself. If any single check fails, stop and withdraw.
              </p>
            </div>
          </div>

          <div className="checks">
            {[
              { h: "Non-custodial",             p: "No transfer / withdraw / mint on the account. Your balance is yours on-chain." },
              { h: "Not upgradeable",           p: "No proxy, no upgradeTo, no delegatecall storage escape, no selfdestruct." },
              { h: "Fee cap hardcoded",         p: "MAX_FEE_BPS = 2000 is a constant. Governance cannot raise it. Current fee is 10% of gas." },
              { h: "Guardian is immutable",     p: "GUARDIAN is set at deploy. No setter exists. Verify it on-chain yourself." },
              { h: "Exit path is free",         p: "finalizeEmergencyExit does not touch FEE_COLLECTOR. Code is law." },
              { h: "Deployer EOA is burned",    p: "After multi-chain deploy, the deployer private key is destroyed on a public livestream." },
              { h: "Front-end on IPFS",         p: "ENS contenthash points to IPFS CID. You can self-host the UI from source." },
              { h: "Same address, every chain", p: "Factory and verifier deployed with same salt + nonce. Open explorers side-by-side." },
            ].map((c, i) => (
              <div key={i} className="card check fade">
                <div className="check-num" aria-hidden="true">{String(i + 1).padStart(2, "0")}</div>
                <h3 className="check-title">{c.h}</h3>
                <p>{c.p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 05 CODE */}
      <section id="code" className="section cv">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">05</div>
            <div>
              <div className="section-eyebrow">The actual code</div>
              <h2 className="section-title">Four surfaces · one state machine.</h2>
              <p className="section-sub">
                The same account semantics across Solidity, Rust (core),
                Cairo (Starknet), and TypeScript (wallet). Pulled directly from the
                open-source repo.
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

      {/* FOOTER */}
      <footer className="footer">
        <div className="container">
          <div className="footer-top">
            <div className="footer-col footer-brand">
              <div className="brand" style={{ fontSize: 18, marginBottom: 8 }}>
                <span className="brand-mark" />
                <span>aegis</span>
              </div>
              <p>
                A protocol built in response to the 2026-10-07 warnings from
                Vitalik Buterin and Justin Drake. Hash-only, chain-agnostic,
                rug-proof by construction.
              </p>
            </div>
            <div className="footer-col">
              <h3 className="footer-col-title">Protocol</h3>
              <a href="#chains">Chains</a>
              <a href="#arch">Architecture</a>
              <a href="#why">Threat model</a>
              <a href="#verify">Self-verify</a>
            </div>
            <div className="footer-col">
              <h3 className="footer-col-title">Repo</h3>
              <a href="https://github.com/imadegoodstuff/aegis-protocol" target="_blank" rel="noreferrer">GitHub</a>
              <a href="https://github.com/imadegoodstuff/aegis-protocol/blob/main/SPEC.md" target="_blank" rel="noreferrer">SPEC.md</a>
              <a href="https://github.com/imadegoodstuff/aegis-protocol/blob/main/ADAPTERS.md" target="_blank" rel="noreferrer">ADAPTERS.md</a>
              <a href="https://github.com/imadegoodstuff/aegis-protocol/blob/main/docs/TESTNET_DEMO.md" target="_blank" rel="noreferrer">Testnet demo</a>
            </div>
            <div className="footer-col">
              <h3 className="footer-col-title">Credits</h3>
              <a href="https://github.com/nconsigny/SPHINCS-" target="_blank" rel="noreferrer">nconsigny/SPHINCS-</a>
              <a href="https://pq.ethereum.org/" target="_blank" rel="noreferrer">pq.ethereum.org</a>
              <a href="https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf" target="_blank" rel="noreferrer">FIPS 205 SLH-DSA</a>
            </div>
          </div>
          <div className="footer-bottom">
            <span>v0.1 · pre-audit · not for mainnet use · MIT (contracts) + GPL-3.0 (wallet UI)</span>
            <span>build {BUILD} · press ⌘K anywhere</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

function CardSkeleton({ height }: { height: number }) {
  return (
    <div
      className="card"
      style={{
        height,
        display: "flex", alignItems: "center", justifyContent: "center",
        color: "var(--text-4)", fontFamily: "var(--font-mono)", fontSize: 12,
      }}
    >
      loading…
    </div>
  );
}

function DerivePanelSkeleton() {
  return <CardSkeleton height={720} />;
}
