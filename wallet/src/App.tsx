import { useEffect, useRef, useState } from "react";
import ChainDashboard from "./components/ChainDashboard";
import ChainMarquee   from "./components/ChainMarquee";
import CodeShowcase   from "./components/CodeShowcase";
import CommandPalette from "./components/CommandPalette";
import DerivePanel    from "./components/DerivePanel";
import Terminal       from "./components/Terminal";

// Vite replaces this at build time via `vite build --define`-style; we access it loosely to avoid typing env.
const BUILD = (((import.meta as unknown as { env?: Record<string, string> }).env?.VITE_BUILD_SHA) || "6b91b49").slice(0, 7);

function LiveTicker() {
  const [clock, setClock] = useState("--:--:--");
  useEffect(() => {
    const t = () =>
      setClock(new Date().toISOString().slice(11, 19) + " UTC");
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

/** cursor-tracking light on cards */
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

export default function App() {
  useMouseGlow();
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const els = rootRef.current?.querySelectorAll<HTMLElement>(".fade");
    if (!els) return;
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => e.isIntersecting && e.target.classList.add("in")),
      { threshold: 0.08 }
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  return (
    <div ref={rootRef}>
      <div className="mesh" />
      <div className="grid" />
      <div className="grain" />
      <CommandPalette />

      {/* NAV */}
      <nav className="nav">
        <div className="container nav-inner">
          <div className="brand">
            <span className="brand-mark" />
            <span>aegis</span>
            <span className="chip" style={{ marginLeft: 4 }}>v0.1 preview</span>
          </div>
          <LiveTicker />
          <div className="nav-cluster">
            <a className="nav-link" href="#chains">Chains</a>
            <a className="nav-link" href="#why">Threat</a>
            <a className="nav-link" href="#verify">Verify</a>
            <a className="nav-link" href="#code">Code</a>
            <a className="nav-link" href="#spec">Spec</a>
            <span className="nav-kbd"><kbd>⌘</kbd><kbd>K</kbd></span>
            <a
              className="btn btn-sm"
              href="https://github.com/imadegoodstuff/aegis-protocol"
              target="_blank" rel="noreferrer"
            >
              <span>★</span> GitHub
            </a>
          </div>
        </div>
      </nav>

      {/* HERO */}
      <header className="hero">
        <div className="container">
          <div className="hero-pill fade">
            <span className="pulse" />
            <span>Post-AI-math readiness · hash-only signatures · zero custody</span>
          </div>
          <h1 className="hero-title fade d1">
            One seed.<br />
            <span className="grad">Every chain.</span><br />
            Quantum-safe signatures today.
          </h1>
          <p className="hero-sub fade d2">
            Aegis is a per-user, immutable smart account with SPHINCS+ hash-based
            signatures. One BIP-39 mnemonic deploys the same address on 30+ EVM chains
            and derives independent accounts on Starknet, Solana, Cosmos, Move chains,
            and more. No bridge. No pool. No admin. No token.
          </p>
          <div className="hero-ctas fade d3">
            <a className="btn btn-primary" href="#chains">Try live derivation →</a>
            <a className="btn" href="#verify">10-second self-verify</a>
            <a className="btn btn-ghost" href="#spec">Read the spec</a>
          </div>

          <div className="stats fade d3">
            <div className="stat">
              <div className="stat-k">chains · launch day</div>
              <div className="stat-v">13</div>
              <div className="stat-s">12 EVM + Starknet · same identity</div>
            </div>
            <div className="stat">
              <div className="stat-k">roadmap · 2027</div>
              <div className="stat-v">23</div>
              <div className="stat-s">+ Solana, Cosmos, Move, TRON, TON, NEAR</div>
            </div>
            <div className="stat">
              <div className="stat-k">timelock · emergency exit</div>
              <div className="stat-v">7d</div>
              <div className="stat-s">PQ key can veto a stolen ECDSA</div>
            </div>
            <div className="stat">
              <div className="stat-k">fee ceiling · hardcoded</div>
              <div className="stat-v">20%</div>
              <div className="stat-s">of gas · constant · ungovernable</div>
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
          <div className="fade"><DerivePanel /></div>
          <div className="fade"><Terminal /></div>
        </div>
      </section>

      {/* 02 THREAT MODEL */}
      <section id="why" className="section">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">02</div>
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
                <li><span className="mark">▶</span> SPHINCS+-192s hash-only signatures on every supported chain</li>
                <li><span className="mark">▶</span> Non-custodial: funds in your per-user immutable contract</li>
                <li><span className="mark">▶</span> No admin, no upgrade, no selfdestruct, no pause</li>
                <li><span className="mark">▶</span> ECDSA fallback: 7-day timelock to your pre-committed guardian</li>
                <li><span className="mark">▶</span> PQ key can veto a stolen-ECDSA exit attempt</li>
                <li><span className="mark">▶</span> Protocol fee hard-capped at 20% in a <code>constant</code></li>
                <li><span className="mark">▶</span> Account survives on any fork that preserves state root</li>
              </ul>
            </div>
            <div className="card promise-card bad">
              <h3><span className="ic">!</span> Honestly out of scope</h3>
              <ul className="promise-list">
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

      {/* 03 VERIFY */}
      <section id="verify" className="section">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">03</div>
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
                <div className="check-num">{String(i + 1).padStart(2, "0")}</div>
                <h4>{c.h}</h4>
                <p>{c.p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 04 CODE */}
      <section id="code" className="section">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">04</div>
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
          <div className="fade"><CodeShowcase /></div>
        </div>
      </section>

      {/* 05 SPEC */}
      <section id="spec" className="section">
        <div className="container">
          <div className="section-head fade">
            <div className="section-num">05</div>
            <div>
              <div className="section-eyebrow">Technical foundation</div>
              <h2 className="section-title">Standing on hash-only cryptography.</h2>
              <p className="section-sub">
                Aegis composes already-published, publicly-audited primitives.
                Nothing novel in the cryptography — the novelty is the packaging,
                the chain coverage, and the rug-proof architecture.
              </p>
            </div>
          </div>

          <div className="card" style={{ padding: 36 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 28 }}>
              {[
                ["Signature",        "SPHINCS+-192s (FIPS 205 SLH-DSA)",       "48 years hash-based lineage"],
                ["Verifier",         "nconsigny / SPHINCs- C13 (vendored)",     "FIPS 205 §4.2 · ~190K gas"],
                ["ZK (future)",      "STARK / FRI · hash-only",                 "no KZG · no pairing"],
                ["KEM (v0.2 note)",  "Classic McEliece 348864",                 "code-based · non-lattice · non-EC"],
                ["Account model",    "ERC-7579 modular validator",              "composable · portable"],
                ["Multi-chain",      "CREATE same deployer + nonce + bytecode", "deterministic address"],
                ["Fallback",         "secp256k1 ECDSA → 7d timelock → guardian","defense in depth"],
                ["Rotation (v0.2)",  "per-op PQ key rotation",                  "shrinks exposure window to 1"],
              ].map(([k, v, s]) => (
                <div key={k}>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--text-4)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8 }}>{k}</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, color: "var(--text)", marginBottom: 4 }}>{v}</div>
                  <div style={{ fontSize: 12.5, color: "var(--text-3)" }}>{s}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

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
              <h5>Protocol</h5>
              <a href="#chains">Chains</a>
              <a href="#why">Threat model</a>
              <a href="#verify">Self-verify</a>
              <a href="#spec">Spec</a>
            </div>
            <div className="footer-col">
              <h5>Repo</h5>
              <a href="https://github.com/imadegoodstuff/aegis-protocol" target="_blank" rel="noreferrer">GitHub</a>
              <a href="https://github.com/imadegoodstuff/aegis-protocol/blob/main/SPEC.md" target="_blank" rel="noreferrer">SPEC.md</a>
              <a href="https://github.com/imadegoodstuff/aegis-protocol/blob/main/ADAPTERS.md" target="_blank" rel="noreferrer">ADAPTERS.md</a>
              <a href="https://github.com/imadegoodstuff/aegis-protocol/blob/main/docs/TESTNET_DEMO.md" target="_blank" rel="noreferrer">Testnet demo</a>
            </div>
            <div className="footer-col">
              <h5>Credits</h5>
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
