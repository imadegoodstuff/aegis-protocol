import { useEffect, useRef } from "react";
import ChainDashboard from "./components/ChainDashboard";
import Terminal from "./components/Terminal";

export default function App() {
  // simple IntersectionObserver reveal
  const rootRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const els = rootRef.current?.querySelectorAll<HTMLElement>(".fade");
    if (!els) return;
    const io = new IntersectionObserver(
      (entries) =>
        entries.forEach((e) => e.isIntersecting && e.target.classList.add("in")),
      { threshold: 0.08 }
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, []);

  return (
    <div ref={rootRef}>
      {/* NAV */}
      <nav className="nav">
        <div className="container nav-inner">
          <div className="brand">
            <span className="brand-mark" />
            <span>aegis</span>
            <span className="chip" style={{ marginLeft: 8 }}>v0.1 preview</span>
          </div>
          <div className="nav-links">
            <a className="nav-link" href="#chains">Chains</a>
            <a className="nav-link" href="#why">Why</a>
            <a className="nav-link" href="#verify">Verify</a>
            <a className="nav-link" href="#spec">Spec</a>
            <a
              className="btn"
              href="https://github.com/imadegoodstuff/aegis-protocol"
              target="_blank"
              rel="noreferrer"
            >
              <span>★</span> GitHub
            </a>
          </div>
        </div>
      </nav>

      {/* HERO */}
      <header className="hero">
        <div className="container">
          <div className="hero-eyebrow fade">
            <span className="pulse" />
            Post-AI-math readiness · hash-only signatures · zero custody
          </div>
          <h1 className="hero-title fade">
            One seed. <span className="grad">Every chain.</span>
            <br />
            Quantum-safe signatures today.
          </h1>
          <p className="hero-sub fade">
            Aegis is a per-user, immutable smart account with SPHINCS+ hash-based
            signatures. One BIP-39 mnemonic deploys the same address on 30+ EVM
            chains and derives independent accounts on Starknet, Solana, Cosmos,
            and more. No bridge. No pool. No admin. No token.
          </p>
          <div className="hero-ctas fade">
            <a className="btn btn-primary" href="#chains">Launch preview →</a>
            <a className="btn" href="#verify">10-second self-verify</a>
            <a className="btn" href="#spec">Read the spec</a>
          </div>

          <div className="hero-stats fade">
            <div className="hero-stat">
              <div className="hero-stat-num">30+</div>
              <div className="hero-stat-label">EVM chains · same address</div>
            </div>
            <div className="hero-stat">
              <div className="hero-stat-num">0</div>
              <div className="hero-stat-label">Admin keys · pools · bridges</div>
            </div>
            <div className="hero-stat">
              <div className="hero-stat-num">7d</div>
              <div className="hero-stat-label">ECDSA fallback timelock</div>
            </div>
            <div className="hero-stat">
              <div className="hero-stat-num">20%</div>
              <div className="hero-stat-label">Hard-capped fee ceiling</div>
            </div>
          </div>
        </div>
      </header>

      {/* CHAINS */}
      <section id="chains" className="section">
        <div className="container">
          <div className="section-head fade">
            <div className="section-eyebrow">Multi-chain · one identity</div>
            <h2 className="section-title">Your assets, every chain, one signature.</h2>
            <p className="section-sub">
              One seed derives a SPHINCS+ keypair. The same immutable factory
              address on every EVM chain (CREATE2) gives you a predictable
              account at the same address. Non-EVM chains derive independent
              accounts from the same seed.
            </p>
          </div>
          <div className="fade">
            <ChainDashboard />
          </div>
          <div className="fade">
            <Terminal />
          </div>
        </div>
      </section>

      {/* WHY */}
      <section id="why" className="section">
        <div className="container">
          <div className="section-head fade">
            <div className="section-eyebrow">Threat model · honest version</div>
            <h2 className="section-title">What Aegis protects — and what it can't.</h2>
            <p className="section-sub">
              Aegis strengthens the signature layer only. No marketing: here is
              exactly what you get and what still depends on the underlying
              chain, your device, and the broader cryptographic community.
            </p>
          </div>

          <div className="promise fade">
            <div className="glass promise-card good">
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
            <div className="glass promise-card bad">
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

      {/* VERIFY */}
      <section id="verify" className="section">
        <div className="container">
          <div className="section-head fade">
            <div className="section-eyebrow">10-second self-verification</div>
            <h2 className="section-title">Trust the code. Not us.</h2>
            <p className="section-sub">
              Open your Aegis address on any block explorer. Verify each of the
              following yourself. If any single check fails, stop and withdraw.
            </p>
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
              <div key={i} className="glass check fade">
                <div className="check-num">{i + 1}</div>
                <h4>{c.h}</h4>
                <p>{c.p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* SPEC */}
      <section id="spec" className="section">
        <div className="container">
          <div className="section-head fade">
            <div className="section-eyebrow">Technical foundation</div>
            <h2 className="section-title">Standing on the shoulders of hash-only cryptography.</h2>
            <p className="section-sub">
              Aegis composes already-published, publicly-audited primitives.
              Nothing novel in the cryptography itself — the novelty is the
              packaging, the chain coverage, and the rug-proof architecture.
            </p>
          </div>

          <div className="glass" style={{ padding: 32 }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 24 }}>
              {[
                ["Signature",        "SPHINCS+-192s (FIPS 205 SLH-DSA)", "48 years hash-based lineage"],
                ["ZK (future)",      "STARK / FRI, hash-only",            "no KZG, no pairing"],
                ["KEM (v0.2 note)",  "Classic McEliece 348864",           "code-based, non-lattice, non-EC"],
                ["Account model",   "ERC-7579 modular validator",         "composable, portable"],
                ["Multi-chain",     "CREATE2 same salt + nonce + bytecode", "deterministic address"],
                ["Verifier",        "nconsigny / SPHINCs- C13 fork",     "FIPS 205 §11.2.2, 190K gas"],
                ["Fallback",        "secp256k1 ECDSA → 7d timelock → guardian", "defense in depth"],
                ["Rotation (v0.2)", "per-op PQ key rotation",            "shrinks exposure window to 1"],
              ].map(([k, v, s]) => (
                <div key={k}>
                  <div className="section-eyebrow" style={{ color: "var(--fg-3)", fontSize: 10, marginBottom: 6 }}>{k}</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, color: "var(--fg-0)", marginBottom: 4 }}>{v}</div>
                  <div style={{ fontSize: 12, color: "var(--fg-2)" }}>{s}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="footer">
        <div className="container">
          <div className="footer-top fade">
            <div>
              <div className="brand" style={{ fontSize: 18, marginBottom: 8 }}>
                <span className="brand-mark" />
                <span>aegis</span>
              </div>
              <div style={{ color: "var(--fg-2)", maxWidth: 420, fontSize: 14, lineHeight: 1.6 }}>
                A protocol built in response to the 2026-10-07 warnings from
                Vitalik Buterin and Justin Drake. Hash-only, chain-agnostic,
                rug-proof by construction.
              </div>
            </div>
            <div className="footer-links">
              <a href="#chains">Chains</a>
              <a href="#why">Threat model</a>
              <a href="#verify">Self-verify</a>
              <a href="#spec">Spec</a>
            </div>
          </div>
          <div className="footer-bottom">
            v0.1 · pre-audit · not for mainnet use · released under MIT (contracts) + GPL-3.0 (wallet UI)
          </div>
        </div>
      </footer>
    </div>
  );
}
