import { useEffect, useState } from "react";

type Line =
  | { kind: "cmd"; text: string }
  | { kind: "out"; text: string; tone?: "ok" | "warn" | "muted" };

const SCRIPT: Line[] = [
  { kind: "cmd", text: "aegis identity new" },
  { kind: "out", text: "generating 256-bit BIP-39 entropy …", tone: "muted" },
  { kind: "out", text: "deriving SPHINCS+-192s keypair (hash-only, PQ-safe)", tone: "muted" },
  { kind: "out", text: "pq_pk  = 0x9f2a…c714 (48 B)",       tone: "muted" },
  { kind: "out", text: "guardian = 0xC0ldStoR...ag3",       tone: "muted" },

  { kind: "cmd", text: "aegis deploy --all-chains" },
  { kind: "out", text: "ethereum   deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "bsc        deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "polygon    deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "arbitrum   deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "optimism   deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "base       deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "avalanche  deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "linea      deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "+ 4 more EVM chains … all same address ✓", tone: "ok" },
  { kind: "out", text: "starknet   deployed  0x05a7…8f91  ✓", tone: "ok" },

  { kind: "cmd", text: "aegis send --to 0xBEEF --amount 0.1 --chain base" },
  { kind: "out", text: "signing with SPHINCS+-192s …",      tone: "muted" },
  { kind: "out", text: "signature 16,224 bytes · verify gas 290k", tone: "muted" },
  { kind: "out", text: "tx 0x7a3f…c21e confirmed in 2.1s ✓", tone: "ok" },
  { kind: "out", text: "protocol fee: 0.00012 ETH (10% of gas)", tone: "muted" },

  { kind: "cmd", text: "aegis verify --self --chain all" },
  { kind: "out", text: "contract immutable          ✓", tone: "ok" },
  { kind: "out", text: "no proxy / no selfdestruct  ✓", tone: "ok" },
  { kind: "out", text: "guardian = your cold wallet ✓", tone: "ok" },
  { kind: "out", text: "max fee bps = 2000 (constant) ✓", tone: "ok" },
  { kind: "out", text: "deployer EOA burned on all chains ✓", tone: "ok" },
];

const TYPE_SPEED  = 24;   // ms per char for cmd lines
const OUT_DELAY   = 180;  // ms before out line appears
const CMD_PAUSE   = 420;  // ms pause after cmd before output

export default function Terminal() {
  const [lineIdx, setLineIdx] = useState(0);
  const [cmdText, setCmdText] = useState("");

  useEffect(() => {
    if (lineIdx >= SCRIPT.length) {
      // loop
      const t = setTimeout(() => {
        setLineIdx(0);
        setCmdText("");
      }, 4000);
      return () => clearTimeout(t);
    }
    const line = SCRIPT[lineIdx];
    if (line.kind === "cmd") {
      let i = 0;
      const target = line.text;
      setCmdText("");
      const iv = setInterval(() => {
        i++;
        setCmdText(target.slice(0, i));
        if (i >= target.length) {
          clearInterval(iv);
          setTimeout(() => setLineIdx((v) => v + 1), CMD_PAUSE);
        }
      }, TYPE_SPEED);
      return () => clearInterval(iv);
    } else {
      const t = setTimeout(() => setLineIdx((v) => v + 1), OUT_DELAY);
      return () => clearTimeout(t);
    }
  }, [lineIdx]);

  const rendered = SCRIPT.slice(0, lineIdx);

  return (
    <div className="glass terminal">
      <div className="terminal-head">
        <span className="terminal-dot td-r" />
        <span className="terminal-dot td-y" />
        <span className="terminal-dot td-g" />
        <span className="terminal-title">aegis@multichain · ~/wallet</span>
      </div>
      <div className="terminal-body">
        {rendered.map((l, i) =>
          l.kind === "cmd" ? (
            <div key={i} className="term-line">
              <span className="prompt">λ </span>
              <span className="cmd">{l.text}</span>
            </div>
          ) : (
            <div key={i} className="term-line">
              <span className={`out ${l.tone === "ok" ? "ok" : l.tone === "warn" ? "warn" : ""}`}>
                {l.text}
              </span>
            </div>
          )
        )}
        {lineIdx < SCRIPT.length && SCRIPT[lineIdx]?.kind === "cmd" && (
          <div className="term-line">
            <span className="prompt">λ </span>
            <span className="cmd">{cmdText}</span>
            <span className="cursor" />
          </div>
        )}
      </div>
    </div>
  );
}
