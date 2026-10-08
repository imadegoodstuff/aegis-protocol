import { useEffect, useRef, useState } from "react";

type Line =
  | { kind: "cmd"; parts: Array<{ t: string; c?: "verb" | "flag" | "arg" | "str" }> }
  | { kind: "out"; text: string; tone?: "ok" | "warn" | "muted" };

// Each cmd is tokenized so we can color verb/flag/arg/string.
const C = (verb: string, ...rest: Array<{ t: string; c?: "flag" | "arg" | "str" }>): Line =>
  ({ kind: "cmd", parts: [{ t: verb, c: "verb" }, ...rest] });
const F = (t: string) => ({ t, c: "flag" as const });
const A = (t: string) => ({ t, c: "arg"  as const });
const S = (t: string) => ({ t, c: "str"  as const });

const SCRIPT: Line[] = [
  C("aegis identity new", F(" --words 24")),
  { kind: "out", text: "generating 256-bit BIP-39 entropy …", tone: "muted" },
  { kind: "out", text: "deriving SPHINCS+-192s keypair (hash-only, PQ-safe)", tone: "muted" },
  { kind: "out", text: "pq_pk       0x9f2a…c714  (48 B)",       tone: "muted" },
  { kind: "out", text: "pq_pk_hash  0x368d…9196",               tone: "muted" },
  { kind: "out", text: "guardian    0xC0ldStoR...ag3",          tone: "muted" },

  C("aegis deploy", F(" --all-chains"), F(" --verifier"), A(" prod")),
  { kind: "out", text: "ethereum   deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "bsc        deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "polygon    deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "arbitrum   deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "optimism   deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "base       deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "avalanche  deployed  0xAEG5…b2E1  ✓", tone: "ok" },
  { kind: "out", text: "+ 5 more EVM chains · all SAME address ✓", tone: "ok" },
  { kind: "out", text: "starknet   deployed  0x05a7…8f91  ✓", tone: "ok" },

  C("aegis send", F(" --chain"), A(" base"), F(" --to"), S(" 0xBEEF…1234"), F(" --amount"), A(" 0.1")),
  { kind: "out", text: "signing with SPHINCS+-192s …",      tone: "muted" },
  { kind: "out", text: "signature 16,224 bytes · verify gas 290k", tone: "muted" },
  { kind: "out", text: "tx 0x7a3f…c21e confirmed in 2.1s ✓", tone: "ok" },
  { kind: "out", text: "protocol fee: 0.00012 ETH (10% of gas)", tone: "muted" },

  C("aegis verify", F(" --self"), F(" --chain"), A(" all")),
  { kind: "out", text: "contract immutable          ✓", tone: "ok" },
  { kind: "out", text: "no proxy / no selfdestruct  ✓", tone: "ok" },
  { kind: "out", text: "guardian = your cold wallet ✓", tone: "ok" },
  { kind: "out", text: "max fee bps = 2000 (constant) ✓", tone: "ok" },
  { kind: "out", text: "deployer EOA burned on all chains ✓", tone: "ok" },
];

const TYPE_SPEED = 45;   // slower, more theatrical
const OUT_DELAY  = 240;
const CMD_PAUSE  = 700;

export default function Terminal() {
  const [lineIdx, setLineIdx] = useState(0);
  const [typed, setTyped] = useState("");
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (lineIdx >= SCRIPT.length) {
      const t = setTimeout(() => { setLineIdx(0); setTyped(""); }, 6000);
      return () => clearTimeout(t);
    }
    const line = SCRIPT[lineIdx];
    if (line.kind === "cmd") {
      const full = line.parts.map((p) => p.t).join("");
      let i = 0;
      setTyped("");
      const iv = setInterval(() => {
        i++;
        setTyped(full.slice(0, i));
        if (i >= full.length) {
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

  // auto-scroll to bottom
  useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [lineIdx, typed]);

  // slice typed into coloured spans in order of the full tokens
  const renderTypingCmd = (parts: Line & { kind: "cmd" }) => {
    let remaining = typed.length;
    const nodes: React.ReactNode[] = [];
    for (let i = 0; i < parts.parts.length; i++) {
      const p = parts.parts[i];
      if (remaining <= 0) break;
      const take = p.t.slice(0, Math.min(remaining, p.t.length));
      nodes.push(
        <span key={i} className={p.c ? `cmd-${p.c}` : undefined}>{take}</span>
      );
      remaining -= p.t.length;
    }
    return nodes;
  };

  const rendered = SCRIPT.slice(0, lineIdx);
  const current = SCRIPT[lineIdx];
  const isTypingCmd = current && current.kind === "cmd";

  return (
    <div className="card terminal cinematic">
      <div className="terminal-head">
        <span className="td td-r" />
        <span className="td td-y" />
        <span className="td td-g" />
        <span className="terminal-title"><span className="k">aegis@multichain:</span>~/wallet · <span className="k">SPHINCS+-192s</span></span>
      </div>
      <div className="terminal-body" ref={bodyRef}>
        {rendered.map((l, i) => {
          if (l.kind === "cmd") {
            return (
              <div key={i} className="term-line">
                <span className="prompt">λ </span>
                <span className="cmd">
                  {l.parts.map((p, j) => <span key={j} className={p.c ? `cmd-${p.c}` : undefined}>{p.t}</span>)}
                </span>
              </div>
            );
          }
          return (
            <div key={i} className="term-line">
              <span className={`out ${l.tone === "ok" ? "ok" : l.tone === "warn" ? "warn" : ""}`}>{l.text}</span>
            </div>
          );
        })}
        {isTypingCmd && (
          <div className="term-line active">
            <span className="prompt">λ </span>
            <span className="cmd">
              {renderTypingCmd(current as Extract<Line, { kind: "cmd" }>)}
              <span className="cursor" />
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
