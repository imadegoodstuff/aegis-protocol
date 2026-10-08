// Bench — every number here is measured on the visitor's device when they
// press Run. Nothing is simulated or pre-recorded.
//
// Protocol of the experiment:
//   1. hash throughput (keccak256, 64-byte input, pure JS)       → ns/hash
//   2. CCHS-K-20 keygen in the worker pool (top, recovery, subtree 0) → ms
//   3. sign operation #0 (first in subtree: two layers)           → ms, bytes
//   4. sign operation #1 (cached subtree: one layer)              → ms, bytes
//   5. local verification of both; tamper check                  → pass/fail
// The master key is random per run and discarded.

import { useEffect, useRef, useState } from "react";
import { keccak_256 } from "@noble/hashes/sha3";
import { cchsK, signatureBytes, toHex, type Tree } from "../aegis/cchs";
import { CchsPool } from "../aegis/cchsPool";

type Entry = { t: string; k: string; v: string; tone?: "ok" | "warn" | "muted" };

const now = () => new Date().toISOString().slice(11, 23);

const grp = (n: number) => n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, "\u2009");

export default function LabBench() {
  const [log, setLog] = useState<Entry[]>([]);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const poolRef = useRef<CchsPool | null>(null);
  const bodyRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => () => poolRef.current?.terminate(), []);
  useEffect(() => { bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight }); }, [log]);

  const push = (k: string, v: string, tone?: Entry["tone"]) => setLog((l) => [...l, { t: now(), k, v, tone }]);

  async function run() {
    if (running) return;
    setRunning(true); setDone(false); setLog([]);
    const yieldUi = () => new Promise((r) => setTimeout(r, 30));
    try {
      const hc = navigator.hardwareConcurrency || 4;
      push("device", `${hc} logical cores · ${navigator.userAgent.includes("Mobile") ? "mobile" : "desktop"} · ${navigator.platform}`, "muted");

      // 1. hash throughput
      await yieldUi();
      const buf = new Uint8Array(64).fill(7);
      const N = 20000;
      let t0 = performance.now();
      for (let i = 0; i < N; i++) keccak_256(buf);
      const perHash = (performance.now() - t0) * 1e6 / N;
      push("keccak256", `${grp(Math.round(perHash))} ns / hash (64 B input, pure JS, main thread)`);

      // 2. keygen
      const master = crypto.getRandomValues(new Uint8Array(32));
      const key = { master };
      if (!poolRef.current) poolRef.current = new CchsPool();
      const pool = poolRef.current;
      push("keygen", `CCHS-K-20 · ${pool.size} workers · 2 304 WOTS+ leaves · ~2.3 M hashes …`, "muted");
      await yieldUi();
      const cache = new Map<string, Tree>();
      const pub = await pool.keygen(key, "K", cache);
      push("keygen", `${(pub.tookMs / 1000).toFixed(2)} s · root ${toHex(pub.root).slice(0, 18)}… · recovery root ${toHex(pub.recRoot).slice(0, 10)}…`, "ok");

      // 3. sign #0
      const digest = (i: number) => cchsK.executeDigest({
        chainId: 1n, account: new Uint8Array(20).fill(0xaa), nonce: BigInt(i), idx: BigInt(i),
        target: new Uint8Array(20).fill(0xbe), value: 10n ** 18n, dataHash: keccak_256(new Uint8Array(0)),
      });
      const m0 = digest(0);
      await yieldUi();
      t0 = performance.now();
      const s0 = cchsK.sign(key, 0, m0, false, cache);
      const sign0 = performance.now() - t0;
      push("sign #0", `${sign0.toFixed(1)} ms · first in subtree · 2 layers · ${grp(signatureBytes(s0))} B`);

      // 4. sign #1
      const m1 = digest(1);
      t0 = performance.now();
      const s1 = cchsK.sign(key, 1, m1, true, cache);
      const sign1 = performance.now() - t0;
      push("sign #1", `${sign1.toFixed(1)} ms · subtree cached · 1 layer · ${grp(signatureBytes(s1))} B`);

      // 5. verify
      await yieldUi();
      t0 = performance.now();
      const r0 = cchsK.verify(pub, 0, m0, s0);
      const v0 = performance.now() - t0;
      t0 = performance.now();
      cchsK.verify(pub, 1, m1, s1, r0);
      const v1 = performance.now() - t0;
      push("verify", `#0 ${v0.toFixed(1)} ms (both layers) · #1 ${v1.toFixed(1)} ms (against cached R₀) · accepted`, "ok");

      // tamper: flip one bit of one chain value of #1
      const bad = { ...s1, l0: { wots: s1.l0.wots.map((w) => w.slice()), auth: s1.l0.auth } };
      bad.l0.wots[3][0] ^= 1;
      let rejected = false;
      try { cchsK.verify(pub, 1, m1, bad, r0); } catch { rejected = true; }
      push("tamper", rejected ? "one bit flipped in chain 3 → rejected (bad subtree root)" : "ACCEPTED — this is a bug", rejected ? "ok" : "warn");

      // replay: same signature, different message
      let replay = false;
      try { cchsK.verify(pub, 1, digest(7), s1, r0); } catch { replay = true; }
      push("front-run", replay ? "signature #1 against a different digest → rejected" : "ACCEPTED — this is a bug", replay ? "ok" : "warn");

      push("summary", `keygen ${(pub.tookMs / 1000).toFixed(2)} s · sign ${sign1.toFixed(0)} ms · verify ${v1.toFixed(0)} ms · sig ${grp(signatureBytes(s1))} B · assumption: keccak256 preimage resistance`, "ok");
      setDone(true);
    } catch (e) {
      push("error", (e as Error).message, "warn");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="card bench">
      <div className="bench-head">
        <div>
          <div className="section-eyebrow">Bench · measured on your device</div>
          <div className="bench-title">Run the protocol locally</div>
        </div>
        <button className="btn btn-primary" onClick={run} disabled={running}>
          {running ? "running…" : done ? "Run again" : "Run experiment"}
        </button>
      </div>
      <div className="bench-body mono" ref={bodyRef} aria-live="polite">
        {log.length === 0 && (
          <div className="bench-empty">
            keygen → sign (first-in-subtree) → sign (cached) → verify → tamper → front-run.
            <br />A random master key is generated for the run and discarded. Nothing leaves the page.
          </div>
        )}
        {log.map((e, i) => (
          <div key={i} className={`bench-line ${e.tone ?? ""}`}>
            <span className="bench-t">{e.t}</span>
            <span className="bench-k">{e.k}</span>
            <span className="bench-v">{e.v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
