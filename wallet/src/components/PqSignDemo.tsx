import { useMemo, useState } from "react";
import { isValidMnemonic } from "../aegis/derive";
import { useAegisWorker } from "../aegis/useAegisWorker";
import { sha256 } from "@noble/hashes/sha256";
import CopyBtn from "./CopyBtn";

/**
 * Live FIPS 205 SLH-DSA-SHAKE-192s signing demo — runs via Web Worker so the
 * UI stays responsive. Signatures verify under any compliant library.
 */
export default function PqSignDemo({ mnemonic }: { mnemonic: string }) {
  const worker = useAegisWorker();
  const [message, setMessage] = useState("Hello, post-quantum world.");
  const [sig, setSig] = useState<Uint8Array | null>(null);
  const [pk, setPk]   = useState<Uint8Array | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [elapsed, setElapsed] = useState<{ sign?: number; verify?: number }>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const ok = isValidMnemonic(mnemonic);

  const sigPreview = useMemo(() => {
    if (!sig) return "";
    let hex = ""; for (const b of sig) hex += b.toString(16).padStart(2, "0");
    return hex.slice(0, 96) + "…" + hex.slice(-32);
  }, [sig]);

  async function run() {
    setErr(null); setBusy(true);
    try {
      const digest = sha256(new TextEncoder().encode(message));
      let hex = "0x"; for (const b of digest) hex += b.toString(16).padStart(2, "0");
      const res = await worker.sign(mnemonic, hex);
      setSig(res.signature); setPk(res.publicKey); setElapsed({ sign: res.tookMs });
      const t0 = performance.now();
      const v = await worker.verify(res.publicKey, digest, res.signature);
      const t1 = performance.now();
      setVerified(v.verified); setElapsed({ sign: res.tookMs, verify: t1 - t0 });
    } catch (e) { setErr((e as Error).message); }
    finally { setBusy(false); }
  }

  if (!ok) return null;

  return (
    <div className="card pq-demo">
      <div className="pq-demo-head">
        <div>
          <div className="section-eyebrow" style={{ color: "var(--accent)" }}>Real PQ signature · in your browser</div>
          <h3>Prove the wallet is not a stub.</h3>
          <p>
            Sign and verify a <code>SLH-DSA-SHAKE-192s (FIPS 205)</code> signature from your
            mnemonic. Runs in a Web Worker via <code>@noble/post-quantum</code> (audited).
            Verifies under any compliant FIPS 205 library.
          </p>
        </div>
      </div>

      <div className="derive-input">
        <label className="derive-label">
          <span>Message to sign</span>
          <textarea
            className="derive-area"
            rows={2}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
        </label>
      </div>

      <div className="pq-demo-actions">
        <button className="btn btn-primary" onClick={run} disabled={busy}>
          {busy ? "signing in worker…" : sig ? "sign again" : "sign with SLH-DSA-SHAKE-192s"}
        </button>
        <div className="pq-demo-meta">
          <span><b>SCHEME</b> SLH-DSA-SHAKE-192s</span>
          <span><b>PK</b> {pk?.length ?? 48} B</span>
          <span><b>SIG</b> {sig ? sig.length.toLocaleString() + " B" : "—"}</span>
          {elapsed.sign !== undefined && <span><b>SIGN</b> {elapsed.sign.toFixed(0)} ms</span>}
          {elapsed.verify !== undefined && <span><b>VERIFY</b> {elapsed.verify.toFixed(0)} ms</span>}
        </div>
      </div>

      {err && <div className="swap-note err">{err}</div>}

      {sig && pk && (
        <div className="pq-demo-out">
          <div className="pq-demo-row">
            <div className="pq-demo-k">signature</div>
            <div className="pq-demo-v mono">{sigPreview}</div>
            <CopyBtn
              value={Array.from(sig).map((b) => b.toString(16).padStart(2, "0")).join("")}
              label="copy hex"
            />
          </div>
          <div className="pq-demo-row">
            <div className="pq-demo-k">verify</div>
            <div className="pq-demo-v mono">
              {verified
                ? <span style={{ color: "var(--accent)" }}>✓ VERIFIED by slh_dsa_shake_192s.verify()</span>
                : <span style={{ color: "var(--warn)" }}>✗ FAILED</span>}
            </div>
          </div>
          <div className="pq-demo-row">
            <div className="pq-demo-k">public key</div>
            <div className="pq-demo-v mono">
              {Array.from(pk).map((b) => b.toString(16).padStart(2, "0")).join("")}
            </div>
            <CopyBtn
              value={Array.from(pk).map((b) => b.toString(16).padStart(2, "0")).join("")}
              label="copy"
            />
          </div>
          <div className="pq-demo-note">
            This signature is a real FIPS 205 artifact — verify with any compliant
            implementation (<code>@noble/post-quantum</code>, <code>pqcrypto</code>,
            Open Quantum Safe <code>liboqs</code>, or the NIST reference).
          </div>
        </div>
      )}
    </div>
  );
}
