import { useEffect, useMemo, useState } from "react";
import { identity, isValidMnemonic, pqSign, pqVerify } from "../aegis/derive";
import { sha256 } from "@noble/hashes/sha256";
import CopyBtn from "./CopyBtn";

/**
 * Live FIPS 205 SLH-DSA-SHAKE-192s signing demo.
 * - Keygen from mnemonic (same seed as the address derivation).
 * - Sign arbitrary message, get a REAL 16,224-byte post-quantum signature.
 * - Verify in-browser.
 *
 * This proves the wallet is NOT a stub: signatures are produced by
 * @noble/post-quantum's FIPS 205 implementation (audited, deterministic,
 * verifiable by any compliant library — pqcrypto, OQS, reference impl).
 */
export default function PqSignDemo({ mnemonic }: { mnemonic: string }) {
  const [message, setMessage] = useState("Hello, post-quantum world.");
  const [sig, setSig] = useState<Uint8Array | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [elapsed, setElapsed] = useState<{ keygen?: number; sign?: number; verify?: number }>({});
  const [busy, setBusy] = useState(false);

  const ok = isValidMnemonic(mnemonic);

  // Keygen is pre-computed once per mnemonic
  const id = useMemo(() => {
    if (!ok) return null;
    try {
      const t = performance.now();
      const i = identity(mnemonic);
      // keygen time
      setElapsed((e) => ({ ...e, keygen: performance.now() - t }));
      return i;
    } catch { return null; }
  }, [mnemonic, ok]);

  // reset when inputs change
  useEffect(() => { setSig(null); setVerified(null); }, [message, mnemonic]);

  const run = async () => {
    if (!id) return;
    setBusy(true);
    // yield to the browser so the busy state renders
    await new Promise((r) => setTimeout(r, 10));
    const digest = sha256(new TextEncoder().encode(message));
    const t0 = performance.now();
    const s = pqSign(id, digest);
    const t1 = performance.now();
    const v = pqVerify(id.slhPublicKey, digest, s);
    const t2 = performance.now();
    setSig(s);
    setVerified(v);
    setElapsed((e) => ({ ...e, sign: t1 - t0, verify: t2 - t1 }));
    setBusy(false);
  };

  const sigPreview = useMemo(() => {
    if (!sig) return "";
    const hex = Array.from(sig).map((b) => b.toString(16).padStart(2, "0")).join("");
    return hex.slice(0, 96) + "…" + hex.slice(-32);
  }, [sig]);

  if (!ok) return null;

  const scheme = "SLH-DSA-SHAKE-192s (FIPS 205)";

  return (
    <div className="card pq-demo">
      <div className="pq-demo-head">
        <div>
          <div className="section-eyebrow" style={{ color: "var(--accent)" }}>Real PQ signature · in your browser</div>
          <h3>Prove the wallet is not a stub.</h3>
          <p>
            Keygen, sign, and verify a <code>{scheme}</code> signature from your
            mnemonic. All operations run locally via <code>@noble/post-quantum</code>
            (audited). Signatures verify under any compliant FIPS 205 library.
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
          {busy ? "signing…" : sig ? "sign again" : "sign with SLH-DSA-SHAKE-192s"}
        </button>
        <div className="pq-demo-meta">
          <span><b>SCHEME</b> {scheme}</span>
          <span><b>PK</b> {id?.slhPublicKey.length ?? 0} B</span>
          <span><b>SIG</b> {sig ? sig.length.toLocaleString() + " B" : "—"}</span>
          {elapsed.keygen !== undefined && <span><b>KEYGEN</b> {elapsed.keygen.toFixed(0)} ms</span>}
          {elapsed.sign   !== undefined && <span><b>SIGN</b> {elapsed.sign.toFixed(0)} ms</span>}
          {elapsed.verify !== undefined && <span><b>VERIFY</b> {elapsed.verify.toFixed(0)} ms</span>}
        </div>
      </div>

      {sig && (
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
              {Array.from(id!.slhPublicKey).map((b) => b.toString(16).padStart(2, "0")).join("")}
            </div>
            <CopyBtn
              value={Array.from(id!.slhPublicKey).map((b) => b.toString(16).padStart(2, "0")).join("")}
              label="copy"
            />
          </div>
          <div className="pq-demo-note">
            This signature is a real FIPS 205 artifact — you can verify it with any
            compliant implementation (<code>@noble/post-quantum</code>,
            {" "}<code>pqcrypto</code>, Open Quantum Safe <code>liboqs</code>, or the
            NIST reference impl). Try: save the <code>message</code>,{" "}
            <code>pk</code>, and <code>sig</code>, run them through{" "}
            <code>slh_dsa_shake_192s.verify(pk, sha256(message), sig)</code> in any
            environment — it will return <code>true</code>.
          </div>
        </div>
      )}
    </div>
  );
}
