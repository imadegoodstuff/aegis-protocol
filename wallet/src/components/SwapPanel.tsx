// Hybrid account line (AegisAccountV2): ECDSA for daily operations, a
// post-quantum commitment for one-shot recovery. The contracts and tests live
// in evm/; nothing of this line is deployed on any chain, so this card states
// the position and shows the commitment the mnemonic would carry. The live,
// hash-only path is the Protect panel above.

import { useMemo } from "react";
import { keccak256, type Hex } from "viem";
import { identity, isValidMnemonic } from "../aegis/derive";
import CopyBtn from "./CopyBtn";

const REPO = "https://github.com/imadegoodstuff/aegis-protocol";

export default function SwapPanel({ mnemonic }: { mnemonic: string }) {
  const pqPkHash = useMemo<Hex | null>(() => {
    if (!isValidMnemonic(mnemonic)) return null;
    try { return keccak256(identity(mnemonic).slhPublicKey); } catch { return null; }
  }, [mnemonic]);

  return (
    <div className="card swap-panel">
      <div className="swap-head">
        <div className="section-eyebrow">Hybrid account · AegisAccountV2 · source only</div>
        <h3>ECDSA every day, a hash-based key in reserve.</h3>
        <p>
          For small or frequent payments the 2.5 KB CCHS signature is the wrong tool. The hybrid account keeps a
          normal ECDSA owner and commits to a post-quantum public key that can rotate the owner once if ECDSA is
          ever broken. <code>AegisAccountV2</code>, its factory and <code>UpgradeHelper</code> are in{" "}
          <a href={`${REPO}/tree/main/evm/src`} target="_blank" rel="noreferrer">evm/src</a> with tests; they are
          not deployed on any chain and this page does not deploy them.
        </p>
      </div>
      {pqPkHash && (
        <div className="swap-grid">
          <div className="swap-cell">
            <div className="k">Commitment this mnemonic would carry</div>
            <div className="v mono swap-hash">{pqPkHash} <CopyBtn value={pqPkHash} /></div>
          </div>
          <div className="swap-cell">
            <div className="k">Recovery signature</div>
            <div className="v">SLH-DSA-SHAKE-192s today (FIPS 205) · CCHS planned as the replacement</div>
          </div>
        </div>
      )}
    </div>
  );
}
