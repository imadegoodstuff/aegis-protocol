// Web Worker: runs expensive SLH-DSA keygen off the main thread so the UI
// never freezes. Vite will bundle this as a separate chunk via `?worker`.

import { identity, pqSign, pqVerify } from "./derive";

type ReqDerive = { id: number; kind: "derive"; mnemonic: string; passphrase?: string };
type ReqSign   = { id: number; kind: "sign";   mnemonic: string; passphrase?: string; digestHex: string };
type ReqVerify = { id: number; kind: "verify"; publicKey: Uint8Array; digest: Uint8Array; signature: Uint8Array };
type Req = ReqDerive | ReqSign | ReqVerify;

function fromHex(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
function toHex(b: Uint8Array): string {
  let s = ""; for (const x of b) s += x.toString(16).padStart(2, "0"); return s;
}

self.addEventListener("message", (ev: MessageEvent<Req>) => {
  const req = ev.data;
  try {
    if (req.kind === "derive") {
      const id = identity(req.mnemonic, req.passphrase ?? "");
      // transfer the public bits + addresses; keep secret keys inside worker life if needed
      self.postMessage({
        id: req.id,
        ok: true,
        result: {
          slhPublicKeyHex: toHex(id.slhPublicKey),
          slhPkHashHex:    toHex(new Uint8Array(32)), // computed in main (keccak)
          // The address object has all the per-chain derivations
          addresses: {
            evmAddress: id.evmAddress,
            tronBase58: id.tronBase58,
            tronRawHex: id.tronRawHex,
            cosmosOsmo: id.cosmosOsmo,
            cosmosInj: id.cosmosInj,
            cosmosNeutron: id.cosmosNeutron,
            cosmosJuno: id.cosmosJuno,
            cosmosStargaze: id.cosmosStargaze,
            solanaAddress: id.solanaAddress,
            nearImplicit: id.nearImplicit,
            aptosAddress: id.aptosAddress,
            suiAddress: id.suiAddress,
            tonPreview: id.tonPreview,
            btcSegwit: id.btcSegwit,
            pqPkHex: id.pqPkHex,
            pqPkHashHex: id.pqPkHashHex,
          },
          // return the secret key material too so the main thread can sign if it wants
          slhSecretKey: id.slhSecretKey,
          ed25519SecretKey: id.ed25519SecretKey,
          ecdsaSecretKey:   id.ecdsaSecretKey,
        },
      });
    } else if (req.kind === "sign") {
      const id = identity(req.mnemonic, req.passphrase ?? "");
      const digest = fromHex(req.digestHex);
      const t0 = performance.now();
      const sig = pqSign(id, digest);
      const t1 = performance.now();
      self.postMessage({ id: req.id, ok: true, result: {
        signature: sig,
        publicKey: id.slhPublicKey,
        tookMs: t1 - t0,
      } });
    } else if (req.kind === "verify") {
      const ok = pqVerify(req.publicKey, req.digest, req.signature);
      self.postMessage({ id: req.id, ok: true, result: { verified: ok } });
    } else {
      self.postMessage({ id: (req as { id: number }).id, ok: false, error: "unknown kind" });
    }
  } catch (e) {
    self.postMessage({ id: req.id, ok: false, error: (e as Error).message });
  }
});

export {};  // make this a module
