// Thin React hook over the SPHINCS+ Web Worker. Main thread never blocks.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

export type DerivedAddresses = {
  evmAddress: string; tronBase58: string; tronRawHex: string;
  cosmosOsmo: string; cosmosInj: string; cosmosNeutron: string;
  cosmosJuno: string; cosmosStargaze: string;
  solanaAddress: string; nearImplicit: string;
  aptosAddress: string; suiAddress: string;
  tonPreview: string; btcSegwit: string;
  pqPkHex: string; pqPkHashHex: string;
};

type WorkerResp = { id: number; ok: boolean; result?: unknown; error?: string };

export function useAegisWorker() {
  const workerRef = useRef<Worker | null>(null);
  const seqRef    = useRef(0);
  const pendingRef = useRef(new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>());

  useEffect(() => {
    const w = new Worker(new URL("./deriveWorker.ts", import.meta.url), { type: "module" });
    workerRef.current = w;
    w.addEventListener("message", (ev: MessageEvent<WorkerResp>) => {
      const { id, ok, result, error } = ev.data;
      const h = pendingRef.current.get(id);
      if (!h) return;
      pendingRef.current.delete(id);
      ok ? h.resolve(result) : h.reject(new Error(error ?? "worker error"));
    });
    return () => w.terminate();
  }, []);

  const call = useCallback(<T,>(req: Record<string, unknown>): Promise<T> => {
    const w = workerRef.current;
    if (!w) return Promise.reject(new Error("worker not ready"));
    const id = ++seqRef.current;
    return new Promise<T>((resolve, reject) => {
      pendingRef.current.set(id, { resolve: resolve as (v: unknown) => void, reject });
      w.postMessage({ id, ...req });
    });
  }, []);

  return useMemo(() => ({
    derive: (mnemonic: string, passphrase = "") =>
      call<{
        addresses: DerivedAddresses;
        slhPublicKey?: Uint8Array; slhSecretKey?: Uint8Array;
        ed25519SecretKey?: Uint8Array; ecdsaSecretKey?: Uint8Array;
      }>({ kind: "derive", mnemonic, passphrase }),
    sign: (mnemonic: string, digestHex: string, passphrase = "") =>
      call<{ signature: Uint8Array; publicKey: Uint8Array; tookMs: number }>(
        { kind: "sign", mnemonic, passphrase, digestHex }
      ),
    verify: (publicKey: Uint8Array, digest: Uint8Array, signature: Uint8Array) =>
      call<{ verified: boolean }>({ kind: "verify", publicKey, digest, signature }),
  }), [call]);
}

// Debounced hook that re-derives when mnemonic changes
export function useDerived(mnemonic: string, passphrase = ""): {
  addresses: DerivedAddresses | null; loading: boolean; error: string | null;
} {
  const worker = useAegisWorker();
  const [state, setState] = useState<{ addresses: DerivedAddresses | null; loading: boolean; error: string | null }>({
    addresses: null, loading: true, error: null,
  });

  useEffect(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true, error: null }));
    const t = setTimeout(() => {
      worker.derive(mnemonic, passphrase)
        .then((res) => { if (!cancelled) setState({ addresses: res.addresses, loading: false, error: null }); })
        .catch((e) => { if (!cancelled) setState({ addresses: null, loading: false, error: e.message }); });
    }, 200);  // debounce typing
    return () => { cancelled = true; clearTimeout(t); };
  }, [mnemonic, passphrase, worker]);

  return state;
}
