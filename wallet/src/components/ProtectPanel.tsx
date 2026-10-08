// Protect: one hash-only identity, one click per chain.
//
// 1. Keys for both CCHS sets are generated in the worker pool from the mnemonic.
// 2. The EVM account address is predicted offline (same on every EVM chain).
// 3. Each chain row reads live state over public RPC: factory present?
//    account deployed? balance.
// 4. "Protect" switches the injected wallet to that chain and sends one
//    transaction: AegisCCHSFactory.deploy{value}(root, recRoot, false).
//    Nothing is signed or sent without the user's wallet confirmation.

import { useEffect, useMemo, useRef, useState } from "react";
import type { Address, Chain, Hex } from "viem";
import { formatEther, parseEther } from "viem";
import {
  detectInjected, requestAccounts, getChainId, switchChain, makePublicClient, makeWalletClient, shortAddr, PROTECT_CHAINS,
} from "../aegis/wallet";
import { isValidMnemonic } from "../aegis/derive";
import { CchsPool } from "../aegis/cchsPool";
import { deriveCchsIdentity, FACTORY_ABI, FACTORY_ADDRESS, type CchsIdentity } from "../aegis/cchsAccount";
import CopyBtn from "./CopyBtn";

type ChainState = {
  factory: "unknown" | "absent" | "present";
  account: "unknown" | "absent" | "deployed";
  balance: bigint | null;
  error?: string;
};

type RowAction = { phase: "idle" | "switching" | "confirm" | "pending" | "done" | "error"; tx?: Hex; msg?: string };

const NON_EVM = [
  { name: "Solana", set: "S-20", status: "program source in solana/; not deployed" },
  { name: "Cosmos (CosmWasm)", set: "S-20", status: "contract source in cosmwasm/; not deployed" },
  { name: "NEAR", set: "S-20", status: "contract source in near/; not deployed" },
  { name: "Aptos / Sui", set: "S-20", status: "Move modules in aptos/, sui/; not deployed" },
  { name: "Starknet", set: "S-20", status: "Cairo source in cairo/; not deployed" },
  { name: "TON", set: "S-20", status: "FunC source in ton/; not deployed" },
  { name: "Bitcoin", set: "WOTS+ tapleaf", status: "needs OP_CAT for transaction binding (BIP-347, not active)" },
];

export default function ProtectPanel({ mnemonic }: { mnemonic: string }) {
  const valid = isValidMnemonic(mnemonic);
  const poolRef = useRef<CchsPool | null>(null);
  const [id, setId] = useState<CchsIdentity | null>(null);
  const [genMs, setGenMs] = useState<number | null>(null);
  const [genErr, setGenErr] = useState<string | null>(null);
  const [states, setStates] = useState<Record<number, ChainState>>({});
  const [actions, setActions] = useState<Record<number, RowAction>>({});
  const [amount, setAmount] = useState("");
  const [wallet, setWallet] = useState<{ account: Address; chainId: number } | null>(null);

  useEffect(() => {
    poolRef.current = new CchsPool();
    return () => poolRef.current?.terminate();
  }, []);

  // Derive identity (debounced) whenever the mnemonic changes.
  useEffect(() => {
    if (!valid) { setId(null); return; }
    let cancelled = false;
    setId(null); setGenMs(null); setGenErr(null);
    const t = setTimeout(async () => {
      try {
        const pool = poolRef.current!;
        const res = await deriveCchsIdentity(mnemonic, pool);
        if (!cancelled) { setId(res); setGenMs(res.tookMs); }
      } catch (e) {
        if (!cancelled) setGenErr((e as Error).message);
      }
    }, 300);
    return () => { cancelled = true; clearTimeout(t); };
  }, [mnemonic, valid]);

  // Read chain state for every EVM chain once the address is known.
  useEffect(() => {
    if (!id) { setStates({}); return; }
    let cancelled = false;
    const addr = id.k.address;
    for (const chain of PROTECT_CHAINS) {
      (async () => {
        const pub = makePublicClient(chain);
        try {
          const [fc, ac, bal] = await Promise.all([
            pub.getCode({ address: FACTORY_ADDRESS }),
            pub.getCode({ address: addr }),
            pub.getBalance({ address: addr }),
          ]);
          if (cancelled) return;
          setStates((s) => ({ ...s, [chain.id]: {
            factory: fc && fc !== "0x" ? "present" : "absent",
            account: ac && ac !== "0x" ? "deployed" : "absent",
            balance: bal,
          } }));
        } catch (e) {
          if (cancelled) return;
          const err = e as { shortMessage?: string; message: string };
          setStates((s) => ({ ...s, [chain.id]: { factory: "unknown", account: "unknown", balance: null, error: err.shortMessage ?? err.message } }));
        }
      })();
    }
    return () => { cancelled = true; };
  }, [id, actions]);

  const walletPresent = typeof window !== "undefined" && !!detectInjected();

  async function protect(chain: Chain) {
    if (!id) return;
    const set = (a: RowAction) => setActions((s) => ({ ...s, [chain.id]: a }));
    try {
      set({ phase: "switching" });
      let w = wallet;
      if (!w) {
        const account = await requestAccounts();
        const chainId = await getChainId();
        w = { account, chainId }; setWallet(w);
      }
      if (w.chainId !== chain.id) { await switchChain(chain.id); w = { ...w, chainId: chain.id }; setWallet(w); }
      set({ phase: "confirm" });
      const wc = makeWalletClient(chain, w.account);
      const value = amount && Number(amount) > 0 ? parseEther(amount) : 0n;
      const tx = await wc.writeContract({
        address: FACTORY_ADDRESS, abi: FACTORY_ABI, functionName: "deploy",
        args: [id.k.root, id.k.recRoot, false], value, chain, account: w.account,
      });
      set({ phase: "pending", tx });
      await makePublicClient(chain).waitForTransactionReceipt({ hash: tx });
      set({ phase: "done", tx });
    } catch (e) {
      set({ phase: "error", msg: (e as { shortMessage?: string }).shortMessage ?? (e as Error).message });
    }
  }

  const protectedCount = useMemo(() => Object.values(states).filter((s) => s.account === "deployed").length, [states]);

  if (!valid) return null;

  return (
    <div className="card swap-panel protect-panel">
      <div className="swap-head">
        <div className="section-eyebrow">Protect · hash-only account</div>
        <h3>One key. Same address on every EVM chain. One click each.</h3>
        <p>
          Your mnemonic derives a CCHS master key. The <code>CCHS-K-20</code> roots fix your account address through a
          CREATE2 factory that lives at the same address on every EVM chain, so the address below is yours before anything
          is deployed. <strong>Protect</strong> sends one transaction: create the account and move ETH into it. Every later
          operation from that account is a hash-based signature; no elliptic curves anywhere.
        </p>
      </div>

      {!id && !genErr && (
        <div className="swap-note">generating hash-based keys in {poolRef.current?.size ?? "…"} workers…</div>
      )}
      {genErr && <div className="swap-note err">{genErr}</div>}

      {id && (
        <>
          <div className="swap-grid">
            <div className="swap-cell">
              <div className="k">Post-quantum account (all EVM chains)</div>
              <div className="v mono">{id.k.address} <CopyBtn value={id.k.address} /></div>
            </div>
            <div className="swap-cell">
              <div className="k">K-20 root · recovery root</div>
              <div className="v mono">{shortAddr(id.k.root)} · {shortAddr(id.k.recRoot)}</div>
            </div>
            <div className="swap-cell">
              <div className="k">S-20 root (non-EVM chains)</div>
              <div className="v mono">{shortAddr(id.s.root)} · {shortAddr(id.s.recRoot)}</div>
            </div>
            <div className="swap-cell">
              <div className="k">Keygen</div>
              <div className="v">{genMs != null ? `${(genMs / 1000).toFixed(2)} s · ${poolRef.current?.size} workers` : "—"}</div>
            </div>
          </div>

          <div className="swap-badges">
            <span className="chip chip-accent">2^20 signatures · 256 recoveries · SHA-256 / keccak only</span>
            <span className="chip">{protectedCount} of {PROTECT_CHAINS.length} EVM chains protected</span>
          </div>

          <label className="swap-amount">
            <span>ETH to move in with each Protect</span>
            <input type="number" step="0.001" min="0" placeholder="0.0" value={amount} onChange={(e) => setAmount(e.target.value)} />
            <span className="hint">leave empty = create the account only</span>
          </label>

          <div className="protect-rows">
            {PROTECT_CHAINS.map((chain) => {
              const st = states[chain.id];
              const act = actions[chain.id] ?? { phase: "idle" };
              const sym = chain.nativeCurrency.symbol;
              let status: string;
              if (!st) status = "reading…";
              else if (st.error) status = `rpc: ${st.error}`;
              else if (st.account === "deployed") status = `protected · ${formatEther(st.balance ?? 0n)} ${sym}`;
              else if (st.factory === "absent") status = "factory not yet published on this chain";
              else status = st.balance && st.balance > 0n ? `address holds ${formatEther(st.balance)} ${sym}, account not deployed` : "ready";
              const canProtect = walletPresent && st && st.factory === "present" && act.phase !== "pending" && act.phase !== "switching" && act.phase !== "confirm";
              return (
                <div className="protect-row" key={chain.id}>
                  <div className="protect-chain">
                    <span className="protect-name">{chain.name}</span>
                    <span className="protect-status">{status}</span>
                    {act.phase === "error" && <span className="protect-err">{act.msg}</span>}
                    {act.tx && <span className="protect-tx mono">{shortAddr(act.tx)}</span>}
                  </div>
                  <button
                    className={`btn ${st?.account === "deployed" ? "" : "btn-primary"} btn-sm`}
                    disabled={!canProtect}
                    onClick={() => protect(chain)}
                    title={!walletPresent ? "Install an injected wallet" : st?.factory !== "present" ? "The factory has not been deployed on this chain yet" : ""}
                  >
                    {act.phase === "switching" ? "switching…" : act.phase === "confirm" ? "confirm in wallet…" : act.phase === "pending" ? "pending…"
                      : st?.account === "deployed" ? (amount && Number(amount) > 0 ? `Add ${amount} ${sym}` : "Protected") : "Protect"}
                  </button>
                </div>
              );
            })}
          </div>

          <details className="protect-more">
            <summary>Other chains (CCHS-S-20)</summary>
            <div className="protect-rows">
              {NON_EVM.map((c) => (
                <div className="protect-row" key={c.name}>
                  <div className="protect-chain">
                    <span className="protect-name">{c.name}</span>
                    <span className="protect-status">{c.set} · {c.status}</span>
                  </div>
                  <button className="btn btn-sm" disabled>Not yet</button>
                </div>
              ))}
            </div>
          </details>

          {!walletPresent && (
            <div className="swap-note warn">
              Protect needs an injected EVM wallet (MetaMask, Rabby, Trust) to pay for the deployment. The address above is
              already yours; anyone can fund it now and deploy later.
            </div>
          )}
        </>
      )}
    </div>
  );
}
