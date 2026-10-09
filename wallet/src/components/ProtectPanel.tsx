// Protect: one hash-only identity, one click per chain, any asset.
//
// 1. Keys for both CCHS sets are generated in the worker pool from the mnemonic.
// 2. The EVM account address is predicted offline (same on every EVM chain).
// 3. Each chain row reads live state over public RPC: factory present?
//    account deployed? native balance, balances of the ERC-20s you listed.
// 4. "Protect" switches the injected wallet to that chain and sends one
//    transaction: AegisCCHSFactory.deployAndMove{value}(root, recRoot, false, erc20s)
//    (after the ERC-20 approvals it needs). On an existing account it moves
//    the assets in with plain transfers instead.
// 5. "Spend" moves anything back out: the digest is computed locally, checked
//    against the contract's nextDigest, signed with the CCHS key, and the
//    `execute` call is relayed by the injected wallet, which only pays gas.
//    Nothing is signed or sent without the user's wallet confirmation.

import { useEffect, useMemo, useRef, useState } from "react";
import type { Address, Chain, Hex } from "viem";
import { encodeFunctionData, erc20Abi, formatEther, formatUnits, hexToBytes, isAddress, keccak256, parseEther, parseUnits } from "viem";
import {
  detectInjected, requestAccounts, getChainId, switchChain, makePublicClient, makeWalletClient, shortAddr, PROTECT_CHAINS,
} from "../aegis/wallet";
import { isValidMnemonic } from "../aegis/derive";
import { CchsPool } from "../aegis/cchsPool";
import { deriveCchsIdentity, ACCOUNT_ABI, FACTORY_ABI, FACTORY_ADDRESS, DETERMINISTIC_PROXY, FACTORY_PUBLISH_DATA, type CchsIdentity } from "../aegis/cchsAccount";
import { cchsK, H, toAbiLayerSig, EMPTY_LAYER_SIG, signatureBytes } from "../aegis/cchs";
import CopyBtn from "./CopyBtn";

type TokenState = { symbol: string; decimals: number; eoa: bigint; account: bigint; allowance: bigint };

type ChainState = {
  factory: "unknown" | "absent" | "present";
  proxy: "unknown" | "absent" | "present";
  account: "unknown" | "absent" | "deployed";
  balance: bigint | null;
  tokens: Record<Address, TokenState>;
  error?: string;
};

type RowAction = { phase: "idle" | "switching" | "confirm" | "pending" | "done" | "error"; tx?: Hex; msg?: string; step?: string };

type SpendState = { phase: "idle" | "reading" | "signing" | "confirm" | "pending" | "done" | "error"; msg?: string; tx?: Hex; bytes?: number; layers?: number };

const NON_EVM = [
  { name: "Solana", set: "C-20", status: "single-packet program in solana/: cache_subtree once per 1 024 operations, then one 864 B signature per execute (v0 tx with lookup table, 1 082 B); fixture-tested, not deployed" },
  { name: "TRON", set: "K-20 / S-20", status: "same contracts built for the TVM in tron/ (byte-identical init code, 0x41 CREATE2 predictor); not published on Nile or mainnet" },
  { name: "Osmosis · Injective · Neutron · Juno · Stargaze", set: "S-20", status: "CosmWasm contract in cosmwasm/, compiled in CI; not uploaded on any chain (Osmosis and Injective also require governance for code upload)" },
  { name: "NEAR", set: "S-20", status: "contract source in near/, compiled in CI; not deployed" },
  { name: "Aptos / Sui", set: "S-20", status: "Move modules in aptos/ (resource account, zeroed auth key, no signer in execute) and sui/ (any Coin<T> vault); immutable publication documented; fixture + end-to-end tests in CI; not published" },
  { name: "Starknet", set: "S-20", status: "Cairo account in cairo/, built and tested in CI; not declared" },
  { name: "TON", set: "S-20", status: "FunC account in ton/, sandbox-tested; not deployed" },
  { name: "Bitcoin", set: "WOTS+ tapleaf", status: "no construction under current consensus binds a hash-based witness to a transaction (CCHS.spec.md 7.1); needs OP_CAT (BIP-347). Address derived here is BIP-84 P2WPKH, single-use, not labelled post-quantum" },
];

function parseTokens(s: string): Address[] {
  const out: Address[] = [];
  for (const raw of s.split(/[\s,;]+/)) {
    const t = raw.trim();
    if (t && isAddress(t) && !out.includes(t as Address)) out.push(t as Address);
  }
  return out;
}

export default function ProtectPanel({ mnemonic }: { mnemonic: string }) {
  const valid = isValidMnemonic(mnemonic);
  const poolRef = useRef<CchsPool | null>(null);
  const [id, setId] = useState<CchsIdentity | null>(null);
  const [genMs, setGenMs] = useState<number | null>(null);
  const [genErr, setGenErr] = useState<string | null>(null);
  const [states, setStates] = useState<Record<number, ChainState>>({});
  const [actions, setActions] = useState<Record<number, RowAction>>({});
  const [amount, setAmount] = useState("");
  const [tokenText, setTokenText] = useState("");
  const [wallet, setWallet] = useState<{ account: Address; chainId: number } | null>(null);
  const [refresh, setRefresh] = useState(0);

  // Spend form
  const [spendChain, setSpendChain] = useState<number | "">("");
  const [spendAsset, setSpendAsset] = useState("native");
  const [spendTo, setSpendTo] = useState("");
  const [spendAmt, setSpendAmt] = useState("");
  const [spend, setSpend] = useState<SpendState>({ phase: "idle" });

  const tokens = useMemo(() => parseTokens(tokenText), [tokenText]);

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
    const eoa = wallet?.account;
    for (const chain of PROTECT_CHAINS) {
      (async () => {
        const pub = makePublicClient(chain);
        try {
          const [fc, px, ac, bal] = await Promise.all([
            pub.getCode({ address: FACTORY_ADDRESS }),
            pub.getCode({ address: DETERMINISTIC_PROXY }),
            pub.getCode({ address: addr }),
            pub.getBalance({ address: addr }),
          ]);
          const toks: Record<Address, TokenState> = {};
          await Promise.all(tokens.map(async (t) => {
            try {
              const [symbol, decimals, accountBal, eoaBal, allowance] = await Promise.all([
                pub.readContract({ address: t, abi: erc20Abi, functionName: "symbol" }),
                pub.readContract({ address: t, abi: erc20Abi, functionName: "decimals" }),
                pub.readContract({ address: t, abi: erc20Abi, functionName: "balanceOf", args: [addr] }),
                eoa ? pub.readContract({ address: t, abi: erc20Abi, functionName: "balanceOf", args: [eoa] }) : Promise.resolve(0n),
                eoa ? pub.readContract({ address: t, abi: erc20Abi, functionName: "allowance", args: [eoa, FACTORY_ADDRESS] }) : Promise.resolve(0n),
              ]);
              toks[t] = { symbol, decimals, account: accountBal, eoa: eoaBal, allowance };
            } catch { /* not an ERC-20 on this chain */ }
          }));
          if (cancelled) return;
          setStates((s) => ({ ...s, [chain.id]: {
            factory: fc && fc !== "0x" ? "present" : "absent",
            proxy: px && px !== "0x" ? "present" : "absent",
            account: ac && ac !== "0x" ? "deployed" : "absent",
            balance: bal,
            tokens: toks,
          } }));
        } catch (e) {
          if (cancelled) return;
          const err = e as { shortMessage?: string; message: string };
          setStates((s) => ({ ...s, [chain.id]: { factory: "unknown", proxy: "unknown", account: "unknown", balance: null, tokens: {}, error: err.shortMessage ?? err.message } }));
        }
      })();
    }
    return () => { cancelled = true; };
  }, [id, tokens, wallet, refresh]);

  const walletPresent = typeof window !== "undefined" && !!detectInjected();

  async function connect(chain: Chain) {
    let w = wallet;
    if (!w) {
      const account = await requestAccounts();
      const chainId = await getChainId();
      w = { account, chainId }; setWallet(w);
    }
    if (w.chainId !== chain.id) { await switchChain(chain.id); w = { ...w, chainId: chain.id }; setWallet(w); }
    return w;
  }

  async function protect(chain: Chain) {
    if (!id) return;
    const set = (a: RowAction) => setActions((s) => ({ ...s, [chain.id]: a }));
    const st = states[chain.id];
    try {
      set({ phase: "switching" });
      const w = await connect(chain);
      const wc = makeWalletClient(chain, w.account);
      const pub = makePublicClient(chain);
      const value = amount && Number(amount) > 0 ? parseEther(amount) : 0n;
      const movable = tokens.filter((t) => (st?.tokens[t]?.eoa ?? 0n) > 0n);
      let tx: Hex;

      if (st?.account === "deployed") {
        // Existing account: plain transfers in. Each one is a wallet confirmation.
        for (const t of movable) {
          const ts = st.tokens[t];
          set({ phase: "confirm", step: `move ${formatUnits(ts.eoa, ts.decimals)} ${ts.symbol}` });
          const h = await wc.writeContract({ address: t, abi: erc20Abi, functionName: "transfer", args: [id.k.address, ts.eoa], chain, account: w.account });
          set({ phase: "pending", tx: h, step: `move ${ts.symbol}` });
          await pub.waitForTransactionReceipt({ hash: h });
        }
        if (value === 0n && movable.length === 0) { set({ phase: "done" }); setRefresh((n) => n + 1); return; }
        if (value > 0n) {
          set({ phase: "confirm", step: `move ${amount} ${chain.nativeCurrency.symbol}` });
          tx = await wc.sendTransaction({ to: id.k.address, value, chain, account: w.account });
          set({ phase: "pending", tx });
          await pub.waitForTransactionReceipt({ hash: tx });
          set({ phase: "done", tx });
        } else set({ phase: "done" });
        setRefresh((n) => n + 1);
        return;
      }

      // Factory missing on this chain: publish it through the deterministic proxy first.
      // Anyone may do this; the address is fixed by (salt, init code), not by the sender.
      if (st?.factory === "absent") {
        if (st.proxy !== "present") throw new Error("deterministic-deployment proxy is absent on this chain");
        set({ phase: "confirm", step: "publish the CCHS factory on this chain (one-time, ~2.9 M gas)" });
        const h = await wc.sendTransaction({ to: DETERMINISTIC_PROXY, data: FACTORY_PUBLISH_DATA, chain, account: w.account });
        set({ phase: "pending", tx: h, step: "publishing factory" });
        await pub.waitForTransactionReceipt({ hash: h });
        const code = await pub.getCode({ address: FACTORY_ADDRESS });
        if (!code || code === "0x") throw new Error("factory did not appear at the expected address");
      }

      // New account: approvals first, then one deployAndMove (or deploy).
      for (const t of movable) {
        const ts = st!.tokens[t];
        if (ts.allowance >= ts.eoa) continue;
        set({ phase: "confirm", step: `approve ${ts.symbol} for the factory` });
        const h = await wc.writeContract({ address: t, abi: erc20Abi, functionName: "approve", args: [FACTORY_ADDRESS, ts.eoa], chain, account: w.account });
        set({ phase: "pending", tx: h, step: `approve ${ts.symbol}` });
        await pub.waitForTransactionReceipt({ hash: h });
      }
      set({ phase: "confirm", step: movable.length ? `create account · move ${movable.length} token${movable.length > 1 ? "s" : ""}${value > 0n ? ` + ${amount} ${chain.nativeCurrency.symbol}` : ""}` : "create account" });
      tx = movable.length
        ? await wc.writeContract({ address: FACTORY_ADDRESS, abi: FACTORY_ABI, functionName: "deployAndMove", args: [id.k.root, id.k.recRoot, false, movable], value, chain, account: w.account })
        : await wc.writeContract({ address: FACTORY_ADDRESS, abi: FACTORY_ABI, functionName: "deploy", args: [id.k.root, id.k.recRoot, false], value, chain, account: w.account });
      set({ phase: "pending", tx });
      await pub.waitForTransactionReceipt({ hash: tx });
      set({ phase: "done", tx });
      setRefresh((n) => n + 1);
    } catch (e) {
      set({ phase: "error", msg: (e as { shortMessage?: string }).shortMessage ?? (e as Error).message });
    }
  }

  /** Spend from the hash-only account: CCHS-signed `execute`, relayed by the injected wallet. */
  async function doSpend() {
    if (!id || spendChain === "") return;
    const chain = PROTECT_CHAINS.find((c) => c.id === spendChain)!;
    const st = states[chain.id];
    try {
      if (!isAddress(spendTo)) throw new Error("recipient is not an address");
      setSpend({ phase: "reading" });
      const pub = makePublicClient(chain);
      const account = id.k.address;

      // 1. Build the call.
      let target: Address, value = 0n, data: Hex = "0x";
      if (spendAsset === "native") {
        target = spendTo as Address; value = parseEther(spendAmt || "0");
      } else {
        const ts = st?.tokens[spendAsset as Address];
        if (!ts) throw new Error("token not loaded on this chain");
        target = spendAsset as Address;
        data = encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [spendTo as Address, parseUnits(spendAmt || "0", ts.decimals)] });
      }

      // 2. Read account state and the contract's own digest.
      const [nextIdx, nonce, needsTop, onchainDigest] = await Promise.all([
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "nextIdx" }) as Promise<bigint>,
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "nonce" }) as Promise<bigint>,
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "needsTopLayer" }) as Promise<boolean>,
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "nextDigest", args: [target, value, data] }) as Promise<Hex>,
      ]);

      // 3. Compute the digest locally and refuse to sign if the contract disagrees.
      const m = cchsK.executeDigest({
        chainId: BigInt(chain.id), account: hexToBytes(account), nonce, idx: nextIdx,
        target: hexToBytes(target), value, dataHash: hexToBytes(keccak256(data)),
      });
      const local = ("0x" + Array.from(m, (b) => b.toString(16).padStart(2, "0")).join("")) as Hex;
      if (local.toLowerCase() !== onchainDigest.toLowerCase()) throw new Error("local digest does not match the contract; refusing to sign");

      // 4. Sign. The bottom tree for this index comes from the worker pool if it is not cached yet.
      setSpend({ phase: "signing" });
      const idx = Number(nextIdx);
      const treeIdx = BigInt(idx >> H);
      const ck = `0/${treeIdx}`;
      if (!id.trees.K.has(ck)) id.trees.K.set(ck, await poolRef.current!.tree(id.master, "K", 0, treeIdx, H));
      const sig = cchsK.sign(id.master, idx, m, !needsTop, id.trees.K);
      // Local verification before anything leaves the device.
      cchsK.verify({ root: hexToBytes(id.k.root), recRoot: hexToBytes(id.k.recRoot) }, idx, m, sig, needsTop ? undefined : id.trees.K.get(ck)!.root);

      // 5. Relay through the injected wallet (it pays gas; it holds no authority over the account).
      setSpend({ phase: "confirm", bytes: signatureBytes(sig), layers: sig.l1 ? 2 : 1 });
      const w = await connect(chain);
      const wc = makeWalletClient(chain, w.account);
      const tx = await wc.writeContract({
        address: account, abi: ACCOUNT_ABI, functionName: "execute",
        args: [target, value, data, toAbiLayerSig(sig.l0), !!sig.l1, sig.l1 ? toAbiLayerSig(sig.l1) : EMPTY_LAYER_SIG],
        chain, account: w.account,
      });
      setSpend({ phase: "pending", tx, bytes: signatureBytes(sig), layers: sig.l1 ? 2 : 1 });
      await pub.waitForTransactionReceipt({ hash: tx });
      setSpend({ phase: "done", tx, bytes: signatureBytes(sig), layers: sig.l1 ? 2 : 1 });
      setRefresh((n) => n + 1);
    } catch (e) {
      setSpend({ phase: "error", msg: (e as { shortMessage?: string }).shortMessage ?? (e as Error).message });
    }
  }

  const protectedChains = useMemo(() => PROTECT_CHAINS.filter((c) => states[c.id]?.account === "deployed"), [states]);
  const spendTokens = spendChain === "" ? [] : Object.entries(states[spendChain]?.tokens ?? {});

  if (!valid) return null;

  return (
    <div className="card swap-panel protect-panel">
      <div className="swap-head">
        <div className="section-eyebrow">Protect · hash-only account · any asset</div>
        <h3>One key. Same address on every EVM chain. One click each.</h3>
        <p>
          Your mnemonic derives a CCHS master key. The <code>CCHS-K-20</code> roots fix your account address through a
          CREATE2 factory that lives at the same address on every EVM chain, so the address below is yours before anything
          is deployed. <strong>Protect</strong> creates the account and moves the native coin and any ERC-20s you list into
          it in one transaction; NFTs can be sent to it with a normal safe transfer. <strong>Spend</strong> moves anything
          back out with a hash-based signature; the browser wallet only relays and pays gas.
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
              <div className="v mono addr">{id.k.address} <CopyBtn value={id.k.address} /></div>
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
            <span className="chip">{protectedChains.length} of {PROTECT_CHAINS.length} EVM chains protected</span>
            {wallet && <span className="chip">relayer {shortAddr(wallet.account)}</span>}
          </div>

          <div className="protect-inputs">
            <label className="swap-amount">
              <span>Native coin to move in with each Protect</span>
              <input type="number" step="0.001" min="0" placeholder="0.0" value={amount} onChange={(e) => setAmount(e.target.value)} />
              <span className="hint">leave empty = create the account only</span>
            </label>
            <label className="swap-amount">
              <span>ERC-20 tokens to move in (addresses, one per line)</span>
              <textarea rows={2} spellCheck={false} placeholder="0x… (USDC, WETH, any ERC-20 on that chain)" value={tokenText} onChange={(e) => setTokenText(e.target.value)} />
              <span className="hint">
                {tokens.length === 0 ? "the whole balance of each token in your browser wallet is moved; approvals are requested as needed"
                  : !wallet ? `${tokens.length} token${tokens.length > 1 ? "s" : ""} · connect a wallet (click any Protect) to read balances`
                  : `${tokens.length} token${tokens.length > 1 ? "s" : ""} listed`}
              </span>
            </label>
          </div>

          <div className="protect-rows">
            {PROTECT_CHAINS.map((chain) => {
              const st = states[chain.id];
              const act = actions[chain.id] ?? { phase: "idle" };
              const sym = chain.nativeCurrency.symbol;
              const held = st ? Object.values(st.tokens).filter((t) => t.account > 0n).map((t) => `${formatUnits(t.account, t.decimals)} ${t.symbol}`) : [];
              const movable = st ? Object.values(st.tokens).filter((t) => t.eoa > 0n).map((t) => `${formatUnits(t.eoa, t.decimals)} ${t.symbol}`) : [];
              let status: string;
              if (!st) status = "reading…";
              else if (st.error) status = `rpc: ${st.error}`;
              else if (st.account === "deployed") status = `protected · ${formatEther(st.balance ?? 0n)} ${sym}${held.length ? " · " + held.join(" · ") : ""}`;
              else if (st.factory === "absent") status = st.proxy === "present" ? "factory not published here yet · your first Protect publishes it (one extra transaction)" : "no deterministic-deployment proxy on this chain";
              else status = st.balance && st.balance > 0n ? `address holds ${formatEther(st.balance)} ${sym}, account not deployed` : "ready";
              if (movable.length && st && !st.error) status += ` · wallet has ${movable.join(", ")}`;
              const busy = act.phase === "pending" || act.phase === "switching" || act.phase === "confirm";
              const canProtect = walletPresent && st && !st.error && (st.factory === "present" || st.proxy === "present") && !busy;
              const label = act.phase === "switching" ? "switching…" : act.phase === "confirm" ? "confirm in wallet…" : act.phase === "pending" ? "pending…"
                : st?.account === "deployed" ? ((amount && Number(amount) > 0) || movable.length ? "Move in" : "Protected") : st?.factory === "absent" ? "Publish + Protect" : "Protect";
              return (
                <div className="protect-row" key={chain.id}>
                  <div className="protect-chain">
                    <span className="protect-name">{chain.name}</span>
                    <span className="protect-status">{status}</span>
                    {busy && act.step && <span className="protect-status">{act.step}</span>}
                    {act.phase === "error" && <span className="protect-err">{act.msg}</span>}
                    {act.tx && <span className="protect-tx mono">{shortAddr(act.tx)}</span>}
                  </div>
                  <button
                    className={`btn ${st?.account === "deployed" ? "" : "btn-primary"} btn-sm`}
                    disabled={!canProtect || label === "Protected"}
                    onClick={() => protect(chain)}
                    title={!walletPresent ? "Install an injected wallet" : st?.factory === "absent" ? "Publishes the factory through the deterministic proxy, then creates your account" : ""}
                  >
                    {label}
                  </button>
                </div>
              );
            })}
          </div>

          <div className="spend">
            <div className="section-eyebrow">Spend · hash-signed execute</div>
            {protectedChains.length === 0 ? (
              <p className="swap-note">Once an account exists on a chain, this form moves any asset out of it with a CCHS signature: the digest is computed here, cross-checked with the contract's <code>nextDigest</code>, signed, locally verified, then relayed.</p>
            ) : (
              <>
                <div className="spend-grid">
                  <label><span>Chain</span>
                    <select value={spendChain} onChange={(e) => { setSpendChain(e.target.value ? Number(e.target.value) : ""); setSpendAsset("native"); }}>
                      <option value="">select…</option>
                      {protectedChains.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                    </select>
                  </label>
                  <label><span>Asset</span>
                    <select value={spendAsset} onChange={(e) => setSpendAsset(e.target.value)} disabled={spendChain === ""}>
                      <option value="native">{spendChain === "" ? "native" : PROTECT_CHAINS.find((c) => c.id === spendChain)!.nativeCurrency.symbol}</option>
                      {spendTokens.map(([a, t]) => <option key={a} value={a}>{t.symbol} · {formatUnits(t.account, t.decimals)}</option>)}
                    </select>
                  </label>
                  <label><span>Recipient</span><input spellCheck={false} placeholder="0x…" value={spendTo} onChange={(e) => setSpendTo(e.target.value)} /></label>
                  <label><span>Amount</span><input type="number" min="0" step="any" placeholder="0.0" value={spendAmt} onChange={(e) => setSpendAmt(e.target.value)} /></label>
                </div>
                <div className="spend-actions">
                  <button className="btn btn-primary btn-sm" disabled={!walletPresent || spendChain === "" || !spendTo || !spendAmt || ["reading", "signing", "confirm", "pending"].includes(spend.phase)} onClick={doSpend}>
                    {spend.phase === "reading" ? "reading account…" : spend.phase === "signing" ? "signing (hash chains)…" : spend.phase === "confirm" ? "confirm relay in wallet…" : spend.phase === "pending" ? "pending…" : "Sign with CCHS and relay"}
                  </button>
                  {spend.bytes != null && <span className="protect-status">signature {spend.bytes.toLocaleString("en-US")} B · {spend.layers} layer{spend.layers === 2 ? "s" : ""}{spend.layers === 2 ? " (first in subtree; the verifier caches the subtree root)" : " (subtree cached)"}</span>}
                  {spend.tx && <span className="protect-tx mono">{shortAddr(spend.tx)}</span>}
                  {spend.phase === "error" && <span className="protect-err">{spend.msg}</span>}
                  {spend.phase === "done" && <span className="protect-status ok">executed</span>}
                </div>
              </>
            )}
          </div>

          <details className="protect-more">
            <summary>Other chains (CCHS-S-20) · current state, honestly</summary>
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
