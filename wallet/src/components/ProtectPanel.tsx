// Protect: one hash-only identity, one click per chain, any asset.
//
// 1. Keys for both CCHS sets are generated in the worker pool from the mnemonic.
// 2. One key tree per EVM chain; each account address is predicted offline.
// 3. Each chain row reads live state over public RPC: factory present?
//    account deployed? native balance, balances of the ERC-20s you listed.
// 4. "Protect" switches the injected wallet to that chain and sends one
//    transaction: AegisCCHSFactory.deployAndMove{value}(root, recRoot, false, erc20s)
//    (after the ERC-20 approvals it needs). On an existing account it moves
//    the assets in with plain transfers instead.
// 5. "Spend" moves anything back out: the digest is computed locally, checked
//    against the contract's digestAt for this device's lane, signed with the CCHS key, and the
//    `execute` call is relayed by the injected wallet, which only pays gas.
//    Nothing is signed or sent without the user's wallet confirmation.

import { useEffect, useMemo, useRef, useState } from "react";
import type { Address, Chain, Hex } from "viem";
import { encodeFunctionData, erc20Abi, formatEther, formatUnits, hexToBytes, isAddress, keccak256, parseEther, parseUnits } from "viem";
import {
  detectInjected, requestAccounts, getChainId, switchChain, makePublicClient, makeWalletClient, shortAddr, PROTECT_CHAINS,
} from "../aegis/wallet";
import { isValidMnemonic, mnemonicEntropyBits, CCHS_MIN_SEED_BITS } from "../aegis/derive";
import { CchsPool } from "../aegis/cchsPool";
import { cchsMaster, deriveChainIdentity, type ChainIdentity, ACCOUNT_ABI, FACTORY_ABI, FACTORY_ADDRESS, DETERMINISTIC_PROXY, FACTORY_PUBLISH_DATA, nextSigningIndex, markIndexSigned, recordMissing, epochKey, deviceLane, setDeviceLane, laneFirst, LANES, highestRecoverySigned, markRecoverySigned, type CchsIdentity } from "../aegis/cchsAccount";
import { cchsK, H, toAbiLayerSig, signatureBytes, toHex, type CchsKey, type Tree } from "../aegis/cchs";
import CopyBtn from "./CopyBtn";
import { RWA_TOKENS, rwaOnChain, rwaByAddress, gateText, type RwaToken } from "../data/rwa";

type TokenState = {
  symbol: string; decimals: number; eoa: bigint; account: bigint; allowance: bigint;
  rwa?: RwaToken;
  /** Result of simulating `transfer(aegisAccount, …)` from the connected wallet: would the token accept the account as a holder? */
  accepts?: "yes" | "no" | "unknown"; acceptsMsg?: string;
};

/** Reason string of a simulated call, trimmed to what the user needs. */
function revertReason(e: unknown): string {
  const err = e as { shortMessage?: string; details?: string; message?: string };
  const s = err.details || err.shortMessage || err.message || "reverted";
  return s.replace(/\s+/g, " ").slice(0, 160);
}

/** True when a failed `eth_call` failed in transport or at the node, not in the contract: nothing can be concluded about the token. */
function isTransportError(e: unknown): boolean {
  const names = new Set(["HttpRequestError", "TimeoutError", "InternalRpcError", "LimitExceededRpcError", "ResourceUnavailableRpcError", "RpcRequestError"]);
  const walk = (e as { walk?: (fn: (err: unknown) => boolean) => unknown }).walk;
  if (typeof walk === "function") return !!walk.call(e, (err) => names.has((err as { name?: string }).name ?? ""));
  return names.has((e as { name?: string }).name ?? "");
}

type ChainState = {
  factory: "unknown" | "absent" | "present";
  proxy: "unknown" | "absent" | "present";
  account: "unknown" | "absent" | "deployed";
  balance: bigint | null;
  tokens: Record<Address, TokenState>;
  error?: string;
};

type RowAction = { phase: "idle" | "switching" | "confirm" | "pending" | "done" | "error"; tx?: Hex; msg?: string; step?: string };

type SpendState = { phase: "idle" | "reading" | "signing" | "confirm" | "pending" | "done" | "error" | "rotate" | "rotating" | "rotated"; msg?: string; tx?: Hex; bytes?: number; layers?: number; epoch?: number; nextIdx?: number; lane?: number };

const NON_EVM = [
  { name: "Solana", set: "C-20", status: "usable from the Solana panel below: create + lookup table, move SOL and any SPL / Token-2022 token (memecoins included) into the vault, spend with one 864 B signature per execute (v0 tx, 1 089 B); program id AoQ7c3…jMQKr, live on mainnet-beta (deployed from CI, slot 454 874 054; upgrade authority still the deployer key)" },
  { name: "TRON", set: "K-20 / S-20", status: "same contracts built for the TVM in tron/ (byte-identical init code, 0x41 CREATE2 predictor); not published on Nile or mainnet" },
  { name: "Osmosis · Injective · Neutron · Juno · Stargaze", set: "S-20", status: "CosmWasm contract in cosmwasm/, compiled in CI; not uploaded on any chain (Osmosis and Injective also require governance for code upload)" },
  { name: "NEAR", set: "S-20", status: "contract source in near/, compiled in CI; not deployed" },
  { name: "Aptos / Sui", set: "S-20", status: "Move modules in aptos/ (resource account, zeroed auth key, no signer in execute) and sui/ (any Coin<T> vault); immutable publication documented; fixture + end-to-end tests in CI; not published" },
  { name: "Starknet", set: "S-20", status: "Cairo account in cairo/, built and tested in CI; not declared" },
  { name: "TON", set: "S-20", status: "FunC account in ton/, sandbox-tested; not deployed" },
  { name: "Bitcoin", set: "CCHS-UTXO (WOTS+ tapleaves)", status: "live on Bitcoin Inquisition signet, where OP_CAT and OP_CHECKSIGFROMSTACK are active: see the Bitcoin panel below. Mainnet has neither opcode, so no construction there binds a hash-based witness to a transaction (BITCOIN.md §3); the mainnet address is BIP-84 P2WPKH, single-use, not labelled post-quantum" },
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
  const seedBits = mnemonicEntropyBits(mnemonic);
  // A CCHS account is as strong as the seed behind it: a quantum search over
  // the seed costs about 2^(bits/2) steps, so 128 bits of mnemonic sit far
  // below the 2^113 of the signatures (CCHS.spec.md §5.6, P4). A weak seed
  // may still derive its keys and Spend (nothing is ever stranded), but it
  // may not Protect: no account is created or funded behind such a seed.
  const strongSeed = seedBits >= CCHS_MIN_SEED_BITS;
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
  const [lane, setLane] = useState(() => deviceLane());
  const [spend, setSpend] = useState<SpendState>({ phase: "idle" });

  const [withRwa, setWithRwa] = useState(true);
  const listed = useMemo(() => parseTokens(tokenText), [tokenText]);
  /** Tokens to read and move on one chain: the ones listed by address plus, when enabled, the known RWA tokens issued there. */
  const tokensFor = (chainId: number): Address[] => {
    if (!withRwa) return listed;
    const out = [...listed];
    for (const { address } of rwaOnChain(chainId)) if (!out.some((a) => a.toLowerCase() === address.toLowerCase())) out.push(address);
    return out;
  };

  useEffect(() => {
    poolRef.current = new CchsPool();
    return () => poolRef.current?.terminate();
  }, []);

  // Derive the identity (debounced) whenever the mnemonic changes: the master,
  // then one key tree per EVM chain, published as each one completes.
  useEffect(() => {
    if (!valid) { setId(null); return; }
    let cancelled = false;
    setId(null); setGenMs(null); setGenErr(null);
    const t = setTimeout(async () => {
      try {
        const pool = poolRef.current!;
        const master = cchsMaster(mnemonic);
        const evm = new Map<number, ChainIdentity>();
        setId({ master, evm });
        const t0 = performance.now();
        for (const chain of PROTECT_CHAINS) {
          const ci = await deriveChainIdentity(master, chain.id, pool);
          if (cancelled) return;
          evm.set(chain.id, ci);
          setId({ master, evm: new Map(evm) });
          setGenMs(performance.now() - t0);
        }
      } catch (e) {
        if (!cancelled) setGenErr((e as Error).message);
      }
    }, 300);
    return () => { cancelled = true; clearTimeout(t); };
  }, [mnemonic, valid]);

  // Read chain state for every EVM chain whose address is known. Each
  // (chain, address, inputs) combination is read once per refresh.
  const fetched = useRef(new Set<string>());
  useEffect(() => {
    if (!id) { setStates({}); fetched.current.clear(); return; }
    let cancelled = false;
    const eoa = wallet?.account;
    for (const chain of PROTECT_CHAINS) {
      const addr = id.evm.get(chain.id)?.address;
      if (!addr) continue;
      const tokens = tokensFor(chain.id);
      const sig = `${chain.id}:${addr}:${refresh}:${eoa ?? ''}:${tokens.join(',')}`;
      if (fetched.current.has(sig)) continue;
      fetched.current.add(sig);
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
              const ts: TokenState = { symbol, decimals, account: accountBal, eoa: eoaBal, allowance, rwa: rwaByAddress(chain.id, t) };
              // Gated tokens refuse recipients their issuer has not registered. Ask the
              // token itself, from the connected wallet's point of view, before anything
              // is approved or moved: a reverting `transfer(account, …)` means the Aegis
              // address is not (yet) an acceptable holder.
              if (ts.rwa && ts.rwa.gate !== "open" && eoa) {
                try {
                  await pub.call({ account: eoa, to: t, data: encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [addr, eoaBal > 0n ? 1n : 0n] }) });
                  ts.accepts = "yes";
                } catch (e) {
                  if (isTransportError(e)) { ts.accepts = "unknown"; ts.acceptsMsg = `rpc: ${revertReason(e)}`; }
                  else { ts.accepts = "no"; ts.acceptsMsg = revertReason(e); }
                }
              } else if (ts.rwa && ts.rwa.gate !== "open") ts.accepts = "unknown";
              toks[t] = ts;
            } catch { /* not an ERC-20 on this chain */ }
          }));
          if (cancelled) { fetched.current.delete(sig); return; }
          setStates((s) => ({ ...s, [chain.id]: {
            factory: fc && fc !== "0x" ? "present" : "absent",
            proxy: px && px !== "0x" ? "present" : "absent",
            account: ac && ac !== "0x" ? "deployed" : "absent",
            balance: bal,
            tokens: toks,
          } }));
        } catch (e) {
          if (cancelled) { fetched.current.delete(sig); return; }
          const err = e as { shortMessage?: string; message: string };
          setStates((s) => ({ ...s, [chain.id]: { factory: "unknown", proxy: "unknown", account: "unknown", balance: null, tokens: {}, error: err.shortMessage ?? err.message } }));
        }
      })();
    }
    return () => { cancelled = true; };
  }, [id, listed, withRwa, wallet, refresh]); // tokensFor is a pure function of `listed` and `withRwa`

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

  /** Key tree and address of one chain; throws until that chain has been derived. */
  function chainIdentity(chainId: number): ChainIdentity {
    const ci = id?.evm.get(chainId);
    if (!ci) throw new Error("keys for this chain are still being derived");
    return ci;
  }

  async function protect(chain: Chain) {
    if (!id || !strongSeed) return;
    const set = (a: RowAction) => setActions((s) => ({ ...s, [chain.id]: a }));
    const st = states[chain.id];
    try {
      const ci = chainIdentity(chain.id);
      set({ phase: "switching" });
      const w = await connect(chain);
      const wc = makeWalletClient(chain, w.account);
      const pub = makePublicClient(chain);
      const value = amount && Number(amount) > 0 ? parseEther(amount) : 0n;
      const movable = tokensFor(chain.id).filter((t) => (st?.tokens[t]?.eoa ?? 0n) > 0n);
      // A gated RWA token whose issuer has not registered the account would make
      // deployAndMove revert as a whole; leave it in the wallet and say why.
      const refused = movable.filter((t) => st?.tokens[t]?.accepts === "no");
      if (refused.length) {
        const r = st!.tokens[refused[0]];
        throw new Error(`${r.symbol} will not accept the Aegis address as a holder (${r.acceptsMsg ?? "transfer reverts"}). Register ${ci.address} with ${r.rwa?.issuer ?? "the issuer"} first${r.rwa?.register ? `: ${r.rwa.register}` : ""}.`);
      }
      let tx: Hex;

      if (st?.account === "deployed") {
        // Existing account: plain transfers in. Each one is a wallet confirmation.
        for (const t of movable) {
          const ts = st.tokens[t];
          set({ phase: "confirm", step: `move ${formatUnits(ts.eoa, ts.decimals)} ${ts.symbol}` });
          const h = await wc.writeContract({ address: t, abi: erc20Abi, functionName: "transfer", args: [ci.address, ts.eoa], chain, account: w.account });
          set({ phase: "pending", tx: h, step: `move ${ts.symbol}` });
          await pub.waitForTransactionReceipt({ hash: h });
        }
        if (value === 0n && movable.length === 0) { set({ phase: "done" }); setRefresh((n) => n + 1); return; }
        if (value > 0n) {
          set({ phase: "confirm", step: `move ${amount} ${chain.nativeCurrency.symbol}` });
          tx = await wc.sendTransaction({ to: ci.address, value, chain, account: w.account });
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
        ? await wc.writeContract({ address: FACTORY_ADDRESS, abi: FACTORY_ABI, functionName: "deployAndMove", args: [ci.root, ci.recRoot, ci.seed, false, movable], value, chain, account: w.account })
        : await wc.writeContract({ address: FACTORY_ADDRESS, abi: FACTORY_ABI, functionName: "deploy", args: [ci.root, ci.recRoot, ci.seed, false], value, chain, account: w.account });
      set({ phase: "pending", tx });
      await pub.waitForTransactionReceipt({ hash: tx });
      set({ phase: "done", tx });
      setRefresh((n) => n + 1);
    } catch (e) {
      set({ phase: "error", msg: (e as { shortMessage?: string }).shortMessage ?? (e as Error).message });
    }
  }

  /** Spend from the hash-only account: CCHS-signed `execute`, relayed by the injected wallet. */
  // Keys and trees per (chain, epoch). Epoch 0 is the chain's tree derived at
  // load; later epochs are derived on demand from the chain key and checked
  // against the roots the chain holds before any signature is made with them.
  type EpochKeys = { key: CchsKey; trees: Map<string, Tree>; root: Hex; recRoot: Hex; seed: Hex };
  const epochTrees = useRef<Map<string, EpochKeys>>(new Map());
  async function epochKeys(chainId: number, epoch: number, onchain: { root: Hex; recRoot: Hex; seed: Hex }) {
    const ci = chainIdentity(chainId);
    const k = `${chainId}/${epoch}`;
    let e = epochTrees.current.get(k);
    if (!e) {
      if (epoch === 0) e = { key: ci.key, trees: ci.trees, root: ci.root, recRoot: ci.recRoot, seed: ci.seed };
      else {
        const key = epochKey(ci.key, epoch);
        const trees = new Map<string, Tree>();
        const pub = await poolRef.current!.keygen(key, "K", trees);
        e = { key, trees, root: toHex(pub.root) as Hex, recRoot: toHex(pub.recRoot) as Hex, seed: toHex(pub.seed) as Hex };
      }
      epochTrees.current.set(k, e);
    }
    const same = (a: Hex, b: Hex) => a.toLowerCase() === b.toLowerCase();
    if (!same(e.root, onchain.root) || !same(e.recRoot, onchain.recRoot) || !same(e.seed, onchain.seed)) {
      throw new Error(`the chain holds a public key for epoch ${epoch} that this mnemonic does not derive; the account was recovered with a different key`);
    }
    return e;
  }
  const readPublicKey = (pub: ReturnType<typeof makePublicClient>, account: Address) => Promise.all([
    pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "root" }) as Promise<Hex>,
    pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "recRoot" }) as Promise<Hex>,
    pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "pkSeed" }) as Promise<Hex>,
  ]).then(([root, recRoot, seed]) => ({ root, recRoot, seed }));

  /**
   * Recovery as key rotation: epoch e -> e + 1 with keys derived from the same
   * master. The message is a pure function of (chain, account, recNonce, epoch),
   * so re-signing a dropped rotation yields the same message under the same
   * recovery leaf; the leaf is still recorded before signing.
   */
  async function doRotate() {
    if (!id || spendChain === "") return;
    const chain = PROTECT_CHAINS.find((c) => c.id === spendChain)!;
    try {
      const pub = makePublicClient(chain);
      const ci = chainIdentity(chain.id);
      const account = ci.address;
      setSpend({ phase: "rotating", msg: "reading account…" });
      const [epochBig, recNonce, onchain] = await Promise.all([
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "epoch" }) as Promise<bigint>,
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "recNonce" }) as Promise<bigint>,
        readPublicKey(pub, account),
      ]);
      const epoch = Number(epochBig);
      if (Number(recNonce) <= highestRecoverySigned(chain.id, account)) {
        throw new Error("a rotation signed by this device for this recovery leaf is still pending; wait for it to land or be dropped");
      }
      setSpend({ phase: "rotating", msg: `deriving keys for epoch ${epoch} and ${epoch + 1}…` });
      const cur = await epochKeys(chain.id, epoch, onchain);
      const next = epochKey(ci.key, epoch + 1);
      const nextTrees = new Map<string, Tree>();
      const nextPub = await poolRef.current!.keygen(next, "K", nextTrees);
      epochTrees.current.set(`${chain.id}/${epoch + 1}`, { key: next, trees: nextTrees, root: toHex(nextPub.root) as Hex, recRoot: toHex(nextPub.recRoot) as Hex, seed: toHex(nextPub.seed) as Hex });
      const m = cchsK.recoveryDigest({ chainId: BigInt(chain.id), account: hexToBytes(account), recNonce, newRoot: nextPub.root, newRecRoot: nextPub.recRoot, newSeed: nextPub.seed });
      setSpend({ phase: "rotating", msg: "signing with the recovery tree…" });
      markRecoverySigned(chain.id, account, Number(recNonce));
      const sig = cchsK.signRecovery(cur.key, Number(recNonce), m, cur.trees);
      const w = await connect(chain);
      const wc = makeWalletClient(chain, w.account);
      setSpend({ phase: "rotating", msg: "confirm relay in wallet…" });
      const tx = await wc.writeContract({
        address: account, abi: ACCOUNT_ABI, functionName: "recover",
        args: [toHex(nextPub.root) as Hex, toHex(nextPub.recRoot) as Hex, toHex(nextPub.seed) as Hex, sig.wots.map((x) => toHex(x) as Hex), sig.auth.map((x) => toHex(x) as Hex)],
        chain, account: w.account,
      });
      setSpend({ phase: "rotating", msg: "pending…", tx });
      await pub.waitForTransactionReceipt({ hash: tx });
      markIndexSigned(chain.id, account, epoch + 1, -1, deviceLane()); // fresh record for the new epoch in this device's lane
      setSpend({ phase: "rotated", epoch: epoch + 1, tx });
      setRefresh((n) => n + 1);
    } catch (e) {
      setSpend({ phase: "error", msg: (e as { shortMessage?: string }).shortMessage ?? (e as Error).message });
    }
  }

  async function doSpend() {
    if (!id || spendChain === "") return;
    const chain = PROTECT_CHAINS.find((c) => c.id === spendChain)!;
    const st = states[chain.id];
    try {
      if (!isAddress(spendTo)) throw new Error("recipient is not an address");
      setSpend({ phase: "reading" });
      const pub = makePublicClient(chain);
      const ci = chainIdentity(chain.id);
      const account = ci.address;

      // 1. Build the call.
      let target: Address, value = 0n, data: Hex = "0x";
      if (spendAsset === "native") {
        target = spendTo as Address; value = parseEther(spendAmt || "0");
      } else {
        const ts = st?.tokens[spendAsset as Address];
        if (!ts) throw new Error("token not loaded on this chain");
        target = spendAsset as Address;
        data = encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [spendTo as Address, parseUnits(spendAmt || "0", ts.decimals)] });
        // Simulate the inner call from the account before a leaf is spent on it.
        // Gated RWA tokens refuse recipients their issuer has not registered; the
        // signature would be consumed by a reverting execute, so stop here instead.
        try {
          await pub.call({ account, to: target, data });
        } catch (e) {
          if (isTransportError(e)) throw new Error(`could not simulate the transfer (${revertReason(e)}); try again before a leaf is used`);
          const why = revertReason(e);
          throw new Error(ts.rwa
            ? `${ts.symbol} refuses this transfer (${why}). ${ts.rwa.gate === "open" ? "" : `${ts.rwa.issuer} must have registered the recipient ${spendTo}; ${gateText(ts.rwa.gate)}.`} No leaf was used.`
            : `${ts.symbol} transfer would revert (${why}). No leaf was used.`);
        }
      }

      // 2. Choose the leaf in this device's lane: never below the lane's nextIdx,
      //    never one this device signed before. Other devices own other lanes.
      const lane = deviceLane();
      const [nextIdx, nonce, epochBig, onchain] = await Promise.all([
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "nextIdx", args: [lane] }) as Promise<bigint>,
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "nonce", args: [lane] }) as Promise<bigint>,
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "epoch" }) as Promise<bigint>,
        readPublicKey(pub, account),
      ]);
      const epoch = Number(epochBig);
      if (recordMissing(chain.id, account, epoch, nextIdx, lane)) {
        setSpend({ phase: "rotate", epoch, nextIdx: Number(nextIdx) - laneFirst(lane), lane });
        return;
      }
      const { key, trees } = await epochKeys(chain.id, epoch, onchain);
      const idx = nextSigningIndex(chain.id, account, epoch, nextIdx, lane);
      const [needsTop, onchainDigest] = await Promise.all([
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "needsTopLayerAt", args: [BigInt(idx)] }) as Promise<boolean>,
        pub.readContract({ address: account, abi: ACCOUNT_ABI, functionName: "digestAt", args: [BigInt(idx), target, value, data] }) as Promise<Hex>,
      ]);

      // 3. Compute the digest locally and refuse to sign if the contract disagrees.
      const m = cchsK.executeDigest({
        chainId: BigInt(chain.id), account: hexToBytes(account), nonce, idx: BigInt(idx),
        target: hexToBytes(target), value, dataHash: hexToBytes(keccak256(data)),
      });
      const local = ("0x" + Array.from(m, (b) => b.toString(16).padStart(2, "0")).join("")) as Hex;
      if (local.toLowerCase() !== onchainDigest.toLowerCase()) throw new Error("local digest does not match the contract; refusing to sign");

      // 4. Sign. The index is recorded as used before the signature exists, so a
      //    crash between the two can only waste a leaf, never reuse one.
      setSpend({ phase: "signing" });
      const treeIdx = BigInt(idx >> H);
      const ck = `0/${treeIdx}`;
      if (!trees.has(ck)) trees.set(ck, await poolRef.current!.tree(key, "K", 0, treeIdx, H));
      markIndexSigned(chain.id, account, epoch, idx, lane);
      const sig = cchsK.sign(key, idx, m, !needsTop, trees);
      // Local verification against the public key the chain holds, before anything leaves the device.
      cchsK.verify({ root: hexToBytes(onchain.root), recRoot: hexToBytes(onchain.recRoot), seed: hexToBytes(onchain.seed) }, idx, m, sig, needsTop ? undefined : trees.get(ck)!.root);

      // 5. Relay through the injected wallet (it pays gas; it holds no authority over the account).
      setSpend({ phase: "confirm", bytes: signatureBytes(sig), layers: sig.l1 ? 2 : 1 });
      const w = await connect(chain);
      const wc = makeWalletClient(chain, w.account);
      const tx = sig.l1
        ? await wc.writeContract({
            address: account, abi: ACCOUNT_ABI, functionName: "executeFirst",
            args: [target, value, data, BigInt(idx), toAbiLayerSig(sig.l0), toAbiLayerSig(sig.l1)],
            chain, account: w.account,
          })
        : await wc.writeContract({
            address: account, abi: ACCOUNT_ABI, functionName: "execute",
            args: [target, value, data, BigInt(idx), toAbiLayerSig(sig.l0)],
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
        <h3>One mnemonic. An independent key tree and account on every EVM chain. One click each.</h3>
        {!strongSeed && (
          <p className="protect-warn">
            This mnemonic carries {seedBits} bits of entropy; CCHS requires {CCHS_MIN_SEED_BITS}. A hash-based account is
            exactly as strong as the seed behind it: the signatures cost an attacker at least 2^113 quantum steps, but a
            search over a {seedBits}-bit seed checked against one public chain value costs about 2^{seedBits / 2 + 12}, and
            every key of every chain derives from that seed. Protect is disabled for this phrase. Spend still works, so
            anything an earlier build put behind it can be moved to an account made from a 24-word mnemonic.
          </p>
        )}
        <p>
          Your mnemonic derives a CCHS master key, and from it a separate <code>CCHS-K-20</code> tree for each chain
          (a WOTS+ leaf signs one message, so no tree is ever shared between chains). Each tree's roots fix an account
          address on that chain through a CREATE2 factory that lives at the same address everywhere, so every address
          below is yours before anything is deployed. <strong>Protect</strong> creates the account and moves the native
          coin and any ERC-20s you list into it in one transaction — tokenised treasuries and gold included, with the
          issuer's allowlist checked first; NFTs can be sent to it with a normal safe transfer.{" "}
          <strong>Spend</strong> moves anything back out with a hash-based signature; the browser wallet only relays and pays gas.
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
              <div className="k">Key trees derived</div>
              <div className="v">{id.evm.size} of {PROTECT_CHAINS.length} EVM chains{id.evm.size < PROTECT_CHAINS.length ? " · deriving…" : ""}</div>
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
                {listed.length === 0 ? "the whole balance of each token in your browser wallet is moved; approvals are requested as needed"
                  : !wallet ? `${listed.length} token${listed.length > 1 ? "s" : ""} · connect a wallet (click any Protect) to read balances`
                  : `${listed.length} token${listed.length > 1 ? "s" : ""} listed`}
              </span>
            </label>
            <label className="swap-amount protect-rwa">
              <span>Tokenised real-world assets</span>
              <span className="protect-rwa-toggle">
                <input type="checkbox" checked={withRwa} onChange={(e) => setWithRwa(e.target.checked)} />
                <span>include the known issuers' tokens on each chain: {RWA_TOKENS.map((t) => t.symbol).join(", ")}</span>
              </span>
              <span className="hint">
                An Aegis account holds them like any ERC-20. Most are gated: the issuer's contract refuses holders it has not
                registered, so each row below asks the token whether it accepts your Aegis address before anything is moved,
                and Spend simulates the transfer before a leaf is used.
              </span>
            </label>
          </div>

          <div className="protect-rows">
            {PROTECT_CHAINS.map((chain) => {
              const st = states[chain.id];
              const ci = id.evm.get(chain.id);
              const act = actions[chain.id] ?? { phase: "idle" };
              const sym = chain.nativeCurrency.symbol;
              const held = st ? Object.values(st.tokens).filter((t) => t.account > 0n).map((t) => `${formatUnits(t.account, t.decimals)} ${t.symbol}`) : [];
              const movable = st ? Object.values(st.tokens).filter((t) => t.eoa > 0n).map((t) => `${formatUnits(t.eoa, t.decimals)} ${t.symbol}`) : [];
              let status: string;
              if (!ci) status = "deriving key tree…";
              else if (!st) status = "reading…";
              else if (st.error) status = `rpc: ${st.error}`;
              else if (st.account === "deployed") status = `protected · ${formatEther(st.balance ?? 0n)} ${sym}${held.length ? " · " + held.join(" · ") : ""}`;
              else if (st.factory === "absent") status = st.proxy === "present" ? "factory not published here yet · your first Protect publishes it (one extra transaction)" : "no deterministic-deployment proxy on this chain";
              else status = st.balance && st.balance > 0n ? `address holds ${formatEther(st.balance)} ${sym}, account not deployed` : "ready";
              if (movable.length && st && !st.error) status += ` · wallet has ${movable.join(", ")}`;
              // Gated RWA tokens on this chain: what the token said when asked whether the account may hold it.
              const gated = st ? Object.values(st.tokens).filter((t) => t.rwa && t.rwa.gate !== "open") : [];
              const rwaLine = gated.length
                ? gated.map((t) => `${t.symbol}: ${t.accepts === "yes" ? "accepts this account" : t.accepts === "no" ? `refuses this account (${t.acceptsMsg ?? "transfer reverts"}) · register it at ${t.rwa!.register ?? t.rwa!.issuer}` : t.acceptsMsg ? `could not ask the token (${t.acceptsMsg})` : "connect a wallet to ask the token"}`).join(" · ")
                : null;
              const busy = act.phase === "pending" || act.phase === "switching" || act.phase === "confirm";
              const canProtect = walletPresent && ci && st && !st.error && (st.factory === "present" || st.proxy === "present") && !busy;
              const label = act.phase === "switching" ? "switching…" : act.phase === "confirm" ? "confirm in wallet…" : act.phase === "pending" ? "pending…"
                : st?.account === "deployed" ? ((amount && Number(amount) > 0) || movable.length ? "Move in" : "Protected") : st?.factory === "absent" ? "Publish + Protect" : "Protect";
              return (
                <div className="protect-row" key={chain.id}>
                  <div className="protect-chain">
                    <span className="protect-name">{chain.name}</span>
                    {ci && <span className="protect-tx mono">{ci.address} <CopyBtn value={ci.address} /></span>}
                    <span className="protect-status">{status}</span>
                    {rwaLine && <span className="protect-status protect-rwa-status" title={gated.map((t) => `${t.symbol} · ${t.rwa!.issuer} · ${gateText(t.rwa!.gate)}`).join("\n")}>RWA · {rwaLine}</span>}
                    {busy && act.step && <span className="protect-status">{act.step}</span>}
                    {act.phase === "error" && <span className="protect-err">{act.msg}</span>}
                    {act.tx && <span className="protect-tx mono">{shortAddr(act.tx)}</span>}
                  </div>
                  <button
                    className={`btn ${st?.account === "deployed" ? "" : "btn-primary"} btn-sm`}
                    disabled={!canProtect || !strongSeed || label === "Protected"}
                    onClick={() => protect(chain)}
                    title={!strongSeed ? `A ${seedBits}-bit seed is below the ${CCHS_MIN_SEED_BITS} bits CCHS requires` : !walletPresent ? "Install an injected wallet" : st?.factory === "absent" ? "Publishes the factory through the deterministic proxy, then creates your account" : ""}
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
              <p className="swap-note">Once an account exists on a chain, this form moves any asset out of it with a CCHS signature: the digest is computed here, cross-checked with the contract's <code>digestAt</code>, signed, locally verified, then relayed. The leaf index is chosen here (never below the chain's <code>nextIdx</code>, never one this device signed before) and recorded before signing, so a dropped transaction abandons a leaf instead of reusing one.</p>
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
                      {spendTokens.map(([a, t]) => <option key={a} value={a}>{t.symbol}{t.rwa ? ` (${t.rwa.issuer})` : ""} · {formatUnits(t.account, t.decimals)}</option>)}
                    </select>
                  </label>
                  <label><span>Recipient</span><input spellCheck={false} placeholder="0x…" value={spendTo} onChange={(e) => setSpendTo(e.target.value)} /></label>
                  <label><span>Amount</span><input type="number" min="0" step="any" placeholder="0.0" value={spendAmt} onChange={(e) => setSpendAmt(e.target.value)} /></label>
                  <label title="The account's 2^20 leaves are split into 16 lanes with independent on-chain counters. Give every device its own lane; devices then sign concurrently without coordinating. Never let two devices share a lane."><span>Device lane</span>
                    <select value={lane} onChange={(e) => { setDeviceLane(Number(e.target.value)); setLane(Number(e.target.value)); }}>
                      {Array.from({ length: LANES }, (_, i) => <option key={i} value={i}>{i}{i === 0 ? " (default)" : ""} · leaves {(laneFirst(i)).toLocaleString("en-US")}–{(laneFirst(i + 1) - 1).toLocaleString("en-US")}</option>)}
                    </select>
                  </label>
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
                {(spend.phase === "rotate" || spend.phase === "rotating" || spend.phase === "rotated") && (
                  <div className="spend-actions">
                    <span className="protect-err">
                      {spend.phase === "rotate" && <>This device has no signing record for lane {spend.lane} of this account (epoch {spend.epoch}, {spend.nextIdx} leaves of the lane used). It cannot know which leaves an earlier copy signed, so it will not sign in this lane in this epoch. Either give this device a lane no other device uses (device lane, above), or rotate the keys: one recovery transaction opens a fresh index space (epoch {spend.epoch! + 1}, keys derived from the same mnemonic).</>}
                      {spend.phase === "rotating" && (spend.msg ?? "rotating…")}
                      {spend.phase === "rotated" && <>keys rotated to epoch {spend.epoch}; you can sign now</>}
                    </span>
                    {spend.phase === "rotate" && <button className="btn btn-sm" disabled={!walletPresent} onClick={doRotate}>Rotate keys (recovery)</button>}
                    {spend.tx && <span className="protect-tx mono">{shortAddr(spend.tx)}</span>}
                  </div>
                )}
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
              Protect needs an injected EVM wallet (MetaMask, Rabby, Trust) to pay for the deployment. The addresses above are
              already yours; anyone can fund them now and deploy later.
            </div>
          )}
        </>
      )}
    </div>
  );
}
