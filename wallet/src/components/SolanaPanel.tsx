// Solana: the CCHS-C-20 account of solana/programs/aegis_account, usable from
// the browser against the cluster where the program is deployed (devnet).
//
// 1. The mnemonic derives the Solana chain key; the epoch-0 public key is
//    computed on the worker pool and fixes the account PDA and its vault.
// 2. Protect: a connected Solana wallet (Phantom, Backpack, Solflare — any
//    Wallet Standard wallet) pays to create the account and its lookup table,
//    then moves SOL and any SPL / Token-2022 token it holds into the vault.
// 3. Spend: the device signs one WOTS+ leaf over (account, nonce, idx, target,
//    data); the wallet pays the fee of the `execute` transaction and has no
//    authority over the vault. The first leaf of a subtree publishes the
//    subtree root with `cache_subtree` first.
//
// Everything below says which cluster it is on; the program exists on devnet.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { isValidMnemonic } from "../aegis/derive";
import { cchsMaster } from "../aegis/cchsAccount";
import { CchsPool } from "../aegis/cchsPool";
import {
  DEFAULT_RPC, EXPLORER, LAMPORTS_PER_SOL, Rpc, TOKEN_2022_PROGRAM, TOKEN_PROGRAM, connectSolanaWallet, formatAmount, fromBase58,
  parseAmount, shortKey, solanaWallets, toBase58, type Cluster, type ConnectedSolanaWallet, type TokenHolding,
} from "../aegis/solana";
import {
  CAPACITY, RECOVERIES, SOLANA_PROGRAM_ID, createAccount, createTable, decodeAccount, decodeTable, depositSol, depositToken, deriveSolanaIdentity,
  epochSigner, findTable, highestSigned, recordMissing, recover, spend, vaultHoldings,
  type AccountState, type Flow, type Signer, type SolanaIdentity, type SpendStep,
} from "../aegis/solanaAccount";
import CopyBtn from "./CopyBtn";

interface ChainView {
  programDeployed: boolean;
  state: AccountState | null;
  vault: { lamports: bigint; tokens: TokenHolding[] };
  table: { address: Uint8Array; addresses: Uint8Array[] } | null;
  walletLamports: bigint;
  walletTokens: TokenHolding[];
}
type Busy = { what: string } | null;
type Result = { kind: "ok" | "err"; text: string; sig?: string } | null;

const sol = (l: bigint) => formatAmount(l, 9);
const num = (n: number | bigint) => Number(n).toLocaleString("en-US");
const STEP_TEXT: Record<SpendStep, string> = {
  reading: "reading the account…",
  signing: "signing (hash chains)…",
  caching: "publishing the subtree root (cache_subtree)…",
  confirming: "creating the recipient's token account…",
  executing: "sending execute (v0, lookup table)…",
};

export default function SolanaPanel({ mnemonic }: { mnemonic: string }) {
  const valid = isValidMnemonic(mnemonic);
  const poolRef = useRef<CchsPool | null>(null);
  const signers = useRef(new Map<string, Signer>());
  const [cluster, setCluster] = useState<Cluster>("devnet");
  const [rpcUrl, setRpcUrl] = useState(DEFAULT_RPC.devnet);
  const [id, setId] = useState<SolanaIdentity | null>(null);
  const [deriveErr, setDeriveErr] = useState<string | null>(null);
  const [view, setView] = useState<ChainView | null>(null);
  const [viewErr, setViewErr] = useState<string | null>(null);
  const [wallet, setWallet] = useState<ConnectedSolanaWallet | null>(null);
  const [busy, setBusy] = useState<Busy>(null);
  const [result, setResult] = useState<Result>(null);
  const [depositAmt, setDepositAmt] = useState("");
  const [tokenAmts, setTokenAmts] = useState<Record<string, string>>({});
  const [spendTo, setSpendTo] = useState("");
  const [spendAsset, setSpendAsset] = useState("sol");
  const [spendAmt, setSpendAmt] = useState("");
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => { poolRef.current = new CchsPool(); return () => poolRef.current?.terminate(); }, []);
  const rpc = useMemo(() => new Rpc(rpcUrl), [rpcUrl]);

  // Derive the identity (public key only) when the mnemonic changes.
  useEffect(() => {
    if (!valid) { setId(null); return; }
    let cancelled = false;
    setId(null); setView(null); setDeriveErr(null); setResult(null); signers.current.clear();
    const t = setTimeout(async () => {
      try {
        const master = cchsMaster(mnemonic);
        const i = await deriveSolanaIdentity(master, poolRef.current!);
        if (!cancelled) setId(i);
      } catch (e) { if (!cancelled) setDeriveErr((e as Error).message); }
    }, 400);
    return () => { cancelled = true; clearTimeout(t); };
  }, [mnemonic, valid]);

  const read = useCallback(async (i: SolanaIdentity, w: ConnectedSolanaWallet | null) => {
    setViewErr(null);
    try {
      const [prog, acct, vault, tableAddr] = await Promise.all([rpc.accountInfo(SOLANA_PROGRAM_ID), rpc.accountInfo(i.account), vaultHoldings(rpc, i.vault), findTable(rpc, cluster, i.account).catch(() => null)]);
      let table: ChainView["table"] = null;
      if (tableAddr) {
        const t = await rpc.accountInfo(tableAddr);
        if (t) table = { address: tableAddr, addresses: decodeTable(t.data) };
      }
      const [walletLamports, wa, wb] = w
        ? await Promise.all([rpc.balance(w.publicKey), rpc.tokenAccounts(w.publicKey, TOKEN_PROGRAM), rpc.tokenAccounts(w.publicKey, TOKEN_2022_PROGRAM)])
        : [0n, [], []];
      setView({
        programDeployed: !!prog?.executable,
        state: acct ? decodeAccount(acct.data) : null,
        vault, table, walletLamports,
        walletTokens: [...wa, ...wb].filter((t) => t.amount > 0n),
      });
    } catch (e) { setViewErr((e as Error).message); }
  }, [rpc, cluster]);

  useEffect(() => { if (id) void read(id, wallet); }, [id, wallet, read, refresh]);

  function pickCluster(c: Cluster) { setCluster(c); setRpcUrl(DEFAULT_RPC[c]); setView(null); setResult(null); }

  async function run(what: string, fn: () => Promise<{ signature: string; bytes?: number; note?: string }>) {
    setBusy({ what }); setResult(null);
    try {
      const r = await fn();
      setResult({ kind: "ok", text: `${what}: ${r.note ?? ""}${r.bytes ? ` ${num(r.bytes)} bytes` : ""}`.trim(), sig: r.signature });
      setRefresh((n) => n + 1);
    } catch (e) { setResult({ kind: "err", text: (e as Error).message }); }
    finally { setBusy(null); setConfirmRotate(false); }
  }

  async function connect() {
    setResult(null);
    try { setWallet(await connectSolanaWallet()); } catch (e) { setResult({ kind: "err", text: (e as Error).message }); }
  }
  const flow = (): Flow => { if (!wallet) throw new Error("connect a Solana wallet first"); return { rpc, cluster, wallet }; };

  async function doSpend() {
    if (!id || !view?.state || !view.table) return;
    const st = view.state;
    const to = fromBase58(spendTo);
    const req = spendAsset === "sol"
      ? { kind: "sol" as const, to, amount: parseAmount(spendAmt, 9) }
      : (() => { const t = view.vault.tokens.find((t) => toBase58(t.mint) === spendAsset); if (!t) throw new Error("token not in the vault"); return { kind: "token" as const, to, amount: parseAmount(spendAmt, t.decimals), token: t }; })();
    const signer = epochSigner(id, st.epoch, poolRef.current!, signers.current);
    await run("spend", async () => {
      const r = await spend(flow(), id, st, signer, view.table!, req, (s) => setBusy({ what: STEP_TEXT[s] }));
      setSpendAmt("");
      return { signature: r.signature, bytes: r.bytes, note: `leaf ${r.idx}${r.cached ? "" : ` · subtree cached first (${num(r.cacheBytes ?? 0)} bytes)`} · execute` };
    });
  }

  if (!valid) return null;
  const st = view?.state ?? null;
  const accountB58 = id ? toBase58(id.account) : "";
  const vaultB58 = id ? toBase58(id.vault) : "";
  const missing = st && id ? recordMissing(cluster, accountB58, st) : false;
  const signedHere = st && id ? highestSigned(cluster, accountB58, st.epoch) : null;
  const wallets = solanaWallets();

  return (
    <div className="card swap-panel protect-panel solana-panel">
      <div className="swap-head">
        <div className="section-eyebrow">Solana · {cluster} · program account with a hash-only owner</div>
        <h3>The CCHS account on Solana: SOL and any SPL token held by a vault that only a WOTS+ signature can move.</h3>
        <p>
          The account is a PDA of the Aegis program keyed by the root of your C-20 tree; its vault is a second PDA that holds SOL
          and owns the token accounts. <code>execute</code> verifies one WOTS+ leaf (SHA-256, 26 chains of 24 bytes) against the
          cached subtree root and then signs the inner instruction as the vault, so the connected wallet only pays fees.
          Tokens are moved with <code>TransferChecked</code>; a memecoin is an SPL mint like any other.{" "}
          The program has one id on every cluster (<span className="mono">{shortKey(toBase58(SOLANA_PROGRAM_ID))}</span>) and is deployed by the
          repository's <code>solana-deploy</code> workflow, devnet first; it is not on mainnet-beta. The panel reads whether the program
          exists on the selected cluster before letting you do anything.
        </p>
      </div>

      <div className="swap-badges">
        <span className="chip chip-accent">C-20 · w=256 · 2^20 leaves per epoch · {RECOVERIES} recoveries · 864-byte layer</span>
        <span className="chip">execute ≈ 1 089 B v0 · cache_subtree ≈ 1 180 B · 0.6–1.2 M CU</span>
        <label className="chip" style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
          cluster
          <select value={cluster} onChange={(e) => pickCluster(e.target.value as Cluster)}>
            <option value="devnet">devnet</option>
            <option value="mainnet-beta">mainnet-beta (program not deployed)</option>
          </select>
        </label>
        <button className="btn btn-sm" disabled={!id} onClick={() => setRefresh((n) => n + 1)}>Refresh</button>
      </div>

      {!id && !deriveErr && <div className="swap-note">deriving the Solana key tree…</div>}
      {deriveErr && <div className="swap-note err">{deriveErr}</div>}

      {id && (
        <>
          <div className="protect-rows">
            <div className="protect-row">
              <div className="protect-chain">
                <span className="protect-name">Account PDA</span>
                <span className="protect-tx mono">{accountB58} <CopyBtn value={accountB58} /></span>
                <span className="protect-status">
                  key tree derived in {Math.round(id.tookMs)} ms ·{" "}
                  <a href={EXPLORER(cluster, "address", accountB58)} target="_blank" rel="noreferrer">explorer</a>
                  {st ? ` · epoch ${st.epoch} · next leaf ${num(st.nextIdx)} of ${num(CAPACITY)} · nonce ${st.nonce} · recoveries used ${st.recNonce}` : view ? " · not created yet" : ""}
                </span>
              </div>
            </div>
            <div className="protect-row">
              <div className="protect-chain">
                <span className="protect-name">Vault (send SOL and tokens here, or use the wallet below)</span>
                <span className="protect-tx mono">{vaultB58} <CopyBtn value={vaultB58} /></span>
                <span className="protect-status">
                  {view ? <>{sol(view.vault.lamports)} SOL{view.vault.tokens.map((t) => <span key={toBase58(t.address)}> · {formatAmount(t.amount, t.decimals)} <span className="mono">{shortKey(toBase58(t.mint))}</span></span>)}</> : viewErr ? <span className="protect-err">{viewErr}</span> : "reading…"}
                  {" · "}<a href={EXPLORER(cluster, "address", vaultB58)} target="_blank" rel="noreferrer">explorer</a>
                </span>
              </div>
            </div>
          </div>

          {view && !view.programDeployed && (
            <div className="swap-note warn">The Aegis program is not deployed on {cluster} at this RPC. Nothing can be created or spent here; switch to devnet.</div>
          )}

          <div className="spend-grid" style={{ marginTop: 12 }}>
            <label><span>RPC endpoint</span><input spellCheck={false} value={rpcUrl} onChange={(e) => setRpcUrl(e.target.value)} /></label>
            <label><span>Fee-paying wallet</span>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                {wallet
                  ? <span className="mono" title={wallet.address}>{wallet.name} · {shortKey(wallet.address)}{view ? ` · ${sol(view.walletLamports)} SOL` : ""}</span>
                  : <button className="btn btn-sm" onClick={connect}>{wallets.length ? `Connect ${wallets.map((w) => w.name).join(" / ")}` : "Connect Solana wallet"}</button>}
                {wallet && <button className="btn btn-sm" onClick={() => setWallet(null)}>disconnect</button>}
              </div>
            </label>
          </div>
          {cluster === "devnet" && wallet && view && view.walletLamports < 50_000_000n && (
            <div className="protect-status">The wallet needs devnet SOL for fees and rent: <a href="https://faucet.solana.com/" target="_blank" rel="noreferrer">faucet.solana.com</a> (set the wallet to devnet).</div>
          )}

          {/* ----------------------------------------------------------- Protect */}
          {view?.programDeployed && (
            <div className="spend">
              <div className="section-eyebrow">Protect · the wallet pays, the vault receives</div>
              {!st ? (
                <div className="spend-actions">
                  <button className="btn btn-primary btn-sm" disabled={!wallet || !!busy} onClick={() => run("create", async () => { const r = await createAccount(flow(), id); return { ...r, note: `account + lookup table ${shortKey(toBase58(r.table))}` }; })}>
                    {busy?.what === "create" ? "creating…" : "Create account (create + lookup table, one transaction)"}
                  </button>
                  <span className="protect-status">Rent for the 138-byte account and the lookup table, about 0.005 SOL, paid by the wallet.</span>
                </div>
              ) : (
                <>
                  {!view.table && (
                    <div className="swap-note warn">
                      No lookup table found for this account (needed by the v0 <code>execute</code> transaction).{" "}
                      <button className="btn btn-sm" disabled={!wallet || !!busy} onClick={() => run("lookup table", async () => { const r = await createTable(flow(), id); return { ...r, note: shortKey(toBase58(r.table)) }; })}>Create lookup table</button>
                    </div>
                  )}
                  <div className="spend-grid">
                    <label><span>Move SOL into the vault</span>
                      <div style={{ display: "flex", gap: 6 }}>
                        <input type="number" min="0" step="0.001" placeholder="0.1" value={depositAmt} onChange={(e) => setDepositAmt(e.target.value)} />
                        <button className="btn btn-sm" disabled={!wallet || !!busy || !depositAmt} onClick={() => run("deposit SOL", async () => { const r = await depositSol(flow(), id.vault, parseAmount(depositAmt, 9)); setDepositAmt(""); return r; })}>Move</button>
                      </div>
                    </label>
                  </div>
                  {wallet && view.walletTokens.length > 0 && (
                    <div className="protect-rows">
                      {view.walletTokens.map((t) => {
                        const mint = toBase58(t.mint);
                        return (
                          <div className="protect-row" key={toBase58(t.address)}>
                            <div className="protect-chain">
                              <span className="protect-name">Token <span className="mono">{shortKey(mint)}</span>{t.tokenProgram === TOKEN_2022_PROGRAM ? " · Token-2022" : ""}</span>
                              <span className="protect-status">wallet holds {formatAmount(t.amount, t.decimals)} · <a href={EXPLORER(cluster, "address", mint)} target="_blank" rel="noreferrer">mint</a></span>
                            </div>
                            <div style={{ display: "flex", gap: 6 }}>
                              <input type="text" placeholder="amount" style={{ width: 120 }} value={tokenAmts[mint] ?? ""} onChange={(e) => setTokenAmts({ ...tokenAmts, [mint]: e.target.value })} />
                              <button className="btn btn-sm" disabled={!!busy || !(tokenAmts[mint] ?? "")} onClick={() => run(`move ${shortKey(mint)}`, async () => { const r = await depositToken(flow(), id.vault, t, parseAmount(tokenAmts[mint], t.decimals)); setTokenAmts({ ...tokenAmts, [mint]: "" }); return r; })}>Move all or part</button>
                              <button className="btn btn-sm" disabled={!!busy} onClick={() => setTokenAmts({ ...tokenAmts, [mint]: formatAmount(t.amount, t.decimals) })}>max</button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                  {wallet && view.walletTokens.length === 0 && <div className="protect-status">The connected wallet holds no SPL tokens on {cluster}; any it holds would be listed here with a Move button.</div>}
                </>
              )}
            </div>
          )}

          {/* ------------------------------------------------------------- Spend */}
          {st && view?.programDeployed && (
            <div className="spend">
              <div className="section-eyebrow">Spend · one WOTS+ leaf, verified by the program</div>
              {missing && (
                <div className="swap-note warn">
                  This account has signed {num(st.nextIdx)} leaves in epoch {st.epoch.toString()} but this device holds no record of them (another device or browser profile did). A leaf must never be signed twice, so this device cannot spend in this epoch; rotate keys to continue from a fresh index space.
                </div>
              )}
              <div className="spend-grid">
                <label><span>Recipient (base58)</span><input spellCheck={false} placeholder="wallet address" value={spendTo} onChange={(e) => setSpendTo(e.target.value)} /></label>
                <label><span>Asset</span>
                  <select value={spendAsset} onChange={(e) => setSpendAsset(e.target.value)}>
                    <option value="sol">SOL ({sol(view.vault.lamports)})</option>
                    {view.vault.tokens.map((t) => <option key={toBase58(t.mint)} value={toBase58(t.mint)}>{shortKey(toBase58(t.mint))} ({formatAmount(t.amount, t.decimals)})</option>)}
                  </select>
                </label>
                <label><span>Amount</span><input type="text" placeholder="0.01" value={spendAmt} onChange={(e) => setSpendAmt(e.target.value)} /></label>
              </div>
              <div className="spend-actions">
                <button className="btn btn-primary btn-sm" disabled={!wallet || !!busy || missing || !view.table || !spendTo || !spendAmt} onClick={doSpend}>
                  {busy && busy.what !== "create" && busy.what !== "rotate" ? busy.what : "Sign and execute"}
                </button>
                {!confirmRotate
                  ? <button className="btn btn-sm" disabled={!wallet || !!busy} title="Move to the next epoch: fresh index space, keys derived from the same mnemonic." onClick={() => setConfirmRotate(true)}>Rotate keys (recover)</button>
                  : <button className="btn btn-sm" disabled={!!busy} onClick={() => run("rotate", async () => { const r = await recover(flow(), id, st, poolRef.current!); return { ...r, note: `now epoch ${r.epoch}` }; })}>Confirm rotation to epoch {(st.epoch + 1n).toString()}</button>}
                <span className="protect-status">{signedHere === null ? "no leaf signed on this device in this epoch" : `highest leaf signed here: ${signedHere}`}</span>
              </div>
              <div className="protect-status">
                The leaf is recorded as used before it is signed. The first leaf of each 1 024-leaf subtree costs an extra <code>cache_subtree</code> transaction (the top-layer proof); later leaves of the subtree go straight to <code>execute</code>. Token recipients without a token account get one created by the wallet first.
              </div>
            </div>
          )}

          {result && (
            <div className={`swap-note ${result.kind === "err" ? "err" : ""}`}>
              {result.text}
              {result.sig && <> · <a href={EXPLORER(cluster, "tx", result.sig)} target="_blank" rel="noreferrer" className="mono">{shortKey(result.sig)}</a></>}
            </div>
          )}

          <details className="protect-more">
            <summary>What is and is not protected here</summary>
            <div className="protect-status" style={{ display: "grid", gap: 6 }}>
              <span>Authorisation: WOTS+ over SHA-256 (C-20: 26 chains, w = 256), one leaf per <code>execute</code>, verified by the program against the subtree root registered with <code>cache_subtree</code>; the index rule makes a leaf unusable after it is spent or skipped. The connected wallet signs nothing that authorises the vault.</span>
              <span>Assets: SOL in the vault and any SPL or Token-2022 token in the vault's associated token accounts; NFTs are token accounts too and move the same way (amount 1). Programs other than System and Token can be called by passing other inner instructions; this panel only builds transfers.</span>
              <span>Network: devnet first, where SOL has no value; the warning above appears when the program does not exist on the selected cluster. Its upgrade authority is the deployer key of the workflow; the program id is the same on every cluster. Mainnet-beta: not deployed. State is on chain; the only thing this device keeps is which leaves it already signed.</span>
            </div>
          </details>
        </>
      )}
    </div>
  );
}
