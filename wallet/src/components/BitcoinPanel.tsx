// Bitcoin (signet): the CCHS-UTXO account of BITCOIN.md §5, usable end to end.
//
// 1. The mnemonic derives the Bitcoin chain key; the epoch's public key (top tree
//    and recovery tree) is computed here in well under a second. Bottom subtrees
//    are built only when a leaf of them is about to be signed.
// 2. The lineage is read back from a public signet explorer: every spend of the
//    current address is decoded into the successor state, so the wallet has no
//    state of its own beyond "which leaves this device already signed".
// 3. Send builds one transaction spending every UTXO at the current address:
//    output 0 the successor (the same account, next state), output 1 the payment.
//    The leaf is signed once; the fee is fixed before signing.
// 4. Broadcast goes to a Bitcoin Inquisition node through a relay (bitcoin/relay),
//    because ordinary nodes do not relay OP_CAT spends. The raw transaction can
//    also be copied and sent by hand.
//
// Signet coins have no value. Mainnet is not supported: the opcodes are not
// active there, and a P2TR output has a key path (BITCOIN.md §4, §5.1).

import { useCallback, useEffect, useMemo, useState } from "react";
import { isValidMnemonic } from "../aegis/derive";
import { cchsMaster, chainKey, labelChainTag } from "../aegis/cchsAccount";
import {
  BtcAccount, SIGNET_EXPLORER, MIN_FEERATE, MIN_SUCCESSOR, DEFAULT_RELAY,
  recommendedFeerate, broadcastViaRelay, relayInfo, stateLabel,
  type Lineage, type PreparedSpend,
} from "../aegis/btcAccount";
import { DEFAULT_HT, HB } from "../aegis/btcCchs";
import CopyBtn from "./CopyBtn";

type Phase = "idle" | "signing" | "broadcasting" | "sent" | "error";

const sat = (n: bigint | number) => Number(n).toLocaleString("en-US");
const short = (s: string) => s.length > 20 ? `${s.slice(0, 10)}…${s.slice(-8)}` : s;

const FAUCETS = [
  { name: "faucet.rgbmap.org", url: "https://faucet.rgbmap.org/" },
  { name: "signetfaucet.com", url: "https://signetfaucet.com/" },
  { name: "alt.signetfaucet.com", url: "https://alt.signetfaucet.com/" },
];

export default function BitcoinPanel({ mnemonic }: { mnemonic: string }) {
  const valid = isValidMnemonic(mnemonic);
  const [account, setAccount] = useState<BtcAccount | null>(null);
  const [lineage, setLineage] = useState<Lineage | null>(null);
  const [syncErr, setSyncErr] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [feerate, setFeerate] = useState(MIN_FEERATE);
  const [to, setTo] = useState("");
  const [amount, setAmount] = useState("");
  const [relay, setRelay] = useState(DEFAULT_RELAY);
  const [relayState, setRelayState] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [msg, setMsg] = useState<string | null>(null);
  const [prepared, setPrepared] = useState<PreparedSpend | null>(null);
  const [confirmRecover, setConfirmRecover] = useState(false);

  // Derive the account (public key only) when the mnemonic changes.
  useEffect(() => {
    if (!valid) { setAccount(null); setLineage(null); return; }
    let cancelled = false;
    setAccount(null); setLineage(null); setPrepared(null); setPhase("idle"); setMsg(null);
    const t = setTimeout(() => {
      try {
        const master = cchsMaster(mnemonic);
        const acct = new BtcAccount(chainKey(master, labelChainTag("bitcoin")), DEFAULT_HT);
        if (!cancelled) { setAccount(acct); setRelay(acct.relayUrl); }
      } catch (e) { if (!cancelled) setSyncErr((e as Error).message); }
    }, 400);
    return () => { cancelled = true; clearTimeout(t); };
  }, [mnemonic, valid]);

  const sync = useCallback(async (acct: BtcAccount) => {
    setSyncing(true); setSyncErr(null);
    try {
      const [lin, fr] = await Promise.all([acct.sync(), recommendedFeerate()]);
      setLineage(lin); setFeerate((f) => (f === MIN_FEERATE ? fr : f));
    } catch (e) { setSyncErr((e as Error).message); }
    finally { setSyncing(false); }
  }, []);

  useEffect(() => { if (account) void sync(account); }, [account, sync]);

  // Poll while a spend is pending (the explorer sees it only once mined).
  useEffect(() => {
    if (!account || !lineage?.pending) return;
    const id = setInterval(() => void sync(account), 30_000);
    return () => clearInterval(id);
  }, [account, lineage?.pending, sync]);

  const balance = useMemo(() => lineage?.utxos.reduce((a, u) => a + u.value, 0n) ?? 0n, [lineage]);
  const confirmed = useMemo(() => lineage?.utxos.filter((u) => u.confirmed).reduce((a, u) => a + u.value, 0n) ?? 0n, [lineage]);
  const relayOk = relay.trim().length > 0;

  async function checkRelay() {
    setRelayState("checking…");
    try {
      const i = await relayInfo(relay);
      setRelayState(i.chain !== "signet" ? `relay is on ${i.chain}, not signet` : !i.op_cat || !i.checksigfromstack ? "relay node lacks OP_CAT / CSFS" : `signet · height ${i.blocks.toLocaleString("en-US")} · OP_CAT + CSFS active`);
      if (account) account.relayUrl = relay.trim();
    } catch (e) { setRelayState(`unreachable: ${(e as Error).message}`); }
  }

  async function build(leaf?: "recover") {
    if (!account || !lineage) return;
    setPhase("signing"); setMsg(null); setPrepared(null); setConfirmRecover(false);
    await new Promise((r) => setTimeout(r, 30));   // let the status render before the hash chains
    try {
      const sats = amount.trim() ? BigInt(Math.round(Number(amount) * 1e8)) : 0n;
      if (!leaf && (!to.trim() || sats <= 0n)) throw new Error("enter a recipient and an amount");
      const p = account.prepare(lineage, { to: leaf ? undefined : to, sat: leaf ? undefined : sats, feerate, leaf });
      setPrepared(p); setPhase("idle");
    } catch (e) { setPhase("error"); setMsg((e as Error).message); }
  }

  async function broadcast() {
    if (!account || !lineage || !prepared) return;
    setPhase("broadcasting"); setMsg(null);
    try {
      const id = await broadcastViaRelay(relay, prepared.hex);
      if (id.toLowerCase() !== prepared.txid) throw new Error(`relay returned a different txid: ${id}`);
      account.recordBroadcast(prepared, lineage.address);
      setPhase("sent"); setMsg(id); setPrepared(null); setTo(""); setAmount("");
      void sync(account);
    } catch (e) { setPhase("error"); setMsg((e as Error).message); }
  }

  if (!valid) return null;

  return (
    <div className="card swap-panel protect-panel btc-panel">
      <div className="swap-head">
        <div className="section-eyebrow">Bitcoin · signet · hash-only account carried by the UTXO</div>
        <h3>The CCHS account on Bitcoin, live on signet. Each spend is a WOTS+ signature over the transaction itself.</h3>
        <p>
          Every UTXO of the account commits to its state <code>(root, recRoot, epoch, cached subtree, nextIdx)</code> in three
          Tapscript leaves; a spend verifies one WOTS+ signature over the transaction's own sighash against the cached
          subtree root, enforces the index rule, and creates the successor UTXO. No elliptic-curve secret is involved
          anywhere. <strong>Signet only</strong>: the opcodes this needs (<code>OP_CAT</code>, <code>OP_CHECKSIGFROMSTACK</code>)
          are active on Bitcoin Inquisition signet and not on mainnet, and a P2TR output keeps a key path a quantum adversary
          could use. Signet coins have no value; the mainnet Bitcoin address of this wallet remains plain P2WPKH and is not post-quantum.
        </p>
      </div>

      {!account && !syncErr && <div className="swap-note">deriving the Bitcoin key tree…</div>}
      {syncErr && <div className="swap-note err">{syncErr} <button className="btn btn-sm" onClick={() => account && sync(account)}>retry</button></div>}

      {account && lineage && (
        <>
          <div className="swap-grid">
            <div className="swap-cell">
              <div className="k">Balance</div>
              <div className="v">{sat(balance)} sat{confirmed !== balance ? ` · ${sat(confirmed)} confirmed` : ""}</div>
            </div>
            <div className="swap-cell">
              <div className="k">State</div>
              <div className="v">{stateLabel(lineage.state)}</div>
            </div>
            <div className="swap-cell">
              <div className="k">Spends left this epoch</div>
              <div className="v">{account.spendsLeft(lineage.state).toLocaleString("en-US")} of {(1 << (DEFAULT_HT + HB)).toLocaleString("en-US")}</div>
            </div>
            <div className="swap-cell">
              <div className="k">Lineage</div>
              <div className="v">{lineage.steps.length} spend{lineage.steps.length === 1 ? "" : "s"} on chain{lineage.pending ? " · 1 pending" : ""}</div>
            </div>
          </div>

          <div className="swap-badges">
            <span className="chip chip-accent">WOTS+ w=16 · 2^{DEFAULT_HT + HB} leaves per epoch · 256 recoveries · SHA-256 only</span>
            <span className="chip">exec ≈ 3 300 vB · first in subtree ≈ 6 340 vB · recover ≈ 3 210 vB</span>
            <button className="btn btn-sm" disabled={syncing} onClick={() => sync(account)}>{syncing ? "reading chain…" : "Refresh"}</button>
          </div>

          <div className="protect-rows">
            <div className="protect-row">
              <div className="protect-chain">
                <span className="protect-name">Account address (current state)</span>
                <span className="protect-tx mono">{lineage.address} <CopyBtn value={lineage.address} /></span>
                <span className="protect-status">
                  Send signet coins here. The address changes after every spend (the successor commits to the new state);
                  coins sent to an earlier address of the lineage stay spendable with that state's leaves.{" "}
                  <a href={`${SIGNET_EXPLORER}/address/${lineage.address}`} target="_blank" rel="noreferrer">explorer</a>
                  {" · faucets: "}
                  {FAUCETS.map((f, i) => <span key={f.name}>{i > 0 && ", "}<a href={f.url} target="_blank" rel="noreferrer">{f.name}</a></span>)}
                </span>
                {lineage.utxos.length > 1 && <span className="protect-status">{lineage.utxos.length} UTXOs here; the next spend consumes all of them (one WOTS+ leaf each)</span>}
              </div>
            </div>
          </div>

          {lineage.pending && (
            <div className="swap-note warn">
              Pending: <span className="mono">{short(lineage.pending.txid)}</span> ({lineage.pending.leaf}, {sat(lineage.pending.vsize)} vB, fee {sat(lineage.pending.fee)} sat → {lineage.pending.successor}),
              broadcast {Math.round((Date.now() - lineage.pending.when) / 60000)} min ago. Only Inquisition nodes see it until it is mined; signet blocks are about 10 minutes apart.{" "}
              <a href={`${SIGNET_EXPLORER}/tx/${lineage.pending.txid}`} target="_blank" rel="noreferrer">explorer</a>
              {" "}<CopyBtn value={lineage.pending.hex} />
              <button className="btn btn-sm" style={{ marginLeft: 8 }} onClick={async () => { try { await broadcastViaRelay(relay, lineage.pending!.hex); setMsg("rebroadcast"); } catch (e) { setMsg((e as Error).message); } }}>rebroadcast</button>
              <button className="btn btn-sm" style={{ marginLeft: 8 }} title="Forget this transaction locally. The leaf it signed is never reused." onClick={() => { account.discardPending(); void sync(account); }}>discard</button>
            </div>
          )}

          <div className="spend">
            <div className="section-eyebrow">Send · one WOTS+ signature per input</div>
            <div className="spend-grid">
              <label><span>Recipient (signet tb1…)</span><input spellCheck={false} placeholder="tb1q… or tb1p…" value={to} onChange={(e) => setTo(e.target.value)} /></label>
              <label><span>Amount (sBTC)</span><input type="number" min="0" step="0.00001" placeholder="0.0001" value={amount} onChange={(e) => setAmount(e.target.value)} /></label>
              <label><span>Fee rate (sat/vB)</span><input type="number" min={MIN_FEERATE} step="0.1" value={feerate} onChange={(e) => setFeerate(Math.max(MIN_FEERATE, Number(e.target.value) || MIN_FEERATE))} /></label>
              <label><span>Relay (Inquisition node)</span>
                <div style={{ display: "flex", gap: 6 }}>
                  <input spellCheck={false} placeholder="https://…" value={relay} onChange={(e) => { setRelay(e.target.value); setRelayState(null); }} />
                  <button className="btn btn-sm" disabled={!relayOk} onClick={checkRelay}>check</button>
                </div>
              </label>
            </div>
            {relayState && <div className="protect-status">{relayState}</div>}
            <div className="spend-actions">
              <button className="btn btn-primary btn-sm" disabled={!!lineage.pending || !lineage.nextLeaf || confirmed === 0n || phase === "signing" || phase === "broadcasting"} onClick={() => build()}>
                {phase === "signing" ? "signing (hash chains)…" : `Sign ${lineage.nextLeaf === "execFirst" ? "(first in subtree)" : "(subtree cached)"}`}
              </button>
              {!confirmRecover
                ? <button className="btn btn-sm" disabled={!!lineage.pending || confirmed === 0n || phase === "signing"} title="Move to the next epoch: a fresh index space, keys derived from the same mnemonic. Use it when the epoch is exhausted or another copy of this wallet may have signed leaves this device does not know about." onClick={() => setConfirmRecover(true)}>Rotate keys (recover)</button>
                : <button className="btn btn-sm" onClick={() => build("recover")}>Confirm rotation to epoch {lineage.state.epoch + 1}</button>}
              {phase === "error" && <span className="protect-err">{msg}</span>}
              {phase === "sent" && <span className="protect-status ok">sent · <a href={`${SIGNET_EXPLORER}/tx/${msg}`} target="_blank" rel="noreferrer" className="mono">{short(msg ?? "")}</a></span>}
              {phase === "idle" && msg && <span className="protect-status">{msg}</span>}
            </div>
            {!lineage.nextLeaf && <div className="swap-note warn">This epoch's leaves are used up. Rotate keys to continue.</div>}
            {confirmed === 0n && !lineage.pending && <div className="swap-note">Fund the address above first (a confirmed UTXO is required). The successor output keeps at least {sat(MIN_SUCCESSOR)} sat.</div>}

            {prepared && (
              <div className="swap-note">
                <div><strong>{prepared.leaf}</strong> · {prepared.inputs.length} input{prepared.inputs.length > 1 ? "s" : ""} · {sat(prepared.vsize)} vB · fee {sat(prepared.fee)} sat ({prepared.feerate.toFixed(2)} sat/vB)</div>
                {prepared.payment && <div>pays {sat(prepared.payment.sat)} sat to <span className="mono">{short(prepared.payment.to)}</span></div>}
                <div>successor {sat(prepared.tx.vout[0].value)} sat at <span className="mono">{short(prepared.nextAddress)}</span> · {stateLabel(prepared.next)}</div>
                <div className="protect-status">The leaf is signed and recorded; it will not be signed again. Broadcast it, or copy the raw transaction and submit it to any Bitcoin Inquisition node (<code>bitcoin-cli sendrawtransaction</code>).</div>
                <div className="spend-actions">
                  <button className="btn btn-primary btn-sm" disabled={!relayOk || phase === "broadcasting"} onClick={broadcast}>{phase === "broadcasting" ? "broadcasting…" : relayOk ? "Broadcast via relay" : "Set a relay to broadcast"}</button>
                  <CopyBtn value={prepared.hex} /> <span className="protect-status">raw tx {(prepared.hex.length / 2).toLocaleString("en-US")} B</span>
                  <span className="mono protect-status">{short(prepared.txid)}</span>
                </div>
              </div>
            )}
          </div>

          {lineage.steps.length > 0 && (
            <details className="protect-more" open>
              <summary>Lineage · every spend of this account on signet</summary>
              <div className="protect-rows">
                {lineage.steps.map((s, i) => (
                  <div className="protect-row" key={s.txid}>
                    <div className="protect-chain">
                      <span className="protect-name">{i + 1}. {s.leaf}</span>
                      <span className="protect-tx mono"><a href={`${SIGNET_EXPLORER}/tx/${s.txid}`} target="_blank" rel="noreferrer">{s.txid}</a></span>
                      <span className="protect-status">→ {s.state}{s.confirmed ? ` · block ${s.height?.toLocaleString("en-US")}` : " · unconfirmed"}</span>
                    </div>
                  </div>
                ))}
              </div>
            </details>
          )}

          <details className="protect-more">
            <summary>What is and is not protected here</summary>
            <div className="protect-status" style={{ display: "grid", gap: 6 }}>
              <span>Authorisation: WOTS+ (SHA-256), one leaf per spend, verified by consensus against the subtree root cached in the UTXO; a leaf is never signed twice. Binding to the transaction: the sighash is tied to the WOTS+ message with <code>OP_CHECKSIG</code> + <code>OP_CHECKSIGFROMSTACK</code> on a public key everybody knows (<code>d = 1</code>), so no secret curve key exists.</span>
              <span>Not enforced by consensus on P2TR: that the successor output commits to the updated state (the signer builds it, the signature covers it). Open: the P2TR key path, a NUMS point here, which a discrete-log adversary could spend. Both close with a key-less output type (BIP-360 P2MR).</span>
              <span>Network: Bitcoin Inquisition signet. Mainnet has neither opcode; this account cannot exist there today. Reads use mempool.space; broadcasts need an Inquisition node (the relay).</span>
            </div>
          </details>
        </>
      )}
    </div>
  );
}
