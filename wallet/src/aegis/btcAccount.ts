// Bitcoin signet account for the wallet UI: the CCHS-UTXO lineage of btcCchs.ts
// read back from the chain, spent, and tracked across sessions.
//
// Reads go to a public esplora API (mempool.space signet): the lineage is public
// data, every spend is a confirmed transaction there. Writes cannot: a spend uses
// OP_CAT and OP_CHECKSIGFROMSTACK, which ordinary nodes treat as OP_SUCCESS and
// refuse to relay. Broadcasting therefore goes to a Bitcoin Inquisition node
// behind a small relay (bitcoin/relay), or the user carries the raw transaction
// to such a node by hand. Until a spend is mined it is invisible to the esplora
// API, so the wallet remembers it locally.
//
// Index discipline: a WOTS+ leaf is signed once. Consensus enforces idx ≥ nextIdx
// for the UTXO being spent, but a signed-and-unsent transaction would leave a
// second signature possible; the highest leaf signed per subtree is stored before
// signing and never reused.

import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { type CchsKey } from './cchs';
import { epochKey } from './cchsAccount';
import {
  HB, NO_SUBTREE, LAYER_BOTTOM, LAYER_TOP, LAYER_REC,
  publicKeyB, bottomOf, accountOutput, decodeSpend,
  execWitness, execFirstWitness, recoverWitness,
  initialState, afterExec, afterExecFirst, afterRecover,
  verifyExec, verifyExecFirst, verifyRecover, wotsSignB, authPathB,
  type BtcState, type BtcPublic, type BtcTrees, type LeafName,
} from './btcCchs';
import {
  type Tx, type Prevout, serialize, txid as txidOf, txidFromHex, txidToHex, vsize, weight,
  sighashScriptPath, bindingFor, p2trAddress, scriptPubKeyOf, type Network,
} from './btcTx';

export const SIGNET_API = 'https://mempool.space/signet/api';
export const SIGNET_EXPLORER = 'https://mempool.space/signet';
/** Observed floor of the signet block producer; the API's "recommended" 1 sat/vB is not mined reliably. */
export const MIN_FEERATE = 2;
/** Smallest successor output the wallet will create. */
export const MIN_SUCCESSOR = 1_000n;
export const DUST = 330n;
/** Relay set at build time (VITE_BTC_SIGNET_RELAY); the user can override it in the UI. */
export const DEFAULT_RELAY: string = ((import.meta as unknown as { env?: Record<string, string | undefined> }).env?.VITE_BTC_SIGNET_RELAY) ?? '';

export interface BtcUtxo { txid: string; vout: number; value: bigint; confirmed: boolean }
export interface LineageStep { txid: string; leaf: LeafName; state: string; confirmed: boolean; height?: number }
export interface Lineage {
  state: BtcState; address: string; utxos: BtcUtxo[]; steps: LineageStep[];
  /** Leaf the next spend would use, or null when the epoch is exhausted (recover first). */
  nextLeaf: LeafName | null;
  pending: PendingSpend | null;
}
export interface PendingSpend {
  txid: string; hex: string; leaf: LeafName; when: number; from: string; to: string;
  vsize: number; fee: number; successor: string;
}
export interface PreparedSpend {
  tx: Tx; hex: string; txid: string; leaf: LeafName; vsize: number; weight: number; fee: number; feerate: number;
  inputs: BtcUtxo[]; next: BtcState; nextAddress: string; payment: { to: string; sat: bigint } | null;
}

export const stateLabel = (st: BtcState) => `epoch ${st.epoch}, t ${st.t === NO_SUBTREE ? '∅' : st.t}, nextIdx ${st.nextIdx}`;

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(SIGNET_API + path, init);
  if (!r.ok) throw new Error(`${path}: ${r.status} ${(await r.text()).slice(0, 200)}`);
  const text = await r.text();
  try { return JSON.parse(text) as T; } catch { return text as unknown as T; }
}

interface EsploraTx {
  txid: string;
  vin: Array<{ txid: string; vout: number; witness?: string[]; prevout: { scriptpubkey: string; scriptpubkey_address?: string; value: number } }>;
  vout: Array<{ scriptpubkey: string; scriptpubkey_address?: string; value: number }>;
  status: { confirmed: boolean; block_height?: number };
}

export async function recommendedFeerate(): Promise<number> {
  try {
    const f = await api<{ fastestFee: number }>('/v1/fees/recommended');
    return Math.max(MIN_FEERATE, f.fastestFee);
  } catch { return MIN_FEERATE; }
}

export async function txStatus(txid: string): Promise<{ confirmed: boolean; height?: number } | null> {
  try {
    const s = await api<{ confirmed: boolean; block_height?: number }>(`/tx/${txid}/status`);
    return { confirmed: s.confirmed, height: s.block_height };
  } catch { return null; }
}

/** Relay to a Bitcoin Inquisition node (bitcoin/relay). Returns the txid the node reports. */
export async function broadcastViaRelay(relayUrl: string, hex: string): Promise<string> {
  const r = await fetch(relayUrl.replace(/\/$/, '') + '/tx', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: hex });
  const text = await r.text();
  if (!r.ok) throw new Error(text.slice(0, 300) || `relay ${r.status}`);
  try { return (JSON.parse(text) as { txid: string }).txid; } catch { return text.trim(); }
}

export async function relayInfo(relayUrl: string): Promise<{ chain: string; blocks: number; op_cat: boolean; checksigfromstack: boolean }> {
  const r = await fetch(relayUrl.replace(/\/$/, '') + '/info');
  if (!r.ok) throw new Error(`relay ${r.status}`);
  return r.json();
}

const store = {
  get<T>(k: string): T | null { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) as T : null; } catch { return null; } },
  set(k: string, v: unknown) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } },
  del(k: string) { try { localStorage.removeItem(k); } catch { /* ignore */ } },
};

export class BtcAccount {
  readonly net: Network = 'signet';
  private epochs = new Map<number, { key: CchsKey; pub: BtcPublic; trees: BtcTrees }>();
  private readonly id: string;

  constructor(private readonly chain: CchsKey, readonly HT: number) {
    this.id = bytesToHex(this.epochOf(0).pub.root).slice(0, 16);
  }

  epochOf(e: number) {
    let x = this.epochs.get(e);
    if (!x) { const key = epochKey(this.chain, e); const { pub, trees } = publicKeyB(key, this.HT); x = { key, pub, trees }; this.epochs.set(e, x); }
    return x;
  }

  addressOf(st: BtcState): string { return p2trAddress(accountOutput(st).output.scriptPubKey, this.net); }
  get address0(): string { return this.addressOf(initialState(this.epochOf(0).pub, 0, this.HT)); }

  // ---- persistence

  private k(s: string) { return `aegis/btc/${this.net}/${s}/${this.id}`; }
  private signedKey(st: BtcState, t: number) { return `${this.k('signed')}/${st.epoch}/${t}`; }
  highestSigned(st: BtcState, t: number): number { return store.get<number>(this.signedKey(st, t)) ?? -1; }
  private markSigned(st: BtcState, t: number, leaf: number) { store.set(this.signedKey(st, t), Math.max(leaf, this.highestSigned(st, t))); }
  get relayUrl(): string { return store.get<string>(`aegis/btc/${this.net}/relay`) ?? DEFAULT_RELAY; }
  set relayUrl(u: string) { if (u) store.set(`aegis/btc/${this.net}/relay`, u); else store.del(`aegis/btc/${this.net}/relay`); }
  get pending(): PendingSpend | null { return store.get<PendingSpend>(this.k('pending')); }
  private setPending(p: PendingSpend | null) { if (p) store.set(this.k('pending'), p); else store.del(this.k('pending')); }

  // ---- chain reads

  /** Follow the lineage from the first address: each spend of the current address is decoded into the successor state. */
  async sync(): Promise<Lineage> {
    let st = initialState(this.epochOf(0).pub, 0, this.HT);
    const steps: LineageStep[] = [];
    for (let hops = 0; hops < 10_000; hops++) {
      const addr = this.addressOf(st);
      const txs = await api<EsploraTx[]>(`/address/${addr}/txs`);
      const spend = txs.find(tx => tx.vin.some(i => i.prevout.scriptpubkey_address === addr));
      if (!spend) {
        const raw = await api<Array<{ txid: string; vout: number; value: number; status: { confirmed: boolean } }>>(`/address/${addr}/utxo`);
        const utxos = raw.map(u => ({ txid: u.txid, vout: u.vout, value: BigInt(u.value), confirmed: u.status.confirmed }))
          .sort((a, b) => Number(b.value - a.value));
        let pending = this.pending;
        if (pending) {
          if (pending.from !== addr) pending = null;              // already reflected on chain
          else if ((await txStatus(pending.txid))?.confirmed) pending = null;
          if (!pending) this.setPending(null);
        }
        return { state: st, address: addr, utxos, steps, nextLeaf: this.nextLeaf(st), pending };
      }
      const ours = spend.vin.filter(i => i.prevout.scriptpubkey_address === addr);
      let next: BtcState | null = null;
      for (const vin of ours) {
        const d = decodeSpend(st, (vin.witness ?? []).map(hexToBytes));
        if (!d) throw new Error(`cannot decode spend ${spend.txid} of ${addr}`);
        const after = d.leaf === 'exec' ? afterExec(st, d.idx!)
          : d.leaf === 'execFirst' ? afterExecFirst(st, d.tNew!, d.idx!, d.R!)
          : afterRecover(st, this.epochOf(st.epoch + 1).pub);
        next = next && after.nextIdx < next.nextIdx ? next : after;   // several inputs: the highest index wins
        if (vin === ours[0]) steps.push({ txid: spend.txid, leaf: d.leaf, state: '', confirmed: spend.status.confirmed, height: spend.status.block_height });
      }
      st = next!;
      steps[steps.length - 1].state = stateLabel(st);
    }
    throw new Error('lineage too long');
  }

  nextLeaf(st: BtcState): LeafName | null {
    if (st.t !== NO_SUBTREE && Math.max(st.nextIdx, this.highestSigned(st, st.t) + 1) < 1 << HB) return 'exec';
    if (st.t + 1 < 1 << this.HT) return 'execFirst';
    return null;
  }

  /** Spends remaining in this epoch before a recovery is needed (upper bound). */
  spendsLeft(st: BtcState): number {
    const inCurrent = st.t === NO_SUBTREE ? 0 : (1 << HB) - Math.max(st.nextIdx, this.highestSigned(st, st.t) + 1);
    return inCurrent + ((1 << this.HT) - st.t - 1) * (1 << HB);
  }

  // ---- spending

  /**
   * Build and sign one transaction spending every UTXO at the current address:
   * output 0 is the successor, output 1 the payment (omitted when `to` is empty).
   * `leaf` defaults to the cheapest available; 'recover' rotates the epoch.
   */
  prepare(lin: Lineage, opts: { to?: string; sat?: bigint; feerate: number; leaf?: LeafName; confirmedOnly?: boolean }): PreparedSpend {
    const st = lin.state;
    const inputs = opts.confirmedOnly === false ? lin.utxos : lin.utxos.filter(u => u.confirmed);
    if (!inputs.length) throw new Error('no confirmed UTXO at the account address');
    if (lin.pending) throw new Error('a spend is pending; wait for it or discard it first');
    const leaf = opts.leaf ?? lin.nextLeaf;
    if (!leaf) throw new Error('epoch exhausted: recover to the next epoch');
    const { key, trees } = this.epochOf(st.epoch);
    const out = accountOutput(st);
    const script = out.leaves[leaf]; if (!script) throw new Error(`${leaf} is not available in ${stateLabel(st)}`);
    const n = inputs.length;

    // indices
    let tNew = st.t, first = 0;
    if (leaf === 'exec') { first = Math.max(st.nextIdx, this.highestSigned(st, st.t) + 1); if (first + n > 1 << HB) throw new Error('subtree exhausted for this many inputs'); }
    if (leaf === 'execFirst') { tNew = st.t + 1; first = this.highestSigned(st, tNew) + 1; if (tNew >= 1 << this.HT || first + n > 1 << HB) throw new Error('no subtree left: recover'); }
    if (leaf === 'recover' && n > 1) throw new Error('recover one UTXO at a time');

    // successor
    let next: BtcState;
    if (leaf === 'exec') next = afterExec(st, first + n - 1);
    else if (leaf === 'execFirst') next = afterExecFirst(st, tNew, first + n - 1, bottomOf(key, trees, tNew).root);
    else next = afterRecover(st, this.epochOf(st.epoch + 1).pub);
    const nextOut = accountOutput(next);

    // transaction, fee from the witness upper bound
    const tx: Tx = {
      version: 2, locktime: 0,
      vin: inputs.map(u => ({ txid: txidFromHex(u.txid), vout: u.vout, sequence: 0xffffffff, witness: [] })),
      vout: [{ value: 0n, scriptPubKey: nextOut.output.scriptPubKey }],
    };
    const payment = opts.to && opts.sat && opts.sat > 0n ? { to: opts.to.trim(), sat: opts.sat } : null;
    if (payment) {
      if (payment.sat < DUST) throw new Error(`payment below dust (${DUST} sat)`);
      tx.vout.push({ value: payment.sat, scriptPubKey: scriptPubKeyOf(payment.to) });
    }
    for (let i = 0; i < n; i++) tx.vin[i].witness = [...placeholder(leaf, st), script, out.controlBlock(leaf)];
    const feerate = Math.max(MIN_FEERATE, opts.feerate);
    const fee = BigInt(Math.ceil(vsize(tx) * feerate));
    const total = inputs.reduce((a, u) => a + u.value, 0n);
    const change = total - fee - (payment?.sat ?? 0n);
    if (change < MIN_SUCCESSOR) throw new Error(`insufficient funds: ${total} sat in, ${fee} sat fee, successor needs ≥ ${MIN_SUCCESSOR} sat`);
    tx.vout[0].value = change;

    // sign every input once
    const prevouts: Prevout[] = inputs.map(() => ({ value: 0n, scriptPubKey: out.output.scriptPubKey }));
    inputs.forEach((u, i) => { prevouts[i].value = u.value; });
    for (let i = 0; i < n; i++) {
      const m = sighashScriptPath(tx, prevouts, i, script);
      const b = bindingFor(m);
      let items: Uint8Array[], ok: boolean;
      if (leaf === 'exec') {
        const idx = first + i; this.markSigned(st, st.t, idx);
        bottomOf(key, trees, st.t);
        items = execWitness(key, trees, st, idx, b);
        ok = verifyExec(st, idx, m, wotsSignB(key, LAYER_BOTTOM, st.t, idx, m), authPathB(trees.bottom[st.t], idx));
      } else if (leaf === 'execFirst') {
        const idx = first + i; this.markSigned(st, tNew, idx);
        const bottom = bottomOf(key, trees, tNew);
        items = execFirstWitness(key, trees, st, tNew, idx, b);
        ok = verifyExecFirst(st, tNew, idx, m, bottom.root,
          wotsSignB(key, LAYER_BOTTOM, tNew, idx, m), authPathB(bottom, idx),
          wotsSignB(key, LAYER_TOP, 0, tNew, bottom.root), authPathB(trees.top, tNew));
      } else {
        items = recoverWitness(key, trees, st, b);
        ok = verifyRecover(st, m, wotsSignB(key, LAYER_REC, 0, st.epoch, m), authPathB(trees.rec, st.epoch));
      }
      if (!ok) throw new Error('reference verifier rejects the witness');
      tx.vin[i].witness = [...items, script, out.controlBlock(leaf)];
    }
    const hex = bytesToHex(serialize(tx, true));
    const id = txidToHex(txidOf(tx));
    return { tx, hex, txid: id, leaf, vsize: vsize(tx), weight: weight(tx), fee: Number(fee), feerate: Number(fee) / vsize(tx), inputs, next, nextAddress: this.addressOf(next), payment };
  }

  /** Record a broadcast so the UI survives a reload while the esplora API cannot see the transaction. */
  recordBroadcast(p: PreparedSpend, from: string) {
    this.setPending({ txid: p.txid, hex: p.hex, leaf: p.leaf, when: Date.now(), from, to: p.nextAddress, vsize: p.vsize, fee: p.fee, successor: stateLabel(p.next) });
  }
  discardPending() { this.setPending(null); }
}

/** Witness upper bound (every digit and bit one byte) for the fee. */
function placeholder(leaf: LeafName, st: BtcState): Uint8Array[] {
  const z = (n: number) => new Uint8Array(n);
  const pairs = () => Array.from({ length: 67 * 2 }, (_, i) => z(i % 2 === 0 ? 32 : 1));
  const bytes = () => Array.from({ length: 32 }, () => z(1));
  const sibs = (h: number) => Array.from({ length: h }, () => z(32));
  const bits = (h: number) => Array.from({ length: h }, () => z(1));
  const head = [z(64), z(32), z(32)];
  if (leaf === 'exec') return [...head, ...bytes(), ...sibs(HB), ...pairs(), ...bits(HB)];
  if (leaf === 'recover') return [...head, ...bytes(), ...sibs(8), ...pairs()];
  return [...head, ...bytes(), ...sibs(st.HT), ...pairs(), ...bytes(), ...sibs(HB), ...pairs(), ...bits(HB), ...bits(st.HT)];
}
