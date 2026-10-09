// Bitcoin: run a CCHS-UTXO lineage against a node that enforces OP_CAT and
// OP_CHECKSIGFROMSTACK (Bitcoin Inquisition: regtest for development, signet
// for the public record). Builds the account, funds its first output (regtest:
// from the node wallet; signet: waits for an external payment to the printed
// address), then spends through the lineage
//
//   execFirst → exec → exec → recover → execFirst
//
// each spend consumed by the next, and prints txids, weights and fees. Every
// transaction is checked with the wallet's reference verifier and the node's
// testmempoolaccept before it is broadcast. The signing key is a test master
// given in the environment; nothing here touches a wallet with value.
//
//   BTC_NETWORK=regtest|signet  BTC_RPC_URL  BTC_RPC_USER  BTC_RPC_PASS
//   BTC_MASTER_HEX   32-byte test master (hex)
//   BTC_TOP_HEIGHT   top-tree height (default 4: 16 subtrees × 1024 leaves per epoch)
//   BTC_FEERATE      sat/vB (default 1.1)
//   BTC_PAY_TO       optional address that receives BTC_PAY_SAT (default 10 000) sat in every spend
//   BTC_FUND_SAT     regtest funding amount (default 300 000)
//   BTC_STEPS        comma list of execFirst|exec|recover (default above)
//
//   npm run btc-flow     (from wallet/)

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import {
  HB, NO_SUBTREE, keygenB, accountOutput, initialState, afterExec, afterExecFirst, afterRecover,
  execWitness, execFirstWitness, recoverWitness, verifyExec, verifyExecFirst, verifyRecover,
  wotsSignB, authPathB, LAYER_BOTTOM, LAYER_TOP, LAYER_REC, type BtcState, type BtcTrees, type LeafName, type BtcPublic,
} from '../src/aegis/btcCchs.ts';
import {
  sighashScriptPath, bindingFor, serialize, vsize, weight, txid, txidToHex, txidFromHex, p2trAddress, scriptPubKeyOf,
  type Tx, type Prevout, type Network,
} from '../src/aegis/btcTx.ts';
import { chainKey, epochKey, labelChainTag } from '../src/aegis/cchsAccount.ts';
import type { CchsKey } from '../src/aegis/cchs.ts';

const env = (k: string, d?: string) => process.env[k] ?? d ?? (() => { throw new Error(`${k} not set`); })();
const net = env('BTC_NETWORK', 'regtest') as Network;
const RPC = env('BTC_RPC_URL', net === 'regtest' ? 'http://127.0.0.1:18443' : 'http://127.0.0.1:38332');
const AUTH = 'Basic ' + Buffer.from(`${env('BTC_RPC_USER')}:${env('BTC_RPC_PASS')}`).toString('base64');
const HT = Number(env('BTC_TOP_HEIGHT', '4'));
const FEERATE = Number(env('BTC_FEERATE', '1.1'));
const PAY_TO = process.env.BTC_PAY_TO;
const PAY_SAT = BigInt(env('BTC_PAY_SAT', '10000'));
const STEPS = env('BTC_STEPS', 'execFirst,exec,exec,recover,execFirst').split(',') as LeafName[];

async function rpc<T = unknown>(method: string, params: unknown[] = [], wallet?: string): Promise<T> {
  const res = await fetch(wallet ? `${RPC}/wallet/${wallet}` : RPC, {
    method: 'POST', headers: { Authorization: AUTH, 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '1.0', id: 'aegis', method, params }),
  });
  const j = await res.json() as { result: T; error: { code: number; message: string } | null };
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
}
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
const log = (...a: unknown[]) => console.log(...a);

// ---------------------------------------------------------------- account

const master: CchsKey = { master: hexToBytes(env('BTC_MASTER_HEX')) };
if (master.master.length !== 32) throw new Error('BTC_MASTER_HEX must be 32 bytes');
const key0 = chainKey(master, labelChainTag('bitcoin'));

const epochs = new Map<number, { key: CchsKey; pub: BtcPublic; trees: BtcTrees }>();
function epochOf(e: number) {
  let x = epochs.get(e);
  if (!x) {
    const key = epochKey(key0, e);
    log(`keygen epoch ${e}: 2^${HT} subtrees × 2^${HB} leaves + top + recovery …`);
    const t0 = Date.now();
    const { pub, trees } = keygenB(key, HT);
    log(`  ${((Date.now() - t0) / 1000).toFixed(1)} s  root ${bytesToHex(pub.root)}  recRoot ${bytesToHex(pub.recRoot)}  seed ${bytesToHex(pub.seed)}`);
    x = { key, pub, trees }; epochs.set(e, x);
  }
  return x;
}

/** Upper bound of the witness: every digit and bit as one byte. Used to fix the fee before signing (a leaf is never signed twice). */
function placeholderWitness(leaf: LeafName, st: BtcState): Uint8Array[] {
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

interface Utxo { txid: Uint8Array; vout: number; value: bigint; scriptPubKey: Uint8Array }
interface Step { leaf: LeafName; txid: string; vsize: number; weight: number; fee: number; feerate: string; script: number; witness: number; state: string }
const steps: Step[] = [];
const stateStr = (st: BtcState) => `epoch ${st.epoch}, t ${st.t === NO_SUBTREE ? '∅' : st.t}, nextIdx ${st.nextIdx}`;

async function spend(leaf: LeafName, utxo: Utxo, st: BtcState, pick: { tNew?: number; idx?: number }): Promise<{ utxo: Utxo; state: BtcState }> {
  const { key, trees } = epochOf(st.epoch);
  const out = accountOutput(st);
  const script = out.leaves[leaf]; if (!script) throw new Error(`${leaf} absent in ${stateStr(st)}`);
  // successor state
  let next: BtcState;
  if (leaf === 'exec') next = afterExec(st, pick.idx!);
  else if (leaf === 'execFirst') next = afterExecFirst(st, pick.tNew!, pick.idx!, trees.bottom[pick.tNew!].root);
  else next = afterRecover(st, epochOf(st.epoch + 1).pub);
  const nextOut = accountOutput(next);
  // transaction with the fee fixed from the witness upper bound
  const tx: Tx = { version: 2, locktime: 0, vin: [{ txid: utxo.txid, vout: utxo.vout, sequence: 0xffffffff, witness: [] }], vout: [] };
  tx.vout.push({ value: 0n, scriptPubKey: nextOut.output.scriptPubKey });
  if (PAY_TO) tx.vout.push({ value: PAY_SAT, scriptPubKey: scriptPubKeyOf(PAY_TO) });
  tx.vin[0].witness = [...placeholderWitness(leaf, st), script, out.controlBlock(leaf)];
  const fee = BigInt(Math.ceil(vsize(tx) * FEERATE));
  tx.vout[0].value = utxo.value - fee - (PAY_TO ? PAY_SAT : 0n);
  if (tx.vout[0].value < 1_000n) throw new Error('insufficient funds for the successor output');
  const prevouts: Prevout[] = [{ value: utxo.value, scriptPubKey: utxo.scriptPubKey }];
  const m = sighashScriptPath(tx, prevouts, 0, script);
  const b = bindingFor(m);
  // sign (one leaf, once) and check with the reference verifier
  let items: Uint8Array[], okRef: boolean;
  if (leaf === 'exec') {
    items = execWitness(key, trees, st, pick.idx!, b);
    okRef = verifyExec(st, pick.idx!, m, wotsSignB(key, LAYER_BOTTOM, st.t, pick.idx!, m), authPathB(trees.bottom[st.t], pick.idx!));
  } else if (leaf === 'execFirst') {
    const R = trees.bottom[pick.tNew!].root;
    items = execFirstWitness(key, trees, st, pick.tNew!, pick.idx!, b);
    okRef = verifyExecFirst(st, pick.tNew!, pick.idx!, m, R,
      wotsSignB(key, LAYER_BOTTOM, pick.tNew!, pick.idx!, m), authPathB(trees.bottom[pick.tNew!], pick.idx!),
      wotsSignB(key, LAYER_TOP, 0, pick.tNew!, R), authPathB(trees.top, pick.tNew!));
  } else {
    items = recoverWitness(key, trees, st, b);
    okRef = verifyRecover(st, m, wotsSignB(key, LAYER_REC, 0, st.epoch, m), authPathB(trees.rec, st.epoch));
  }
  if (!okRef) throw new Error('reference verifier rejects our own witness');
  tx.vin[0].witness = [...items, script, out.controlBlock(leaf)];
  const hex = bytesToHex(serialize(tx, true));
  const id = txidToHex(txid(tx));
  const accept = await rpc<Array<{ allowed: boolean; 'reject-reason'?: string; vsize?: number; fees?: { base: number } }>>('testmempoolaccept', [[hex]]);
  if (!accept[0].allowed) throw new Error(`${leaf} ${id}: node rejects: ${accept[0]['reject-reason']}`);
  await rpc('sendrawtransaction', [hex]);
  const w = weight(tx), v = vsize(tx);
  const witBytes = tx.vin[0].witness.reduce((a, x) => a + x.length + (x.length < 0xfd ? 1 : 3), 0) + 1;
  steps.push({ leaf, txid: id, vsize: v, weight: w, fee: Number(fee), feerate: (Number(fee) / v).toFixed(2), script: script.length, witness: witBytes, state: stateStr(next) });
  log(`${leaf.padEnd(9)} ${id}  ${v} vB  ${w} WU  fee ${fee} sat  leaf ${script.length} B  → ${stateStr(next)}`);
  return { utxo: { txid: txid(tx), vout: 0, value: tx.vout[0].value, scriptPubKey: nextOut.output.scriptPubKey }, state: next };
}

// ------------------------------------------------------------------- main

async function fund(address: string, spk: Uint8Array): Promise<Utxo> {
  if (net === 'regtest') {
    const W = 'aegis-flow';
    try { await rpc('createwallet', [W]); } catch { try { await rpc('loadwallet', [W]); } catch { /* loaded */ } }
    const mine = await rpc<string>('getnewaddress', [], W);
    const bal = await rpc<number>('getbalance', [], W);
    if (bal < 1) await rpc('generatetoaddress', [101, mine]);
    const sat = BigInt(env('BTC_FUND_SAT', '300000'));
    const id = await rpc<string>('sendtoaddress', [address, Number(sat) / 1e8], W);
    await rpc('generatetoaddress', [1, mine]);
    const gt = await rpc<{ hex: string }>('gettransaction', [id], W);
    const raw = await rpc<{ vout: Array<{ n: number; scriptPubKey: { hex: string } }> }>('decoderawtransaction', [gt.hex]);
    const vout = raw.vout.find(o => o.scriptPubKey.hex === bytesToHex(spk))!.n;
    log(`funded ${address} with ${sat} sat in ${id}:${vout}`);
    return { txid: txidFromHex(id), vout, value: sat, scriptPubKey: spk };
  }
  log(`\nsend signet coins to  ${address}\nwaiting for a confirmed UTXO …`);
  for (;;) {
    const scan = await rpc<{ unspents: Array<{ txid: string; vout: number; amount: number }> }>('scantxoutset', ['start', [`addr(${address})`]]);
    if (scan.unspents.length) {
      const u = scan.unspents[0];
      const sat = BigInt(Math.round(u.amount * 1e8));
      log(`funded with ${sat} sat in ${u.txid}:${u.vout}`);
      return { txid: txidFromHex(u.txid), vout: u.vout, value: sat, scriptPubKey: spk };
    }
    await sleep(20_000);
  }
}

async function main() {
  const info = await rpc<{ chain: string; blocks: number; initialblockdownload: boolean }>('getblockchaininfo');
  log(`node: ${info.chain} at height ${info.blocks}${info.initialblockdownload ? ' (still syncing)' : ''}`);
  const dep = await rpc<{ deployments: Record<string, { active: boolean }> }>('getdeploymentinfo');
  for (const d of ['op_cat', 'checksigfromstack']) if (!dep.deployments[d]?.active) throw new Error(`${d} is not active on this node`);

  // BTC_RESUME=txid:vout:sat:epoch:t:nextIdx continues an existing lineage from its current UTXO (t = -1 for nothing cached).
  const resume = process.env.BTC_RESUME?.split(':');
  const e0 = resume ? Number(resume[3]) : 0;
  const { pub, trees: trees0 } = epochOf(e0);
  let state = initialState(pub, e0, HT);
  if (resume) {
    const t = Number(resume[4]);
    state = { ...state, t, R: t === NO_SUBTREE ? state.R : trees0.bottom[t].root, nextIdx: Number(resume[5]) };
  }
  let out = accountOutput(state);
  const addr0 = p2trAddress(out.output.scriptPubKey, net);
  log(`account (${stateStr(state)}): ${addr0}`);
  let utxo = resume
    ? { txid: txidFromHex(resume[0]), vout: Number(resume[1]), value: BigInt(resume[2]), scriptPubKey: out.output.scriptPubKey }
    : await fund(addr0, out.output.scriptPubKey);

  let tNew = 0, idx = 0;
  for (const leaf of STEPS) {
    let pick: { tNew?: number; idx?: number } = {};
    if (leaf === 'execFirst') { tNew = state.t + 1; idx = 0; pick = { tNew, idx }; }
    else if (leaf === 'exec') { idx = state.nextIdx; pick = { idx }; }
    const r = await spend(leaf, utxo, state, pick);
    utxo = r.utxo; state = r.state; out = accountOutput(state);
    if (net === 'regtest') await rpc('generatetoaddress', [1, await rpc<string>('getnewaddress', [], 'aegis-flow')]);
  }
  log(`\nfinal UTXO ${txidToHex(utxo.txid)}:0  ${utxo.value} sat  at ${p2trAddress(utxo.scriptPubKey, net)}  (${stateStr(state)})`);
  log('\n| step | txid | vB | WU | fee (sat) | sat/vB | leaf script B | witness B | successor state |');
  log('|---|---|---|---|---|---|---|---|---|');
  for (const s of steps) log(`| ${s.leaf} | ${s.txid} | ${s.vsize} | ${s.weight} | ${s.fee} | ${s.feerate} | ${s.script} | ${s.witness} | ${s.state} |`);
  console.log('\n' + JSON.stringify({ network: net, HT, feerate: FEERATE, address0: addr0, steps }, null, 1));
}

main().catch(e => { console.error(e); process.exit(1); });
