// Bitcoin: execute the CCHS-UTXO leaves (btcCchs.ts) and the flat WOTS+ leaf
// (btcTapscript.ts) against the witnesses the wallet produces, with an
// interpreter for exactly the Tapscript opcodes they use (BIP-342 semantics:
// minimal numbers, MINIMALIF, 1000-element stack, 520-byte items, clean
// stack) plus BIP-347 OP_CAT and BIP-348 OP_CHECKSIGFROMSTACK. OP_CHECKSIG is
// evaluated against the BIP-341 sighash of a real transaction built by
// btcTx.ts, so the binding gadget is exercised, not mocked away.
//
// Consensus is the node, not this file: the same scripts and witnesses are
// run on Bitcoin Inquisition signet by scripts/btc-flow.mts and the results
// are recorded in BITCOIN.md §5.6. This check pins the sizes quoted there and
// catches regressions without a node.
//
//   npm run btc     (from wallet/)

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { schnorr } from '@noble/curves/secp256k1';
import {
  buildBtcHashAccount, btcWotsSign, spendWitness, wotsLeafScript, wotsWitness, btcWotsPublic, scriptNum, tapLeafHash,
} from '../src/aegis/btcTapscript.ts';
import {
  OP, HB, keygenB, accountOutput, initialState, afterExecFirst, afterExec, afterRecover,
  execWitness, execFirstWitness, recoverWitness, verifyExec, verifyExecFirst, verifyRecover,
  wotsSignB, authPathB, LAYER_BOTTOM, type LeafName,
} from '../src/aegis/btcCchs.ts';
import { sighashScriptPath, bindingFor, serialize, vsize, weight, type Tx, type Prevout } from '../src/aegis/btcTx.ts';
import { chainKey, epochKey, labelChainTag } from '../src/aegis/cchsAccount.ts';
import type { CchsKey } from '../src/aegis/cchs.ts';

let fails = 0;
const ok = (c: boolean, what: string) => { console.log(`${c ? 'ok  ' : 'FAIL'} ${what}`); if (!c) fails++; };

// ------------------------------------------------------------ interpreter

const MAX_STACK = 1000, MAX_ITEM = 520;

function num(b: Uint8Array): number {
  if (b.length === 0) return 0;
  if (b.length > 4) throw new Error('number too large');
  let n = 0;
  for (let i = 0; i < b.length; i++) n |= b[i] << (8 * i);
  const neg = (b[b.length - 1] & 0x80) !== 0;
  if (neg) n &= ~(0x80 << (8 * (b.length - 1)));
  if (bytesToHex(scriptNum(neg ? -n : n)) !== bytesToHex(b)) throw new Error('non-minimal number');
  return neg ? -n : n;
}
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const truthy = (b: Uint8Array) => b.some((x, i) => x !== 0 && !(i === b.length - 1 && x === 0x80));
const bool = (c: boolean) => (c ? scriptNum(1) : new Uint8Array(0));

interface Exec { ok: boolean; reason?: string; stack: Uint8Array[]; sha256Calls: number; maxStack: number }

/** `sighash`: what OP_CHECKSIG verifies against (the transaction's BIP-341 digest). */
function run(script: Uint8Array, witness: Uint8Array[], sighash?: Uint8Array): Exec {
  const stack = [...witness], alt: Uint8Array[] = [];
  let sha256Calls = 0, maxStack = stack.length;
  const cond: boolean[] = [];
  const live = () => cond.every(Boolean);
  const pop = () => { if (stack.length === 0) throw new Error('stack underflow'); return stack.pop()!; };
  const pushI = (x: Uint8Array) => {
    if (x.length > MAX_ITEM) throw new Error('item too large');
    stack.push(x);
    maxStack = Math.max(maxStack, stack.length + alt.length);
    if (stack.length + alt.length > MAX_STACK) throw new Error('stack limit');
  };
  const checksig = (sig: Uint8Array, pk: Uint8Array, msg: Uint8Array) => {
    if (sig.length === 0) return false;
    if (sig.length !== 64 || pk.length !== 32) throw new Error('sig/pubkey length');
    if (!schnorr.verify(sig, msg, pk)) throw new Error('invalid Schnorr signature');
    return true;
  };
  let pcAt = 0;
  try {
    let pc = 0;
    while (pc < script.length) {
      pcAt = pc;
      const op = script[pc++];
      let data: Uint8Array | null = null;
      if (op >= 0x01 && op <= 0x4b) { data = script.slice(pc, pc + op); pc += op; }
      else if (op === OP.PUSHDATA1) { const n = script[pc++]; data = script.slice(pc, pc + n); pc += n; }
      else if (op === OP.PUSHDATA2) { const n = script[pc] | (script[pc + 1] << 8); pc += 2; data = script.slice(pc, pc + n); pc += n; }
      if (op === OP.IF) {
        if (live()) {
          const c = pop();
          if (c.length > 1 || (c.length === 1 && c[0] !== 1)) throw new Error('MINIMALIF');
          cond.push(truthy(c));
        } else cond.push(false);
        continue;
      }
      if (op === OP.ELSE) { if (!cond.length) throw new Error('ELSE without IF'); cond[cond.length - 1] = !cond[cond.length - 1]; continue; }
      if (op === OP.ENDIF) { if (!cond.length) throw new Error('ENDIF without IF'); cond.pop(); continue; }
      if (!live()) continue;
      if (data) { pushI(data); continue; }
      if (op === OP._0) { pushI(new Uint8Array(0)); continue; }
      if (op === OP._1NEGATE) { pushI(scriptNum(-1)); continue; }
      if (op >= OP._1 && op <= OP._16) { pushI(scriptNum(op - 0x50)); continue; }
      switch (op) {
        case OP.DUP: { const a = pop(); pushI(a); pushI(a); break; }
        case OP.DROP: pop(); break;
        case OP._2DROP: pop(); pop(); break;
        case OP.SWAP: { const b = pop(), a = pop(); pushI(b); pushI(a); break; }
        case OP.OVER: { const b = pop(), a = pop(); pushI(a); pushI(b); pushI(a); break; }
        case OP.ROT: { const c = pop(), b = pop(), a = pop(); pushI(b); pushI(c); pushI(a); break; }
        case OP._2SWAP: { const d = pop(), c = pop(), b = pop(), a = pop(); pushI(c); pushI(d); pushI(a); pushI(b); break; }
        case OP.TUCK: { const b = pop(), a = pop(); pushI(b); pushI(a); pushI(b); break; }
        case OP.TOALTSTACK: alt.push(pop()); break;
        case OP.FROMALTSTACK: if (alt.length === 0) throw new Error('alt underflow'); pushI(alt.pop()!); break;
        case OP.PICK: { const n = num(pop()); if (n < 0 || n >= stack.length) throw new Error('pick range'); pushI(stack[stack.length - 1 - n]); break; }
        case OP.ROLL: { const n = num(pop()); if (n < 0 || n >= stack.length) throw new Error('roll range'); const [x] = stack.splice(stack.length - 1 - n, 1); pushI(x); break; }
        case OP.CAT: { const b = pop(), a = pop(); const r = new Uint8Array(a.length + b.length); r.set(a); r.set(b, a.length); pushI(r); break; }
        case OP.EQUAL: { const b = pop(), a = pop(); pushI(bool(eq(a, b))); break; }
        case OP.EQUALVERIFY: { const b = pop(), a = pop(); if (!eq(a, b)) throw new Error('EQUALVERIFY'); break; }
        case OP.VERIFY: if (!truthy(pop())) throw new Error('VERIFY'); break;
        case OP.ADD: { const b = num(pop()), a = num(pop()); pushI(scriptNum(a + b)); break; }
        case OP.GREATERTHAN: { const b = num(pop()), a = num(pop()); pushI(bool(a > b)); break; }
        case OP.GREATERTHANOREQUAL: { const b = num(pop()), a = num(pop()); pushI(bool(a >= b)); break; }
        case OP.WITHIN: { const max = num(pop()), min = num(pop()), x = num(pop()); pushI(bool(x >= min && x < max)); break; }
        case OP.SHA256: pushI(sha256(pop())); sha256Calls++; break;
        case OP.CHECKSIG: case OP.CHECKSIGVERIFY: {
          if (!sighash) throw new Error('CHECKSIG without a transaction');
          const pk = pop(), sig = pop(); const r = checksig(sig, pk, sighash);
          if (op === OP.CHECKSIG) pushI(bool(r)); else if (!r) throw new Error('CHECKSIGVERIFY');
          break;
        }
        case OP.CHECKSIGFROMSTACK: { const pk = pop(), msg = pop(), sig = pop(); pushI(bool(checksig(sig, pk, msg))); break; }
        default: throw new Error(`unsupported opcode 0x${op.toString(16)}`);
      }
    }
    if (cond.length) throw new Error('unbalanced conditional');
    if (stack.length !== 1) throw new Error(`clean stack violated: ${stack.length} items`);
    if (!truthy(stack[0])) throw new Error('false result');
    return { ok: true, stack, sha256Calls, maxStack };
  } catch (e) {
    return { ok: false, reason: `${(e as Error).message} at byte ${pcAt}/${script.length}`, stack, sha256Calls, maxStack };
  }
}

// --------------------------------------------------- a transaction to sign

const HT = 2; // top height for the check: 4 subtrees; the protocol value is a build parameter (btcCchs.ts)
const master: CchsKey = { master: new Uint8Array(32).fill(0x42) };
const key0 = chainKey(master, labelChainTag('bitcoin'));

interface Spend { tx: Tx; prevouts: Prevout[]; sighash: Uint8Array }
/** One-input, two-output transaction spending `prev` through `leafScript`; the witness is filled in by the caller. */
function spendTx(prevTxid: Uint8Array, prevValue: bigint, prevSpk: Uint8Array, nextSpk: Uint8Array, leafScript: Uint8Array): Spend {
  const tx: Tx = {
    version: 2, locktime: 0,
    vin: [{ txid: prevTxid, vout: 0, sequence: 0xffffffff, witness: [] }],
    vout: [{ value: prevValue - 20_000n, scriptPubKey: nextSpk }, { value: 10_000n, scriptPubKey: Uint8Array.of(0x00, 0x14, ...new Uint8Array(20).fill(0x33)) }],
  };
  const prevouts = [{ value: prevValue, scriptPubKey: prevSpk }];
  return { tx, prevouts, sighash: sighashScriptPath(tx, prevouts, 0, leafScript) };
}

console.log(`keygen: 2^${HT} bottom subtrees of 2^${HB} leaves, top tree, recovery tree …`);
const t0 = Date.now();
const { pub, trees } = keygenB(key0, HT);
console.log(`  ${((Date.now() - t0) / 1000).toFixed(1)} s`);

const FUND = 1_000_000n;
let state = initialState(pub, 0, HT);
let out = accountOutput(state);
let prevTxid = sha256(new TextEncoder().encode('funding'));
let value = FUND;
const sizes: Record<string, { script: number; witness: number; vsize: number; weight: number; maxStack: number }> = {};

function record(name: string, leaf: Uint8Array, witnessItems: Uint8Array[], s: Spend, ex: Exec) {
  const wit = [...witnessItems, leaf, out.controlBlock(name as LeafName)];
  s.tx.vin[0].witness = wit;
  const serialized = serialize(s.tx, true);
  sizes[name] = { script: leaf.length, witness: wit.reduce((a, x) => a + x.length + (x.length < 0xfd ? 1 : 3), 0) + 1, vsize: vsize(s.tx), weight: weight(s.tx), maxStack: ex.maxStack };
  ok(serialized.length > 0, `${name}: tx ${vsize(s.tx)} vB (${weight(s.tx)} WU), leaf ${leaf.length} B, witness ${sizes[name].witness} B, peak stack ${ex.maxStack}`);
}

// 1. execFirst in subtree 1 at leaf 7 (fresh account: nothing cached).
{
  const tNew = 1, leaf = 7;
  const script = out.leaves.execFirst!;
  const next = afterExecFirst(state, tNew, leaf, trees.bottom[tNew].root);
  const nextOut = accountOutput(next);
  const s = spendTx(prevTxid, value, out.output.scriptPubKey, nextOut.output.scriptPubKey, script);
  const w = execFirstWitness(key0, trees, state, tNew, leaf, bindingFor(s.sighash));
  const ex = run(script, w, s.sighash);
  ok(ex.ok, `execFirst leaf accepts the wallet's witness (${ex.reason ?? 'clean stack'})`);
  ok(ex.sha256Calls === 2 * (67 * 15 + 5 + 1) + HB + HT, `execFirst evaluates two WOTS+ layers and both paths in ${ex.sha256Calls} SHA-256 calls`);
  ok(verifyExecFirst(state, tNew, leaf, s.sighash, trees.bottom[tNew].root,
    wotsSignB(key0, LAYER_BOTTOM, tNew, leaf, s.sighash), authPathB(trees.bottom[tNew], leaf),
    wotsSignB(key0, 1, 0, tNew, trees.bottom[tNew].root), authPathB(trees.top, tNew)), 'reference verifier agrees');
  // Rejections.
  const other = sha256(s.sighash);
  ok(!run(script, execFirstWitness(key0, trees, state, tNew, leaf, bindingFor(other)), s.sighash).ok, 'execFirst: a witness bound to another sighash is rejected by CHECKSIG');
  const forged = { ...bindingFor(other), m: s.sighash };
  ok(!run(script, execFirstWitness(key0, trees, state, tNew, leaf, forged), s.sighash).ok, 'execFirst: message that is not what the Schnorr signature signs is rejected by CHECKSIGFROMSTACK');
  const w2 = execFirstWitness(key0, trees, state, tNew, leaf, bindingFor(s.sighash));
  const bad = w2.slice(); bad[bad.length - 1] = scriptNum(1); // top bit of t' set: 1 → 3, the signature is leaf 1's
  ok(!run(script, bad, s.sighash).ok, 'execFirst: subtree index bits that disagree with the top-layer signature are rejected');
  const st0 = { ...state, t: 1 };
  const outT1 = accountOutput(st0);
  ok(!run(outT1.leaves.execFirst!, w2, s.sighash).ok, "execFirst: t' must exceed the cached subtree (t' = 1 against t = 1 is rejected)");
  record('execFirst', script, w, s, ex);
  prevTxid = sha256(serialize(s.tx, false)); value = s.tx.vout[0].value; state = next; out = nextOut;
}

// 2. exec at leaf 8 of the cached subtree, then at leaf 9; leaf 8 again is refused.
for (const leaf of [8, 9]) {
  const script = out.leaves.exec!;
  const next = afterExec(state, leaf);
  const nextOut = accountOutput(next);
  const s = spendTx(prevTxid, value, out.output.scriptPubKey, nextOut.output.scriptPubKey, script);
  const w = execWitness(key0, trees, state, leaf, bindingFor(s.sighash));
  const ex = run(script, w, s.sighash);
  ok(ex.ok, `exec at leaf ${leaf} with nextIdx ${state.nextIdx} accepts (${ex.reason ?? 'clean stack'})`);
  ok(ex.sha256Calls === 67 * 15 + 5 + 1 + HB, `exec evaluates one WOTS+ layer and one path in ${ex.sha256Calls} SHA-256 calls`);
  ok(verifyExec(state, leaf, s.sighash, wotsSignB(key0, LAYER_BOTTOM, state.t, leaf, s.sighash), authPathB(trees.bottom[state.t], leaf)), 'reference verifier agrees');
  if (leaf === 9) {
    const reuse = execWitness(key0, trees, state, 8, bindingFor(s.sighash));
    ok(!run(script, reuse, s.sighash).ok, `exec: leaf 8 against nextIdx ${state.nextIdx} is rejected (index rule)`);
    const PAIRS = 3 + 32 + HB; // after sig_B m P, the 32 message bytes and the path
    const flipped = w.slice(); flipped[PAIRS] = sha256(flipped[PAIRS]); // chain 66 advanced by one step
    ok(!run(script, flipped, s.sighash).ok, 'exec: a chain value advanced by one step is rejected');
    const otherLeaf = execWitness(key0, trees, state, 10, bindingFor(s.sighash));
    otherLeaf.splice(otherLeaf.length - HB, HB, ...w.slice(-HB)); // leaf-10 signature and path under leaf-9 bits
    ok(!run(script, otherLeaf, s.sighash).ok, 'exec: a leaf-10 signature presented as leaf 9 is rejected (path)');
    const nonMinimal = w.slice(); nonMinimal[nonMinimal.length - 1] = Uint8Array.of(0x00);
    ok(!run(script, nonMinimal, s.sighash).ok, 'exec: a non-minimal bit is rejected (MINIMALIF)');
    record('exec', script, w, s, ex);
  }
  prevTxid = sha256(serialize(s.tx, false)); value = s.tx.vout[0].value; state = next; out = nextOut;
}

// 3. recover to epoch 1.
{
  const script = out.leaves.recover!;
  const key1 = epochKey(key0, 1);
  const { pub: pub1 } = keygenB(key1, HT);
  const next = afterRecover(state, pub1);
  const nextOut = accountOutput(next);
  const s = spendTx(prevTxid, value, out.output.scriptPubKey, nextOut.output.scriptPubKey, script);
  const w = recoverWitness(key0, trees, state, bindingFor(s.sighash));
  const ex = run(script, w, s.sighash);
  ok(ex.ok, `recover (epoch 0 → 1) accepts (${ex.reason ?? 'clean stack'})`);
  ok(verifyRecover(state, s.sighash, wotsSignB(key0, 0xff, 0, 0, s.sighash), authPathB(trees.rec, 0)), 'reference verifier agrees');
  const wrongEpoch = recoverWitness(key0, trees, { ...state, epoch: 1 }, bindingFor(s.sighash));
  ok(!run(script, wrongEpoch, s.sighash).ok, 'recover: the recovery leaf of another epoch is rejected');
  record('recover', script, w, s, ex);
  ok(nextOut.leaves.exec === undefined && next.t === -1 && next.epoch === 1, 'successor after recover caches nothing and carries epoch 1');
}

// 4. Size pins (BITCOIN.md §5.6).
console.log(JSON.stringify(sizes, null, 1));
ok(sizes.exec.script === 9_718, `exec leaf is 9 718 B (got ${sizes.exec.script})`);
ok(sizes.execFirst.script === 19_240, `execFirst leaf is 19 240 B at HT = ${HT} (got ${sizes.execFirst.script})`);
ok(sizes.recover.script === 9_454, `recover leaf is 9 454 B (got ${sizes.recover.script})`);
ok(sizes.exec.vsize >= 3_290 && sizes.exec.vsize <= 3_310, `exec spend is ≈ 3 300 vB (got ${sizes.exec.vsize}; digits encode in 0 or 1 byte)`);
ok(sizes.recover.vsize >= 3_195 && sizes.recover.vsize <= 3_215, `recover spend is ≈ 3 205 vB (got ${sizes.recover.vsize})`);
ok(sizes.exec.maxStack < 1000 && sizes.execFirst.maxStack < 1000, 'peak stack depth stays under the 1000-element limit');

// 5. Flat variant of CCHS.spec.md §7.1(a) (btcTapscript.ts), kept for the size it is quoted at.
{
  const sighash = sha256(new TextEncoder().encode('a transaction'));
  const pks = btcWotsPublic(key0, 5);
  const script = wotsLeafScript(pks);
  const sig = btcWotsSign(key0, 5, sighash);
  const good = run(script, wotsWitness(sig, sighash));
  ok(good.ok && good.sha256Calls === 67 * 15, `flat leaf accepts its witness with 67 × 15 chain steps (${good.reason ?? 'ok'})`);
  ok(!run(script, wotsWitness(sig, sha256(sighash))).ok, 'flat leaf rejects another message');
  ok(script.length === 5752, `flat leaf is 5 752 B (got ${script.length})`);
  const acct = buildBtcHashAccount(key0, 4);
  const wit = spendWitness(acct, key0, 5, sighash);
  ok(wit.length === 136 && eq(tapLeafHash(wit[wit.length - 2]), acct.tree.levels[0][5]), 'flat witness: 134 items + script + control block, leaf hashes into the tree');
}

console.log(fails === 0 ? '\nall checks passed' : `\n${fails} check(s) failed`);
process.exit(fails === 0 ? 0 : 1);
