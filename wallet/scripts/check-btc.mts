// Bitcoin Tapscript leaf: execute the WOTS+ leaf script against the witness
// the wallet produces, with an interpreter for exactly the opcodes the script
// uses (BIP-342 semantics: minimal numbers, 1000-element stack, clean stack,
// 520-byte items). Also pins the sizes quoted in BITCOIN.md and CCHS.spec.md
// §7.1. This does not and cannot check transaction binding (BITCOIN.md §3);
// it checks that the signature logic a future binding fragment relies on is
// what the documents say it is.
//
//   npm run btc     (from wallet/)

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import {
  OP, buildBtcHashAccount, btcWotsSign, controlBlock, spendWitness, tapLeafHash,
  tapPath, wotsLeafScript, wotsWitness, btcWotsPublic, scriptNum,
} from '../src/aegis/btcTapscript.ts';
import { chainKey, labelChainTag } from '../src/aegis/cchsAccount.ts';
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
  // minimal encoding (BIP-62 / BIP-342 MINIMALDATA)
  if (bytesToHex(scriptNum(neg ? -n : n)) !== bytesToHex(b)) throw new Error('non-minimal number');
  return neg ? -n : n;
}
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const truthy = (b: Uint8Array) => b.some((x, i) => x !== 0 && !(i === b.length - 1 && x === 0x80));

interface Exec { ok: boolean; reason?: string; stack: Uint8Array[]; sha256Calls: number }

function run(script: Uint8Array, witness: Uint8Array[]): Exec {
  const stack = [...witness], alt: Uint8Array[] = [];
  let sha256Calls = 0;
  const pop = () => { if (stack.length === 0) throw new Error('stack underflow'); return stack.pop()!; };
  const pushI = (x: Uint8Array) => { if (x.length > MAX_ITEM) throw new Error('item too large'); stack.push(x); if (stack.length + alt.length > MAX_STACK) throw new Error('stack limit'); };
  try {
    let pc = 0;
    while (pc < script.length) {
      const op = script[pc++];
      if (op >= 0x01 && op <= 0x4b) { pushI(script.slice(pc, pc + op)); pc += op; continue; }
      if (op === OP.PUSHDATA1) { const n = script[pc++]; pushI(script.slice(pc, pc + n)); pc += n; continue; }
      if (op === OP.PUSHDATA2) { const n = script[pc] | (script[pc + 1] << 8); pc += 2; pushI(script.slice(pc, pc + n)); pc += n; continue; }
      if (op === OP._0) { pushI(new Uint8Array(0)); continue; }
      if (op === OP._1NEGATE) { pushI(scriptNum(-1)); continue; }
      if (op >= OP._1 && op <= OP._16) { pushI(scriptNum(op - 0x50)); continue; }
      switch (op) {
        case OP.DUP: { const a = pop(); pushI(a); pushI(a); break; }
        case OP.DROP: pop(); break;
        case OP._2DROP: pop(); pop(); break;
        case OP.TOALTSTACK: alt.push(pop()); break;
        case OP.FROMALTSTACK: if (alt.length === 0) throw new Error('alt underflow'); pushI(alt.pop()!); break;
        case OP.PICK: { const n = num(pop()); if (n < 0 || n >= stack.length) throw new Error('pick range'); pushI(stack[stack.length - 1 - n]); break; }
        case OP.TUCK: { const b = pop(), a = pop(); pushI(b); pushI(a); pushI(b); break; }
        case OP.EQUAL: { const b = pop(), a = pop(); pushI(eq(a, b) ? scriptNum(1) : new Uint8Array(0)); break; }
        case OP.EQUALVERIFY: { const b = pop(), a = pop(); if (!eq(a, b)) throw new Error('EQUALVERIFY'); break; }
        case OP.VERIFY: if (!truthy(pop())) throw new Error('VERIFY'); break;
        case OP.ADD: { const b = num(pop()), a = num(pop()); pushI(scriptNum(a + b)); break; }
        case OP.WITHIN: { const max = num(pop()), min = num(pop()), x = num(pop()); pushI(x >= min && x < max ? scriptNum(1) : new Uint8Array(0)); break; }
        case OP.SHA256: pushI(sha256(pop())); sha256Calls++; break;
        default: throw new Error(`unsupported opcode 0x${op.toString(16)}`);
      }
    }
    if (stack.length !== 1) throw new Error(`clean stack violated: ${stack.length} items`);
    if (!truthy(stack[0])) throw new Error('false result');
    return { ok: true, stack, sha256Calls };
  } catch (e) {
    return { ok: false, reason: (e as Error).message, stack, sha256Calls };
  }
}

// ------------------------------------------------------------------- tests

const key: CchsKey = chainKey({ master: new Uint8Array(32).fill(0x42) }, labelChainTag('bitcoin'));
const sighash = sha256(new TextEncoder().encode('a transaction'));
const other = sha256(new TextEncoder().encode('a different transaction'));

// 1. Leaf script accepts the wallet's witness and rejects tampering.
const pks = btcWotsPublic(key, 5);
const script = wotsLeafScript(pks);
const sig = btcWotsSign(key, 5, sighash);
const good = run(script, wotsWitness(sig, sighash));
ok(good.ok, `leaf script accepts a correct WOTS+ witness (${good.sha256Calls} SHA-256 evaluations, clean stack)`);
ok(good.sha256Calls === 67 * 15, 'the script evaluates exactly 67 × 15 chain steps');

const wrongMsg = run(script, wotsWitness(sig, other));
ok(!wrongMsg.ok, `digits of another message with the same chain values are rejected (${wrongMsg.reason})`);

const flipped = sig.map((v, i) => (i === 3 ? sha256(v) : v));
ok(!run(script, wotsWitness(flipped, sighash)).ok, 'a chain value advanced by one step is rejected');

const d = (() => { const w = wotsWitness(sig, sighash); const i = w.length - 1; w[i] = scriptNum(num(w[i]) === 15 ? 14 : num(w[i]) + 1); return w; })();
ok(!run(script, d).ok, 'a digit that disagrees with its chain value is rejected (checksum or pick)');

const otherLeafSig = btcWotsSign(key, 6, sighash);
ok(!run(script, wotsWitness(otherLeafSig, sighash)).ok, 'a signature from another leaf is rejected');

const nonMinimal = (() => { const w = wotsWitness(sig, sighash); w[w.length - 1] = Uint8Array.of(0x00); return w; })();
ok(!run(script, nonMinimal).ok, 'a non-minimally encoded digit is rejected (MINIMALDATA)');

// 2. Sizes quoted in BITCOIN.md §5.6 and CCHS.spec.md §7.1.
ok(script.length === 5752, `leaf script is 5 752 B (got ${script.length})`);
const acct = buildBtcHashAccount(key, 4);
const wit = spendWitness(acct, key, 5, sighash);
const raw = wit.reduce((a, x) => a + x.length, 0);
const serialized = wit.reduce((a, x) => a + x.length + (x.length < 0xfd ? 1 : 3), 0);
const nonZeroDigits = wotsWitness(sig, sighash).filter((x, i) => i % 2 === 1 && x.length > 0).length;
ok(wit.length === 136, `witness has 134 WOTS items + script + control block (got ${wit.length})`);
ok(raw === 2144 + nonZeroDigits + 5752 + 161, `witness payload for a 2^4 tree is 8 057 B + one byte per non-zero digit (${raw} B, ${nonZeroDigits} non-zero digits)`);
ok(serialized === raw + 136 + 2, `serialized witness adds a length prefix per item (${serialized} B)`);
const cb = controlBlock(acct.output, tapPath(acct.tree, 5));
ok(cb.length === 1 + 32 + 4 * 32, 'control block is 1 + 32 + 32·height bytes');
ok(eq(wit[wit.length - 2], acct.leafScript(5)) && eq(tapLeafHash(wit[wit.length - 2]), acct.tree.levels[0][5]), 'spent leaf hashes to the tree leaf');
ok(acct.output.scriptPubKey.length === 34 && acct.output.scriptPubKey[0] === OP._1, 'output is a 34-byte P2TR scriptPubKey (NUMS internal key; see BITCOIN.md L1 for why P2MR is required)');

// 3. Per-chain key: the Bitcoin tree is not the EVM tree.
const evmKey: CchsKey = chainKey({ master: new Uint8Array(32).fill(0x42) }, Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 1));
ok(!eq(btcWotsPublic(evmKey, 5)[0], pks[0]), 'leaf 5 of the Bitcoin tree differs from leaf 5 of the chain-1 tree');

console.log(fails === 0 ? '\nall checks passed' : `\n${fails} check(s) failed`);
process.exit(fails === 0 ? 0 : 1);
