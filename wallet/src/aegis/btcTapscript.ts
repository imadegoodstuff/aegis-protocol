// Bitcoin: flat Taproot tree of WOTS+ leaves (CCHS.spec.md §7.1a).
//
// What this file does today:
//   - derives 2^h one-time WOTS+ keys (w = 16, 67 chains) from the CCHS key of
//     the Bitcoin chain (chainKey(master, labelChainTag('bitcoin')), never the
//     bare master or another chain's key: a leaf exists on one chain only),
//     chain function F(x) = SHA256(x) (Script has no tweakable hash),
//   - emits one tapleaf script per key that verifies all 67 chains against the
//     hard-coded public values and checks the Winternitz checksum arithmetically,
//   - builds the BIP-341 script tree, output key (NUMS internal key) and
//     control blocks, and produces the spend witness for a leaf.
//
// What it cannot do yet, and says so in the output: bind the signed digits to
// the spending transaction. That needs OP_CAT (BIP-347) or
// OP_CHECKSIGFROMSTACK (BIP-348); `binding` is the insertion point for that
// fragment. Independently of binding, the output built here is P2TR, whose
// key path a discrete-log adversary can take whatever the internal key is; a
// key-less output type (BIP-360 P2MR) is required as well. See BITCOIN.md.
// Do not fund an output built by this file on a network with value.
//
// `wallet/scripts/check-btc.mts` executes the leaf script in an interpreter
// for the opcodes it uses and pins the sizes quoted in the documents.

import { sha256 } from '@noble/hashes/sha256';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { concatBytes, hexToBytes } from '@noble/hashes/utils';
import { LEN, W, digits, sk, type CchsKey } from './cchs';

// ----------------------------------------------------------------- opcodes

export const OP = {
  _0: 0x00, PUSHDATA1: 0x4c, PUSHDATA2: 0x4d, _1NEGATE: 0x4f, _1: 0x51, _16: 0x60,
  VERIFY: 0x69, TOALTSTACK: 0x6b, FROMALTSTACK: 0x6c, _2DROP: 0x6d, DROP: 0x75,
  DUP: 0x76, PICK: 0x79, TUCK: 0x7d, EQUAL: 0x87, EQUALVERIFY: 0x88,
  ADD: 0x93, WITHIN: 0xa5, SHA256: 0xa8,
} as const;

/** Minimal push of a byte string. */
export function push(data: Uint8Array): Uint8Array {
  if (data.length === 0) return Uint8Array.of(OP._0);
  if (data.length === 1 && data[0] >= 1 && data[0] <= 16) return Uint8Array.of(0x50 + data[0]);
  if (data.length === 1 && data[0] === 0x81) return Uint8Array.of(OP._1NEGATE);
  if (data.length < 0x4c) return concatBytes(Uint8Array.of(data.length), data);
  if (data.length <= 0xff) return concatBytes(Uint8Array.of(OP.PUSHDATA1, data.length), data);
  return concatBytes(Uint8Array.of(OP.PUSHDATA2, data.length & 0xff, data.length >> 8), data);
}

/** Minimal script-number encoding (little-endian, sign bit in top byte). */
export function scriptNum(n: number): Uint8Array {
  if (n === 0) return new Uint8Array(0);
  const neg = n < 0; let a = Math.abs(n);
  const out: number[] = [];
  while (a > 0) { out.push(a & 0xff); a >>= 8; }
  if (out[out.length - 1] & 0x80) out.push(neg ? 0x80 : 0);
  else if (neg) out[out.length - 1] |= 0x80;
  return Uint8Array.from(out);
}
export const pushNum = (n: number) => push(scriptNum(n));

// ------------------------------------------------------------ WOTS+ (btc)

export const BTC_LAYER = 0xb0; // key-derivation domain for the Bitcoin tree

const F = (x: Uint8Array) => sha256(x);

export function btcChainSecret(key: CchsKey, leafIdx: number, c: number): Uint8Array {
  return sk(key, BTC_LAYER, 0n, leafIdx, c);
}

/** 67 public chain ends for leaf `leafIdx`. */
export function btcWotsPublic(key: CchsKey, leafIdx: number): Uint8Array[] {
  const out: Uint8Array[] = new Array(LEN);
  for (let c = 0; c < LEN; c++) {
    let x = btcChainSecret(key, leafIdx, c);
    for (let s = 0; s < W - 1; s++) x = F(x);
    out[c] = x;
  }
  return out;
}

/** WOTS+ signature of 32-byte `m` with leaf `leafIdx`: 67 chain values. */
export function btcWotsSign(key: CchsKey, leafIdx: number, m: Uint8Array): Uint8Array[] {
  const d = digits(m);
  const out: Uint8Array[] = new Array(LEN);
  for (let c = 0; c < LEN; c++) {
    let x = btcChainSecret(key, leafIdx, c);
    for (let s = 0; s < d[c]; s++) x = F(x);
    out[c] = x;
  }
  return out;
}

export type Binding = 'none' | { opcat: Uint8Array };

/**
 * Tapleaf script verifying one WOTS+ key.
 *
 * Witness layout (bottom → top): sig_66 d_66 … sig_1 d_1 sig_0 d_0, so chain 0
 * is processed first. For each chain the script:
 *   checks 0 ≤ d < 16, saves d, computes the 16 chain states
 *   s_0 = sig, s_i = SHA256(s_{i-1}) on the stack, picks s_{15-d} (= pk iff
 *   sig = F^d(sk)), compares with the hard-coded pk, drops the states.
 * Then it pops the 3 checksum digits, forms csum = 256·d64 + 16·d65 + d66,
 * adds the 64 message digits (leaving them on the stack) and requires the
 * total to equal 64·15 = 960.
 *
 * The 64 message digits (d_0 deepest … d_63 on top) are then handed to the
 * binding fragment. With `binding: 'none'` they are dropped and the script
 * returns true, which is NOT transaction-binding; see file header.
 */
export function wotsLeafScript(pks: Uint8Array[], binding: Binding = 'none'): Uint8Array {
  if (pks.length !== LEN) throw new Error('need 67 public chain ends');
  const parts: Uint8Array[] = [];
  const op = (...codes: number[]) => parts.push(Uint8Array.from(codes));

  for (let c = 0; c < LEN; c++) {
    op(OP.DUP, OP._0, OP._16, OP.WITHIN, OP.VERIFY);     // 0 <= d < 16
    op(OP.TOALTSTACK);                                    // alt: d
    for (let i = 1; i < W; i++) op(OP.DUP, OP.SHA256);    // s_0..s_15, s_15 on top
    op(OP.FROMALTSTACK, OP.DUP, OP.TOALTSTACK);           // d on top, copy kept in alt
    op(OP.PICK);                                          // s_{15-d}
    parts.push(push(pks[c]));
    op(OP.EQUALVERIFY);
    for (let i = 0; i < W / 2; i++) op(OP._2DROP);        // drop the 16 states
  }
  // alt (top → bottom): d_66 d_65 d_64 d_63 … d_0
  op(OP.FROMALTSTACK);                                    // d_66
  op(OP.FROMALTSTACK);                                    // d_65
  for (let i = 0; i < 4; i++) op(OP.DUP, OP.ADD);         // 16·d_65
  op(OP.ADD);
  op(OP.FROMALTSTACK);                                    // d_64
  for (let i = 0; i < 8; i++) op(OP.DUP, OP.ADD);         // 256·d_64
  op(OP.ADD);                                             // csum
  for (let c = 0; c < 64; c++) op(OP.FROMALTSTACK, OP.TUCK, OP.ADD); // digits stay below acc
  parts.push(pushNum(64 * (W - 1)));
  op(OP.EQUALVERIFY);
  // Stack now (bottom → top): d_63 … d_0. The first digit popped from the
  // altstack (d_63) is TUCKed deepest; each later one lands above it.
  if (binding === 'none') {
    for (let i = 0; i < 32; i++) op(OP._2DROP);
    op(OP._1);
  } else {
    parts.push(binding.opcat);
  }
  return concatBytes(...parts);
}

/** Witness stack items for a leaf spend (excluding script and control block). */
export function wotsWitness(sig: Uint8Array[], m: Uint8Array): Uint8Array[] {
  const d = digits(m);
  const items: Uint8Array[] = [];
  for (let c = LEN - 1; c >= 0; c--) { items.push(sig[c]); items.push(scriptNum(d[c])); }
  return items; // bottom → top
}

// ----------------------------------------------------------------- BIP-341

export const tagged = (tag: string, ...data: Uint8Array[]) => schnorr.utils.taggedHash(tag, ...data);
export const LEAF_VERSION = 0xc0;

function compactSize(n: number): Uint8Array {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
  return Uint8Array.of(0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff);
}

export function tapLeafHash(script: Uint8Array, version = LEAF_VERSION): Uint8Array {
  return tagged('TapLeaf', Uint8Array.of(version), compactSize(script.length), script);
}

function lexLess(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
}

export function tapBranchHash(a: Uint8Array, b: Uint8Array): Uint8Array {
  return lexLess(a, b) ? tagged('TapBranch', a, b) : tagged('TapBranch', b, a);
}

/** BIP-341 "nothing up my sleeve" internal key: lift_x(SHA256(G)). */
export const NUMS_INTERNAL_KEY = hexToBytes('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0');

export interface TapTree {
  height: number;
  levels: Uint8Array[][];   // levels[0] = leaf hashes
  root: Uint8Array;
}

export function buildTapTree(leafHashes: Uint8Array[]): TapTree {
  const height = Math.log2(leafHashes.length);
  if (!Number.isInteger(height)) throw new Error('leaf count must be a power of two');
  const levels: Uint8Array[][] = [leafHashes];
  for (let k = 0; k < height; k++) {
    const prev = levels[k], next: Uint8Array[] = new Array(prev.length / 2);
    for (let i = 0; i < next.length; i++) next[i] = tapBranchHash(prev[2 * i], prev[2 * i + 1]);
    levels.push(next);
  }
  return { height, levels, root: levels[height][0] };
}

export function tapPath(t: TapTree, leafIdx: number): Uint8Array[] {
  const path: Uint8Array[] = [];
  let pos = leafIdx;
  for (let k = 0; k < t.height; k++) { path.push(t.levels[k][pos ^ 1]); pos >>= 1; }
  return path;
}

export interface TaprootOutput {
  outputKey: Uint8Array;     // 32-byte x-only
  parity: 0 | 1;
  scriptPubKey: Uint8Array;  // OP_1 <32>
  internalKey: Uint8Array;
  merkleRoot: Uint8Array;
}

export function taprootOutput(internalKey: Uint8Array, merkleRoot: Uint8Array): TaprootOutput {
  const t = tagged('TapTweak', internalKey, merkleRoot);
  const P = schnorr.utils.lift_x(bytesToBigInt(internalKey));
  const Q = P.add(secp256k1.ProjectivePoint.BASE.multiply(bytesToBigInt(t)));
  const aff = Q.toAffine();
  const outputKey = bigIntTo32(aff.x);
  const parity = (aff.y & 1n) === 1n ? 1 : 0;
  return { outputKey, parity, scriptPubKey: concatBytes(Uint8Array.of(OP._1, 0x20), outputKey), internalKey, merkleRoot };
}

export function controlBlock(out: TaprootOutput, path: Uint8Array[], version = LEAF_VERSION): Uint8Array {
  return concatBytes(Uint8Array.of(version | out.parity), out.internalKey, ...path);
}

function bytesToBigInt(b: Uint8Array): bigint {
  let n = 0n; for (const x of b) n = (n << 8n) | BigInt(x); return n;
}
function bigIntTo32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}

// ------------------------------------------------------------- full flow

export interface BtcHashAccount {
  height: number;
  binding: 'none' | 'opcat';
  tree: TapTree;
  output: TaprootOutput;
  /** Leaf scripts are regenerated on demand from the master; only hashes are kept. */
  leafScript: (leafIdx: number) => Uint8Array;
}

/**
 * Build the flat WOTS+ Taproot tree for `2^height` one-time keys.
 * Pure function of the master; call once and persist `tree.levels` if needed.
 */
export function buildBtcHashAccount(key: CchsKey, height: number, binding: Binding = 'none'): BtcHashAccount {
  const n = 1 << height;
  const leafScript = (i: number) => wotsLeafScript(btcWotsPublic(key, i), binding);
  const leafHashes: Uint8Array[] = new Array(n);
  for (let i = 0; i < n; i++) leafHashes[i] = tapLeafHash(leafScript(i));
  const tree = buildTapTree(leafHashes);
  const output = taprootOutput(NUMS_INTERNAL_KEY, tree.root);
  return { height, binding: binding === 'none' ? 'none' : 'opcat', tree, output, leafScript };
}

/** Complete script-path witness: [wots items…, leaf script, control block]. */
export function spendWitness(acct: BtcHashAccount, key: CchsKey, leafIdx: number, sighash: Uint8Array): Uint8Array[] {
  const sig = btcWotsSign(key, leafIdx, sighash);
  return [...wotsWitness(sig, sighash), acct.leafScript(leafIdx), controlBlock(acct.output, tapPath(acct.tree, leafIdx))];
}
