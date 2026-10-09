// Bitcoin: CCHS carried by the UTXO lineage (BITCOIN.md §5).
//
// An account is a chain of UTXOs. Each UTXO is a P2TR output whose script tree
// hard-codes the account state after the previous spend:
//
//   state = (root, recRoot, pkSeed, epoch, t, R_t, nextIdx)
//
// and offers three leaves, all generated from the same template:
//
//   exec       spend with WOTS+ leaf idx ≥ nextIdx of the cached subtree t,
//              authenticated against R_t (10-level path): the cheap path
//   execFirst  first spend in a new subtree t' > t: the top-layer WOTS+
//              signature of leaf t' on R_{t'} and its path to root, then the
//              bottom layer as in exec
//   recover    WOTS+ leaf `epoch` of the recovery tree, under recRoot
//
// Every leaf signs the BIP-341 sighash of the spending transaction. The
// sighash is bound to the transaction with OP_CHECKSIG + OP_CHECKSIGFROMSTACK
// on one Schnorr signature under a public key with a public private key
// (d = 1): a signature valid for the transaction (CHECKSIG) and for the
// witness-supplied message (CHECKSIGFROMSTACK) proves the message is the
// transaction's sighash. No secret is involved; a quantum adversary gains
// nothing from the Schnorr key. The authorisation is the WOTS+ signature.
//
// Hashing (SHA-256 only, every call tweaked with the tree's public seed):
//
//   SP(layer, tree)          = pkSeed(16) ‖ layer(1) ‖ tag(tree)
//   A(layer, tree, leaf)     = SP ‖ tag(leaf)
//   chain  s_i               = SHA256(A ‖ chain(1) ‖ s_{i-1})               i = 1..15
//   group  g_j               = SHA256(A ‖ 0xf0 ‖ j ‖ e_hi ‖ … ‖ e_lo)        j = 4..0 (see GROUPS)
//   leaf                     = SHA256(A ‖ 0xf1 ‖ g_4 ‖ g_3 ‖ g_2 ‖ g_1 ‖ g_0)
//   node(parentPos, level)   = SHA256(SP ‖ tag(parentPos) ‖ 0xf2 ‖ level ‖ left ‖ right)
//   tag(x)                   = LE32(2^24 + x)   (= the minimal Script number of 2^24 + x)
//
// `tag` makes a 4-byte field out of a Script number with one OP_ADD, so the
// leaf index and node positions chosen by the spender enter every hash. The
// grouped leaf compression exists because OP_CAT caps a stack element at 520
// bytes (15 × 32 + 26 = 506). Chains, leaves and nodes are otherwise the
// CCHS.spec.md §3–§5 construction with the spec's ADRS fields in a layout a
// script can assemble by concatenation, with one omission: the chain address
// has no step index. The script evaluates all 16 positions of a chain from
// the witness value without knowing the digit, so the true step would be
// d + i and cost the digit at every step (≈ 5 KB per leaf). Omitting it
// leaves at most 15 targets per chain position, a factor below 2^4 in the
// multi-target term; seed, layer, tree, leaf and chain separation is intact.
//
// What consensus enforces here and what it does not: a leaf verifies the
// WOTS+ signature, the index rule and the sighash binding; it cannot verify
// that the successor output commits to the updated state, because a P2TR
// output key is an elliptic-curve tweak of the tree root and Script has no
// curve arithmetic. The successor is therefore built by the signer and
// covered by the signature, not forced by a covenant; the covenant form
// requires a key-less output type (BIP-360 P2MR), see BITCOIN.md §5.5. The
// key path of every output here is the BIP-341 NUMS point: unspendable
// classically, spendable by a discrete-log adversary. Do not fund these
// outputs on a network with value.

import { sha256 } from '@noble/hashes/sha256';
import { concatBytes } from '@noble/hashes/utils';
import { LEN, W, H, REC_H, SEED_BYTES, digits, sk, pkSeed, eq, type CchsKey, type Tree } from './cchs';
import {
  OP as OP0, push, pushNum, scriptNum, tapLeafHash, tapBranchHash, taprootOutput,
  NUMS_INTERNAL_KEY, LEAF_VERSION, type TaprootOutput,
} from './btcTapscript';

// ----------------------------------------------------------------- opcodes

export const OP = {
  ...OP0,
  _2: 0x52, _3: 0x53,
  IF: 0x63, ELSE: 0x67, ENDIF: 0x68, _2SWAP: 0x72, OVER: 0x78, ROLL: 0x7a, ROT: 0x7b, SWAP: 0x7c,
  CAT: 0x7e, GREATERTHAN: 0xa0, GREATERTHANOREQUAL: 0xa2,
  CHECKSIG: 0xac, CHECKSIGVERIFY: 0xad, CHECKSIGFROMSTACK: 0xcc,
} as const;

// ------------------------------------------------------------- parameters

export const LAYER_BOTTOM = 0x00;
export const LAYER_TOP = 0x01;
export const LAYER_REC = 0xff;
/** Bottom-subtree height (leaves per subtree = 2^HB). Fixed by the spec at 10. */
export const HB = H;
/** Recovery-tree height. */
export const HR = REC_H;
/** Default top-tree height for a build. The spec value is 10; a smaller tree is a build parameter, not a protocol change. */
export const DEFAULT_HT = 4;
/** Leaf compression groups, in the order the script hashes them (descending chain index). */
export const GROUPS: ReadonlyArray<readonly [number, number]> = [[60, 66], [45, 59], [30, 44], [15, 29], [0, 14]];
const TAG_BASE = 1 << 24;
const TYPE_GROUP = 0xf0, TYPE_LEAF = 0xf1, TYPE_NODE = 0xf2;
/** "No subtree cached yet": the state of a fresh account or of the first UTXO after a recovery. */
export const NO_SUBTREE = -1;

// ------------------------------------------------------------- hashing

export const tag = (x: number): Uint8Array => scriptNum(TAG_BASE + x);

export function SP(seed: Uint8Array, layer: number, tree: number): Uint8Array {
  if (seed.length !== SEED_BYTES) throw new Error('pkSeed must be 16 bytes');
  return concatBytes(seed, Uint8Array.of(layer), tag(tree));
}
export const A = (seed: Uint8Array, layer: number, tree: number, leaf: number) => concatBytes(SP(seed, layer, tree), tag(leaf));

function chainStep(a: Uint8Array, c: number, x: Uint8Array): Uint8Array {
  return sha256(concatBytes(a, Uint8Array.of(c), x));
}
/** Apply chain steps producing s_{from+1} … s_{to} from s_from. */
export function chainB(a: Uint8Array, c: number, from: number, to: number, x: Uint8Array): Uint8Array {
  for (let i = from + 1; i <= to; i++) x = chainStep(a, c, x);
  return x;
}

export function leafB(a: Uint8Array, ends: Uint8Array[]): Uint8Array {
  if (ends.length !== LEN) throw new Error('need 67 chain ends');
  const gs: Uint8Array[] = [];
  for (let j = 0; j < GROUPS.length; j++) {
    const [lo, hi] = GROUPS[j];
    const parts: Uint8Array[] = [a, Uint8Array.of(TYPE_GROUP, GROUPS.length - 1 - j)];
    for (let c = hi; c >= lo; c--) parts.push(ends[c]);
    gs.push(sha256(concatBytes(...parts)));
  }
  return sha256(concatBytes(a, Uint8Array.of(TYPE_LEAF), ...gs));
}

export function nodeB(sp: Uint8Array, parentPos: number, level: number, left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(sp, tag(parentPos), Uint8Array.of(TYPE_NODE, level), left, right));
}

// ---------------------------------------------------------------- trees

export function endsB(key: CchsKey, layer: number, tree: number, leaf: number): Uint8Array[] {
  const a = A(pkSeed(key), layer, tree, leaf);
  const out: Uint8Array[] = new Array(LEN);
  for (let c = 0; c < LEN; c++) out[c] = chainB(a, c, 0, W - 1, sk(key, layer, BigInt(tree), leaf, c));
  return out;
}

export function wotsSignB(key: CchsKey, layer: number, tree: number, leaf: number, m: Uint8Array): Uint8Array[] {
  const a = A(pkSeed(key), layer, tree, leaf);
  const d = digits(m);
  const out: Uint8Array[] = new Array(LEN);
  for (let c = 0; c < LEN; c++) out[c] = chainB(a, c, 0, d[c], sk(key, layer, BigInt(tree), leaf, c));
  return out;
}

export function endsFromSigB(a: Uint8Array, m: Uint8Array, sig: Uint8Array[]): Uint8Array[] {
  const d = digits(m);
  return sig.map((s, c) => chainB(a, c, d[c], W - 1, s));
}

export function buildTreeB(seed: Uint8Array, layer: number, tree: number, leaves: Uint8Array[]): Tree {
  const height = Math.log2(leaves.length);
  if (!Number.isInteger(height)) throw new Error('leaf count must be a power of two');
  const sp = SP(seed, layer, tree);
  const levels: Uint8Array[][] = [leaves];
  for (let k = 0; k < height; k++) {
    const prev = levels[k], next: Uint8Array[] = new Array(prev.length / 2);
    for (let i = 0; i < next.length; i++) next[i] = nodeB(sp, i, k, prev[2 * i], prev[2 * i + 1]);
    levels.push(next);
  }
  return { height, levels, root: levels[height][0] };
}

export function authPathB(t: Tree, leaf: number): Uint8Array[] {
  const path: Uint8Array[] = [];
  let pos = leaf;
  for (let k = 0; k < t.height; k++) { path.push(t.levels[k][pos ^ 1]); pos >>= 1; }
  return path;
}

export function rootFromPathB(sp: Uint8Array, leafHash: Uint8Array, leaf: number, path: Uint8Array[]): Uint8Array {
  let r = leafHash, pos = leaf;
  for (let k = 0; k < path.length; k++) {
    r = (pos & 1) === 0 ? nodeB(sp, pos >> 1, k, r, path[k]) : nodeB(sp, pos >> 1, k, path[k], r);
    pos >>= 1;
  }
  return r;
}

function wotsTree(key: CchsKey, layer: number, tree: number, height: number): Tree {
  const seed = pkSeed(key);
  const n = 1 << height, leaves: Uint8Array[] = new Array(n);
  for (let i = 0; i < n; i++) leaves[i] = leafB(A(seed, layer, tree, i), endsB(key, layer, tree, i));
  return buildTreeB(seed, layer, tree, leaves);
}

/** All trees of one epoch key: 2^HT bottom subtrees, the top tree over their roots, the recovery tree. */
export interface BtcTrees { HT: number; bottom: Tree[]; top: Tree; rec: Tree }
export interface BtcPublic { root: Uint8Array; recRoot: Uint8Array; seed: Uint8Array }

export function bottomTree(key: CchsKey, t: number): Tree { return wotsTree(key, LAYER_BOTTOM, t, HB); }

export function keygenB(key: CchsKey, HT = DEFAULT_HT): { pub: BtcPublic; trees: BtcTrees } {
  const r = publicKeyB(key, HT);
  for (let t = 0; t < 1 << HT; t++) bottomOf(key, r.trees, t);
  return r;
}

/**
 * The public key alone: top tree (2^HT WOTS+ keys, their leaves sign the bottom roots
 * later) and recovery tree. No bottom subtree is built; `bottomOf` adds them on demand.
 * This is what a wallet needs to show the address: ~2^HT + 2^HR WOTS+ keys instead of 2^(HT+HB).
 */
export function publicKeyB(key: CchsKey, HT = DEFAULT_HT): { pub: BtcPublic; trees: BtcTrees } {
  const seed = pkSeed(key);
  const top = wotsTree(key, LAYER_TOP, 0, HT);
  const rec = wotsTree(key, LAYER_REC, 0, HR);
  return { pub: { root: top.root, recRoot: rec.root, seed: seed.slice() }, trees: { HT, bottom: [], top, rec } };
}

/** Bottom subtree t of an epoch, built once and cached in `trees.bottom`. */
export function bottomOf(key: CchsKey, trees: BtcTrees, t: number): Tree {
  if (t < 0 || t >= 1 << trees.HT) throw new Error('subtree index');
  return trees.bottom[t] ??= bottomTree(key, t);
}

// ---------------------------------------------------------- script builder

class SB {
  parts: Uint8Array[] = [];
  op(...codes: number[]) { this.parts.push(Uint8Array.from(codes)); return this; }
  push(b: Uint8Array) { this.parts.push(push(b)); return this; }
  num(n: number) { this.parts.push(pushNum(n)); return this; }
  bytes() { return concatBytes(...this.parts); }
}

/** Push a one-byte string. OP_N is the minimal push for 1..16; 0 and 17..255 need a data push. */
function pushByte(s: SB, b: number) { s.push(Uint8Array.of(b)); }

/**
 * Stack [b_0 … b_{h-1}] (b_{h-1} on top) → [idx]; saves (b_{h-1}, p_{h-1}, …, b_1, p_1, b_0)
 * on the alt stack so that `merkleClimb` pops b_k then p_{k+1} at level k.
 * p_k is the position of the level-k ancestor: p_0 = idx, p_h = 0 (not saved).
 */
function bitsToIndex(s: SB, h: number, under = 0) {
  if (under > 0) s.num(under).op(OP.ROLL);                      // b_{h-1} above the `under` items
  s.op(OP.DUP, OP.TOALTSTACK);                                  // b_{h-1}
  if (h > 1) s.op(OP.DUP, OP.TOALTSTACK);                       // p_{h-1} = b_{h-1}
  for (let k = h - 2; k >= 0; k--) {
    if (under === 0) s.op(OP.SWAP); else s.num(under + 1).op(OP.ROLL);
    s.op(OP.DUP, OP.TOALTSTACK);                                // b_k
    s.op(OP.SWAP, OP.DUP, OP.ADD, OP.ADD);                      // acc = 2·acc + b_k
    if (k > 0) s.op(OP.DUP, OP.TOALTSTACK);                     // p_k
  }
}

/** [x] → [tag(x)] */
const toTag = (s: SB) => s.num(TAG_BASE).op(OP.ADD);

/**
 * One WOTS+ chain. Stack [… sig d K_1 … K_keep] with `keep` kept items on top of
 * the (sig, d) pair → [… K_1 … K_keep]; alt += d, then alt += s_15 (the chain end).
 * K_keep must be A = SP ‖ tag(leaf) (the chain's address prefix).
 */
function chainBlock(s: SB, c: number, keep: number) {
  if (keep === 1) s.op(OP.ROT, OP.ROT);
  else if (keep === 2) s.op(OP._2SWAP);
  else { s.num(keep + 1).op(OP.ROLL); s.num(keep + 1).op(OP.ROLL); }
  s.op(OP.DUP, OP._0, OP._16, OP.WITHIN, OP.VERIFY);              // 0 ≤ d < 16
  s.op(OP.TOALTSTACK);                                            // alt += d
  s.op(OP.OVER); pushByte(s, c); s.op(OP.CAT);                    // A ‖ c
  s.op(OP.SWAP);                                                  // [… A, A‖c, s_0]
  for (let i = 1; i < W; i++) {
    s.op(OP.DUP); s.num(i + 1); s.op(OP.PICK, OP.SWAP, OP.CAT, OP.SHA256);  // s_i = SHA256(A‖c‖s_{i-1})
  }
  s.op(OP.FROMALTSTACK, OP.DUP, OP.TOALTSTACK, OP.PICK);          // s_{15-d}
  s.op(OP.TOALTSTACK);                                            // alt += chain end
  for (let i = 0; i < W / 2; i++) s.op(OP._2DROP);                // s_0 … s_15
  s.op(OP.DROP);                                                  // A ‖ c
}

/**
 * Alt (top→bottom) e_66 d_66 e_65 d_65 … e_0 d_0; stack [… A] →
 * stack [… d_66 d_65 … d_0 leaf]. Digits stay on the main stack for the
 * checksum; `leaf` is the compressed WOTS+ public key of CCHS at address A.
 */
function endsToLeaf(s: SB) {
  s.op(OP._0);                                                    // acc = ∅
  let ndig = 0, haveG = false;
  for (let j = 0; j < GROUPS.length; j++) {
    const [lo, hi] = GROUPS[j];
    for (let c = hi; c >= lo; c--) {
      s.op(OP.FROMALTSTACK, OP.CAT, OP.FROMALTSTACK, OP.SWAP);   // acc ‖= e_c ; digit goes under acc
      ndig++;
    }
    const depthA = ndig + (haveG ? 1 : 0) + 1;
    s.num(depthA).op(OP.PICK).push(Uint8Array.of(TYPE_GROUP, GROUPS.length - 1 - j)).op(OP.CAT, OP.SWAP, OP.CAT, OP.SHA256); // g_j
    if (haveG) { s.num(hi - lo + 2).op(OP.ROLL, OP.SWAP, OP.CAT); }   // G ‖= g_j
    haveG = true;
    if (j < GROUPS.length - 1) s.op(OP._0);
  }
  s.num(LEN + 1).op(OP.ROLL).push(Uint8Array.of(TYPE_LEAF)).op(OP.CAT, OP.SWAP, OP.CAT, OP.SHA256); // leaf = SHA256(A ‖ f1 ‖ G)
}

/**
 * Stack [… node]; siblings at constant depth `sibDepth` (the item under node
 * and the digits); alt supplies b_k then p_{k+1} per level (see bitsToIndex).
 */
function merkleClimb(s: SB, h: number, sp: Uint8Array, sibDepth: number) {
  for (let k = 0; k < h; k++) {
    s.num(sibDepth).op(OP.ROLL);                                  // sibling
    s.op(OP.FROMALTSTACK, OP.IF, OP.SWAP, OP.ENDIF, OP.CAT);      // left ‖ right
    if (k < h - 1) {
      s.op(OP.FROMALTSTACK); toTag(s);                            // tag(p_{k+1})
      s.push(sp).op(OP.SWAP, OP.CAT).push(Uint8Array.of(TYPE_NODE, k)).op(OP.CAT, OP.SWAP, OP.CAT, OP.SHA256);
    } else {
      s.push(concatBytes(sp, tag(0), Uint8Array.of(TYPE_NODE, k))).op(OP.SWAP, OP.CAT, OP.SHA256);
    }
  }
}

/** Same climb with the leaf position fixed in the script (recovery leaf = epoch). */
function merkleClimbFixed(s: SB, h: number, sp: Uint8Array, sibDepth: number, leaf: number) {
  let pos = leaf;
  for (let k = 0; k < h; k++) {
    s.num(sibDepth).op(OP.ROLL);
    if (pos & 1) s.op(OP.SWAP);
    s.op(OP.CAT);
    pos >>= 1;
    s.push(concatBytes(sp, tag(pos), Uint8Array.of(TYPE_NODE, k))).op(OP.SWAP, OP.CAT, OP.SHA256);
  }
}

/**
 * Stack [… d_66 d_65 d_64 d_63 … d_0] → [… ]; verifies the Winternitz checksum
 * and moves d_0 … d_63 to the alt stack (d_63 on top).
 */
function checksum(s: SB) {
  s.num(64).op(OP.ROLL); s.num(65).op(OP.ROLL); s.num(66).op(OP.ROLL);   // [… d_63 … d_0 d_64 d_65 d_66]
  s.op(OP.ROT);                                                          // d_64 on top
  for (let i = 0; i < 8; i++) s.op(OP.DUP, OP.ADD);                      // 256·d_64
  s.op(OP.ROT);                                                          // d_65 on top
  for (let i = 0; i < 4; i++) s.op(OP.DUP, OP.ADD);                      // 16·d_65
  s.op(OP.ADD, OP.ADD);                                                  // csum
  for (let i = 0; i < 64; i++) s.op(OP.OVER, OP.ADD, OP.SWAP, OP.TOALTSTACK);
  s.num(64 * (W - 1)).op(OP.EQUALVERIFY);
}

/**
 * Stack [… B_0 … B_31 X_1 … X_off] with `off` other items above the 32
 * message bytes; alt supplies d_63, d_62, … → [… X_1 … X_off M] where
 * M = B_0 ‖ … ‖ B_31 and each pair (d_{2j}, d_{2j+1}) is verified to be the
 * nibbles of B_j: 16·hi + lo + 256 is the two-byte Script number B_j ‖ 0x01.
 */
function bytesFromDigits(s: SB, off: number) {
  for (let j = 31; j >= 0; j--) {
    const first = j === 31;
    if (off === 0) s.op(first ? OP.DUP : OP.OVER);
    else { s.num(off + (first ? 0 : 1)).op(OP.ROLL, OP.DUP); }
    s.op(OP._1, OP.CAT);                                                 // B_j ‖ 01
    s.op(OP.FROMALTSTACK, OP.FROMALTSTACK);                              // lo, hi
    for (let i = 0; i < 4; i++) s.op(OP.DUP, OP.ADD);
    s.op(OP.ADD); s.num(256).op(OP.ADD, OP.EQUALVERIFY);
    if (!first) { if (off !== 0) s.op(OP.SWAP); s.op(OP.CAT); }          // B_j ‖ acc
  }
}

/** Stack [sig m P M] → [1]: M = m, and (sig, P) is valid for both m and this transaction's sighash. */
function binding(s: SB) {
  s.op(OP._2, OP.PICK, OP.EQUALVERIFY);
  s.op(OP._2, OP.PICK, OP.OVER, OP.CHECKSIGVERIFY, OP.CHECKSIGFROMSTACK);
}

// -------------------------------------------------------------- the leaves

export interface BtcState {
  root: Uint8Array; recRoot: Uint8Array; seed: Uint8Array;
  epoch: number;
  /** cached subtree, or NO_SUBTREE */
  t: number;
  /** root of subtree t (ignored when t = NO_SUBTREE) */
  R: Uint8Array;
  /** lowest leaf index of subtree t still usable */
  nextIdx: number;
  HT: number;
}

/**
 * exec: witness (bottom → top)
 *   sig_B m P  B_0 … B_31  sib_9 … sib_0  (sig_66 d_66) … (sig_0 d_0)  b_0 … b_9
 */
export function execLeaf(st: BtcState): Uint8Array {
  if (st.t === NO_SUBTREE) throw new Error('no cached subtree');
  const s = new SB();
  const sp = SP(st.seed, LAYER_BOTTOM, st.t);
  bitsToIndex(s, HB);
  s.op(OP.DUP).num(st.nextIdx).op(OP.GREATERTHANOREQUAL, OP.VERIFY);
  toTag(s); s.push(sp).op(OP.SWAP, OP.CAT);                                // A
  for (let c = 0; c < LEN; c++) chainBlock(s, c, 1);
  endsToLeaf(s);
  merkleClimb(s, HB, sp, LEN + 1);
  s.push(st.R).op(OP.EQUALVERIFY);
  checksum(s);
  bytesFromDigits(s, 0);
  binding(s);
  return s.bytes();
}

/**
 * execFirst: witness (bottom → top)
 *   sig_B m P  RB_0 … RB_31  tsib_{HT-1} … tsib_0  (tsig_66 td_66) … (tsig_0 td_0)
 *   B_0 … B_31  sib_9 … sib_0  (sig_66 d_66) … (sig_0 d_0)  b_0 … b_9  c_0 … c_{HT-1}
 * where c are the bits of the new subtree index t', RB the bytes of R_{t'}.
 */
export function execFirstLeaf(st: BtcState): Uint8Array {
  const s = new SB();
  const spTop = SP(st.seed, LAYER_TOP, 0);
  // t' from its bits (alt: top bits/positions, popped by the top climb last)
  bitsToIndex(s, st.HT);
  s.op(OP.DUP).num(st.t).op(OP.GREATERTHAN, OP.VERIFY);
  toTag(s);                                                                // tagT
  // idx from its bits, which lie under tagT (alt: bottom bits/positions, popped by the bottom climb first)
  bitsToIndex(s, HB, 1);
  toTag(s);                                                                // [tagT tagI]
  s.op(OP.OVER, OP.SWAP, OP.CAT);                                          // [tagT tagT‖tagI]
  s.push(concatBytes(st.seed, Uint8Array.of(LAYER_BOTTOM))).op(OP.SWAP, OP.CAT); // [tagT A_bot]
  for (let c = 0; c < LEN; c++) chainBlock(s, c, 2);
  endsToLeaf(s);                                                           // [tagT d_66 … d_0 leaf]
  // bottom climb: SP_bot = seed ‖ 0x00 ‖ tagT is not a script constant; build it per level from tagT
  for (let k = 0; k < HB; k++) {
    s.num(LEN + 2).op(OP.ROLL);                                            // sibling
    s.op(OP.FROMALTSTACK, OP.IF, OP.SWAP, OP.ENDIF, OP.CAT);
    if (k < HB - 1) { s.op(OP.FROMALTSTACK); toTag(s); } else s.push(tag(0));
    s.push(Uint8Array.of(TYPE_NODE, k)).op(OP.CAT);                        // tag(p) ‖ f2 ‖ k
    s.num(LEN + 2).op(OP.PICK);                                            // tagT
    s.push(concatBytes(st.seed, Uint8Array.of(LAYER_BOTTOM))).op(OP.SWAP, OP.CAT, OP.SWAP, OP.CAT, OP.SWAP, OP.CAT, OP.SHA256);
  }
  s.op(OP.TOALTSTACK);                                                     // alt: R
  checksum(s);                                                             // alt: R d_0 … d_63 ; stack [… B_0 … B_31 tagT]
  bytesFromDigits(s, 1);                                                   // [… tagT M]
  s.op(OP.FROMALTSTACK);                                                   // [… tagT M R]
  s.op(OP._2, OP.PICK).push(spTop).op(OP.SWAP, OP.CAT);                    // A_top = SP_top ‖ tagT
  s.op(OP._3, OP.ROLL, OP.DROP);                                           // [… M R A_top]
  for (let c = 0; c < LEN; c++) chainBlock(s, c, 3);
  endsToLeaf(s);                                                           // [… M R td_66 … td_0 leaf]
  merkleClimb(s, st.HT, spTop, LEN + 3);
  s.push(st.root).op(OP.EQUALVERIFY);
  checksum(s);                                                             // [… RB_0 … RB_31 M R]
  bytesFromDigits(s, 2);                                                   // [… M R RM]
  s.op(OP.EQUALVERIFY);                                                    // R = RM
  binding(s);
  return s.bytes();
}

/**
 * recover: witness (bottom → top)
 *   sig_B m P  B_0 … B_31  sib_7 … sib_0  (sig_66 d_66) … (sig_0 d_0)
 */
export function recoverLeaf(st: BtcState): Uint8Array {
  const s = new SB();
  const sp = SP(st.seed, LAYER_REC, 0);
  s.push(A(st.seed, LAYER_REC, 0, st.epoch));
  for (let c = 0; c < LEN; c++) chainBlock(s, c, 1);
  endsToLeaf(s);
  merkleClimbFixed(s, HR, sp, LEN + 1, st.epoch);
  s.push(st.recRoot).op(OP.EQUALVERIFY);
  checksum(s);
  bytesFromDigits(s, 0);
  binding(s);
  return s.bytes();
}

// ------------------------------------------------------------ the output

export type LeafName = 'exec' | 'execFirst' | 'recover';

export interface BtcAccountOutput {
  state: BtcState;
  leaves: Partial<Record<LeafName, Uint8Array>>;
  leafHashes: Partial<Record<LeafName, Uint8Array>>;
  output: TaprootOutput;
  controlBlock: (leaf: LeafName) => Uint8Array;
}

/** Script tree: (exec, execFirst) under one branch, recover beside it; without a cached subtree just (execFirst, recover). */
export function accountOutput(st: BtcState): BtcAccountOutput {
  const leaves: Partial<Record<LeafName, Uint8Array>> = { execFirst: execFirstLeaf(st), recover: recoverLeaf(st) };
  if (st.t !== NO_SUBTREE) leaves.exec = execLeaf(st);
  const lh: Partial<Record<LeafName, Uint8Array>> = {};
  for (const k of Object.keys(leaves) as LeafName[]) lh[k] = tapLeafHash(leaves[k]!);
  let root: Uint8Array, paths: Partial<Record<LeafName, Uint8Array[]>>;
  if (leaves.exec) {
    const inner = tapBranchHash(lh.exec!, lh.execFirst!);
    root = tapBranchHash(inner, lh.recover!);
    paths = { exec: [lh.execFirst!, lh.recover!], execFirst: [lh.exec!, lh.recover!], recover: [inner] };
  } else {
    root = tapBranchHash(lh.execFirst!, lh.recover!);
    paths = { execFirst: [lh.recover!], recover: [lh.execFirst!] };
  }
  const output = taprootOutput(NUMS_INTERNAL_KEY, root);
  return {
    state: st, leaves, leafHashes: lh, output,
    controlBlock: (leaf) => {
      const p = paths[leaf]; if (!p) throw new Error(`leaf ${leaf} absent in this state`);
      return concatBytes(Uint8Array.of(LEAF_VERSION | output.parity), NUMS_INTERNAL_KEY, ...p);
    },
  };
}

// ----------------------------------------------------------- witnesses

const bits = (x: number, h: number): Uint8Array[] => Array.from({ length: h }, (_, k) => scriptNum((x >> k) & 1));
const bytes1 = (m: Uint8Array): Uint8Array[] => Array.from(m, b => Uint8Array.of(b));
function pairs(sig: Uint8Array[], m: Uint8Array): Uint8Array[] {
  const d = digits(m), out: Uint8Array[] = [];
  for (let c = LEN - 1; c >= 0; c--) out.push(sig[c], scriptNum(d[c]));
  return out;
}

export interface Binding { sig: Uint8Array; m: Uint8Array; P: Uint8Array }

/** Witness items of an `exec` spend at global index idx = t·2^HB + leaf, without script and control block. */
export function execWitness(key: CchsKey, trees: BtcTrees, st: BtcState, leaf: number, b: Binding): Uint8Array[] {
  const sig = wotsSignB(key, LAYER_BOTTOM, st.t, leaf, b.m);
  const bottom = trees.bottom[st.t];
  return [b.sig, b.m, b.P, ...bytes1(b.m), ...authPathB(bottom, leaf).reverse(), ...pairs(sig, b.m), ...bits(leaf, HB)];
}

export function execFirstWitness(key: CchsKey, trees: BtcTrees, st: BtcState, tNew: number, leaf: number, b: Binding): Uint8Array[] {
  const bottom = trees.bottom[tNew];
  const R = bottom.root;
  const sig = wotsSignB(key, LAYER_BOTTOM, tNew, leaf, b.m);
  const tsig = wotsSignB(key, LAYER_TOP, 0, tNew, R);
  return [
    b.sig, b.m, b.P, ...bytes1(R), ...authPathB(trees.top, tNew).reverse(), ...pairs(tsig, R),
    ...bytes1(b.m), ...authPathB(bottom, leaf).reverse(), ...pairs(sig, b.m), ...bits(leaf, HB), ...bits(tNew, st.HT),
  ];
}

export function recoverWitness(key: CchsKey, trees: BtcTrees, st: BtcState, b: Binding): Uint8Array[] {
  const sig = wotsSignB(key, LAYER_REC, 0, st.epoch, b.m);
  return [b.sig, b.m, b.P, ...bytes1(b.m), ...authPathB(trees.rec, st.epoch).reverse(), ...pairs(sig, b.m)];
}

// ---------------------------------------------------------- state machine

export function initialState(pub: BtcPublic, epoch: number, HT: number): BtcState {
  return { root: pub.root, recRoot: pub.recRoot, seed: pub.seed, epoch, t: NO_SUBTREE, R: new Uint8Array(32), nextIdx: 0, HT };
}

/** Successor state after `exec` at `leaf` of the cached subtree. */
export function afterExec(st: BtcState, leaf: number): BtcState {
  if (st.t === NO_SUBTREE || leaf < st.nextIdx || leaf >= 1 << HB) throw new Error('index rule');
  return { ...st, nextIdx: leaf + 1 };
}

/** Successor state after `execFirst` in subtree tNew at `leaf`. */
export function afterExecFirst(st: BtcState, tNew: number, leaf: number, R: Uint8Array): BtcState {
  if (tNew <= st.t || tNew >= 1 << st.HT || leaf < 0 || leaf >= 1 << HB) throw new Error('index rule');
  return { ...st, t: tNew, R, nextIdx: leaf + 1 };
}

/** Successor state after `recover`: the next epoch's public key, nothing cached. */
export function afterRecover(st: BtcState, next: BtcPublic): BtcState {
  return initialState(next, st.epoch + 1, st.HT);
}

/** What a spending transaction's witness says about the transition from state `st`. */
export interface DecodedSpend { leaf: LeafName; idx?: number; tNew?: number; R?: Uint8Array }

const bitsToInt = (items: Uint8Array[]): number => items.reduce((acc, b, k) => acc | ((b.length === 0 ? 0 : b[0] & 1) << k), 0);

/**
 * Identify the leaf a witness spent and the successor data it carried, by matching
 * the leaf script against the three leaves of `st`. Used to rebuild the lineage state
 * from the chain: a reader with the public key follows outpoint → spend → outpoint.
 * Returns null if the witness is not a spend of this state (another input, another account).
 */
export function decodeSpend(st: BtcState, witness: Uint8Array[]): DecodedSpend | null {
  if (witness.length < 3) return null;
  const script = witness[witness.length - 2];
  const out = accountOutput(st);
  const items = witness.slice(0, -2);
  for (const name of ['exec', 'execFirst', 'recover'] as LeafName[]) {
    const leaf = out.leaves[name];
    if (!leaf || !eq(leaf, script)) continue;
    if (name === 'exec') return { leaf: name, idx: bitsToInt(items.slice(-HB)) };
    if (name === 'execFirst') {
      const c = items.slice(-st.HT), b = items.slice(-st.HT - HB, -st.HT);
      const R = concatBytes(...items.slice(3, 35).map(x => (x.length ? x : Uint8Array.of(0))));
      return { leaf: name, idx: bitsToInt(b), tNew: bitsToInt(c), R };
    }
    return { leaf: name };
  }
  return null;
}

// -------------------------------------------------------- reference check

/** Pure-TypeScript verifier mirroring the leaves (for tests; consensus is the node). */
export function verifyExec(st: BtcState, leaf: number, m: Uint8Array, sig: Uint8Array[], path: Uint8Array[]): boolean {
  if (st.t === NO_SUBTREE || leaf < st.nextIdx) return false;
  const a = A(st.seed, LAYER_BOTTOM, st.t, leaf);
  const r = rootFromPathB(SP(st.seed, LAYER_BOTTOM, st.t), leafB(a, endsFromSigB(a, m, sig)), leaf, path);
  return eq(r, st.R);
}
export function verifyExecFirst(st: BtcState, tNew: number, leaf: number, m: Uint8Array, R: Uint8Array,
  sig: Uint8Array[], path: Uint8Array[], tsig: Uint8Array[], tpath: Uint8Array[]): boolean {
  if (tNew <= st.t) return false;
  const a = A(st.seed, LAYER_BOTTOM, tNew, leaf);
  const r = rootFromPathB(SP(st.seed, LAYER_BOTTOM, tNew), leafB(a, endsFromSigB(a, m, sig)), leaf, path);
  if (!eq(r, R)) return false;
  const at = A(st.seed, LAYER_TOP, 0, tNew);
  const top = rootFromPathB(SP(st.seed, LAYER_TOP, 0), leafB(at, endsFromSigB(at, R, tsig)), tNew, tpath);
  return eq(top, st.root);
}
export function verifyRecover(st: BtcState, m: Uint8Array, sig: Uint8Array[], path: Uint8Array[]): boolean {
  const a = A(st.seed, LAYER_REC, 0, st.epoch);
  const r = rootFromPathB(SP(st.seed, LAYER_REC, 0), leafB(a, endsFromSigB(a, m, sig)), st.epoch, path);
  return eq(r, st.recRoot);
}
