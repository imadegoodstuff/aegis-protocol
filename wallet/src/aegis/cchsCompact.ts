/**
 * CCHS-C-20 — the single-packet parameter set.
 *
 *   n = 24 bytes (SHA-256 truncated; 192-bit preimage security, NIST level 3 like SLH-DSA-192)
 *   w = 256     (one WOTS+ chain per message byte, 2 checksum chains, LEN = 26)
 *   d = 2, h = 10 + 10, recovery tree h = 8   (same hypertree shape as S-20 / K-20)
 *
 * One layer is 26 x 24 + 10 x 24 = 864 bytes, so the cached path, the hot path,
 * fits a 1 232-byte Solana packet with room for the instruction. The top layer is
 * verified in its own transaction (`cache_subtree`): that is sound because a cache
 * entry can only be written through a valid top-layer signature, and it is exactly
 * the property that makes CCHS cheap on every other chain.
 *
 * The price is compute: w = 256 means up to 255 hash steps per chain, 26 chains per
 * layer, so verification is ~3.3 K hashes on average (~6.4 K worst case) instead of
 * ~0.5 K for w = 16. That is what buys a 2.9x smaller signature.
 *
 * Key derivation is domain-separated from S-20 / K-20 (`cchs/sk/c`), so one master
 * seed yields independent keys for every set.
 */
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes } from '@noble/hashes/utils';
import { adrs, eq, type CchsKey, type CchsPublic, type Tree, type LayerSig, type CchsSignature, type HashFn } from './cchs';

export const N = 24;
export const W = 256;
export const MSG_CHAINS = 24;
export const LEN = 26;
export const H = 10;
export const LEAVES = 1 << H;
export const CAPACITY = 1 << (2 * H);
export const REC_H = 8;
export const LAYER_BYTES = (LEN + H) * N; // 864
export const SIG_BYTES_CACHED = LAYER_BYTES;
export const SIG_BYTES_FIRST = 2 * LAYER_BYTES;

const enc = new TextEncoder();
function u32be(n: number): Uint8Array { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0); return b; }
function u64be(n: bigint): Uint8Array { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n); return b; }

/** Builds a CCHS-C-20 instance over the given SHA-256 (pure JS or WASM). F_n(x) = SHA-256(x)[0..24). */
export function makeCompact(sha: HashFn) {
const hashN = (data: Uint8Array): Uint8Array => sha(data).subarray(0, N);

// ------------------------------------------------------------ key derivation
type Hmac = ReturnType<typeof hmac.create>;
const expandCache = new WeakMap<Uint8Array, Hmac>();
function expanderOf(master: Uint8Array): Hmac {
  let h = expandCache.get(master);
  if (!h) { h = hmac.create(sha256, hmac(sha256, new Uint8Array(32), master)); expandCache.set(master, h); }
  return h;
}
const SK_PREFIX = enc.encode('cchs/sk/c');
const skInfo = new Uint8Array(SK_PREFIX.length + 1 + 8 + 4 + 1 + 1);
skInfo.set(SK_PREFIX, 0);
skInfo[skInfo.length - 1] = 0x01;
/** HKDF-SHA256(master, "cchs/sk/c" ‖ layer ‖ treeIdx ‖ leafIdx ‖ chainIdx)[0..24). */
function sk(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number, chainIdx: number): Uint8Array {
  const o = SK_PREFIX.length;
  skInfo[o] = layer; skInfo.set(u64be(treeIdx), o + 1); skInfo.set(u32be(leafIdx), o + 9); skInfo[o + 13] = chainIdx;
  return expanderOf(key.master)._cloneInto().update(skInfo).digest().subarray(0, N);
}

// -------------------------------------------------------------------- digits
/** 24 message bytes ‖ 2 checksum bytes (csum = Σ(255 − m_i) ≤ 6 120, big-endian). */
function digits(m: Uint8Array): Uint8Array {
  if (m.length !== N) throw new Error('message must be 24 bytes');
  const d = new Uint8Array(LEN);
  let csum = 0;
  for (let i = 0; i < MSG_CHAINS; i++) { d[i] = m[i]; csum += 255 - m[i]; }
  d[24] = (csum >> 8) & 0xff; d[25] = csum & 0xff;
  return d;
}

// ----------------------------------------------------------------- the scheme
const scratch56 = new Uint8Array(32 + N);
const scratch80 = new Uint8Array(32 + 2 * N);
const scratchLeaf = new Uint8Array(32 + LEN * N);

function chainSteps(layer: number, treeIdx: bigint, leafIdx: number, c: number, from: number, to: number, x: Uint8Array): Uint8Array {
  if (from >= to) return x;
  scratch56.set(adrs(layer, treeIdx, 0x00, leafIdx, c, 0), 0);
  for (let s = from; s < to; s++) { scratch56[15] = s; scratch56.set(x, 32); x = hashN(scratch56); }
  return x;
}
function leafFromEnds(layer: number, treeIdx: bigint, leafIdx: number, ends: Uint8Array[]): Uint8Array {
  scratchLeaf.set(adrs(layer, treeIdx, 0x01, leafIdx, 0, 0), 0);
  for (let c = 0; c < LEN; c++) scratchLeaf.set(ends[c], 32 + c * N);
  return hashN(scratchLeaf);
}
function nodeHash(layer: number, treeIdx: bigint, parentPos: number, level: number, left: Uint8Array, right: Uint8Array): Uint8Array {
  scratch80.set(adrs(layer, treeIdx, 0x02, parentPos, level, 0), 0);
  scratch80.set(left, 32); scratch80.set(right, 32 + N);
  return hashN(scratch80);
}
function wotsLeaf(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number): Uint8Array {
  const ends: Uint8Array[] = new Array(LEN);
  for (let c = 0; c < LEN; c++) ends[c] = chainSteps(layer, treeIdx, leafIdx, c, 0, W - 1, sk(key, layer, treeIdx, leafIdx, c));
  return leafFromEnds(layer, treeIdx, leafIdx, ends);
}
function leavesRange(key: CchsKey, layer: number, treeIdx: bigint, from: number, to: number): Uint8Array[] {
  const out: Uint8Array[] = new Array(to - from);
  for (let j = from; j < to; j++) out[j - from] = wotsLeaf(key, layer, treeIdx, j);
  return out;
}
function buildTreeFromLeaves(layer: number, treeIdx: bigint, leaves: Uint8Array[]): Tree {
  const height = Math.log2(leaves.length);
  const levels: Uint8Array[][] = [leaves];
  for (let k = 0; k < height; k++) {
    const prev = levels[k], next: Uint8Array[] = new Array(prev.length / 2);
    for (let i = 0; i < next.length; i++) next[i] = nodeHash(layer, treeIdx, i, k, prev[2 * i], prev[2 * i + 1]);
    levels.push(next);
  }
  return { height, levels, root: levels[height][0] };
}
function buildTree(key: CchsKey, layer: number, treeIdx: bigint, height: number): Tree {
  return buildTreeFromLeaves(layer, treeIdx, leavesRange(key, layer, treeIdx, 0, 1 << height));
}
function authPath(t: Tree, leafIdx: number): Uint8Array[] {
  const path: Uint8Array[] = []; let pos = leafIdx;
  for (let k = 0; k < t.height; k++) { path.push(t.levels[k][pos ^ 1].slice()); pos >>= 1; }
  return path;
}
function rootFromPath(layer: number, treeIdx: bigint, leaf: Uint8Array, leafIdx: number, path: Uint8Array[]): Uint8Array {
  let r = leaf, pos = leafIdx;
  for (let k = 0; k < path.length; k++) {
    r = (pos & 1) === 0 ? nodeHash(layer, treeIdx, pos >> 1, k, r, path[k]) : nodeHash(layer, treeIdx, pos >> 1, k, path[k], r);
    pos >>= 1;
  }
  return r;
}

function keygen(key: CchsKey, cache?: Map<string, Tree>): CchsPublic {
  const top = buildTree(key, 1, 0n, H), rec = buildTree(key, 0xff, 0n, REC_H);
  cache?.set('1/0', top); cache?.set('ff/0', rec);
  return { root: top.root, recRoot: rec.root };
}

function wotsSign(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number, m: Uint8Array): Uint8Array[] {
  const d = digits(m), out: Uint8Array[] = new Array(LEN);
  for (let c = 0; c < LEN; c++) out[c] = chainSteps(layer, treeIdx, leafIdx, c, 0, d[c], sk(key, layer, treeIdx, leafIdx, c));
  return out;
}
function wotsEndsFromSig(layer: number, treeIdx: bigint, leafIdx: number, m: Uint8Array, sig: Uint8Array[]): Uint8Array[] {
  const d = digits(m), out: Uint8Array[] = new Array(LEN);
  for (let c = 0; c < LEN; c++) out[c] = chainSteps(layer, treeIdx, leafIdx, c, d[c], W - 1, sig[c]);
  return out;
}
/** Number of hash calls a verifier spends on one layer for message `m` (for cost tables). */
function verifySteps(m: Uint8Array): number {
  const d = digits(m); let s = 0;
  for (let c = 0; c < LEN; c++) s += W - 1 - d[c];
  return s + 1 + H; // chains + leaf + path
}

/** Sign the 24-byte message `m` at leaf `idx`. `subtreeCached` omits the top layer. */
function sign(key: CchsKey, idx: number, m: Uint8Array, subtreeCached: boolean, treeCache?: Map<string, Tree>): CchsSignature {
  if (idx < 0 || idx >= CAPACITY) throw new Error('index exhausted');
  const treeIdx = BigInt(idx >> H), leafIdx = idx & (LEAVES - 1);
  const ck = `0/${treeIdx}`;
  let bottom = treeCache?.get(ck);
  if (!bottom) { bottom = buildTree(key, 0, treeIdx, H); treeCache?.set(ck, bottom); }
  const l0: LayerSig = { wots: wotsSign(key, 0, treeIdx, leafIdx, m), auth: authPath(bottom, leafIdx) };
  if (subtreeCached) return { l0, idx };
  return { l0, l1: topLayer(key, treeIdx, bottom.root, treeCache), idx };
}

/** Top-layer proof for bottom tree `treeIdx` alone: the payload of a `cache_subtree` transaction. */
function topLayer(key: CchsKey, treeIdx: bigint, bottomRoot: Uint8Array, treeCache?: Map<string, Tree>): LayerSig {
  let top = treeCache?.get('1/0');
  if (!top) { top = buildTree(key, 1, 0n, H); treeCache?.set('1/0', top); }
  const leaf = Number(treeIdx);
  return { wots: wotsSign(key, 1, 0n, leaf, bottomRoot), auth: authPath(top, leaf) };
}

/** Bottom-layer root recomputed from a layer-0 signature (what the verifier compares with the cache). */
function bottomRootOf(idx: number, m: Uint8Array, l0: LayerSig): Uint8Array {
  const treeIdx = BigInt(idx >> H), leafIdx = idx & (LEAVES - 1);
  return rootFromPath(0, treeIdx, leafFromEnds(0, treeIdx, leafIdx, wotsEndsFromSig(0, treeIdx, leafIdx, m, l0.wots)), leafIdx, l0.auth);
}
/** Verify a top-layer proof for bottom root `r0` of tree `treeIdx` against `root`. */
function verifyTopLayer(root: Uint8Array, treeIdx: bigint, r0: Uint8Array, l1: LayerSig): boolean {
  const leaf = Number(treeIdx);
  const r1 = rootFromPath(1, 0n, leafFromEnds(1, 0n, leaf, wotsEndsFromSig(1, 0n, leaf, r0, l1.wots)), leaf, l1.auth);
  return eq(r1, root);
}
/** Local verifier mirroring the on-chain state machine. Returns the bottom root to cache, or throws. */
function verify(pub: CchsPublic, idx: number, m: Uint8Array, s: CchsSignature, cachedBottomRoot?: Uint8Array): Uint8Array {
  if (s.idx !== idx) throw new Error('index mismatch');
  const r0 = bottomRootOf(idx, m, s.l0);
  if (cachedBottomRoot) { if (!eq(cachedBottomRoot, r0)) throw new Error('bad subtree root'); return r0; }
  if (!s.l1) throw new Error('missing top layer');
  if (!verifyTopLayer(pub.root, BigInt(idx >> H), r0, s.l1)) throw new Error('bad top root');
  return r0;
}

function signRecovery(key: CchsKey, recNonce: number, m: Uint8Array, treeCache?: Map<string, Tree>): LayerSig {
  let rec = treeCache?.get('ff/0');
  if (!rec) { rec = buildTree(key, 0xff, 0n, REC_H); treeCache?.set('ff/0', rec); }
  return { wots: wotsSign(key, 0xff, 0n, recNonce, m), auth: authPath(rec, recNonce) };
}
function verifyRecovery(recRoot: Uint8Array, recNonce: number, m: Uint8Array, s: LayerSig): boolean {
  const r = rootFromPath(0xff, 0n, leafFromEnds(0xff, 0n, recNonce, wotsEndsFromSig(0xff, 0n, recNonce, m, s.wots)), recNonce, s.auth);
  return eq(r, recRoot);
}

/**
 * Messages are 24 bytes: the chain's 32-byte digest truncated. The chain tag replaces
 * the EVM chain id, as in every non-EVM port:
 *   M = SHA-256("AEGIS_CCHS_V1" ‖ tag ‖ account ‖ nonce(8) ‖ idx(8) ‖ SHA-256(call))[0..24)
 */
function executeDigest(p: { tag: string; account: Uint8Array; nonce: bigint; idx: bigint; callHash: Uint8Array }): Uint8Array {
  return hashN(concatBytes(enc.encode('AEGIS_CCHS_V1'), enc.encode(p.tag), p.account, u64be(p.nonce), u64be(p.idx), p.callHash));
}
function recoveryDigest(p: { tag: string; account: Uint8Array; recNonce: bigint; newRoot: Uint8Array; newRecRoot: Uint8Array }): Uint8Array {
  return hashN(concatBytes(enc.encode('AEGIS_CCHS_RECOVER_V1'), enc.encode(p.tag), p.account, u64be(p.recNonce), p.newRoot, p.newRecRoot));
}

function signatureBytes(s: CchsSignature): number { return s.l1 ? SIG_BYTES_FIRST : SIG_BYTES_CACHED; }

return {
  variant: 'C' as const, N, W, LEN, H, REC_H,
  sk, digits, wotsLeaf, leavesRange, buildTree, buildTreeFromLeaves, rootFromPath,
  keygen, sign, topLayer, bottomRootOf, verifyTopLayer, verify, signRecovery, verifyRecovery,
  executeDigest, recoveryDigest, verifySteps, signatureBytes,
};
}
export type Compact = ReturnType<typeof makeCompact>;

/** CCHS-C-20 over the pure-JS SHA-256. The worker pool binds the WASM core instead (see cchsFast.ts). */
export const cchsC: Compact = makeCompact(sha256);
export const {
  sk, digits, wotsLeaf, leavesRange, buildTree, buildTreeFromLeaves, rootFromPath,
  keygen, sign, topLayer, bottomRootOf, verifyTopLayer, verify, signRecovery, verifyRecovery,
  executeDigest, recoveryDigest, verifySteps, signatureBytes,
} = cchsC;
