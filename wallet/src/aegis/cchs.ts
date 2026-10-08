/**
 * AEGIS CCHS — Chain-Cached Hypertree Signatures, client side.
 * Parameter set CCHS-S-20: SHA-256, w=16, 67 chains, d=2, h=10.
 *
 * Byte-exact with evm/src/AegisCCHS.sol. Spec: ../../../CCHS.spec.md
 *
 * Only dependency: @noble/hashes (sha256, hkdf). Everything is derived
 * lazily from a 32-byte master seed; the client holds no other state.
 */
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { concatBytes } from '@noble/hashes/utils';

export const W = 16;
export const LEN = 67;
export const H = 10;
export const LEAVES = 1 << H;
export const CAPACITY = 1 << (2 * H);
export const REC_H = 8;

const enc = new TextEncoder();
const CSUM_MAX = 64 * (W - 1); // 960

// ------------------------------------------------------------------ utils

function u8(n: number): Uint8Array { return Uint8Array.of(n & 0xff); }
function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0); return b;
}
function u64be(n: bigint): Uint8Array {
  const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n); return b;
}

/** ADRS = layer(1) ‖ treeIdx(8) ‖ type(1) ‖ leafIdx(4) ‖ chainIdx(1) ‖ step(1) ‖ pad(16) */
export function adrs(layer: number, treeIdx: bigint, typ: number, leafIdx: number, chainIdx: number, step: number): Uint8Array {
  const out = new Uint8Array(32);
  out[0] = layer & 0xff;
  out.set(u64be(treeIdx), 1);
  out[9] = typ & 0xff;
  out.set(u32be(leafIdx), 10);
  out[14] = chainIdx & 0xff;
  out[15] = step & 0xff;
  return out;
}

const F = (a: Uint8Array, x: Uint8Array) => sha256(concatBytes(a, x));

/** 64 base-16 message digits ‖ 3 base-16 checksum digits. Matches Solidity `_digits`. */
export function digits(m: Uint8Array): Uint8Array {
  if (m.length !== 32) throw new Error('digest must be 32 bytes');
  const d = new Uint8Array(LEN);
  let csum = 0;
  for (let i = 0; i < 32; i++) {
    const hi = m[i] >> 4, lo = m[i] & 0x0f;
    d[2 * i] = hi; d[2 * i + 1] = lo;
    csum += (W - 1 - hi) + (W - 1 - lo);
  }
  if (csum > CSUM_MAX) throw new Error('unreachable');
  d[64] = (csum >> 8) & 0x0f; d[65] = (csum >> 4) & 0x0f; d[66] = csum & 0x0f;
  return d;
}

// ------------------------------------------------------------- key material

export interface CchsKey {
  master: Uint8Array;        // 32 bytes — the only secret
}

export function sk(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number, chainIdx: number): Uint8Array {
  const info = concatBytes(enc.encode('cchs/sk'), u8(layer), u64be(treeIdx), u32be(leafIdx), u8(chainIdx));
  return hkdf(sha256, key.master, undefined, info, 32);
}

/** Chain end for every chain → 67×32 bytes. */
function wotsChainEnds(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number): Uint8Array[] {
  const pks: Uint8Array[] = new Array(LEN);
  for (let c = 0; c < LEN; c++) {
    let x = sk(key, layer, treeIdx, leafIdx, c);
    for (let s = 0; s < W - 1; s++) x = F(adrs(layer, treeIdx, 0x00, leafIdx, c, s), x);
    pks[c] = x;
  }
  return pks;
}

function leafFromEnds(layer: number, treeIdx: bigint, leafIdx: number, ends: Uint8Array[]): Uint8Array {
  return sha256(concatBytes(adrs(layer, treeIdx, 0x01, leafIdx, 0, 0), ...ends));
}

export function wotsLeaf(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number): Uint8Array {
  return leafFromEnds(layer, treeIdx, leafIdx, wotsChainEnds(key, layer, treeIdx, leafIdx));
}

// ------------------------------------------------------------- Merkle tree

export interface Tree { height: number; levels: Uint8Array[][]; root: Uint8Array }

/** Build the full tree for (layer, treeIdx). levels[0] = leaves, levels[h] = [root]. */
export function buildTree(key: CchsKey, layer: number, treeIdx: bigint, height: number): Tree {
  const n = 1 << height;
  const leaves: Uint8Array[] = new Array(n);
  for (let j = 0; j < n; j++) leaves[j] = wotsLeaf(key, layer, treeIdx, j);
  const levels: Uint8Array[][] = [leaves];
  for (let k = 0; k < height; k++) {
    const prev = levels[k];
    const next: Uint8Array[] = new Array(prev.length / 2);
    for (let i = 0; i < next.length; i++) {
      next[i] = sha256(concatBytes(adrs(layer, treeIdx, 0x02, i, k, 0), prev[2 * i], prev[2 * i + 1]));
    }
    levels.push(next);
  }
  return { height, levels, root: levels[height][0] };
}

export function authPath(t: Tree, leafIdx: number): Uint8Array[] {
  const path: Uint8Array[] = [];
  let pos = leafIdx;
  for (let k = 0; k < t.height; k++) { path.push(t.levels[k][pos ^ 1].slice()); pos >>= 1; }
  return path;
}

export function rootFromPath(layer: number, treeIdx: bigint, leaf: Uint8Array, leafIdx: number, path: Uint8Array[]): Uint8Array {
  let r = leaf, pos = leafIdx;
  for (let k = 0; k < path.length; k++) {
    const a = adrs(layer, treeIdx, 0x02, pos >> 1, k, 0);
    r = (pos & 1) === 0 ? sha256(concatBytes(a, r, path[k])) : sha256(concatBytes(a, path[k], r));
    pos >>= 1;
  }
  return r;
}

// ------------------------------------------------------------------ keygen

export interface CchsPublic { root: Uint8Array; recRoot: Uint8Array }

/** Top tree (layer 1, 2^10 WOTS+ keys) + recovery tree (layer 0xFF, 2^8). ~1.3M hashes. */
export function keygen(key: CchsKey): CchsPublic {
  const top = buildTree(key, 1, 0n, H);
  const rec = buildTree(key, 0xff, 0n, REC_H);
  return { root: top.root, recRoot: rec.root };
}

// -------------------------------------------------------------------- sign

export interface LayerSig { wots: Uint8Array[]; auth: Uint8Array[] }
export interface CchsSignature { l0: LayerSig; l1?: LayerSig; idx: number }

function wotsSign(key: CchsKey, layer: number, treeIdx: bigint, leafIdx: number, m: Uint8Array): Uint8Array[] {
  const d = digits(m);
  const out: Uint8Array[] = new Array(LEN);
  for (let c = 0; c < LEN; c++) {
    let x = sk(key, layer, treeIdx, leafIdx, c);
    for (let s = 0; s < d[c]; s++) x = F(adrs(layer, treeIdx, 0x00, leafIdx, c, s), x);
    out[c] = x;
  }
  return out;
}

/** Complete chains from a signature → chain ends. Matches Solidity `_wotsLeaf` inner loop. */
function wotsEndsFromSig(layer: number, treeIdx: bigint, leafIdx: number, m: Uint8Array, sig: Uint8Array[]): Uint8Array[] {
  const d = digits(m);
  const out: Uint8Array[] = new Array(LEN);
  for (let c = 0; c < LEN; c++) {
    let x = sig[c];
    for (let s = d[c]; s < W - 1; s++) x = F(adrs(layer, treeIdx, 0x00, leafIdx, c, s), x);
    out[c] = x;
  }
  return out;
}

/**
 * Sign message digest `m` at leaf `idx`. If `subtreeCached` is false the
 * top-layer proof is included. Caller supplies `idx` read from chain.
 * Optional `treeCache` avoids rebuilding the bottom tree (pure optimisation).
 */
export function sign(
  key: CchsKey, idx: number, m: Uint8Array, subtreeCached: boolean,
  treeCache?: Map<string, Tree>,
): CchsSignature {
  if (idx < 0 || idx >= CAPACITY) throw new Error('index exhausted');
  const treeIdx = BigInt(idx >> H);
  const leafIdx = idx & (LEAVES - 1);

  const ck = `0/${treeIdx}`;
  let bottom = treeCache?.get(ck);
  if (!bottom) { bottom = buildTree(key, 0, treeIdx, H); treeCache?.set(ck, bottom); }

  const l0: LayerSig = { wots: wotsSign(key, 0, treeIdx, leafIdx, m), auth: authPath(bottom, leafIdx) };
  if (subtreeCached) return { l0, idx };

  const tk = '1/0';
  let top = treeCache?.get(tk);
  if (!top) { top = buildTree(key, 1, 0n, H); treeCache?.set(tk, top); }
  const topLeaf = Number(treeIdx);
  const l1: LayerSig = { wots: wotsSign(key, 1, 0n, topLeaf, bottom.root), auth: authPath(top, topLeaf) };
  return { l0, l1, idx };
}

// ------------------------------------------------------------------ verify

/** Local verifier mirroring the contract. Returns the bottom root to cache, or throws. */
export function verify(
  pub: CchsPublic, idx: number, m: Uint8Array, s: CchsSignature, cachedBottomRoot?: Uint8Array,
): Uint8Array {
  if (s.idx !== idx) throw new Error('index mismatch');
  const treeIdx = BigInt(idx >> H);
  const leafIdx = idx & (LEAVES - 1);

  const ends0 = wotsEndsFromSig(0, treeIdx, leafIdx, m, s.l0.wots);
  const r0 = rootFromPath(0, treeIdx, leafFromEnds(0, treeIdx, leafIdx, ends0), leafIdx, s.l0.auth);

  if (cachedBottomRoot) {
    if (!eq(cachedBottomRoot, r0)) throw new Error('bad subtree root');
    return r0;
  }
  if (!s.l1) throw new Error('missing top layer');
  const topLeaf = Number(treeIdx);
  const ends1 = wotsEndsFromSig(1, 0n, topLeaf, r0, s.l1.wots);
  const r1 = rootFromPath(1, 0n, leafFromEnds(1, 0n, topLeaf, ends1), topLeaf, s.l1.auth);
  if (!eq(r1, pub.root)) throw new Error('bad top root');
  return r0;
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0;
}

// ---------------------------------------------------------------- recovery

export function signRecovery(key: CchsKey, recNonce: number, m: Uint8Array): LayerSig {
  const rec = buildTree(key, 0xff, 0n, REC_H);
  return { wots: wotsSign(key, 0xff, 0n, recNonce, m), auth: authPath(rec, recNonce) };
}

// ------------------------------------------------------ digest construction

/**
 * M = sha256("AEGIS_CCHS_V1" ‖ chainId(32) ‖ account(20) ‖ nonce(8) ‖ idx(8) ‖ target(20) ‖ value(32) ‖ keccak256(data))
 * Mirrors Solidity abi.encodePacked in `execute`. `dataHash` = keccak256(data), computed by caller (viem).
 */
export function executeDigest(p: {
  chainId: bigint; account: Uint8Array; nonce: bigint; idx: bigint;
  target: Uint8Array; value: bigint; dataHash: Uint8Array;
}): Uint8Array {
  const u256 = (n: bigint) => { const b = new Uint8Array(32); let x = n; for (let i = 31; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
  return sha256(concatBytes(
    enc.encode('AEGIS_CCHS_V1'), u256(p.chainId), p.account, u64be(p.nonce), u64be(p.idx),
    p.target, u256(p.value), p.dataHash,
  ));
}

export function recoveryDigest(p: {
  chainId: bigint; account: Uint8Array; recNonce: bigint; newRoot: Uint8Array; newRecRoot: Uint8Array;
}): Uint8Array {
  const u256 = (n: bigint) => { const b = new Uint8Array(32); let x = n; for (let i = 31; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
  return sha256(concatBytes(
    enc.encode('AEGIS_CCHS_RECOVER_V1'), u256(p.chainId), p.account, u64be(p.recNonce), p.newRoot, p.newRecRoot,
  ));
}

// ------------------------------------------------------ ABI encoding helpers

/** Encode a LayerSig as the tuple (bytes32[67], bytes32[10]) expected by the contract. */
export function toAbiLayerSig(l: LayerSig): { wots: `0x${string}`[]; auth: `0x${string}`[] } {
  const hex = (b: Uint8Array) => ('0x' + Array.from(b, x => x.toString(16).padStart(2, '0')).join('')) as `0x${string}`;
  return { wots: l.wots.map(hex), auth: l.auth.map(hex) };
}

/** Empty top-layer tuple for `hasL1 = false` calls. */
export const EMPTY_LAYER_SIG = {
  wots: Array<`0x${string}`>(LEN).fill('0x' + '00'.repeat(32) as `0x${string}`),
  auth: Array<`0x${string}`>(H).fill('0x' + '00'.repeat(32) as `0x${string}`),
};

export function signatureBytes(s: CchsSignature): number {
  const layer = (LEN + H) * 32;
  return s.l1 ? 2 * layer : layer;
}
