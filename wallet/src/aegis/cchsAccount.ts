// One mnemonic, one independent key tree per chain.
//
//   mnemonic ─BIP-39─▶ seed ─HKDF-SHA256("aegis/cchs/master/v1")─▶ 32-byte master
//   master   ─HKDF-SHA256("aegis/cchs/chain/v1" ‖ tag)─▶ 32-byte chain key
//              tag = 0x00 ‖ chainId (u64 BE)   for EVM chains
//                    0x01 ‖ utf8(label)        for other chains (the label of the digest)
//   chain key ─▶ CCHS-K-20 (root, recRoot)  → the EVM account address on that chain
//   chain key ─▶ CCHS-S-20 / C-20           → the verifier of that chain
//
// A WOTS+ leaf signs one message. The chain id inside the digest stops a
// signature from being replayed on another chain, but it would not stop the
// *same leaf* from signing a second, different digest there if both chains
// used one tree: leaf 0 on chain A and leaf 0 on chain B would then be two
// messages under one key. Deriving a separate tree per chain removes that by
// construction, with no coordination between chains or devices. The price is
// that the account address differs per chain; it is still a pure function of
// the mnemonic, the chain id and the factory init code, so every address is
// known before anything is deployed anywhere.

import { mnemonicToSeedSync } from '@scure/bip39';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concatHex, encodeAbiParameters, getContractAddress, keccak256, type Address, type Hex } from 'viem';
import type { CchsKey, Tree, Variant } from './cchs';
import { toHex } from './cchs';
import { CchsPool } from './cchsPool';
import artifacts from './cchsArtifacts.json';

const MASTER_INFO = new TextEncoder().encode('aegis/cchs/master/v1');
const CHAIN_INFO = new TextEncoder().encode('aegis/cchs/chain/v1');

export function cchsMaster(mnemonic: string, passphrase = ''): CchsKey {
  const seed = mnemonicToSeedSync(mnemonic.trim(), passphrase);
  return { master: hkdf(sha256, seed, undefined, MASTER_INFO, 32) };
}

/** Chain tag of an EVM chain: 0x00 ‖ chainId as 8-byte big-endian. */
export function evmChainTag(chainId: number | bigint): Uint8Array {
  const tag = new Uint8Array(9);
  new DataView(tag.buffer).setBigUint64(1, BigInt(chainId));
  return tag;
}
/** Chain tag of a non-EVM chain: 0x01 ‖ utf8(label), label as used in that chain's digest ("solana", "ton", …). */
export function labelChainTag(label: string): Uint8Array {
  const l = new TextEncoder().encode(label);
  const tag = new Uint8Array(1 + l.length);
  tag[0] = 1; tag.set(l, 1);
  return tag;
}
/** Key tree of one chain: HKDF-SHA256(master, info = "aegis/cchs/chain/v1" ‖ tag, 32). */
export function chainKey(master: CchsKey, tag: Uint8Array): CchsKey {
  const info = new Uint8Array(CHAIN_INFO.length + tag.length);
  info.set(CHAIN_INFO, 0); info.set(tag, CHAIN_INFO.length);
  return { master: hkdf(sha256, master.master, undefined, info, 32) };
}

export const FACTORY_ADDRESS = artifacts.factory.address as Address;
export const FACTORY_ABI = artifacts.factory.abi;
export const ACCOUNT_ABI = artifacts.accountAbi;

/** Deterministic-deployment proxy (same address on every EVM chain) and the factory's salt + init code. */
export const DETERMINISTIC_PROXY = artifacts.proxy as Address;
export const FACTORY_SALT = artifacts.salt as Hex;
export const FACTORY_INIT_CODE = artifacts.factory.initCode as Hex;
/** Calldata that publishes the factory through the proxy. Anyone may send it; the result is the same address. */
export const FACTORY_PUBLISH_DATA: Hex = concatHex([FACTORY_SALT, FACTORY_INIT_CODE]);

/** Mirrors AegisCCHSFactory.predict; no RPC needed. */
export function predictAccount(root: Hex, recRoot: Hex, variant: Variant): Address {
  const creation = (variant === 'S' ? artifacts.account.S.creationCode : artifacts.account.K.creationCode) as Hex;
  const initCode = concatHex([creation, encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }], [root, recRoot])]);
  const salt = keccak256(concatHex([root, recRoot, variant === 'S' ? '0x01' : '0x00']));
  return getContractAddress({ opcode: 'CREATE2', from: FACTORY_ADDRESS, salt, bytecode: initCode });
}

// ------------------------------------------------------------ index discipline
//
// A WOTS+ leaf signs exactly one message. The chain enforces monotonic use
// per lane (`idx >= nextIdx(lane)`), but it cannot see a signature that was
// produced and never landed. So the client keeps a write-ahead record of the
// highest index it has signed per (chain, account, epoch, lane), and never
// signs the same index twice: the next signature uses
// max(nextIdx(lane) on chain, highest signed + 1). A leaf whose transaction
// was dropped is simply abandoned.
//
// Lanes. The contract splits the 2^20 leaves into 16 lanes of 65 536 by the
// top four bits of the index, each with its own nextIdx and nonce. A device
// owns one lane (`deviceLane`), so several devices sign concurrently without
// any coordination: the chain keeps every lane monotone, and a transaction of
// one lane never changes the nonce of another. Two devices must not share a
// lane (that is the partition rule of CCHS.spec.md §4.3 made explicit); the
// lane is chosen once per device and shown in the UI.
//
// If the record is missing while the lane has already been used
// (nextIdx(lane) above the lane's first leaf), this device cannot know which
// leaves a previous copy of the record covered, and a dropped transaction may
// still be sitting in a mempool with a leaf above nextIdx. The only complete
// answer is to leave the index space: perform a recovery (new epoch, keys
// derived from the chain key and the epoch number) and start a fresh record
// there. model/cchs-client.mjs shows that the weaker rule "wait until the pool
// drains" is not enough.
//
// Recovery messages are deterministic per (epoch, recNonce): the new roots are
// a pure function of the master and the next epoch, so re-signing a dropped
// recovery produces the same message, never a second one under the same
// recovery leaf. The recovery leaf is still recorded before signing.

export const LANE_BITS = 4;
export const LANES = 1 << LANE_BITS;
export const LANE_SHIFT = 2 * 10 - LANE_BITS; // 2H − LANE_BITS = 16
/** First leaf index of a lane. */
export const laneFirst = (lane: number) => lane << LANE_SHIFT;
/** Lane of a leaf index. */
export const laneOf = (idx: number) => idx >> LANE_SHIFT;

const LANE_KEY = 'aegis/cchs/device-lane';
/** The lane this device signs in (0 unless the user assigned another one for a second device). */
export function deviceLane(): number {
  const v = Number(globalThis.localStorage?.getItem(LANE_KEY) ?? 0);
  return Number.isInteger(v) && v >= 0 && v < LANES ? v : 0;
}
export function setDeviceLane(lane: number): void {
  if (!Number.isInteger(lane) || lane < 0 || lane >= LANES) throw new Error(`lane must be in [0, ${LANES})`);
  globalThis.localStorage?.setItem(LANE_KEY, String(lane));
}

const idxKey = (chainId: number, account: Address, epoch: number, lane: number) =>
  `aegis/cchs/signed/${chainId}/${account.toLowerCase()}/${epoch}${lane ? `/lane/${lane}` : ''}`;
const recKey = (chainId: number, account: Address) => `aegis/cchs/rec-signed/${chainId}/${account.toLowerCase()}`;

/** Highest leaf index this device has ever signed for the account in `epoch` and `lane`, or null if no record exists. */
export function highestSignedIndex(chainId: number, account: Address, epoch: number, lane = 0): number | null {
  const v = globalThis.localStorage?.getItem(idxKey(chainId, account, epoch, lane));
  return v === null || v === undefined ? null : Number(v);
}

/**
 * True when this device must not sign in `lane` under the current epoch: the
 * lane has been used (nextIdx above its first leaf) but this device holds no
 * record for it.
 */
export function recordMissing(chainId: number, account: Address, epoch: number, onchainNext: bigint, lane = 0): boolean {
  return onchainNext > BigInt(laneFirst(lane)) && highestSignedIndex(chainId, account, epoch, lane) === null;
}

/** Index to sign next in `lane`: never below the chain's `nextIdx(lane)`, never one this device used, never outside the lane. */
export function nextSigningIndex(chainId: number, account: Address, epoch: number, onchainNext: bigint, lane = 0): number {
  const rec = highestSignedIndex(chainId, account, epoch, lane);
  const idx = Math.max(Number(onchainNext), (rec ?? -1) + 1, laneFirst(lane));
  if (laneOf(idx) !== lane) throw new Error(`lane ${lane} is exhausted`);
  return idx;
}

/** Record `idx` as used. Call before producing the signature, not after. */
export function markIndexSigned(chainId: number, account: Address, epoch: number, idx: number, lane = 0): void {
  const rec = highestSignedIndex(chainId, account, epoch, lane);
  if (rec === null || idx > rec) globalThis.localStorage?.setItem(idxKey(chainId, account, epoch, lane), String(idx));
}

/** Highest recovery nonce this device has signed for the account, or -1. */
export function highestRecoverySigned(chainId: number, account: Address): number {
  const v = globalThis.localStorage?.getItem(recKey(chainId, account));
  return v === null || v === undefined ? -1 : Number(v);
}
/** Record recovery leaf `recNonce` as used. Call before producing the signature. */
export function markRecoverySigned(chainId: number, account: Address, recNonce: number): void {
  if (recNonce > highestRecoverySigned(chainId, account)) globalThis.localStorage?.setItem(recKey(chainId, account), String(recNonce));
}

const EPOCH_INFO = new TextEncoder().encode('aegis/cchs/epoch/v1');
/**
 * Signing key of `epoch` on one chain. Epoch 0 is the chain key itself; epoch
 * e > 0 is HKDF-SHA256(chainKey, info = "aegis/cchs/epoch/v1" ‖ e as 8-byte BE, 32).
 * Distinct per epoch, so a WOTS+ secret value is never reused across epochs.
 */
export function epochKey(chain: CchsKey, epoch: number): CchsKey {
  if (epoch === 0) return chain;
  const info = new Uint8Array(EPOCH_INFO.length + 8);
  info.set(EPOCH_INFO, 0);
  new DataView(info.buffer).setBigUint64(EPOCH_INFO.length, BigInt(epoch));
  return { master: hkdf(sha256, chain.master, undefined, info, 32) };
}

/** The K-20 tree of one EVM chain at epoch 0 and the account address it fixes there. */
export interface ChainIdentity {
  chainId: number;
  key: CchsKey;
  root: Hex;
  recRoot: Hex;
  address: Address;
  /** Trees built so far for this chain's epoch-0 key, as used by `sign`. */
  trees: Map<string, Tree>;
  tookMs: number;
}

export interface CchsIdentity {
  master: CchsKey;
  /** One entry per EVM chain derived so far. */
  evm: Map<number, ChainIdentity>;
}

/**
 * K-20 tree of one EVM chain via the worker pool: top tree and recovery tree
 * (the first bottom subtree is built when the first signature needs it).
 */
export async function deriveChainIdentity(master: CchsKey, chainId: number, pool: CchsPool): Promise<ChainIdentity> {
  const key = chainKey(master, evmChainTag(chainId));
  const trees = new Map<string, Tree>();
  const t0 = performance.now();
  const pub = await pool.keygen(key, 'K', trees, { firstSubtree: false });
  const root = toHex(pub.root) as Hex, recRoot = toHex(pub.recRoot) as Hex;
  return { chainId, key, root, recRoot, address: predictAccount(root, recRoot, 'K'), trees, tookMs: performance.now() - t0 };
}
