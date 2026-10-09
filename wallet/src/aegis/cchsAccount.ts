// One identity, every chain.
//
//   mnemonic ─BIP-39─▶ seed ─HKDF-SHA256("aegis/cchs/master/v1")─▶ 32-byte CCHS master
//   master ─▶ CCHS-K-20 (root, recRoot)   → EVM account address (same on every EVM chain)
//   master ─▶ CCHS-S-20 (root, recRoot)   → every non-EVM verifier
//
// The EVM address is a pure function of the K-20 roots and the factory init
// code, so it is known before anything is deployed on any chain.

import { mnemonicToSeedSync } from '@scure/bip39';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { concatHex, encodeAbiParameters, getContractAddress, keccak256, type Address, type Hex } from 'viem';
import type { CchsKey, Tree, Variant } from './cchs';
import { toHex } from './cchs';
import { CchsPool } from './cchsPool';
import artifacts from './cchsArtifacts.json';

const MASTER_INFO = new TextEncoder().encode('aegis/cchs/master/v1');

export function cchsMaster(mnemonic: string, passphrase = ''): CchsKey {
  const seed = mnemonicToSeedSync(mnemonic.trim(), passphrase);
  return { master: hkdf(sha256, seed, undefined, MASTER_INFO, 32) };
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
// (`idx >= nextIdx`), but it cannot see a signature that was produced and
// never landed. So the client keeps a write-ahead record of the highest index
// it has signed per (chain, account), and never signs the same index twice:
// the next signature uses max(nextIdx on chain, highest signed + 1). A leaf
// whose transaction was dropped is simply abandoned. If this record is lost
// (new device), wait for any in-flight transaction to settle before signing.

const idxKey = (chainId: number, account: Address) => `aegis/cchs/signed/${chainId}/${account.toLowerCase()}`;

/** Highest leaf index this device has ever signed for the account, or -1. */
export function highestSignedIndex(chainId: number, account: Address): number {
  const v = globalThis.localStorage?.getItem(idxKey(chainId, account));
  return v === null || v === undefined ? -1 : Number(v);
}

/** Index to sign next: never below the chain's `nextIdx`, never one this device used. */
export function nextSigningIndex(chainId: number, account: Address, onchainNext: bigint): number {
  return Math.max(Number(onchainNext), highestSignedIndex(chainId, account) + 1);
}

/** Record `idx` as used. Call before producing the signature, not after. */
export function markIndexSigned(chainId: number, account: Address, idx: number): void {
  if (idx > highestSignedIndex(chainId, account)) globalThis.localStorage?.setItem(idxKey(chainId, account), String(idx));
}

export interface CchsIdentity {
  master: CchsKey;
  k: { root: Hex; recRoot: Hex; address: Address };
  s: { root: Hex; recRoot: Hex };
  /** Trees needed for the first signature on each set; keys as used by `sign`. */
  trees: { K: Map<string, Tree>; S: Map<string, Tree> };
  tookMs: number;
}

/** Full identity via the worker pool. ~1.5 s on a 6-core machine for both sets. */
export async function deriveCchsIdentity(mnemonic: string, pool: CchsPool, passphrase = ''): Promise<CchsIdentity> {
  const master = cchsMaster(mnemonic, passphrase);
  const trees = { K: new Map<string, Tree>(), S: new Map<string, Tree>() };
  const t0 = performance.now();
  const [k, s] = await Promise.all([
    pool.keygen(master, 'K', trees.K),
    pool.keygen(master, 'S', trees.S, { firstSubtree: false }),
  ]);
  const kRoot = toHex(k.root), kRec = toHex(k.recRoot);
  return {
    master,
    k: { root: kRoot, recRoot: kRec, address: predictAccount(kRoot, kRec, 'K') },
    s: { root: toHex(s.root), recRoot: toHex(s.recRoot) },
    trees,
    tookMs: performance.now() - t0,
  };
}
