// TRON (TVM) addresses for CCHS accounts.
//
// The TVM runs the same account and factory bytecode as the EVM build
// (tron/build.mjs verifies the init code is byte-identical to cchsArtifacts.json),
// but two things differ at the address layer:
//   1. CREATE2 uses prefix byte 0x41 instead of 0xff:
//        addr20 = keccak256(0x41 || sender20 || salt32 || keccak256(initCode))[12..32)
//   2. the deterministic-deployment proxy does not exist on TRON, so the factory
//      address is per publisher and must be supplied, not derived.
// Addresses leave the VM as 21 bytes (0x41 || addr20) and are shown base58check-encoded.
//
// Sources: https://developers.tron.network/docs/tvm-vs-evm,
//          https://developers.tron.network/docs/account

import { sha256 } from '@noble/hashes/sha256';
import { base58 } from '@scure/base';
import { concatHex, encodeAbiParameters, hexToBytes, bytesToHex, keccak256, type Address, type Hex } from 'viem';
import type { Variant } from './cchs';
import artifacts from './cchsArtifacts.json';

export const TRON_ADDRESS_PREFIX = 0x41;

/** Values returned by CHAINID inside the TVM; bound into every CCHS digest on that network. */
export const TRON_CHAIN_IDS = { mainnet: 728126428, shasta: 2494104990, nile: 3448148188 } as const;

export const TRON_FULL_HOSTS = {
  mainnet: 'https://api.trongrid.io',
  shasta: 'https://api.shasta.trongrid.io',
  nile: 'https://nile.trongrid.io',
} as const;

export interface TronAddress {
  /** 20-byte EVM-style hex, as used inside the ABI. */
  hex20: Address;
  /** 21-byte hex with the 0x41 prefix, as used by the TRON HTTP API. */
  hex21: string;
  /** base58check form shown by wallets and explorers ("T..."). */
  base58: string;
}

function raw21(addr20: Uint8Array): Uint8Array {
  const out = new Uint8Array(21);
  out[0] = TRON_ADDRESS_PREFIX;
  out.set(addr20, 1);
  return out;
}

/** base58check(0x41 || addr20): payload || sha256(sha256(payload))[0..4). */
export function toTronBase58(addr20: Hex | Uint8Array): string {
  const bytes = typeof addr20 === 'string' ? hexToBytes(addr20) : addr20;
  if (bytes.length !== 20) throw new Error('expected a 20-byte address');
  const payload = raw21(bytes);
  const check = sha256(sha256(payload)).subarray(0, 4);
  const full = new Uint8Array(25);
  full.set(payload);
  full.set(check, 21);
  return base58.encode(full);
}

/** Inverse of toTronBase58; verifies the checksum and prefix. */
export function fromTronBase58(address: string): Address {
  const full = base58.decode(address);
  if (full.length !== 25) throw new Error('TRON address must decode to 25 bytes');
  const payload = full.subarray(0, 21);
  const check = sha256(sha256(payload)).subarray(0, 4);
  if (bytesToHex(check) !== bytesToHex(full.subarray(21))) throw new Error('bad TRON address checksum');
  if (payload[0] !== TRON_ADDRESS_PREFIX) throw new Error('not a 0x41-prefixed TRON address');
  return bytesToHex(payload.subarray(1)) as Address;
}

/** Accepts "T...", "41<40 hex>" or "0x<40 hex>". */
export function parseTronAddress(input: string): Address {
  const s = input.trim();
  if (s.startsWith('T') && s.length === 34) return fromTronBase58(s);
  const h = s.replace(/^0x/i, '');
  if (h.length === 42 && h.toLowerCase().startsWith('41')) return `0x${h.slice(2)}` as Address;
  if (h.length === 40) return `0x${h}` as Address;
  throw new Error(`unrecognised TRON address '${input}'`);
}

export function formatTronAddress(addr20: Address): TronAddress {
  const bytes = hexToBytes(addr20);
  return { hex20: addr20, hex21: `41${bytesToHex(bytes).slice(2)}`, base58: toTronBase58(bytes) };
}

/** TRON CREATE2: keccak256(0x41 || sender || salt || keccak256(initCode))[12..]. */
export function tronCreate2(sender20: Address, salt: Hex, initCode: Hex): Address {
  const prefix: Hex = '0x41';
  const hash = keccak256(concatHex([prefix, sender20, salt, keccak256(initCode)]));
  return `0x${hash.slice(2 + 24)}` as Address;
}

/**
 * Counterfactual TRON address of the account for (root, recRoot, variant)
 * created by the factory at `tronFactory`. Mirrors AegisCCHSFactory.deploy;
 * the on-chain AegisCCHSFactory.predict uses 0xff and is wrong on TRON, so
 * never read it there.
 */
export function predictTronAccount(tronFactory: Address, root: Hex, recRoot: Hex, variant: Variant): TronAddress {
  const creation = (variant === 'S' ? artifacts.account.S.creationCode : artifacts.account.K.creationCode) as Hex;
  const initCode = concatHex([creation, encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }], [root, recRoot])]);
  const salt = keccak256(concatHex([root, recRoot, variant === 'S' ? '0x01' : '0x00']));
  return formatTronAddress(tronCreate2(tronFactory, salt, initCode));
}

/**
 * Address the factory would get if published through a CREATE2-capable
 * deployer contract on TRON. A factory published directly from a key gets a
 * CREATE address that depends on the transaction id and cannot be known in
 * advance; the publisher reports it (tron/deploy-factory.mjs).
 */
export function predictTronFactory(deployer20: Address, salt: Hex): TronAddress {
  return formatTronAddress(tronCreate2(deployer20, salt, artifacts.factory.initCode as Hex));
}
