// Bitcoin transactions for the CCHS-UTXO account: serialization, txid, weight,
// the BIP-341 script-path sighash (SIGHASH_DEFAULT, no annex), bech32m
// addresses, and the transaction-binding Schnorr signature of btcCchs.ts
// (private key 1: public by construction, carries no authority).

import { sha256 } from '@noble/hashes/sha256';
import { schnorr } from '@noble/curves/secp256k1';
import { concatBytes, hexToBytes } from '@noble/hashes/utils';
import { bech32, bech32m } from '@scure/base';
import { tagged, tapLeafHash } from './btcTapscript';
import type { Binding } from './btcCchs';

export interface TxIn { txid: Uint8Array; vout: number; sequence: number; witness: Uint8Array[] }
export interface TxOut { value: bigint; scriptPubKey: Uint8Array }
export interface Tx { version: number; locktime: number; vin: TxIn[]; vout: TxOut[] }
/** What the sighash needs about each spent output. */
export interface Prevout { value: bigint; scriptPubKey: Uint8Array }

const le32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const le64 = (n: bigint) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n, true); return b; };
export function compactSize(n: number): Uint8Array {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
  return concatBytes(Uint8Array.of(0xfe), le32(n));
}
const varBytes = (b: Uint8Array) => concatBytes(compactSize(b.length), b);
const dsha = (b: Uint8Array) => sha256(sha256(b));

/** Internal byte order (little-endian), as hashed and serialized. */
export const txidFromHex = (h: string) => hexToBytes(h).reverse();
export const txidToHex = (b: Uint8Array) => Array.from(b.slice().reverse(), x => x.toString(16).padStart(2, '0')).join('');

function serializeOutpoint(i: TxIn) { return concatBytes(i.txid, le32(i.vout)); }
function serializeOutput(o: TxOut) { return concatBytes(le64(o.value), varBytes(o.scriptPubKey)); }

export function serialize(tx: Tx, withWitness: boolean): Uint8Array {
  const parts: Uint8Array[] = [le32(tx.version)];
  const hasWitness = withWitness && tx.vin.some(i => i.witness.length > 0);
  if (hasWitness) parts.push(Uint8Array.of(0x00, 0x01));
  parts.push(compactSize(tx.vin.length));
  for (const i of tx.vin) parts.push(serializeOutpoint(i), compactSize(0), le32(i.sequence));
  parts.push(compactSize(tx.vout.length));
  for (const o of tx.vout) parts.push(serializeOutput(o));
  if (hasWitness) for (const i of tx.vin) {
    parts.push(compactSize(i.witness.length));
    for (const w of i.witness) parts.push(varBytes(w));
  }
  parts.push(le32(tx.locktime));
  return concatBytes(...parts);
}

export const txid = (tx: Tx) => dsha(serialize(tx, false));
export function weight(tx: Tx): number {
  const base = serialize(tx, false).length, total = serialize(tx, true).length;
  return base * 3 + total;
}
export const vsize = (tx: Tx) => Math.ceil(weight(tx) / 4);

/**
 * BIP-341 sighash for a script-path spend of input `index` with
 * SIGHASH_DEFAULT, ext_flag = 1, no annex, key_version 0, no OP_CODESEPARATOR.
 */
export function sighashScriptPath(tx: Tx, prevouts: Prevout[], index: number, leafScript: Uint8Array): Uint8Array {
  const shaPrevouts = sha256(concatBytes(...tx.vin.map(serializeOutpoint)));
  const shaAmounts = sha256(concatBytes(...prevouts.map(p => le64(p.value))));
  const shaScriptPubKeys = sha256(concatBytes(...prevouts.map(p => varBytes(p.scriptPubKey))));
  const shaSequences = sha256(concatBytes(...tx.vin.map(i => le32(i.sequence))));
  const shaOutputs = sha256(concatBytes(...tx.vout.map(serializeOutput)));
  const msg = concatBytes(
    Uint8Array.of(0x00),                 // sighash epoch
    Uint8Array.of(0x00),                 // hash_type = SIGHASH_DEFAULT
    le32(tx.version), le32(tx.locktime),
    shaPrevouts, shaAmounts, shaScriptPubKeys, shaSequences, shaOutputs,
    Uint8Array.of(0x02),                 // spend_type = ext_flag·2 + annex(0)
    le32(index),
    tapLeafHash(leafScript),
    Uint8Array.of(0x00),                 // key_version
    le32(0xffffffff),                    // codesep_pos
  );
  return tagged('TapSighash', msg);
}

/** The binding triple for a sighash: Schnorr signature under the public key of d = 1. */
export const BINDING_SK = (() => { const b = new Uint8Array(32); b[31] = 1; return b; })();
export const BINDING_PK = schnorr.getPublicKey(BINDING_SK);
export function bindingFor(m: Uint8Array): Binding {
  return { sig: schnorr.sign(m, BINDING_SK), m, P: BINDING_PK };
}

export type Network = 'regtest' | 'signet';
const HRP: Record<Network, string> = { regtest: 'bcrt', signet: 'tb' };

/** bech32m address of a witness-v1 program. */
export function p2trAddress(scriptPubKey: Uint8Array, net: Network): string {
  if (scriptPubKey.length !== 34 || scriptPubKey[0] !== 0x51 || scriptPubKey[1] !== 0x20) throw new Error('not P2TR');
  return bech32m.encode(HRP[net], [1, ...bech32m.toWords(scriptPubKey.subarray(2))], 90);
}

/** scriptPubKey of a bech32 (v0) or bech32m (v1+) address. */
export function scriptPubKeyOf(address: string): Uint8Array {
  const lower = address.toLowerCase() as `${string}1${string}`;
  let words: number[];
  try {
    words = [...bech32m.decode(lower, 90).words];
    if (words[0] === 0) throw new Error('v0 must use bech32');
  } catch {
    words = [...bech32.decode(lower, 90).words];
    if (words[0] !== 0) throw new Error('bad address encoding');
  }
  const version = words.shift()!;
  const prog = bech32m.fromWords(words);
  return concatBytes(Uint8Array.of(version === 0 ? 0x00 : 0x50 + version, prog.length), prog);
}
