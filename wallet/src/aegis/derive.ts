// Aegis — client-side identity derivation.
//
// MATCHES core/src/lib.rs byte-for-byte:
//   seed  = BIP-39 PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048)
//   pq_pk = HKDF-SHA512(seed, info="aegis/sphincs+/192s/v1", 48+96)[..48]
//   pq_sk = HKDF-SHA512(seed, info="aegis/sphincs+/192s/v1", 48+96)[48..]  (STUB)
//   ecdsa_sk = HKDF-SHA512(seed, info="aegis/ecdsa/fallback/v1", 32)
//
// Address derivations (keep in sync with core::addr::*):
//   evm       = keccak256(ecdsa_pubkey_uncompressed[1:])[12:]      (20B)
//   cosmos    = sha256(pq_pk)[:20]                                 (20B, bech32-ready)
//   near      = hex(sha256(pq_pk))                                 (64 chars)
//   tron_raw  = 0x41 || keccak256(ecdsa_pk[1:])[12:]               (21B)
//
// This module uses the audited @noble suite (zero-dep).

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { keccak_256 } from "@noble/hashes/sha3";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bech32 } from "@scure/base";

export type Derived = {
  pqPkHex: string;             // 96 hex chars (48 B)
  pqPkHashHex: string;         // 64 hex chars (32 B keccak256(pk))
  evmAddress: string;          // 0x…40 chars (EIP-55 checksummed)
  cosmosOsmo: string;          // bech32 osmo1…
  cosmosInj: string;           // bech32 inj1…
  cosmosNeutron: string;       // bech32 neutron1…
  nearImplicit: string;        // 64 hex chars (NEAR implicit account id)
  tronRawHex: string;          // 42 hex chars (0x41 || …)
  tronBase58: string;          // T… (34 chars)
};

const SPHINCS_INFO = new TextEncoder().encode("aegis/sphincs+/192s/v1");
const ECDSA_INFO   = new TextEncoder().encode("aegis/ecdsa/fallback/v1");

function hexOf(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** EIP-55 checksum for 20-byte address (returns 0x-prefixed string). */
function toChecksumAddr(addr20: Uint8Array): string {
  const lower = hexOf(addr20);
  const hash  = hexOf(keccak_256(new TextEncoder().encode(lower)));
  let out = "0x";
  for (let i = 0; i < lower.length; i++) {
    out += parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

/** base58check for TRON (version-byte 0x41 is included in `raw21`). */
function base58check(raw21: Uint8Array): string {
  // double-sha256 checksum (first 4 bytes)
  const d1 = sha256(raw21);
  const d2 = sha256(d1);
  const full = new Uint8Array(raw21.length + 4);
  full.set(raw21, 0);
  full.set(d2.slice(0, 4), raw21.length);
  return base58encode(full);
}
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  let s = "";
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b === 0) s = "1" + s; else break; }
  return s;
}

export function isValidMnemonic(mnemonic: string): boolean {
  try { return validateMnemonic(mnemonic.trim(), wordlist); } catch { return false; }
}

export function derive(mnemonic: string, passphrase = ""): Derived {
  const seed = mnemonicToSeedSync(mnemonic.trim(), passphrase);

  // SPHINCS+ material (stub pk)
  const sphincsBytes = hkdf(sha512, seed, undefined, SPHINCS_INFO, 48 + 96);
  const pqPk = sphincsBytes.slice(0, 48);

  // ECDSA fallback
  const ecdsaSk = hkdf(sha512, seed, undefined, ECDSA_INFO, 32);
  const ecdsaPkUncompressed = secp256k1.getPublicKey(ecdsaSk, false); // 65 B incl. 0x04 prefix

  // EVM address: keccak256(pk[1:])[12:]
  const evm20 = keccak_256(ecdsaPkUncompressed.slice(1)).slice(12);
  const evmAddress = toChecksumAddr(evm20);

  // Cosmos: sha256(pq_pk)[:20], bech32-encoded per chain
  const cosmos20 = sha256(pqPk).slice(0, 20);
  const words = bech32.toWords(cosmos20);
  const cosmosOsmo    = bech32.encode("osmo", words);
  const cosmosInj     = bech32.encode("inj",  words);
  const cosmosNeutron = bech32.encode("neutron", words);

  // NEAR implicit account: hex(sha256(pq_pk))
  const nearImplicit = hexOf(sha256(pqPk));

  // TRON raw 21B + base58check
  const tronRaw = new Uint8Array(21);
  tronRaw[0] = 0x41;
  tronRaw.set(keccak_256(ecdsaPkUncompressed.slice(1)).slice(12), 1);
  const tronBase58 = base58check(tronRaw);

  // keccak256(pq_pk) commitment used by EVM factory
  const pqPkHash = keccak_256(pqPk);

  return {
    pqPkHex:        hexOf(pqPk),
    pqPkHashHex:    hexOf(pqPkHash),
    evmAddress,
    cosmosOsmo,
    cosmosInj,
    cosmosNeutron,
    nearImplicit,
    tronRawHex:     "0x" + hexOf(tronRaw),
    tronBase58,
  };
}

/** Factory CREATE2 account-address prediction for the EVM path. */
export function predictEvmAccountAddress(opts: {
  factory: string;            // 0x…
  pqPk: Uint8Array;           // the same 48-byte stub pk
  guardian: string;           // 0x…
  ecdsaOwner: string;         // 0x…
  accountInitCodeHash: string;// 0x… 32B
}): string {
  const factory = hexToBytes(opts.factory);
  const pqPkHash = keccak_256(opts.pqPk);
  const guardian20 = hexToBytes(opts.guardian);
  const owner20    = hexToBytes(opts.ecdsaOwner);

  const salt_in = new Uint8Array(32 + 32 + 32 + 32);
  // abi.encode("AEGIS_V1" right-padded to 32, pq_pk_hash, guardian, owner)
  salt_in.set(new TextEncoder().encode("AEGIS_V1"), 0);
  salt_in.set(pqPkHash, 32);
  salt_in.set(leftPad32(guardian20), 64);
  salt_in.set(leftPad32(owner20),    96);
  const salt = keccak_256(salt_in);

  const buf = new Uint8Array(1 + 20 + 32 + 32);
  buf[0] = 0xff;
  buf.set(factory, 1);
  buf.set(salt, 21);
  buf.set(hexToBytes(opts.accountInitCodeHash), 53);
  const digest = keccak_256(buf);
  return toChecksumAddr(digest.slice(12));
}

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
function leftPad32(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}
