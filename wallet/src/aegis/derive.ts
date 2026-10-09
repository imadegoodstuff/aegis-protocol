// Aegis — client-side identity derivation.
//
// MATCHES core/src/lib.rs byte-for-byte:
//   seed  = BIP-39 PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048)
//   pq_pk = HKDF-SHA512(seed, info="aegis/sphincs+/192s/v1", 48+96)[..48]  (STUB)
//   pq_sk = HKDF-SHA512(seed, info="aegis/sphincs+/192s/v1", 48+96)[48..]  (STUB)
//   ecdsa_sk = HKDF-SHA512(seed, info="aegis/ecdsa/fallback/v1", 32)
//   ed25519_sk = HKDF-SHA512(seed, info="aegis/ed25519/v1", 32)
//
// Per-chain address derivations — STANDARD mainnet schemes.
// Each address below is a REAL mainnet address that can be imported into the
// chain's native wallet (Phantom, Keplr, Petra, Sui Wallet, etc.) and used
// to send/receive on mainnet TODAY. The PQ smart-account layer is a separate
// upgrade that deploys per-chain and the user migrates funds into when ready.
//
//   EVM       keccak256(secp256k1_uncompressed_pk[1:])[12:]       (EIP-55)
//   TRON      base58check(0x41 || keccak256(secp256k1_uncompressed_pk[1:])[12:])
//   Solana    base58(ed25519_pk)                                   (native)
//   Cosmos    bech32(prefix, ripemd160(sha256(secp256k1_compressed_pk)))  — standard
//   Injective bech32("inj", keccak256(secp256k1_uncompressed_pk[1:])[12:])  — Ethermint
//   NEAR      hex(ed25519_pk)                                      (implicit account)
//   Aptos     hex(sha3_256(ed25519_pk || 0x00))                    (ed25519 scheme byte)
//   Sui       hex(blake2b_256(0x00 || ed25519_pk))                 (ed25519 flag byte)
//   TON       hex(sha256(ed25519_pk))                              (preview; real = StateInit hash)
//   Bitcoin   bc1q + bech32(hash160(secp256k1_compressed_pk))      (BIP-84 P2WPKH)
//   Starknet  stub (requires Argent/Braavos account factory; see cairo/ roadmap)
//
// Uses the audited @noble suite (zero-dep).

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { keccak_256 } from "@noble/hashes/sha3";
import { sha3_256 } from "@noble/hashes/sha3";
import { blake2b } from "@noble/hashes/blake2b";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { secp256k1 } from "@noble/curves/secp256k1";
import { ed25519 } from "@noble/curves/ed25519";
import { bech32 } from "@scure/base";
// REAL FIPS 205 SLH-DSA (SPHINCS+) — @noble/post-quantum, audited
import { slh_dsa_shake_192s } from "@noble/post-quantum/slh-dsa";

export type Derived = {
  pqPkHex:         string;     // 96 hex chars (48 B SPHINCS+ pk stub)
  pqPkHashHex:     string;     // 64 hex chars (32 B keccak256(pq_pk))

  // EVM (same address across 30+ chains)
  evmAddress:      string;     // 0x…40 chars, EIP-55 checksummed

  // TRON — same 20B as EVM, different encoding
  tronBase58:      string;     // T… (34 chars)
  tronRawHex:      string;     // 0x41 || keccak256(ecdsa_pk[1:])[12:]

  // Cosmos family — bech32(prefix, sha256(pq_pk)[:20])
  cosmosOsmo:      string;     // osmo1…
  cosmosInj:       string;     // inj1…
  cosmosNeutron:   string;     // neutron1…
  cosmosJuno:      string;     // juno1…
  cosmosStargaze:  string;     // stars1…

  // Solana (SVM) — ed25519 pubkey as base58
  solanaAddress:   string;     // 32-44 chars base58

  // NEAR implicit account — hex(sha256(pq_pk))
  nearImplicit:    string;     // 64 hex chars

  // Aptos — hex(sha3_256(pq_pk || 0xFE))
  aptosAddress:    string;     // 0x + 64 hex chars

  // Sui — hex(blake2b_256(0xFE || pq_pk))
  suiAddress:      string;     // 0x + 64 hex chars

  // TON — preview address = hex(sha256(pq_pk))[:48]; real deploy = hash(StateInit)
  tonPreview:      string;

  // Bitcoin — BIP-84 P2WPKH (SegWit v0, bc1q…). BIP-360 P2MR pending activation.
  btcSegwit:       string;     // bc1q…
};

const SPHINCS_INFO = new TextEncoder().encode("aegis/sphincs+/192s/v1");
const ECDSA_INFO   = new TextEncoder().encode("aegis/ecdsa/fallback/v1");
const ED25519_INFO = new TextEncoder().encode("aegis/ed25519/v1");

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

/** Entropy behind a BIP-39 mnemonic: 11 bits per word, of which 1/33 is checksum (12 words → 128, 24 → 256). */
export function mnemonicEntropyBits(mnemonic: string): number {
  const words = mnemonic.trim().split(/\s+/).filter(Boolean).length;
  return Math.floor((words * 11 * 32) / 33);
}

/** The seed entropy below which a CCHS account is weaker than its signatures (CCHS.spec.md §5.6, path P4). */
export const CCHS_MIN_SEED_BITS = 256;

/** Full identity including the real SLH-DSA secret key (never leaves this closure's return). */
export type Identity = Derived & {
  // Private material — only exposed by `identity()`; `derive()` strips it.
  slhSecretKey: Uint8Array;    // 96 B SLH-DSA-SHAKE-192s secret key (seed/prf/root)
  slhPublicKey: Uint8Array;    // 48 B SLH-DSA-SHAKE-192s public key (seed/root)
  ed25519SecretKey: Uint8Array;
  ecdsaSecretKey: Uint8Array;
};

/** Compute the full identity (incl. secret keys). Use this ONLY in-browser. */
export function identity(mnemonic: string, passphrase = ""): Identity {
  const seed = mnemonicToSeedSync(mnemonic.trim(), passphrase);

  // --- REAL FIPS 205 SLH-DSA-SHAKE-192s keypair ---
  // SLH-DSA keygen takes a 72-byte deterministic seed (3 * n for n=24 bytes).
  // We expand our BIP-39 seed into 72 bytes via HKDF-SHA512 and feed it in.
  const slhSeed = hkdf(sha512, seed, undefined, SPHINCS_INFO, 72);
  const { secretKey: slhSk, publicKey: slhPk } = slh_dsa_shake_192s.keygen(slhSeed);

  const d = _deriveFromKeys(slhPk, seed);
  return {
    ...d.derived,
    slhSecretKey: slhSk,
    slhPublicKey: slhPk,
    ed25519SecretKey: d.edSk,
    ecdsaSecretKey: d.ecdsaSk,
  };
}

/** Address-only derivation (safe to log, no secret material). */
export function derive(mnemonic: string, passphrase = ""): Derived {
  const seed = mnemonicToSeedSync(mnemonic.trim(), passphrase);
  const slhSeed = hkdf(sha512, seed, undefined, SPHINCS_INFO, 72);
  const { publicKey: slhPk } = slh_dsa_shake_192s.keygen(slhSeed);
  return _deriveFromKeys(slhPk, seed).derived;
}

/** Produce a REAL SLH-DSA-SHAKE-192s signature over `digest`. Returns 16,224 bytes. */
export function pqSign(id: Identity, digest: Uint8Array): Uint8Array {
  // noble's `sign(sk, msg)` is deterministic unless `addRand` is passed.
  return slh_dsa_shake_192s.sign(id.slhSecretKey, digest);
}

/** Verify a SLH-DSA-SHAKE-192s signature. */
export function pqVerify(publicKey: Uint8Array, digest: Uint8Array, signature: Uint8Array): boolean {
  try { return slh_dsa_shake_192s.verify(publicKey, digest, signature); }
  catch { return false; }
}

function _deriveFromKeys(slhPk: Uint8Array, seed: Uint8Array): { derived: Derived; edSk: Uint8Array; ecdsaSk: Uint8Array } {
  const pqPk = slhPk;  // 48 bytes, real FIPS 205 SLH-DSA-SHAKE-192s public key

  // --- ECDSA fallback (secp256k1) — used by EVM, TRON, Bitcoin ---
  const ecdsaSk = hkdf(sha512, seed, undefined, ECDSA_INFO, 32);
  const ecdsaPkUncompressed = secp256k1.getPublicKey(ecdsaSk, false); // 65 B (0x04 || X || Y)
  const ecdsaPkCompressed   = secp256k1.getPublicKey(ecdsaSk, true);  // 33 B (02/03 || X)

  // --- Ed25519 (Solana) ---
  const edSk = hkdf(sha512, seed, undefined, ED25519_INFO, 32);
  const edPk = ed25519.getPublicKey(edSk); // 32 B

  // --- EVM: keccak256(pk[1:])[12:] with EIP-55 checksum ---
  const evm20 = keccak_256(ecdsaPkUncompressed.slice(1)).slice(12);
  const evmAddress = toChecksumAddr(evm20);

  // --- TRON: 0x41 || same 20B, then base58check ---
  const tronRaw = new Uint8Array(21);
  tronRaw[0] = 0x41;
  tronRaw.set(evm20, 1);
  const tronBase58 = base58check(tronRaw);

  // --- Cosmos secp256k1 family (standard): ripemd160(sha256(compressed_pk)) ---
  // Importable to Keplr via "Add account via private key" using ecdsaSk.
  const cosmosHash = ripemd160(sha256(ecdsaPkCompressed));
  const cosmosWords = bech32.toWords(cosmosHash);
  const cosmosOsmo     = bech32.encode("osmo", cosmosWords);
  const cosmosNeutron  = bech32.encode("neutron", cosmosWords);
  const cosmosJuno     = bech32.encode("juno", cosmosWords);
  const cosmosStargaze = bech32.encode("stars", cosmosWords);

  // --- Injective (Ethermint style): keccak256(uncompressed_pk[1:])[12:] bech32-encoded
  // Importable to Keplr with EVM-compatible derivation path.
  const injHash20 = keccak_256(ecdsaPkUncompressed.slice(1)).slice(12);
  const cosmosInj = bech32.encode("inj", bech32.toWords(injHash20));

  // --- Solana: raw ed25519 pubkey base58-encoded (standard) ---
  const solanaAddress = base58encode(edPk);

  // --- NEAR implicit account: hex(ed25519_pk) — the pk IS the account id ---
  // Importable to near-cli / NEAR Wallet.
  const nearImplicit = hexOf(edPk);

  // --- Aptos: sha3_256(ed25519_pk || 0x00) — 0x00 = ed25519 single-key scheme byte (standard) ---
  // Importable to Petra Wallet.
  const aptosRaw = new Uint8Array(edPk.length + 1);
  aptosRaw.set(edPk);
  aptosRaw[edPk.length] = 0x00;
  const aptosAddress = "0x" + hexOf(sha3_256(aptosRaw));

  // --- Sui: blake2b_256(0x00 || ed25519_pk) — 0x00 = ed25519 flag byte (standard) ---
  // Importable to Sui Wallet.
  const suiRaw = new Uint8Array(1 + edPk.length);
  suiRaw[0] = 0x00;
  suiRaw.set(edPk, 1);
  const suiAddress = "0x" + hexOf(blake2b(suiRaw, { dkLen: 32 }));

  // --- TON: hex(sha256(ed25519_pk)) — preview. Real wallet address requires
  //     computing hash(StateInit) over the Wallet v4R2 code + initial data cell,
  //     which needs ~50KB of @ton/core. We ship the preview hash here; a user
  //     who wants the actual mainnet TON wallet address uses tonkeeper's
  //     "Import by private key" flow with ed25519SecretKey from this seed.
  const tonPreview = "pubkey: " + hexOf(edPk);

  // --- Bitcoin BIP-84 P2WPKH: bc1q + hash160(ecdsa_compressed) ---
  // Note: this is the SegWit v0 address. BIP-360 P2MR (post-quantum) is pending activation.
  const h160 = ripemd160(sha256(ecdsaPkCompressed));
  const btcWords = bech32.toWords(h160);
  const btcSegwit = bech32.encode("bc", [0, ...btcWords]);

  // keccak256(pq_pk) commitment used by EVM factory
  const pqPkHash = keccak_256(pqPk);

  return {
    derived: {
      pqPkHex:        hexOf(pqPk),
      pqPkHashHex:    hexOf(pqPkHash),
      evmAddress,
      tronBase58,
      tronRawHex:     "0x" + hexOf(tronRaw),
      cosmosOsmo,
      cosmosInj,
      cosmosNeutron,
      cosmosJuno,
      cosmosStargaze,
      solanaAddress,
      nearImplicit,
      aptosAddress,
      suiAddress,
      tonPreview,
      btcSegwit,
    },
    edSk,
    ecdsaSk,
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
