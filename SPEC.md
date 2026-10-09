# Aegis Protocol Specification

Version 0.3 · 2026-10-08 · Draft

This document defines the Aegis account model, key and address derivation, and the two account contracts. The signature scheme used by hash-only accounts is specified separately in [`CCHS.spec.md`](CCHS.spec.md).

---

## 1. Terms

| Term | Definition |
|---|---|
| CCHS | Chain-Cached Hypertree Signatures, the hash-only authorization scheme (`CCHS.spec.md`) |
| `AegisCCHS` | Hash-only account: every operation is a CCHS signature |
| `AegisAccountV2` | Hybrid account: ECDSA for daily operations, post-quantum recovery path |
| SLH-DSA | FIPS 205 stateless hash-based signature (SPHINCS+), used by V2's recovery path |
| `MAX_FEE_BPS` | Hard protocol fee ceiling, `constant 2000` (20 %) |
| `PROTOCOL_FEE_BPS` | Current protocol fee, `constant 1000` (10 % of gas), immutable |

---

## 2. Key derivation

```
BIP-39 mnemonic (24 words, 256-bit entropy)
  └─ PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" ‖ passphrase, 2048) → 64-byte seed
       ├─ HKDF-SHA256(seed, "aegis/cchs/master/v1", 32)       → 32-byte CCHS master
       │    └─ HKDF-SHA256(master, "aegis/cchs/chain/v1" ‖ tag, 32) → CCHS key of one chain
       │         tag = 0x00 ‖ chainId (u64 BE) for EVM chains, 0x01 ‖ utf8(label) otherwise
       │         (epoch e ≥ 1 after recoveries: HKDF-SHA256(key, "aegis/cchs/epoch/v1" ‖ e, 32))
       ├─ HKDF-SHA512(seed, "aegis/sphincs+/192s/v1", 72)     → SLH-DSA-SHAKE-192s seed
       ├─ HKDF-SHA512(seed, "aegis/ecdsa/fallback/v1", 32)    → secp256k1 key (EVM, Cosmos, …)
       └─ HKDF-SHA512(seed, "aegis/ed25519/v1", 32)           → ed25519 key (Solana, Aptos, Sui, NEAR, TON)
```

(HKDF salt is empty in every case. Labels and hash functions match `wallet/src/aegis/derive.ts` and `cchsAccount.ts`.)

All CCHS secret material (every WOTS+ chain of every leaf of every tree) is derived lazily from the 32-byte master as specified in `CCHS.spec.md` §3: one key per chain, so that no one-time leaf exists on two chains (the chain id in the digest prevents replay, not reuse), and within a chain the same key feeds every parameter set under a distinct secret-key label per set (`cchs/sk` for `CCHS-S-20`, `cchs/sk/k` for `CCHS-K-20`, `cchs/sk/c` for `CCHS-C-20`) and the Bitcoin WOTS+ tree (key of label `bitcoin`, S-20 label, layer byte `0xb0`), so no secret value is hashed under two different functions. The client stores nothing else. `evm/test/fixtures/cchs-derivation.json` pins this derivation end to end for one mnemonic.

---

## 3. Address derivation

| Chain family | Scheme |
|---|---|
| EVM | `keccak256(secp256k1_uncompressed[1:])[12:]`, EIP-55 |
| Smart-account (EVM) | `CREATE2(factory, salt = keccak256(owner ‖ pqCommitment), initCodeHash)` — identical on every EVM chain given identical factory bytecode and deployer nonce |
| TRON | `base58check(0x41 ‖ evm_address)` |
| Cosmos SDK (secp256k1) | `bech32(prefix, ripemd160(sha256(compressed_pk)))` |
| Injective (Ethermint) | `bech32("inj", keccak256(uncompressed[1:])[12:])` |
| Solana | `base58(ed25519_pk)` |
| NEAR | `hex(ed25519_pk)` (implicit account) |
| Aptos | `sha3_256(ed25519_pk ‖ 0x00)` |
| Sui | `blake2b_256(0x00 ‖ ed25519_pk)` |
| Bitcoin | BIP-84 P2WPKH `bc1q…` (BIP-86 P2TR for the CCHS Tapscript design) |
| Starknet | `pedersen(classHash, pedersen(pqCommitment, salt))` |

Implementation: `wallet/src/aegis/derive.ts` (23 chains).

---

## 4. `AegisCCHS` — hash-only account

Specified in `CCHS.spec.md`. Summary of the on-chain interface:

```solidity
constructor(bytes32 root, bytes32 recRoot)

function execute(address target, uint256 value, bytes data,
                 uint64 idx, LayerSig l0) returns (bytes)                 // subtree cached
function executeFirst(address target, uint256 value, bytes data,
                 uint64 idx, LayerSig l0, LayerSig l1) returns (bytes)   // registers the subtree
function recover(bytes32 newRoot, bytes32 newRecRoot,
                 bytes32[67] wots, bytes32[8] auth)

function digestAt(uint64 idx, address target, uint256 value, bytes data) view returns (bytes32)
function needsTopLayerAt(uint64 idx) view returns (bool)
function nextDigest(address target, uint256 value, bytes data) view returns (bytes32)  // idx = nextIdx
function needsTopLayer() view returns (bool)

bytes32 root; bytes32 recRoot; uint64 epoch; uint64 nextIdx; uint64 nonce; uint64 recNonce;
mapping(uint256 => bytes32) cachedRoot;   // key = (epoch << 64) | bottomTreeIdx
```

`idx` is chosen by the signer: any `idx ≥ nextIdx` is accepted and `nextIdx` becomes `idx + 1` (`IndexUsed` otherwise). `executeFirst` on an already registered subtree ignores the redundant top layer.

Two contracts share this interface via `AegisCCHSBase`: `AegisCCHS` (`CCHS-S-20`, SHA-256) and `AegisCCHSK` (`CCHS-K-20`, keccak256, EVM default). Both: w = 16, 67 chains, two layers of height 10, 2^20 signatures, 256 recoveries.

`AegisCCHSFactory.deploy(root, recRoot, sha256Variant)` creates either with CREATE2, `salt = keccak256(root ‖ recRoot ‖ variant)`; `predict(...)` returns the address before deployment. The factory is at the same address on every EVM chain; the roots are per chain (CCHS.spec.md §3 derives one key tree per chain, because a one-time leaf must never sign on two chains), so the account address is per chain too, and still predictable offline.

No proxy, no `selfdestruct`, no setters, no owner.

---

## 5. `AegisAccountV2` — hybrid account

```solidity
contract AegisAccountV2 {
    address public ecdsaOwner;                 // rotatable only via pqRecover
    bytes32 public immutable PQ_PK_HASH;       // keccak256(SLH-DSA public key)
    ISphincsVerifier public immutable VERIFIER;
    address public immutable FEE_COLLECTOR;
    uint256 public constant MAX_FEE_BPS = 2000;
    uint256 public constant PROTOCOL_FEE_BPS = 1000;

    function execute(address target, uint256 value, bytes data) payable returns (bytes);
    function executeBatch(address[] targets, uint256[] values, bytes[] datas) payable;
    function pqRecover(address newOwner, bytes pqPk, bytes pqSig);
}
```

- `execute` / `executeBatch`: `msg.sender == ecdsaOwner`. Fee = `gasUsed × gasPrice × PROTOCOL_FEE_BPS / 10000`, paid to `FEE_COLLECTOR` from account balance if available.
- `pqRecover`: requires `keccak256(pqPk) == PQ_PK_HASH` and a valid SLH-DSA-SHAKE-192s signature over `keccak256("AEGIS_PQ_RECOVER_V2" ‖ chainId ‖ account ‖ newOwner ‖ pqRecoveryNonce)`. Rotates `ecdsaOwner`. No fee.
- Verifier: `evm/src/SphincsC13Verifier.sol` wrapping the vendored C13 implementation (~190 K gas, 3 688 B signatures).

**Planned**: V3 replaces the SLH-DSA recovery path with a CCHS recovery root (`CCHS.spec.md` §8), removing the external verifier.

### 5.1 Factory and migration

- `AegisAccountV2Factory.deploy(owner, pqPkHash)` — CREATE2, address predictable on every EVM chain.
- `UpgradeHelper` — atomic: deploy account, pull all approved ERC-20s, forward ETH.

---

## 6. Multi-chain deployment

1. Fresh deployer EOA `D`.
2. On each chain, `D` deploys at nonce 0, 1, 2: verifier, factory, upgrade helper. Identical bytecode (`bytecode_hash = "none"`, `cbor_metadata = false`) gives identical addresses.
3. `D`'s key is destroyed publicly after the last deployment.
4. Anyone can verify: same addresses on every chain, `D` has no further transactions.

Node deployment without Foundry: `deploy/deploy.mjs`.

---

## 7. Fees

- Hybrid accounts: `PROTOCOL_FEE_BPS` of gas on `execute`, `constant`, immutable. Recovery is free.
- Hash-only accounts (`AegisCCHS`): no protocol fee in v1.
- Changing a fee requires deploying a new contract; users migrate voluntarily.

---

## 8. Threat model

### 8.1 Defended

| Threat | Defense |
|---|---|
| Operator exit / rug | No admin key, no upgrade, no treasury; recovery paths need no operator |
| Fee increase | `constant` |
| ECDSA broken (quantum / AI) | V2: `pqRecover` rotates owner; CCHS: never used ECDSA |
| Mempool front-running of a hash signature | WOTS+ checksum: a different message needs a chain value earlier than the one revealed (`CCHS.spec.md` §6.2 C2) |
| Replay | `nonce` and `nextIdx` bound into every digest; strict monotonic |
| Cache poisoning (CCHS) | Writing `cachedRoot` requires a top-layer signature verified against immutable `root`; one write per subtree per epoch |
| Front-end compromise | Static build, self-hosted fonts, immutable asset hashes; users may run locally |

### 8.2 Not defended

| Threat | Why |
|---|---|
| Chain consensus failure | Outside the account layer |
| Compromised user device or leaked seed | Operational security |
| SHA-256 preimage break | Every hash-based scheme, and every chain, fails together |

---

## 9. Versioning

- Contract `VERSION` constants: `AegisCCHS` = `cchs-s-20/1.0.0`, `AegisAccountV2` = `0.2.0`.
- New versions deploy to new addresses. Existing accounts never change.

---

## 10. References

- CCHS: [`CCHS.spec.md`](CCHS.spec.md)
- Lamport, *Constructing digital signatures from a one-way function*, 1979
- Merkle, *Secrecy, authentication and public key systems*, 1979
- Hülsing, *W-OTS+ — Shorter signatures for hash-based signature schemes*, AFRICACRYPT 2013
- RFC 8391, *XMSS: eXtended Merkle Signature Scheme*
- FIPS 205, *Stateless Hash-Based Digital Signature Standard*
- EIP-1014, CREATE2
- nconsigny, SPHINCS+ C13 EVM verifier (vendored under `evm/src/vendor/`)
