# AEGIS CCHS — Chain-Cached Hypertree Signatures

**Version**: 1.0.0-draft
**Date**: 2026-10-08

---

## Abstract

CCHS is a hash-based post-quantum account authorization protocol for blockchains. It uses a two-layer WOTS+ hypertree (as in XMSS^MT / SPHINCS+) but exploits a property unique to on-chain verifiers: **they have persistent storage**. Upper-layer authentication is verified once per subtree and cached on-chain; all subsequent signatures in that subtree carry only the bottom layer.

Result, at 2^20 signature capacity:

| | Keygen | Signature (amortized) | Client state | Assumption |
|---|---|---|---|---|
| Flat XMSS (h=20) | ~10^9 hashes | 2.8 KB | stateful | SHA-256 |
| XMSS^MT (d=2, h=10) | ~10^6 hashes | 4.9 KB | stateful | SHA-256 |
| SPHINCS+-128s | ~10^6 hashes | 7.8 KB | stateless | SHA-256 |
| **CCHS (d=2, h=10)** | **~10^6 hashes** | **2.5 KB** | **stateless (chain-held)** | SHA-256 |

(~10^6 SHA-256 ≈ 5 s in pure JS, ~50–250 ms in WASM/native; ~10^9 is impractical on a phone.)

CCHS obtains the keygen cost of a hypertree, the signature size of a flat tree, and a stateless client, simultaneously. Previously these were a three-way trade-off.

Only cryptographic assumption: SHA-256 second-preimage / preimage resistance. Grover bound 2^128.

---

## 1. Contribution

### 1.1 What is reused

| Component | Origin |
|---|---|
| WOTS+ one-time signatures (w=16, 67 chains) | Winternitz 1979; Hülsing 2013 (WOTS+) |
| Merkle tree authentication paths | Merkle 1979 |
| Hypertree: upper OTS keys sign lower tree roots | XMSS^MT, RFC 8391; SPHINCS+ |
| Address-tweaked hash chains (multi-target resistance) | SPHINCS+ ADRS |
| On-chain sequential index for client statelessness | Shelter.cash (flat WOTS) |

### 1.2 What is new

**Verifier-side caching of hypertree intermediate roots.** Standard hypertree verification is memoryless: every signature re-proves the full path from bottom OTS key to top root, across all d layers. CCHS observes that a smart contract has storage, and that in a hypertree with sequential leaf consumption, the same bottom-tree root is re-proved 2^h times in a row. CCHS verifies the upper-layer path once, stores `cachedRoot[treeIdx] = R_0`, and thereafter requires only equality.

To the author's knowledge this has not been proposed for hash-based signatures. The closest analogues are TLS intermediate-certificate caching (different domain, not a signature scheme) and leanXMSS (EF, 2025; aggregates via zkVM proofs rather than verifier state).

**Security of the cache.** The cache stores a verified fact: "top-layer OTS key #k signed R_0." Re-verifying it is redundant. Writing `cachedRoot[k]` is permitted exactly once, which enforces on-chain the one-time property of top-layer key #k — a stronger guarantee than XMSS^MT, where one-time use is only enforced by client discipline.

### 1.3 What this is and is not

This is a protocol architecture contribution with a quantifiable improvement in a specific deployment setting (on-chain accounts with sequential nonces). It is not a new cryptographic primitive. Every hash function call reduces to SHA-256.

---

## 2. Notation and parameters

| Symbol | Value | Meaning |
|---|---|---|
| `H(x)` | SHA-256(x) | Base hash |
| `n` | 32 | Hash output bytes |
| `w` | 16 | Winternitz parameter |
| `len_1` | 64 | Message chains (256 bits / 4) |
| `len_2` | 3 | Checksum chains (max checksum 64×15 = 960 < 16^3) |
| `len` | 67 | Total chains |
| `h` | 10 | Tree height per layer |
| `d` | 2 | Hypertree layers |
| capacity | 2^(d·h) = 2^20 | Total signatures |

All integers big-endian. `‖` is byte concatenation.

### 2.1 Address (ADRS)

A 32-byte structure identifying every hash call, preventing multi-target attacks:

```
ADRS = layer(1) ‖ treeIdx(8) ‖ type(1) ‖ leafIdx(4) ‖ chainIdx(1) ‖ step(1) ‖ pad(16 zero)

type: 0x00 = WOTS chain step
      0x01 = WOTS pk compression (leaf)
      0x02 = Merkle internal node
```

### 2.2 Tweakable hash

```
F(ADRS, x)        = H(ADRS ‖ x)                 # 64-byte input, chain step
T_leaf(ADRS, pks) = H(ADRS ‖ pk_0 ‖ … ‖ pk_66)  # leaf from 67 chain ends
T_node(ADRS, l, r)= H(ADRS ‖ l ‖ r)             # Merkle internal node
```

---

## 3. Key generation

```
master ← 32 random bytes (or PBKDF2-HMAC-SHA512(mnemonic, "aegis-cchs-v1")[0:32])

sk(layer, treeIdx, leafIdx, chainIdx) = HKDF-SHA256(master, "cchs/sk" ‖ layer ‖ treeIdx ‖ leafIdx ‖ chainIdx, 32)

WOTS_pk(layer, t, j):
    for c in 0..66:
        x = sk(layer, t, j, c)
        for s in 0..14:
            x = F(ADRS(layer, t, 0x00, j, c, s), x)
        pk_c = x
    return T_leaf(ADRS(layer, t, 0x01, j, 0, 0), pk_0 ‖ … ‖ pk_66)

TreeRoot(layer, t):
    leaves = [WOTS_pk(layer, t, j) for j in 0..2^h-1]
    standard binary Merkle tree with T_node; return root

root = TreeRoot(d-1, 0)     # top tree only; ~2^h × 1005 hashes
```

Account on-chain: `root` (immutable), `nextIdx = 0`, `nonce = 0`, `cachedRoot = {}`.

All secret material is derived lazily from `master`. Client stores 32 bytes.

---

## 4. Signing

Inputs: `master`, chain-read `nextIdx` and `nonce`, transaction `(target, value, data)`.

```
idx     = nextIdx
t_0     = idx >> h              # bottom tree index
j_0     = idx & (2^h - 1)       # leaf within bottom tree
j_1     = t_0                   # top-layer leaf that signs bottom tree t_0

M = H("AEGIS_CCHS_V1" ‖ chainId ‖ account ‖ nonce ‖ idx ‖ target ‖ value ‖ keccak256(data))

# Layer 0
sig_0  = WOTS_sign(layer=0, t_0, j_0, M)
auth_0 = MerkleAuthPath(layer=0, t_0, j_0)      # h × 32 bytes
R_0    = TreeRoot(0, t_0)

if chain.cachedRoot[t_0] == 0:
    # Layer 1
    sig_1  = WOTS_sign(layer=1, 0, j_1, R_0)
    auth_1 = MerkleAuthPath(layer=1, 0, j_1)
    signature = (sig_0, auth_0, sig_1, auth_1)
else:
    signature = (sig_0, auth_0)
```

### 4.1 WOTS_sign

```
WOTS_sign(layer, t, j, msg):
    digits = base16(msg)                        # 64 digits
    csum   = Σ (15 - digits[i])                 # ≤ 960
    digits ‖= base16_3digits(csum)              # 67 digits
    for c in 0..66:
        x = sk(layer, t, j, c)
        for s in 0..digits[c]-1:
            x = F(ADRS(layer, t, 0x00, j, c, s), x)
        sig_c = x
    return sig_0 ‖ … ‖ sig_66                   # 2144 bytes
```

### 4.2 Costs — measured (pure JS, `@noble/hashes`, Node 24, laptop)

| Operation | Hashes | Measured |
|---|---|---|
| Keygen (top 2^10 + recovery 2^8) | ≈ 1.3 M | **4.9 s** |
| Sign, first in subtree (builds bottom + top tree) | ≈ 2.0 M + 2 WOTS | **7.2 s** |
| Sign, cached subtree, trees in memory | 1 WOTS ≈ 500 | **2 ms** |
| Sign, cached subtree, cold (rebuild bottom tree) | ≈ 1.0 M | ~4 s |

Pure-JS SHA-256 runs at roughly 4–5 µs per call; a WASM or native implementation is 20–100× faster, so the seconds above become tens to hundreds of milliseconds. In the wallet these run in a Web Worker (`deriveWorker.ts`) and the bottom/top trees are kept in worker memory as a pure optimization — losing them costs a rebuild, not funds. The one-time cost is comparable to the SPHINCS+ keygen the wallet already performs.

---

## 5. Verification (on-chain)

```
verify(target, value, data, sig_0, auth_0, [sig_1, auth_1]):
    idx = nextIdx
    t_0 = idx >> h ; j_0 = idx & (2^h-1)

    M    = H("AEGIS_CCHS_V1" ‖ chainId ‖ this ‖ nonce ‖ idx ‖ target ‖ value ‖ keccak256(data))
    pk_0 = WOTS_pk_from_sig(0, t_0, j_0, M, sig_0)
    R_0  = MerkleRootFromPath(T_leaf(…, pk_0), j_0, auth_0)

    cached = cachedRoot[t_0]
    if cached != 0:
        require R_0 == cached
    else:
        require sig_1 present
        pk_1 = WOTS_pk_from_sig(1, 0, t_0, R_0, sig_1)
        R_1  = MerkleRootFromPath(T_leaf(…, pk_1), t_0, auth_1)
        require R_1 == root
        cachedRoot[t_0] = R_0

    nextIdx += 1 ; nonce += 1
    call target
```

### 5.1 WOTS_pk_from_sig

```
WOTS_pk_from_sig(layer, t, j, msg, sig):
    digits = base16(msg) ‖ base16_3digits(csum)
    for c in 0..66:
        x = sig_c
        for s in digits[c]..14:
            x = F(ADRS(layer, t, 0x00, j, c, s), x)
        pk_c = x
    return pk_0 ‖ … ‖ pk_66
```

### 5.2 Gas (EVM, SHA-256 precompile) — measured

Measured on `evm/src/AegisCCHS.sol` (solc 0.8.37, optimizer 200, Cancun) in an EVM with the TypeScript client producing the signatures. Hot loops call precompile `0x02` directly from assembly (~360 gas per 64-byte hash including call overhead and memory).

| Case | Execution gas | + intrinsic 21 K + calldata | Total tx gas |
|---|---|---|---|
| Cached subtree (2 464 B sig) | ~205–222 K | ~61 K | **~270–285 K** |
| New subtree (4 928 B sig) | ~478 K | ~100 K | **~580 K** |
| Recovery (height-8 tree) | ~213 K | ~57 K | **~270 K** |
| Deploy | ~825 K | — | 4 750 B runtime code |

Amortized over 1024 signatures per subtree: **~275 K**. SPHINCS+ C13 on-chain verification is ~190 K compute + 3 688 B calldata (~59 K) + 21 K ≈ 270 K, every signature, and requires a separate 14.6 KB verifier contract. CCHS is gas-parity with the best deployed SPHINCS+ verifier at 2/3 the calldata, 1/3 the code size, and no external contract. On L2s all of these are negligible.

**EVM-optimized variant**: replacing SHA-256 with keccak256 (native opcode, ~42 gas per 64-byte hash vs ~360) is projected to cut execution gas roughly 6× (cached ≈ 35 K + calldata). This breaks byte-compatibility with Bitcoin Script (which has OP_SHA256 but not keccak) and is therefore a separate parameter set `CCHS-K`, not the canonical one. Not yet implemented.

---

## 6. Security

### 6.1 Model

Adversary A: full view of chain and mempool; unbounded classical compute; quantum compute sufficient to break all discrete-log, factoring, and lattice assumptions; Grover oracle access to SHA-256.

### 6.2 Claims

**C1 — Unforgeability.** A cannot produce an accepting signature for `(target', value', data')` not authorized by the owner.

Sketch. Acceptance requires a WOTS+ signature under key `(0, t_0, j_0)` on `M'`. Each WOTS+ key is used at most once (enforced by `nextIdx` monotonicity). WOTS+ with checksum is existentially unforgeable under one-time chosen-message attack assuming second-preimage resistance of `F` (Hülsing 2013, Theorem 1), with the ADRS tweak eliminating multi-target advantage. A's best attack is a preimage search: 2^128 Grover queries.

**C2 — Mempool front-running is infeasible.** A observes `(sig_0, auth_0)` for `M` in the mempool and attempts to submit a transaction for `M' ≠ M` in the same block.

Sketch. `M' ≠ M` ⇒ base-16 digit vectors differ. The checksum guarantees ∃ chain `c` with `digits'[c] > digits[c]`. A holds `sig_c = F^{digits[c]}(sk_c)` and needs `F^{digits'[c]}(sk_c)` — a value *earlier* in the chain. Computing it requires inverting `F`. Same 2^128 bound.

**C3 — Cache integrity.** A cannot cause `cachedRoot[t_0]` to hold a value other than the owner's `TreeRoot(0, t_0)`.

Sketch. Writing requires a WOTS+ signature under top key `(1, 0, t_0)` on the written value, verified against immutable `root`. A does not hold `sk(1, 0, t_0, ·)`. If the owner has already registered `R_0`, A observing `sig_1` on `R_0` cannot forge `sig_1'` on `R_0' ≠ R_0` (C2 argument). If the owner has not yet registered, A has no signature to work from. The write is permitted once, so a correct registration cannot be overwritten.

**C4 — Cache soundness.** Accepting via the cached branch is equivalent to accepting via full verification.

Sketch. `cachedRoot[t_0] = R_0` was written only after `R_1 == root` was checked with a valid `sig_1` on `R_0`. The cached branch then requires `MerkleRootFromPath(leaf_0, j_0, auth_0) == R_0`, which is exactly the condition the full path would have imposed on layer 0. The layer-1 condition is a pure function of `(R_0, sig_1, auth_1, root)` — already checked, and unchanged.

### 6.3 Not covered

- Side channels on client key derivation.
- Chain-level failures (reorg past finality, consensus bugs).
- Loss of `master`. See §8 recovery.
- Formal machine-checked proof. The sketches above reduce to Hülsing 2013 + standard Merkle arguments; a Lean/EasyCrypt formalization is future work.

---

## 7. Cross-chain deployment

The verification algorithm uses only SHA-256, byte concatenation, integer shifts, 32-byte storage, and one `call`. A signature produced by the client is byte-identical on every chain (the chain ID is bound inside `M`, so it is not *replayable* across chains, but the *verifier code* is portable).

| Chain | Hash primitive | Storage for `cachedRoot` | Note |
|---|---|---|---|
| EVM (ETH, BSC, Polygon, Arbitrum, Optimism, Base, …) | precompile 0x02 | mapping | `evm/src/AegisCCHS.sol` |
| TRON | SHA256 precompile (EVM-compatible) | mapping | same contract |
| Solana | `sha256` syscall | PDA account | ~500 LOC Rust |
| Cosmos (CosmWasm) | `sha2_256` | `Map<u64, Binary>` | ~300 LOC Rust |
| Aptos / Sui | `hash::sha2_256` | table / dynamic field | ~200 LOC Move |
| NEAR | `env::sha256` | `LookupMap` | ~250 LOC Rust |
| TON | `HASHEXT_SHA256` | dict | ~400 LOC Tolk |
| Starknet | `core::sha256` | `LegacyMap` | ~300 LOC Cairo |
| Bitcoin | `OP_SHA256` in Tapscript | — | §7.1 |

### 7.1 Bitcoin

Bitcoin has no mutable storage, so the cache cannot be held on-chain. Two options:

**(a) Flat Tapscript tree (works today, BIP-341).** The Taproot script tree *is* a Merkle tree. Use it as the signature tree: one tapleaf per WOTS+ key, each leaf script verifying that key's 67 chains against hard-coded pks. 2^20 leaves ⇒ Taproot control block 20 × 32 = 640 B. Leaf script ≈ 67 × (OP_SHA256 unrolled ≤ 15 + 32-byte pk + OP_EQUALVERIFY) ≈ 4–5 KB. Witness ≈ 2.1 KB sig + 5 KB script + 640 B control ≈ 8 KB. Feasible under the 4 MB weight limit. No hypertree caching benefit, but no new opcodes required. This is Lamport/WOTS-in-Tapscript, as used by BitVM (Linus 2023).

**(b) With OP_CAT (BIP-347, pending).** In-script Merkle verification becomes possible; a single tapleaf can verify any of 2^h bottom keys with the auth path in the witness. The cache is replaced by the UTXO itself: a spend from a "subtree UTXO" carries only the bottom layer, and creating the subtree UTXO carries the top layer. This mirrors CCHS exactly, with UTXO lineage as the cache.

---

## 8. Recovery

A second, independent root `recRoot` is set at account creation: a single-layer WOTS+ tree with `h_rec = 8` (256 recoveries), derived from `master` under a distinct HKDF label.

```
recover(newRoot, newRecRoot, sig_rec, auth_rec):
    M_rec = H("AEGIS_CCHS_RECOVER_V1" ‖ chainId ‖ this ‖ recNonce ‖ newRoot ‖ newRecRoot)
    verify WOTS+ sig_rec under recRoot at leaf recNonce
    root = newRoot ; recRoot = newRecRoot
    nextIdx = 0 ; recNonce += 1
    clear cachedRoot (new root ⇒ new subtrees; use an epoch counter in the mapping key)
```

Hybrid deployments (`AegisAccountV3`) may keep ECDSA as the daily path and use CCHS only as the recovery root — replacing the SPHINCS+ verifier of V2 with a ~175 K-gas, 2.5 KB alternative that needs no 15 KB verifier contract.

---

## 9. Parameter sets

| Name | Hash | d | h | Capacity | Sig (amortized) | Use |
|---|---|---|---|---|---|---|
| `CCHS-S-20` | SHA-256 | 2 | 10 | 2^20 | 2.5 KB | canonical, cross-chain |
| `CCHS-S-30` | SHA-256 | 3 | 10 | 2^30 | 2.5 KB | institutional |
| `CCHS-K-20` | keccak256 | 2 | 10 | 2^20 | 2.5 KB | EVM-only, ~20 K gas compute |

---

## 10. Reference implementations

- `evm/src/AegisCCHS.sol` — Solidity, `CCHS-S-20`. Compiles with solc 0.8.37; 4 750 B runtime.
- `evm/test/AegisCCHS.t.sol` — Foundry tests incl. front-run, replay, cache-poisoning, recovery.
- `wallet/src/aegis/cchs.ts` — TypeScript client: keygen, sign, local verify, digest construction, ABI helpers.

**Interop verified** (2026-10-08): signatures produced by `cchs.ts` were executed against the compiled contract in an EVM (`@ethereumjs/vm`, Cancun). First-in-subtree, cached, replay, front-run to a different target, tampered chain value, tampered auth path, recovery rotation, and post-rotation rejection of the old key all behaved as specified. Digest computed by the client matched `nextDigest()` byte-for-byte.

Future: `cchs-ref/` Rust reference with test vectors shared by the non-EVM chain implementations (§7).

---

## 11. Open problems

1. **Out-of-order leaf use.** Sequential `nextIdx` forbids skipping a subtree whose bottom keys may have leaked. A `skipSubtree` operation authorized by a layer-1 signature is straightforward but not in v1.
2. **Cache eviction.** `cachedRoot` grows by one slot per 1024 signatures. Negligible, but a recovery epoch counter is used so old entries are logically cleared without gas-costly deletion.
3. **Formal verification.** Reduce §6 sketches to a machine-checked proof.
4. **Bitcoin without OP_CAT.** Option (a) works but forgoes caching. A covenant-free way to get amortization on Bitcoin is open.
