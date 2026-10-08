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

### 5.2 Gas (EVM) — measured

Measured on `evm/src/AegisCCHS.sol` (S-20, SHA-256 precompile from assembly) and `evm/src/AegisCCHSK.sol` (K-20, keccak256 opcode) with the deployed build settings (solc 0.8.37, optimizer 1 000 000 runs, viaIR, Cancun, no metadata — `deploy/deploy-cchs.mjs --build`), the TypeScript client producing the signatures. Execution gas excludes the 21 K intrinsic and calldata (2 464 B ≈ 40 K cached, 4 928 B ≈ 80 K first-in-subtree, at 16 gas/byte; EIP-7623 raises this for calldata-dominated transactions).

| Case | S-20 execution | S-20 total | K-20 execution | K-20 total |
|---|---|---|---|---|
| Cached subtree | ~209 K | **~270 K** | ~116 K | **~177 K** |
| New subtree (first of 1024) | ~452 K | ~553 K | ~249 K | ~350 K |
| Recovery | ~201 K | ~260 K | ~107 K | ~166 K |
| Account deploy via factory | ~1 328 K | — | ~1 306 K | — |
| Runtime code | 6 184 B | | 6 072 B | |

The account also implements the ERC-721 and ERC-1155 receiver callbacks and ERC-165, so any asset can be sent to it with a safe transfer; those four pure functions account for ~0.9 KB of the runtime. (Without them: 5 296 B / 5 184 B, S-20 cached ~232 K, K-20 cached ~118 K. With optimizer 200 runs and no viaIR the code is 3 831 B / 3 666 B and K-20 cached execution is ~128 K; the deployed build trades code size for ~10 K gas per signature.)

Execution gas includes the outgoing `call` (9 K for value transfer, 25 K if it creates the recipient), one packed SSTORE, and the event — roughly 45 K that is not verification. K-20 verification proper is ~75 K; S-20 ~185 K.

SPHINCS+ C13 on-chain verification is ~190 K compute + 3 688 B calldata (~59 K) + 21 K ≈ 270 K per signature and needs a separate 14.6 KB verifier contract. K-20 is ~1/3 cheaper than that on every signature, S-20 is at parity; both use about 1/3 the code and no external contract.

**Which set to deploy.** `CCHS-K-20` is the EVM default: signatures are bound to a chain ID, so an EVM account never shares a signature with Bitcoin Script, and the keccak opcode is the cheaper primitive. `CCHS-S-20` is the cross-chain canonical set and the one every non-EVM port implements. Both are deployed by the same factory (§5.4).

### 5.3 Cross-chain cache portability

The top-layer message is the bottom subtree root `R_0`, which contains no chain identifier. The same top-layer signature `(sig_1, auth_1)` therefore registers subtree `t_0` on every chain running the same parameter set with the same `root`. Registering the correct root is harmless wherever it is replayed. Consequence: the first-in-subtree premium is paid once per subtree globally, not once per chain. A user with accounts on *n* chains who warms subtree *t* on one chain can ship the same `l1` to the others as a sponsored transaction. Bottom-layer signatures remain chain-bound through the digest.

### 5.4 Factory and same-address deployment

`evm/src/AegisCCHSFactory.sol` deploys either set with CREATE2, `salt = keccak256(root ‖ recRoot ‖ variant)`. With metadata-free bytecode and the factory itself placed by the same deployer at the same nonce on every EVM chain, `(root, recRoot, variant)` maps to one address on all of them. `deploy()` is permissionless and idempotent; `predict()` is pure in the chain ID.

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

Bitcoin has no mutable storage, so the cache cannot be held on-chain, and current Script cannot bind a hash-based signature to the spending transaction: a tapleaf can check WOTS+ chains against hard-coded public values (BitVM, Linus 2023), but the digits it checks are witness data, not the sighash. Without `OP_CAT` (BIP-347) or `OP_CHECKSIGFROMSTACK` the script cannot compute or compare the sighash, so a miner could reuse the WOTS+ witness on a transaction paying elsewhere. BitVM is unaffected because its digits are program state, not transaction data. Consequently there is no hash-only, transaction-binding signature on Bitcoin today; the following describes what becomes possible once either opcode activates.

**(a) Flat Tapscript tree + OP_CAT.** The Taproot script tree *is* a Merkle tree. Use it as the signature tree: one tapleaf per WOTS+ key, each leaf script (i) verifying 67 chains against hard-coded pks (BitVM Winternitz pattern: compute the 16 chain states, `OP_PICK` the one at the claimed digit, `OP_EQUALVERIFY`), (ii) checking the 3 checksum digits arithmetically, (iii) reassembling the 64 message digits with `OP_CAT` and comparing them with the sighash reconstructed in-script from witness-supplied transaction fields (the CAT-covenant technique). Measured from the builder: leaf script 5 752 B for (i)+(ii); witness for a 2^4 test tree 8 116 B (134 WOTS items + script + 161 B control block); a 2^20 tree adds 512 B of control block. Plus the sighash fragment. Under the 4 MB weight limit. No hypertree caching benefit. `wallet/src/aegis/btcTapscript.ts` implements the tree builder, leaf-script generator (i)+(ii), BIP-341 tagged hashing and control-block construction; (iii) is left as a marked insertion point until BIP-347 is active on a network with real value.

**(b) With OP_CAT, hypertree form.** In-script Merkle verification becomes possible; a single tapleaf can verify any of 2^h bottom keys with the auth path in the witness. The cache is replaced by the UTXO itself: a spend from a "subtree UTXO" carries only the bottom layer, and creating the subtree UTXO carries the top layer. This mirrors CCHS exactly, with UTXO lineage as the cache.

Until then, the honest Bitcoin posture for a hash-only key is to hold BTC on a chain that has the opcodes, or to use the Taproot key path with a Schnorr key whose spend the owner can migrate once an opcode activates.

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
| `CCHS-S-20` | SHA-256 | 2 | 10 | 2^20 | 2.5 KB | canonical; every non-EVM port; EVM when cross-chain byte identity is wanted |
| `CCHS-K-20` | keccak256 | 2 | 10 | 2^20 | 2.5 KB | EVM default; ~200 K total gas cached |
| `CCHS-S-30` | SHA-256 | 3 | 10 | 2^30 | 2.5 KB | institutional; not yet implemented |

Key derivation (HKDF-SHA256 from the 32-byte master) is identical across sets; only the tweakable hash differs, so one master yields distinct, independent trees per set.

---

## 10. Reference implementations

- `evm/src/AegisCCHSBase.sol` — hash-agnostic account logic (execute, recover, cache, digests).
- `evm/src/AegisCCHS.sol` — `CCHS-S-20`, SHA-256 precompile from assembly. 6 184 B runtime (deployed build).
- `evm/src/AegisCCHSK.sol` — `CCHS-K-20`, keccak256 opcode. 6 072 B runtime (deployed build).
- `evm/src/AegisCCHSFactory.sol` — CREATE2 factory for both sets. `deploy` is payable and forwards ETH; `deployAndMove` also pulls approved ERC-20s, so creating and funding an account is one transaction. The factory itself is published through the deterministic-deployment proxy (`deploy/deploy-cchs.mjs`, or the wallet's first Protect on a chain where it is missing; the sender does not matter), giving it the address `0x52aC1CdF75D5f11BCabE8dD0d8429Cd152Ec0091` on every EVM chain where it has been deployed; the wallet artifact (`wallet/src/aegis/cchsArtifacts.json`) carries the exact init code so account addresses can be predicted offline.
- `evm/test/AegisCCHS.t.sol` — Foundry suites for S-20 and K-20 (front-run by target and by value, replay, tampered chain value, tampered auth path, wrong top layer, cache poisoning, recovery, recovery replay, old key after rotation) plus factory tests (prediction, idempotence, chain independence, ETH forwarding, ERC-20 pull, missing approval). Driven by client-generated vectors.
- `evm/test/fixtures/cchs-s-20.json`, `cchs-k-20.json` — test vectors (master `0x07…07`, chainId 1, account `0x…cc45`): roots, bottom root 0, three operations (first-in-subtree with top layer, two cached), one recovery. The S-20 file is the ground truth for every non-EVM port in §7.
- `wallet/src/aegis/cchs.ts` — TypeScript client, both sets (`cchsS`, `cchsK`, `forVariant`): keygen, sign, local verify, digest construction, ABI helpers, range-based leaf generation for parallel keygen.

**Interop verified** (2026-10-08): for both sets, signatures produced by `cchs.ts` were executed against the compiled contracts in an EVM (`@ethereumjs/vm`, Cancun), with accounts created through the factory (predicted address = deployed address, idempotent). First-in-subtree, cached, front-run to a different target, tampered chain value, recovery rotation, and post-rotation rejection of the old key all behaved as specified. Client digests matched `nextDigest()` byte-for-byte.

---

## 11. Open problems

1. **Out-of-order leaf use.** Sequential `nextIdx` forbids skipping a subtree whose bottom keys may have leaked. A `skipSubtree` operation authorized by a layer-1 signature is straightforward but not in v1.
2. **Cache eviction.** `cachedRoot` grows by one slot per 1024 signatures. Negligible, but a recovery epoch counter is used so old entries are logically cleared without gas-costly deletion.
3. **Formal verification.** Reduce §6 sketches to a machine-checked proof.
4. **Bitcoin without OP_CAT.** Option (a) works but forgoes caching. A covenant-free way to get amortization on Bitcoin is open.
