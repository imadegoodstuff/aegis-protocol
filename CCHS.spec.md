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
| **CCHS (d=2, h=10)** | **~10^6 hashes** | **2.5 KB** | **index on chain + write-ahead record** | SHA-256 |

(~10^6 SHA-256 ≈ 5 s in pure JS, ~50–250 ms in WASM/native; ~10^9 is impractical on a phone.)

CCHS obtains the keygen cost of a hypertree and the signature size of a flat tree while moving the one-time-key index to the chain. Previously these were a three-way trade-off. It is not a stateless scheme in the SPHINCS+ sense: the verifier holds the index and enforces one landed signature per leaf, and the client still keeps a small write-ahead record so that a signature which never landed is not repeated (§4.3). What the client no longer needs is the tree state of XMSS: the record is a single integer per account and losing it costs capacity, not security, provided the device waits for in-flight transactions to settle before signing again.

Only cryptographic assumption: SHA-256 second-preimage / preimage resistance. Quantum bound 2^128 under the tight (SPHINCS+ / FIPS 205) multi-target accounting, 2^113 under the conservative one that gives the address tweak no credit (§5.5); every attack path is costed and the effect of a wider hash output is worked out in §5.6.

---

## 1. Contribution

### 1.1 What is reused

| Component | Origin |
|---|---|
| WOTS+ one-time signatures (w=16, 67 chains) | Winternitz 1979; Hülsing 2013 (WOTS+) |
| Merkle tree authentication paths | Merkle 1979 |
| Hypertree: upper OTS keys sign lower tree roots | XMSS^MT, RFC 8391; SPHINCS+ |
| Address-tweaked hash chains (multi-target resistance) | SPHINCS+ ADRS |
| Public per-key seed in every hash call (multi-user = single-user) | SPHINCS+ / FIPS 205 `PK.seed` |
| On-chain index for one-time keys | Shelter.cash (flat WOTS) |

### 1.2 What is new

**Verifier-side caching of hypertree intermediate roots.** Standard hypertree verification is memoryless: every signature re-proves the full path from bottom OTS key to top root, across all d layers. CCHS observes that a smart contract has storage, and that in a hypertree with sequential leaf consumption, the same bottom-tree root is re-proved 2^h times in a row. CCHS verifies the upper-layer path once, stores `cachedRoot[treeIdx] = R_0`, and thereafter requires only equality.

To the author's knowledge this has not been proposed for hash-based signatures. The closest analogues are TLS intermediate-certificate caching (different domain, not a signature scheme) and leanXMSS (EF, 2025; aggregates via zkVM proofs rather than verifier state).

**Security of the cache.** The cache stores a verified fact: "top-layer OTS key #k signed R_0." Re-verifying it is redundant. Writing `cachedRoot[k]` is permitted exactly once, which enforces on-chain the one-time property of top-layer key #k — a stronger guarantee than XMSS^MT, where one-time use is only enforced by client discipline.

**Signer-chosen index and lanes.** The verifier does not assign leaf indices; the signer chooses any index not below the chain's counter, and the index is part of the signed message. This turns the client's one-time-key bookkeeping into a single integer that is written ahead of each signature, lets a client abandon leaves it no longer trusts without a separate operation, and, with the counter kept per *lane* (a fixed slice of the index space, §4.3 rule 4), lets several devices sign for one account concurrently with no coordination and no shared state: each device's correctness depends only on what it reads itself (§6, invariant LI). Stateful hash-based schemes treat index allocation between signers as a state-management problem outside the scheme (RFC 8391; NIST SP 800-208); here the allocation is a property the verifier enforces.

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
| `pkSeed` | 16 bytes | Public seed of the key tree; last 16 bytes of every ADRS; part of the public key (§3) |
| capacity | 2^(d·h) = 2^20 | Total signatures |

All integers big-endian. `‖` is byte concatenation.

### 2.1 Address (ADRS)

A 32-byte structure identifying every hash call, preventing multi-target attacks:

```
ADRS = layer(1) ‖ treeIdx(8) ‖ type(1) ‖ leafIdx(4) ‖ chainIdx(1) ‖ step(1) ‖ pkSeed(16)

type: 0x00 = WOTS chain step
      0x01 = WOTS pk compression (leaf)
      0x02 = Merkle internal node
```

The first 16 bytes make every hash call of one tree a distinct function from every other call of the same tree. The last 16 bytes, `pkSeed`, make every hash call of one tree a distinct function from the same call in any other tree: without them, position `(layer, treeIdx, leafIdx, chainIdx, step)` would be the *same* tweaked function for every account on every chain, and an adversary attacking 2^k accounts at once would face 2^k targets per function. `pkSeed` is public (it is part of the public key and of the on-chain state, §3, §5) and plays the role of `PK.seed` in SPHINCS+ / FIPS 205; the input lengths of `F`, `T_leaf` and `T_node` do not change. An earlier revision of this document used sixteen zero bytes here; it is superseded by this one, and the fixtures of §10 are generated under the seeded layout.

### 2.2 Tweakable hash

```
F(ADRS, x)        = H(ADRS ‖ x)                 # 64-byte input, chain step
T_leaf(ADRS, pks) = H(ADRS ‖ pk_0 ‖ … ‖ pk_66)  # leaf from 67 chain ends
T_node(ADRS, l, r)= H(ADRS ‖ l ‖ r)             # Merkle internal node
```

---

## 3. Key generation

```
master ← 32 random bytes, or from a BIP-39 mnemonic of 24 words exactly as SPEC.md §2
         (REQUIRED: ≥ 256 bits of seed entropy; a 12-word phrase puts the account at ≈ 2^76, §5.6 P4):
         seed   = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" ‖ passphrase, 2048)   # BIP-39, 64 B
         master = HKDF-SHA256(seed, salt = ∅, info = "aegis/cchs/master/v1", 32)

key(chain) = HKDF-SHA256(master, salt = ∅, info = "aegis/cchs/chain/v1" ‖ tag(chain), 32)   # one tree per chain
    tag(EVM chain)   = 0x00 ‖ chainId as 8 bytes BE
    tag(other chain) = 0x01 ‖ utf8(label)       # the label of that chain's digest: "solana", "ton", …

label(set) = "cchs/sk" (S-20) | "cchs/sk/k" (K-20) | "cchs/sk/c" (C-20, §5.5)
sk(layer, treeIdx, leafIdx, chainIdx) = HKDF-SHA256(key, salt = ∅, label(set) ‖ layer ‖ treeIdx ‖ leafIdx ‖ chainIdx, 32)
    # key = key(chain) at epoch 0, key_e(chain) after e recoveries (§8)
    # layer: 1 byte, treeIdx: 8 bytes BE, leafIdx: 4 bytes BE, chainIdx: 1 byte

seedLabel(set) = "cchs/pkseed" (S-20) | "cchs/pkseed/k" (K-20) | "cchs/pkseed/c" (C-20)
pkSeed = HKDF-SHA256(key, salt = ∅, seedLabel(set), 32)[0..16)
    # public; one per key tree (per chain, per set, per epoch); every ADRS of the tree carries it (§2.1)

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
pk   = (root, recRoot, pkSeed)   # recRoot: §8
```

The public key is the two roots and the seed. `pkSeed` is derived, not chosen, so a client reproduces it from the mnemonic like everything else, and it is rotated with the roots at every recovery (§8) because it is a function of `key_e(chain)`. It is not secret and carries no entropy that matters to the signer; its only job is to separate this tree's hash functions from every other tree's.

Account on-chain: `root` (immutable), `pkSeed`, `nextIdx[l]` and `nonce[l]` for each of the `2^b` lanes (§4.3 rule 4; `b = 4` in the EVM contracts; a fresh lane reads `nextIdx[l] = l · 2^(2h−b)`, `nonce[l] = 0`), `cachedRoot = {}`.

All secret material is derived lazily from `master`. Client stores 32 bytes (plus the index record of §4.3).

**One tree per chain.** The digest of §4 contains the chain id, which stops a signature from being *replayed* on another chain. It does not stop the same leaf from being *used* on another chain: if two chains shared one tree, leaf 0 on chain A and leaf 0 on chain B would sign two different digests under one WOTS+ key, which is exactly the reuse a one-time signature forbids, and no on-chain `nextIdx` can prevent it because each chain sees only its own. Deriving `key(chain)` per chain makes leaves of different chains different leaves by construction; nothing has to be coordinated between chains, devices or records. The consequence is that the account address differs per chain: it is still a pure function of the mnemonic, the chain id and the factory init code, and is known before anything is deployed. The CREATE2 *factory* is at the same address on every EVM chain; the *accounts* it creates are not.

There is one derivation path, and it is the one above; an implementation that derives `master` or `key(chain)` any other way produces a different account. Each parameter set has its own secret-key label, so no WOTS+ secret value is ever exposed through two different one-way functions (S-20 hashes with SHA-256, K-20 with keccak256). `evm/test/fixtures/cchs-derivation.json` fixes the whole chain for one mnemonic (`abandon` ×23 `art`, empty passphrase): seed, master, then for chain id 1, chain id 8453 and the label `ton` the tag, the chain key, `sk(0,0,0,0)`, `root`, `recRoot`, `bottomRoot0` and (EVM) the predicted account. A client is compatible with the reference if and only if it reproduces that file. The signature vectors `cchs-s-20.json` / `cchs-k-20.json` / `cchs-c-20.json` start from a given 32-byte key, which plays the role of `key(chain)`.

---

## 4. Signing

Inputs: `master`, the device's lane `l` (§4.3 rule 4; a single device uses lane 0), chain-read `nextIdx[l]` and `nonce[l]`, the device's own record of the highest index it has signed in the lane (`signedMax`, §4.3), transaction `(target, value, data)`.

```
idx     = max(nextIdx[l], signedMax + 1, l · 2^(2h−b))   # signer-chosen, monotone within the lane (§4.3)
nonce   = nonce[l]
record signedMax = idx                  # write-ahead, before any hashing
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

### 4.3 Index discipline and concurrency

A WOTS+ key signs one message. Two signatures under the same leaf on different messages let an adversary forge any message whose digits are, chain by chain, no smaller than the minimum of the two (checksum chains included); a handful of such pairs exposes the key completely. The verifier enforces one *landed* signature per leaf (`idx ≥ nextIdx`), but it cannot see a signature that was produced and never landed. Index discipline is therefore a client obligation, and the protocol is shaped so that obeying it is cheap:

1. **The signer chooses `idx`.** Any `idx ≥ nextIdx[l]` in lane `l` is accepted; `nextIdx[l]` becomes `idx + 1` and every lower leaf of the lane is abandoned forever. `idx` is bound into `M`, so only the key holder can skip and nobody can force a skip on them. There is no separate `skipSubtree` operation: a signer that no longer trusts the keys of its current subtree signs its next operation at the first leaf of the following subtree (with that subtree's top layer), and the distrusted subtree is behind `nextIdx[l]`.
2. **Write-ahead record.** The device stores the highest index it has signed per `(chainId, account, epoch, lane)` *before* producing the signature. Next index = `max(nextIdx[l], signedMax + 1)`. A transaction that is dropped, replaced, under-priced, or reverted for an unrelated reason leaves its leaf unused on chain, and the client never signs that leaf again: it is abandoned and the next operation uses a higher one. Re-signing the same leaf for a changed call (new target, amount, or gas) is exactly the two-messages case and is never done.
3. **Pending operations.** `nonce[l]` is also bound into `M`, so two operations prepared from the same lane state cannot both land. A client with one operation in flight in its lane waits for it to settle or be dropped before signing the next; a dropped operation does not advance the nonce, so the next signature reuses the nonce but, by rule 2, a fresh leaf.
4. **Several devices: lanes.** The index space is split into `2^b` lanes by the top `b` bits of `idx` (`b = 4`: 16 lanes of 2^16 leaves, 64 subtrees each), and the verifier keeps `nextIdx` and `nonce` *per lane*. A device is assigned one lane and reads, signs and records only in it. Two devices in different lanes then need no coordination at all: the chain enforces monotonicity in each lane, a transaction in one lane changes no digest of another, and their transactions may land in any order (invariant LI, §6). What remains a client obligation is the assignment itself: two devices must never share a lane, exactly as two devices must never share a leaf; the reference wallet stores the device's lane and shows it next to the signing form. The earlier partition "device *d* uses subtrees ≡ *d* mod *n*" was only a client convention under a single counter and is superseded; with one counter, a device's transaction also invalidated every other device's pending digest through the shared nonce.
5. **Lost or rolled-back record.** A device whose record is missing or may be older than the signatures it produced (new install with the account already in use, storage cleared, restore from a backup) must not sign in its lane under the current epoch at all. It cannot know which leaves the lost record covered, and a transaction it signed earlier may still be sitting in a mempool with a leaf above `nextIdx[l]`; "wait until the pool drains, then take `nextIdx` as the lower bound" is not sufficient (the model in §6 produces the counterexample: sign at leaf 0, drop, restore, pool empty, sign a different message at leaf 0). The complete rule is to leave the index space: move to a lane no device has used, or perform a recovery (§8) to the next epoch, whose keys are a different derivation, and start a fresh record there. The reference wallet refuses to sign when `nextIdx[l]` is above the lane's first leaf and no record exists for `(chain, account, epoch, lane)`, and offers both ways out. The record is written per epoch and lane.
6. **Recovery messages are deterministic.** The roots of epoch `e + 1` are a pure function of the master and `e + 1` (§8), so the recovery message at `(epoch, recNonce)` is fixed; a dropped rotation that is signed again is the same message under the same recovery leaf, not a second one. The recovery leaf is nevertheless recorded before signing, like any other leaf. A recovery to a *fresh* master (the compromise case) is a different message and must therefore never be attempted at a `recNonce` for which a deterministic rotation has already been signed; the wallet records both under one counter.
7. **Several chains.** Each chain has its own tree (`key(chain)`, §3). A client must never build a tree for chain B from the key of chain A, however convenient a shared address would be; the chain id in the digest does not make that safe. The model (§6) shows the violation in six states for a client that shares one tree between two chains.
8. **Capacity.** Abandoned leaves cost capacity, not security: 2^20 leaves at one operation per minute last about two years even if every other leaf is abandoned. Recovery (§8) opens a fresh index space under a new root.

Rule 1 also settles two races: a transaction prepared with a top layer still succeeds if someone else registered the subtree in the meantime (`executeFirst` ignores a redundant proof), and a cached-path transaction prepared before a recovery fails cleanly (new epoch, empty cache) rather than being replayable.

---

## 5. Verification (on-chain)

Two entry points share the verification; they differ only in whether the top layer is present, so a cached-path transaction carries one layer of calldata.

```
execute(target, value, data, idx, sig_0, auth_0):          # cached subtree
    l    = idx >> (2h − b)                                  # lane
    require idx ≥ nextIdx[epoch, l]                         # IndexUsed
    t_0 = idx >> h ; j_0 = idx & (2^h-1)
    M    = H("AEGIS_CCHS_V1" ‖ chainId ‖ this ‖ nonce[epoch, l] ‖ idx ‖ target ‖ value ‖ keccak256(data))
    pk_0 = WOTS_pk_from_sig(0, t_0, j_0, M, sig_0)
    R_0  = MerkleRootFromPath(T_leaf(…, pk_0), j_0, auth_0)
    require cachedRoot[epoch, t_0] ≠ 0                      # MissingTopLayer
    require cachedRoot[epoch, t_0] == R_0                   # BadSubtreeRoot
    finish(idx)

executeFirst(target, value, data, idx, sig_0, auth_0, sig_1, auth_1):
    … as above through R_0 …
    if cachedRoot[epoch, t_0] ≠ 0:
        require cachedRoot[epoch, t_0] == R_0               # redundant proof: ignored
    else:
        pk_1 = WOTS_pk_from_sig(1, 0, t_0, R_0, sig_1)
        R_1  = MerkleRootFromPath(T_leaf(…, pk_1), t_0, auth_1)
        require R_1 == root                                 # BadTopRoot
        cachedRoot[epoch, t_0] = R_0

finish(idx):
    nextIdx[epoch, l] = idx + 1 ; nonce[epoch, l] += 1      # effects
    call target                                             # interaction
```

Every `ADRS(…)` above carries the account's stored `pkSeed` (§2.1), so a signature made for one tree reaches no root of another tree even at the same position; the verifier passes the seed into `WOTS_pk_from_sig`, `T_leaf` and `MerkleRootFromPath` and stores it next to the roots (one `bytes16` packed with `epoch` and `recNonce` in the EVM contracts, so it costs no extra storage slot).

Lane state is keyed by `(epoch, l)` and packed in one storage slot per lane (`nonce ‖ nextIdx`), so a signature costs the same one load and one store as a single counter would, plus a one-time 17 K gas when a lane is first used in an epoch (zero to non-zero store). A fresh lane reads as `nextIdx = l · 2^(2h−b)`, `nonce = 0`. `digestAt(idx, …)`, `needsTopLayerAt(idx)`, `nextIdx(l)`, `nonce(l)` and `laneOf(idx)` are the views the client checks before signing.

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

Measured on `evm/src/AegisCCHS.sol` (S-20, SHA-256 precompile from assembly) and `evm/src/AegisCCHSK.sol` (K-20, keccak256 opcode) with the deployed build settings (solc 0.8.37, optimizer 1 000 000 runs, viaIR, Cancun, no metadata — `deploy/deploy-cchs.mjs --build`), the TypeScript client producing the signatures and the whole transaction ABI-encoded. *Total* = 21 000 intrinsic + calldata (measured bytes; 16 gas per non-zero byte, 4 per zero byte; hash output is essentially all non-zero) + execution.

| Case | Calldata | S-20 execution | S-20 total | K-20 execution | K-20 total |
|---|---|---|---|---|---|
| Cached subtree (`execute`) | 2 628 B ≈ 40.2 K | ~200 K | **~261 K** | ~116 K | **~177 K** |
| New subtree (`executeFirst`, first of 1024) | 5 092 B ≈ 79.5 K | ~457 K | ~558 K | ~268 K | ~368 K |
| First signature in a second lane (`executeFirst`) | 5 092 B | ~434 K | ~535 K | ~258 K | ~359 K |
| Recovery | 2 500 B ≈ 39.5 K | ~189 K | ~249 K | ~115 K | ~176 K |
| Account deploy via factory | 132 B | ~1 583 K | ~1 606 K | ~1 562 K | ~1 584 K |
| Runtime code | | 7 237 B | | 7 130 B | |

(`wallet/scripts/evm-flow.mts`, run in CI, prints this table for the current build; the lane state costs one extra keccak for the mapping key and a one-time zero-to-non-zero store per lane and epoch. The 16-byte `pkSeed` adds 32 B of calldata to `recover` and to the account's init code, no hash input bytes and no storage slot; the verification cost per chain step is unchanged, and the differences from the previous revision of this table are within the digit-dependent spread noted below.)

Execution gas moves by about ±10 % with the digits of the particular digest (the verifier walks `w − 1 − digit` steps per chain), so the figures are for the fixture's messages, not bounds. Calldata is about a quarter of the cached-path total and is irreducible for a hash-based signature (2 464 B of chain values and path). EIP-7623 (Pectra) prices calldata at a floor of 10 gas per token when execution is small; execution exceeds the floor on every path here, so the floor never binds. Against ECDSA (65 B, ≈ 24 K for a plain transfer) a cached K-20 operation costs about 7× in gas and 40× in bytes. The design optimizes the amortized cost of a hash-based signature; it does not remove that gap, and for high-frequency or very small payments an ECDSA daily path with CCHS as the recovery root (§8, hybrid) is the right configuration.

The account also implements the ERC-721 and ERC-1155 receiver callbacks and ERC-165, so any asset can be sent to it with a safe transfer; those four pure functions account for ~0.9 KB of the runtime. (Without them: 5 296 B / 5 184 B, S-20 cached ~232 K, K-20 cached ~118 K. With optimizer 200 runs and no viaIR the code is 3 831 B / 3 666 B and K-20 cached execution is ~128 K; the deployed build trades code size for ~10 K gas per signature.)

Execution gas includes the outgoing `call` (9 K for value transfer, 25 K if it creates the recipient), one packed SSTORE, and the event — roughly 45 K that is not verification. K-20 verification proper is ~75 K; S-20 ~160 K.

SPHINCS+ C13 on-chain verification is ~190 K compute + 3 688 B calldata (~59 K) + 21 K ≈ 270 K per signature and needs a separate 14.6 KB verifier contract. K-20 is ~1/3 cheaper than that on every signature, S-20 is at parity; both use about 1/3 the code and no external contract.

**Which set to deploy.** `CCHS-K-20` is the EVM default: signatures are bound to a chain ID, so an EVM account never shares a signature with Bitcoin Script, and the keccak opcode is the cheaper primitive. `CCHS-S-20` is the canonical set and the one every non-EVM port implements (each chain still has its own tree, §3). Both are deployed by the same factory (§5.4).

### 5.3 Cache registration is permissionless, not cross-chain

The top-layer message is the bottom subtree root `R_0`, which contains no chain identifier, and the registration `(sig_1, auth_1)` is valid for any account whose `root` is the tree's root. Registering the correct root is harmless wherever it is replayed, so anyone may submit it (a relayer, a sponsor, the user from another device) and the write is idempotent. It is *not* portable between chains: since each chain has its own tree (§3), no two chains share a `root`, and a top-layer signature produced for chain A registers nothing on chain B. The first-in-subtree premium is therefore paid once per subtree *per chain*. An earlier revision of this section described the same `l1` as valid on every chain of a parameter set; that was true of the shared-tree design and was withdrawn together with it, because sharing a tree also shares its one-time leaves (§3, §4.3 rule 7).

### 5.4 Factory and same-address deployment

`evm/src/AegisCCHSFactory.sol` deploys either set with CREATE2, `salt = keccak256(root ‖ recRoot ‖ pkSeed ‖ variant)` and init code `creationCode ‖ abi.encode(root, recRoot, bytes16 pkSeed)`. With metadata-free bytecode and the factory itself at the same address on every EVM chain, `(root, recRoot, pkSeed, variant)` maps to one address on all of them; since the roots are derived per chain (§3), each chain's account has its own address. `deploy()` is permissionless and idempotent; `predict()` is pure in the chain ID.

### 5.5 Split cache fill and the single-packet set (CCHS-C-20)

The cache write in §5 is the only place a top-layer signature is consumed, and C3/C4 (§6) make it independent of the bottom-layer check that follows. Nothing therefore requires the two layers to arrive in the same transaction. The verifier can expose the cache fill as its own operation:

```
cache_subtree(t_0, R_0, sig_1, auth_1):
    require cachedRoot[epoch, t_0] ∈ {∅, R_0}
    require MerkleRootFromPath(WOTS_pk_from_sig(1, 0, t_0, R_0, sig_1), t_0, auth_1) == root
    cachedRoot[epoch, t_0] = R_0

execute(target, data, sig_0, auth_0):          # one layer, always
    R_0 = cachedRoot[epoch, nextIdx >> h]  ; require R_0 ≠ ∅
    ... as §5 with the cached branch only
```

Soundness is unchanged: `cache_subtree` writes only what a valid top-layer signature on `R_0` authorizes (C3), and `execute` accepts only what full verification would accept (C4). Anyone may submit `cache_subtree`; it is idempotent and, by §5.3, needs no authorization beyond the top-layer signature itself (it is valid only for the chain whose tree produced it). Liveness is also unchanged: the owner can always warm the next subtree before it is needed.

This split matters on chains with a hard transaction-size ceiling. Solana packets are 1 232 bytes; one S-20 layer is 2 464 bytes. For such chains the spec defines a third parameter set whose single layer fits a packet:

| | S-20 / K-20 | **C-20** |
|---|---|---|
| hash output `n` | 32 B | 24 B (SHA-256 truncated) |
| generic preimage cost, classical / Grover | 2^256 / 2^128 | 2^192 / 2^96 |
| NIST category by the AES yardstick | 5 | 3 (AES-192: 2^192 / 2^96) |
| Winternitz `w` | 16 | 256 |
| chains | 64 + 3 = 67 | 24 + 2 = 26 |
| one layer | 2 464 B | **864 B** |
| verifier hashes per layer (avg / worst) | ≈ 520 / 1 001 | ≈ 3 300 / 6 386 |
| keygen hashes (top + recovery + first subtree, single thread) | ≈ 2.3 M | ≈ 15 M |

Measured (`wallet/src/aegis/cchsCompact.ts`, Node 24): keygen top + recovery 15.6 s and first subtree 12.7 s single-threaded in pure JS, 5.4 s for all three on the eight-worker WASM pool; sign 6.5 ms cached / 12.2 ms with top layer; local verify 6.5 ms / 14.5 ms; a legacy Solana `execute` transaction on the cached path (one signer, seven account keys, the 8-byte signer-chosen `idx`, 12-byte inner instruction) is 1 231 B of 1 232, 1 198 B when the recipient is the payer; because C-20 verification exceeds the 200 K default compute budget the transaction also needs `SetComputeUnitLimit`, which fits only as a v0 message with an address lookup table: 1 090 B, leaving 142 B for inner-instruction data; the `cache_subtree` transaction is 1 174 B (1 214 B with the compute-budget instruction). Compute units measured on the SBF build in the `solana-program-test` runtime (CI job `Solana`, `solana/cu-test`): `execute` 616 K / 662 K / 708 K CU for layers of 3 315 / 3 570 / 3 825 chain steps (≈ 180 CU per step plus 20 K), `cache_subtree` 612–658 K, `recover` 652 K, `create` 19 K; the linear fit puts the 6 375-step worst case at ≈ 1.17 M CU, under the 1.4 M per-transaction maximum, so every `execute` needs `SetComputeUnitLimit` (the syscall-only estimate of ≈ 376 K in `solana/README.md` was a lower bound). Bit flip, foreign digest, index replay, wrong cached root, and tampered top-layer path were all rejected; recovery accepted once and rejected on replay. Key derivation is domain-separated (`cchs/sk/c`), so a master seed yields independent C-20 keys. The checksum for `w = 256` is `Σ(255 − m_i) ≤ 6 120`, two base-256 digits.

**Security of C-20, with numbers.** The rows above are generic single-target costs of the truncated hash; the scheme is a multi-target object. What has to be counted, and what the design does about it, is the following.

*Targets within one tree.* Per epoch a verifier may be shown every intermediate chain value of every leaf: 2^20 leaves × 26 chains × 255 positions ≈ 2^32.7 values at layer 0, plus 2^10 × 26 × 255 ≈ 2^22.7 at layer 1, plus leaf and node hashes (≈ 2^21). Call it T ≈ 2^33. For S-20/K-20 the same count is 2^20 × 67 × 15 ≈ 2^29.9, T ≈ 2^30. Each of these values is the output of a *different* tweaked function, because its ADRS (§2.1) is unique within the tree; that is what the SPHINCS+ argument below relies on.

*Targets across trees.* The ADRS fields of §2.1 other than `pkSeed` are the same for every account in existence: leaf 0, chain 0, step 0 of layer 0 is one function for all of them. Before this revision the last 16 bytes of ADRS were zero, so an adversary who collected the chain values of 2^k accounts (all public, on 2^k chains or one chain) had 2^k outputs of each function and the multi-target loss of the whole system was log₂(T) + k bits, not log₂(T). This is the multi-user gap that SPHINCS+ closes with `PK.seed` and that the earlier text of this section did not address. `pkSeed` closes it here: the seed is in every ADRS, so the functions of two trees are distinct at every position, and collecting more accounts gives the adversary more *functions*, not more targets per function. With the seed, the accounting of the whole system equals the accounting of one tree, whatever the number of accounts; the seed does not have to be secret for this, only distinct per tree, which a 128-bit HKDF output gives with collision probability 2^−128 · (accounts)² / 2.

*Conservative accounting* (count the T targets of one tree, give the ADRS tweak no credit): a second preimage on any one of T outputs costs 2^8n / T classically and about 2^(8n − log₂T)/2 with Grover.

| | S-20 / K-20 (n = 32, w = 16) | C-20 (n = 24, w = 256) |
|---|---|---|
| classical | 2^256 / 2^30 ≈ **2^226** | 2^192 / 2^33 ≈ **2^159** |
| quantum (Grover, multi-target) | ≈ **2^113** | ≈ **2^80** |
| AES yardstick | above AES-192 (2^96 quantum) | between AES-128 (2^64) and AES-192 (2^96) |

*Tight accounting* (the SPHINCS+ argument: the address tweak makes every chain position a distinct function, so the adversary must commit to a target before querying; the SM-TCR / SM-DSPR reductions of the SPHINCS+ submission are tight in the random-oracle model and lose only the query count in the quantum ROM): 2^192 / 2^96 for C-20, 2^256 / 2^128 for S-20/K-20, i.e. AES-192 and AES-256 respectively. The Winternitz parameter enters these bounds only through T; `w = 256` costs about 3 bits more of target count than `w = 16` at equal n, not more. The comparison point is SLH-DSA-192 (FIPS 205), which has the same `n = 24`, the same per-call ADRS, the same public seed in every hash input and a *larger* target count (2^64 signatures of a hypertree with 2^63 leaves, plus FORS), and is standardised at category 3 on exactly this argument; C-20 is that argument at a smaller target count with a wider Winternitz chain.

*What this means.* S-20 and K-20 clear the AES-192 yardstick under either accounting. C-20 clears it under the tight accounting and does not under the conservative one, and both accountings are now statements about a single tree regardless of how many accounts exist (the `pkSeed` paragraph above). The honest label for C-20 is therefore "NIST level 3 by the argument that places SLH-DSA-192 at level 3, level 1–2 if that argument is refused". The CCHS-specific parts (the cached subtree root, the signer-chosen index, the epoch-keyed cache) do not add hash targets beyond the hypertree itself, but the written reduction with explicit constants for `(n = 24, w = 256, 2^20)` under the SPHINCS+ framework is still an open item (§11); what this revision removes is the multi-user term that no such reduction could have absorbed. A design alternative that clears the conservative bar is `n = 28` (classical 2^224 / 2^33 ≈ 2^191, quantum ≈ 2^95.5): the layer grows from 864 B to 1 008 B, which no longer fits a legacy Solana packet on the cached path, and by the current layout misses the v0-with-lookup-table limit by about 2 B (1 090 B measured for n = 24 with a 12-byte inner instruction leaves 142 B; n = 28 needs 144 B more), so it would require trimming the instruction encoding or a two-packet path. Until that measurement and the written bound exist, the parameter set stays at n = 24 and carries the two-level label above.

What C-20 trades: ~6× more verifier compute per layer and ~6× more keygen work for a 2.85× smaller signature. On a chain that meters compute rather than bytes (EVM) it is the wrong trade; on a chain that caps bytes per transaction (Solana) it is the only one that gives a single-transaction hot path without a staging buffer.

**Why the top layer does not get its own Winternitz parameter.** CCHS verifies the top layer once per subtree and the bottom layer once per signature, so the two layers could in principle use different `w`: a large `w` on the top layer would shrink the first-in-subtree proof at a compute cost paid only every 2^10 signatures. The arithmetic says no on every chain this document targets. On the EVM with K-20, `w = 256` on the top layer cuts the 67 chains to 34 and the layer from 2 144 B to 1 088 B, saving about 17 K gas of calldata, while the expected chain work rises from 67 × 7.5 ≈ 500 to 34 × 127.5 ≈ 4 335 hash steps; the measured difference between `executeFirst` and `execute` (≈ 125–145 K execution gas for one layer of ≈ 500 steps, 10 Merkle nodes, the public-key compression and the 20 K cache write) puts a step at roughly 200 gas, so the change would add ≈ 0.75 M gas to every first-in-subtree transaction, i.e. ≈ 730 gas per signature amortized against 17 gas saved. On Solana, C-20 already uses `w = 256` on both layers because bytes, not compute, are the binding constraint, and the bottom layer cannot go the other way (`w = 16` with n = 24 needs 51 chains, 1 224 B, which does not fit a packet). On Bitcoin the chain check is unrolled in script, so script size grows linearly in `w` (`BITCOIN.md` §5.6). The layers therefore share one `w` per set, and the asymmetry CCHS exploits is the cache, not the parameter.

### 5.6 Wider hash outputs: which path limits the scheme, and what `n = 36 / 48 / 64` would cost

A longer hash output raises the security of the scheme only along the paths that go through that hash, and only up to the next path that does not. To say which paths exist, fix the game.

**The game.** A receives the public key of one account (`root`, `recRoot`, `pkSeed`), reads the chain and the mempool, and has a signing oracle: for any `(target, value, data)` of its choice the owner signs at the lane's next index and the transaction lands, so A sees every bottom-layer signature, every cache registration with its top-layer signature, and every pending digest before it lands. A wins if the verifier accepts `(target', value', data', idx', sig', auth')` for a tuple the oracle never signed at `idx'` in the current epoch. The hash is the only assumption, so every winning transcript must contain one of the following events, and the cost of the game is the cost of the cheapest:

| Path | Event in a winning transcript | Target count | Classical / quantum at `n = 32` | Grows with `n`? |
|---|---|---|---|---|
| P1 chain step | at a leaf whose signature A has seen (or the one pending), `sig'` contains a chain value *earlier* than the shown one, or a different value with the same image: a (second) preimage of `F` at a position of the tree | `T ≈ 2^30` per tree, every position a distinct tweaked function | tight 2^256 / 2^128; conservative 2^226 / 2^113 | yes |
| P2 leaf and node | at a leaf A has not seen, `(leaf', auth')` hashes to the cached `R_0` or to `root`: a second preimage of `T_leaf` / `T_node` on an authentication path | inside the same `T` | as P1 | yes |
| P3 message digest | `M' = M` for a different `(target', value', data')`, against the one pending digest (a landed digest carries a spent lane nonce and is useless), or `keccak256(data') = keccak256(data)` | one | 2^256 / 2^128 under either accounting (one target, A controls a suffix) | **no** — `M` is a 32-byte `H` by §4, whatever `n` is |
| P4 seed search | A finds the seed (mnemonic or `master`) by Grover search, testing each candidate against one public chain value: candidate → `master` → `key(chain)` → `sk_c` → `F^{d_c}` → compare with the shown `sig_c` (≈ 2^5 hashes per test from `master`; ≈ 2^12 from a mnemonic, PBKDF2's 2 048 HMAC-SHA512 rounds dominate) | one per account; the test needs one landed signature, nothing else | **2^(e/2) · 2^12 for a mnemonic of `e` bits of entropy, capped by 2^128 · 2^5 ≈ 2^133 for the search over the 32-byte `master`**: ≈ 2^133 hash-equivalents at 24 words (`e = 256`), ≈ 2^76 at 12 words (`e = 128`). An earlier revision put this path at "2^128 iterations each costing a key generation (2^20 hashes)" and called it bounded by P1; that was wrong twice — a candidate is checked against a single chain value, not by rebuilding the tree, and the path does not go through a preimage of `F` at all | **no** — the seed is 256 bits whatever `n` is |
| P5 shared seed | two trees whose hash calls are one function at every position, so that P1/P2 have more than one tree's targets per function | — | not a search. `pkSeed` is public: A may create a tree with the victim's seed at no cost, and gains nothing, because its own chain values are not targets (A needs preimages of the *victim's* values, and those are one tree's worth whatever A does). What the seed prevents is two *honest* trees sharing functions; that is a birthday event among honest users, probability `N²/2^129` for `N` accounts, 2^−49 at `N = 2^40`, and there is nothing for an adversary — classical or Grover — to search over, since it does not choose honest users' seeds | no |

Two corrections to earlier wordings of this table are deliberate and kept visible. P5 was listed as "2^128 classical" as though it were a search an adversary could mount and a quantum adversary could halve to 2^64; it is neither: a seed the adversary chooses produces no useful target, and a seed collision between honest trees is a probability, not a cost. P4 was listed first as a 2^128 cap and then as "bounded below by P1"; the row above is the correct accounting, and its consequence is the opposite of the second wording: **P4 is the one path that no choice of `n` or of the digest moves**, because the seed is 256 bits at most (BIP-39's 24 words), and it is the cheapest path of all for a 12-word mnemonic. The units differ between rows — P1–P3 count hash queries of a Grover search, P4 counts hash-equivalent work with the per-candidate cost included — so the comparison is at the level of a few bits, which is also why P4 at ≈ 2^133 is quoted as "about 2^128", not as a gain.

Two consequences are acted on. The reference wallet refuses to create or operate a CCHS account from a mnemonic of fewer than 256 bits (`CCHS_MIN_SEED_BITS` in `wallet/src/aegis/derive.ts`; the Protect panel shows the arithmetic instead of the form), since a 12-word phrase would put the account at ≈ 2^76 behind signatures worth 2^113. And §3's derivation is stated as a requirement, not a convention: `master` is 32 bytes from at least 256 bits of seed entropy.

At `n = 32` the scheme is balanced: under the tight accounting every path costs about 2^128 quantum work, and the number in the abstract is that one. Under the conservative accounting P1/P2 drop to 2^113 and become the limiting paths; P3 and P4 stay at ≈ 2^128. This is the precise sense in which "doubling the output does not double the security": raising `n` moves P1/P2 and nothing else, so

- `n = 36` (288-bit output, the smallest `n` with `8n − log₂T ≥ 256`) lifts the *conservative* bound of P1/P2 to ≈ 2^129 and leaves the scheme at ≈ 2^128, where P3 and P4 now limit;
- `n = 48` lifts P1/P2 to 2^192 tight / ≈ 2^177 conservative, and the scheme is still ≈ 2^128 by P3 and P4;
- `n = 64` lifts P1/P2 to 2^256 / ≈ 2^240 and the scheme is still ≈ 2^128 by P3 and P4.

Moving the scheme as a whole to 2^192 would therefore require all of: `n = 48`; a 384-bit digest in §4 carried by `len_1 = 96` chains; a 48-byte `master`, `key(chain)` and `sk` derivation; and at least 384 bits of seed entropy behind the master, which no BIP-39 mnemonic provides (24 words are 256 bits) — the seed would be a 36-word phrase or a raw 48-byte secret, outside the wallet standard every other key of the user lives in. None of the chains this document targets has a native hash wider than 256 bits (the EVM has `keccak256` and the SHA-256 precompile, Solana `sol_sha256`/`sol_keccak256`, the Move chains `sha2_256`/`sha3_256`, Cairo `sha256`), so every `F`, `T_leaf`, `T_node` and the digest would be two hash calls with a domain byte, and the verifier's hash count doubles on top of the growth in chains.

*A 384-bit digest from 256-bit primitives is itself a claim, not a length.* The construction would be `M = H(0x00 ‖ X) ‖ H(0x01 ‖ X)[0..16]` for the §4 preimage `X` (about 200 bytes, four SHA-256 blocks). In the random-oracle model with the two prefixes the halves are independent and a second preimage costs 2^384 / 2^192. SHA-256 is not a random oracle but a Merkle–Damgård function with a 256-bit chaining state, and the known gap between a concatenation of two such functions and a 2n-bit random oracle is exactly that state: Joux's multicollisions (2004) make collisions on the concatenation cost ≈ 2^128 · (a few), not 2^192, and Dinur's preimage attacks on concatenation combiners (2016) go below 2^256 for messages of ≈ 2^(n/4) blocks. Collisions are not the game here (the digest carries a nonce the adversary does not choose), and a four-block `X` is far from the message lengths those preimage attacks need, so the construction plausibly reaches 2^192 against second preimages of short inputs — but that is an argument about a specific combiner on a specific primitive, and it would have to be written and reviewed before the number could be quoted; `SHA-512/384`, which gives the width natively, has no precompile on any target chain. FIPS 205 defines no `n > 32`, and NIST SP 800-208 admits `n = 24` and `n = 32` for LMS/XMSS; a wider set would be outside every standardised hash-signature parameter and would need its own written bound.

What the three candidates cost, computed from §2 and estimated from the measured K-20 build of §5.2 (≈ 170 gas per hash call plus ≈ 25 K fixed in `execute`, 16 gas per calldata byte, two hash calls per `F` for `n > 32`; these are extrapolations, not measurements, and would move by tens of percent in a real implementation):

| | `n = 32` (K-20, measured) | `n = 36` | `n = 48` | `n = 64` |
|---|---|---|---|---|
| `len_1 + len_2` chains | 64 + 3 = 67 | 72 + 3 = 75 | 96 + 3 = 99 | 128 + 3 = 131 |
| one layer | 2 464 B | 3 060 B | 5 232 B | 9 024 B |
| first-in-subtree (two layers) | 4 928 B | 6 120 B | 10 464 B | 18 048 B |
| verifier hash *calls* per layer, avg | ≈ 520 | ≈ 1 150 | ≈ 1 500 | ≈ 1 980 |
| `execute`, cached, whole transaction | **≈ 173 K** | ≈ 300 K | ≈ 400 K | ≈ 550 K |
| `cachedRoot` and `root` storage | 1 slot each | 2 slots each (+20 K gas per subtree, +40 K at creation) | 2 | 2 |
| Solana single-packet path | C-20 only | none (3 060 B is three packets) | none | none |
| conservative quantum bound, P1/P2 | 2^113 | ≈ 2^129 | ≈ 2^177 | ≈ 2^240 |
| scheme bound with the 32-byte digest and a 256-bit seed (P3, P4) | ≈ 2^128 | ≈ 2^128 | ≈ 2^128 | ≈ 2^128 |
| scheme bound if digest, master *and* seed entropy all widen with `n` (tight / conservative) | 2^128 / 2^113 | ≈ 2^144 / 2^129 | 2^192 / ≈ 2^177 | 2^256 / ≈ 2^240 |

The parameter decision this document takes is therefore: `n = 32` stays the default, labelled as 2^128 under the tight (FIPS 205) accounting and 2^113 under the conservative one, both stated in the abstract, and conditioned on a 256-bit seed, which the wallet enforces. `n = 36` is the candidate if a deployment refuses the tight accounting and wants every path at or above 2^128 for about 1.75× the gas and 1.25× the bytes; it is recorded in §11 as an evaluated alternative with no implementation. A 2^192 configuration is **not** offered: it needs `n = 48`, the 384-bit digest with the combiner argument above, a 48-byte master and a seed outside BIP-39, all at once, and the first three are estimates while the last is a different wallet standard; §11 records the list so that nobody reads the `n = 48` column as a result. `n = 48` or `n = 64` with any of those pieces missing buys nothing for the scheme as a whole. None of this touches the Lean proofs of §6.2, which abstract the hash and hold for every `n`; what a change of `n` does touch is the contracts, the encodings, the fixtures of §10, and the two accountings of §5.5, which would have to be rewritten for the new `T` before the new set could carry a label.

---

## 6. Security

### 6.1 Model

Adversary A: full view of chain and mempool; unbounded classical compute; quantum compute sufficient to break all discrete-log, factoring, and lattice assumptions; Grover oracle access to SHA-256.

### 6.2 Claims

**C1 — Unforgeability.** A cannot produce an accepting signature for `(target', value', data')` not authorized by the owner.

Sketch. Acceptance requires a WOTS+ signature under key `(0, t_0, j_0)` on `M'`. Each WOTS+ key is used at most once (enforced by `nextIdx` monotonicity). WOTS+ with checksum is existentially unforgeable under one-time chosen-message attack assuming second-preimage resistance of `F` (Hülsing 2013, Theorem 1), with the ADRS tweak eliminating multi-target advantage within the tree and `pkSeed` (§2.1) eliminating it across trees. A's best attack is a preimage search: 2^128 Grover queries under the tight accounting, 2^113 if the tweak is given no credit (§5.5, §5.6 path P1). The unconditional claim of this document is the second figure; the first is conditional on the FIPS 205 argument until the reduction of §11 item 8 is written for CCHS.

**C2 — Mempool front-running is infeasible.** A observes `(sig_0, auth_0)` for `M` in the mempool and attempts to submit a transaction for `M' ≠ M` in the same block.

Sketch. `M' ≠ M` ⇒ base-16 digit vectors differ. The checksum guarantees ∃ chain `c` with `digits'[c] > digits[c]`. A holds `sig_c = F^{digits[c]}(sk_c)` and needs `F^{digits'[c]}(sk_c)` — a value *earlier* in the chain. Computing it requires inverting `F`. Same bound as C1. The alternative, `M' = M` for a different transaction, is a second preimage of the single pending 32-byte digest: 2^128 under either accounting (§5.6 path P3).

**C3 — Cache integrity.** A cannot cause `cachedRoot[t_0]` to hold a value other than the owner's `TreeRoot(0, t_0)`.

Sketch. Writing requires a WOTS+ signature under top key `(1, 0, t_0)` on the written value, verified against immutable `root`. A does not hold `sk(1, 0, t_0, ·)`. If the owner has already registered `R_0`, A observing `sig_1` on `R_0` cannot forge `sig_1'` on `R_0' ≠ R_0` (C2 argument). If the owner has not yet registered, A has no signature to work from. The write is permitted once, so a correct registration cannot be overwritten.

**C4 — Cache soundness.** Accepting via the cached branch is equivalent to accepting via full verification.

Sketch. `cachedRoot[t_0] = R_0` was written only after `R_1 == root` was checked with a valid `sig_1` on `R_0`. The cached branch then requires `MerkleRootFromPath(leaf_0, j_0, auth_0) == R_0`, which is exactly the condition the full path would have imposed on layer 0. The layer-1 condition is a pure function of `(R_0, sig_1, auth_1, root)` — already checked, and unchanged.

**C5 — One landed signature per leaf, and signer-controlled skipping.** For every `(epoch, idx)` at most one `execute`/`executeFirst` succeeds, and the `nextIdx` of a lane only moves to a value the key holder signed in that lane.

Sketch. Both entry points require `idx ≥ nextIdx[epoch, l]` for the lane `l` of `idx` and set `nextIdx[epoch, l] = idx + 1` before the external call, so a second acceptance at the same `idx` is impossible and a lower `idx` is rejected without hashing. `idx` is an input to `M`, so a signature at `idx` is not valid at `idx' ≠ idx` (C1), and since the lane is a function of `idx`, neither is it valid in another lane; A cannot therefore move any `nextIdx` anywhere the owner did not sign. Recovery opens fresh lanes under a new `epoch`, and the cache key includes `epoch`, so pre-recovery signatures are not accepted afterwards (their `(layer, t_0, j_0)` keys live under the old `root`; C3). What C5 does not cover is a signature the owner produced that never landed: the chain cannot see it, and §4.3 places that obligation on the client.

**LI — Lane independence.** An acceptance in lane `l` changes the verdict of the verifier on no signature made for another lane. Sketch. The verdict on a signature at `idx'` depends on `nextIdx[epoch, l']`, `nonce[epoch, l']` and `cachedRoot[epoch, idx' >> h]` with `l' = lane(idx')`; an acceptance in lane `l ≠ l'` writes `nextIdx[epoch, l]`, `nonce[epoch, l]` and possibly `cachedRoot[epoch, idx >> h]`, and `idx >> h ≠ idx' >> h` because lanes are unions of whole subtrees (`b ≤ h`). This is what makes a device that owns a lane independent of every other device: nothing it reads can be changed by them.

**State machine.** The account's authorization state is `(root, recRoot, pkSeed, epoch, nextIdx[·], nonce[·], recNonce, cachedRoot)`; the models and proofs below abstract the hash and therefore treat `pkSeed` as part of the key under which a signature was made, not as a separate variable. `model/cchs-state.mjs` explores every reachable state of an abstracted model (`h = 1`, four subtrees in two lanes, one recovery, up to five owner signatures; the hash is replaced by "the recomputed root is right exactly when the inputs are the ones signed") under an adversary that may submit any signature it has seen at any index, target or entry point, in any order, and may forge freely with the bottom keys of any subtree that is entirely behind its lane's `nextIdx`. C3, C4, C5, LI and non-forgeability are checked on every one of ~7 × 10⁷ submissions over ~4.9 × 10⁵ states, and six deliberately broken verifiers (no index check, cache key without epoch, index not in the digest, top layer not bound to `R_0`, index checked against lane 0 for every lane, one nonce shared by all lanes) are each caught; the last one is caught by LI alone, which is the property a single shared counter lacks. It runs in CI. It is a bounded model check of the transition logic, not a proof about the hash function.

**Client model.** `model/cchs-client.mjs` checks the other half: the rules of §4.3 under the events the chain cannot see. Two devices share a master; each keeps a persistent `signedMax` and may back it up and later restore the older copy; signed transactions enter a pool from which they land (verifier rules) or are dropped in any order; recovery to a new epoch is available; every signature ever produced is remembered. The invariant is ONE-MESSAGE: no `(epoch, leaf)` ever signs two different messages. It holds on every reachable state (≈ 1.7 × 10⁵ states, 6.4 × 10⁵ transitions at the model's bounds), and each of five weakened clients is caught with a concrete trace: recording the index after signing (crash in between), restoring a backup and merely waiting for the pool to drain instead of rotating, two devices without partition, no record at all, and recovery with non-deterministic new roots. A second configuration (`--chains=2`) runs two chains with independent on-chain state from one mnemonic; the reference client (one tree per chain, §3) holds, and the mutant `shared-tree`, which signs on both chains from one tree, violates ONE-MESSAGE after two signatures: leaf 0 signs the digest of chain 0 and then the digest of chain 1. `wallet/scripts/check-index-discipline.mts` tests the wallet's implementation of the same rules, and `wallet/scripts/evm-flow.mts` runs the full life cycle including a rotation against the shipped contracts. The client model still partitions two devices by subtree under one counter (the pre-lane convention); the proof below covers the lane rule.

**Machine-checked proofs.** `proofs/` (Lean 4, no Mathlib, built in CI) proves the transition-system part of the above for *every* parameter choice and every reachable state, where the model checks explore small bounds. The hash is abstracted the same way: a signature object remembers its inputs, recomputation over any other inputs yields a value that matches nothing. Proven for the verifier (`proofs/Cchs/Verifier.lean`): C4 (`cache_genuine`: cache entries are the owner's bottom roots of their epoch), `cache_once` (an entry never changes), NF/C3 (`accept_inputs`: an accepted signature was made in the current epoch over exactly the accepted index, lane nonce and target; `register_not_leaked`), C5 (`nextIdx_mono`, `no_double_accept`: no `(epoch, idx)` is accepted twice along any execution), `leaked_rejected` (under the exposure hypothesis of §4.3 the index check alone rejects every submission at a leaf of an abandoned subtree) and LI (`lane_independence`: an update in one lane leaves the verdict on every submission for another lane unchanged; the proof needs only that lanes are unions of whole subtrees). For the client (`proofs/Cchs/Client.lean`), ONE-MESSAGE (`one_message`) for any number of devices with pairwise distinct lanes, under write-ahead records, backup restores (which make a device stale until recovery) and recoveries. What the proofs do **not** cover is stated at the top of each file: hash security, the WOTS+ two-message exposure itself (taken as the hypothesis of `leaked_rejected`), the recovery leaf and multi-chain derivation, and a client that records after signing (excluded by construction, caught by the bounded model). CI rejects `sorry` and any axiom beyond Lean's standard three.

### 6.3 Not covered

- The client device. The reference wallet never persists the mnemonic or any key: `master`, `key(chain)` and the per-epoch keys live in page memory for the session, and `localStorage` holds only the index record and the device lane, neither of which is secret. Malware that reads that memory holds the account, and no parameter of this document changes that; hardware isolation of the signer is the remedy and is not implemented. The timing of WOTS+ signing (chain lengths = the digits of `M`) leaks only `M`, which is public on chain; key generation hashes every chain to its full length. What remains is whatever the JavaScript runtime leaks about the secret itself (heap, garbage collection, swap), which is the compromised-device case above, not a side channel of the scheme.
- Chain-level failures (reorg past finality, consensus bugs).
- Loss of `master`. See §8 recovery.
- Signatures produced by the client that never landed (§4.3); the chain cannot observe them.
- A machine-checked proof of the *cryptographic* reductions. The Lean proofs in `proofs/` cover the transition system with the hash abstracted; the sketches above reduce the rest to Hülsing 2013 + standard Merkle arguments, and formalising that reduction (EasyCrypt-style) is future work.
- External audit. None has been performed.

---

## 7. Cross-chain deployment

The verification algorithm uses only SHA-256, byte concatenation, integer shifts, 32-byte storage, and one `call`. The *verifier code* is portable: the same algorithm runs on every chain. The *keys* are not shared: each chain has its own tree (`key(chain)`, §3), so signatures, roots and cached subtree roots are specific to one chain, and the chain id bound inside `M` additionally stops a signature from being replayed elsewhere.

| Chain | Hash primitive | Storage for `cachedRoot` | Note |
|---|---|---|---|
| EVM (ETH, BSC, Polygon, Arbitrum, Optimism, Base, …) | precompile 0x02 | mapping | `evm/src/AegisCCHS.sol` |
| TRON | SHA256 precompile (EVM-compatible) | mapping | same contract |
| Solana | `sha256` syscall | PDA account | ~500 LOC Rust |
| Cosmos (CosmWasm) | `sha2_256` | `Map<u64, Binary>` | ~300 LOC Rust |
| Aptos / Sui | `hash::sha2_256` | table / dynamic field | ~200 LOC Move |
| NEAR | `env::sha256` | `LookupMap` | ~250 LOC Rust |
| TON | `HASHEXT_SHA256` | dict | FunC, `ton/` |
| Starknet | `core::sha256` | `LegacyMap` | ~300 LOC Cairo |
| Bitcoin | `OP_SHA256` + `OP_CAT` + `OP_CHECKSIGFROMSTACK` in Tapscript | carried by the UTXO (leaf scripts) | §7.1, `wallet/src/aegis/btcCchs.ts` |

### 7.1 Bitcoin

Bitcoin has no mutable storage, so the cache cannot be held on-chain, and current Script cannot bind a hash-based signature to the spending transaction: a tapleaf can check WOTS+ chains against hard-coded public values (BitVM, Linus 2023), but the digits it checks are witness data, not the sighash. Without `OP_CAT` (BIP-347) or `OP_CHECKSIGFROMSTACK` the script cannot compute or compare the sighash, so a miner could reuse the WOTS+ witness on a transaction paying elsewhere. BitVM is unaffected because its digits are program state, not transaction data. Consequently there is no *practical* hash-only, transaction-binding signature on Bitcoin today: what exists (Binohash / QSB, legacy bare scripts that search the sighash with proof of work through `FindAndDelete` and a hash-to-DER parse test, `BITCOIN.md` §3.1) costs about 2^47 of work and a non-standard 10 KB output per spend and is not adopted here. The following describes what becomes possible once either opcode activates.

**(a) Flat Tapscript tree + OP_CAT.** The Taproot script tree *is* a Merkle tree. Use it as the signature tree: one tapleaf per WOTS+ key, each leaf script (i) verifying 67 chains against hard-coded pks (BitVM Winternitz pattern: compute the 16 chain states, `OP_PICK` the one at the claimed digit, `OP_EQUALVERIFY`), (ii) checking the 3 checksum digits arithmetically, (iii) reassembling the 64 message digits with `OP_CAT` and comparing them with the sighash reconstructed in-script from witness-supplied transaction fields (the CAT-covenant technique). Measured from the builder (`wallet/scripts/check-btc.mts`, which executes the leaf in an interpreter for the BIP-342 opcodes it uses: accepts the wallet's witness, rejects foreign digits, advanced chain values, another leaf's signature and non-minimal numbers, clean stack): leaf script 5 752 B for (i)+(ii), 1 005 SHA-256 evaluations; witness payload for a 2^4 test tree 8 057 B plus one byte per non-zero digit (134 WOTS items + script + 161 B control block), about 8.3 KB serialized; a 2^20 tree adds 512 B of control block. Plus the sighash fragment. Under the 4 MB weight limit. No hypertree caching benefit. `wallet/src/aegis/btcTapscript.ts` implements the tree builder, leaf-script generator (i)+(ii), BIP-341 tagged hashing and control-block construction; (iii) is left as a marked insertion point until BIP-347 is active on a network with real value. The output it builds is P2TR with a NUMS internal key, which a discrete-log adversary spends by the key path; the construction therefore also needs a key-less output type (BIP-360 P2MR). The full analysis, the dependency on both changes, and the hypertree design with UTXO-carried state are in `BITCOIN.md`.

**(b) With OP_CAT, hypertree form.** In-script Merkle verification becomes possible; a single tapleaf can verify any of 2^h bottom keys with the auth path in the witness. The cache is replaced by the UTXO itself: a spend from a "subtree UTXO" carries only the bottom layer, and creating the subtree UTXO carries the top layer. This mirrors CCHS exactly, with UTXO lineage as the cache. `BITCOIN.md` §5 specifies it: one universal code tree for all accounts, a per-account state leaf `(root, recRoot, epoch, nextIdx, R_t, t)` authenticated through the spent scriptPubKey in the sighash, `exec` / `execFirst` / `recover` leaves, a signer-chosen successor index so that several UTXOs of one lineage can be spent together, and a size estimate of about 2 500 vB per spend.

**Why no construction under current consensus closes the gap.** The requirement is that a spend be authorized by something a quantum adversary cannot compute, and that the authorization be *bound to the transaction* by rules the network enforces. Every avenue available today fails one of the two:

1. *Key-path or script-path Taproot.* A P2TR output publishes the tweaked key `Q` in the output itself. A discrete-log adversary recovers the key for `Q` without waiting for a spend, so any P2TR UTXO, including one whose internal key is a NUMS point, is spendable by the key path. Script-path restrictions do not help; the key path is always available to whoever holds the key for `Q`.
2. *Hash-locked scripts (P2WSH).* `OP_SHA256 <h> OP_EQUAL` and any WOTS+ chain check reveal preimages in the witness; nothing ties them to the outputs, so the first miner or relayer to see them can rebuild the transaction to pay elsewhere. This is exactly the missing binding, and it is what `OP_CAT`/`OP_CHECKSIGFROMSTACK` supply.
3. *Pre-signed transaction trees with key deletion.* They bind the destination, but the key that signed them is an elliptic-curve key whose public key the adversary learns from the output (P2TR) or from the first spend (P2WPKH). Deletion protects against the owner's own future compromise, not against a key recovered from public data.
4. *Commit-delay-reveal* (publish `H(tx)` first, spend later). Sound as a protocol, but no script can check that a commitment preceded the reveal; enforcement requires a consensus rule, which is why it has only been proposed as a soft fork.
5. *Proof-of-work sensing constructions.* The sighash can be probed through `OP_CHECKSIG` as a yes/no oracle (DER length of a nonce-fixed signature, which a CRQC defeats; or whether a hash of the key recovered from a fixed signature parses as DER, which it does not) and the probe result signed with hash chains (Heilman 2024, Binohash 2026, QSB 2026). The binding is as many bits as the 201-opcode budget lets one search for, about 2^118 against Shor and 2^60–70 against Grover per output at 2^47 of work per spend, and the output is a non-standard legacy script. Not adopted here; `BITCOIN.md` §3.1 records what it gives and the composition that lifts it to this document's level.

The conclusion is a statement about Bitcoin consensus, not about CCHS: a hash-only, transaction-binding spend condition needs an introspection opcode. BIP-347 (`OP_CAT`) and the quantum-resistant output proposals built on hash-based signatures are the activation paths; when either is live, (a) and (b) above apply as written.

**Posture until then** (what the wallet does for its Bitcoin address). Use outputs that do not expose the key before the spend, P2WPKH (BIP-84) rather than P2TR, never reuse an address, send change to a fresh address, and derive those keys from the same master so that they are rotated by the same backup. This limits a quantum adversary to the window between broadcast and confirmation, which is the strongest guarantee available without consensus changes. It is not post-quantum security and the wallet does not label it as such.

---

## 8. Recovery

A second, independent root `recRoot` is set at account creation: a single-layer WOTS+ tree with `h_rec = 8` (256 recoveries), derived from `master` under a distinct HKDF label.

```
recover(newRoot, newRecRoot, newSeed, sig_rec, auth_rec):
    M_rec = H("AEGIS_CCHS_RECOVER_V1" ‖ chainId ‖ this ‖ recNonce ‖ newRoot ‖ newRecRoot ‖ newSeed)
    verify WOTS+ sig_rec under recRoot at leaf recNonce      # under the current pkSeed
    root = newRoot ; recRoot = newRecRoot ; pkSeed = newSeed
    epoch += 1 ; recNonce += 1
    # new epoch ⇒ fresh lane slots (every nextIdx back to the lane's first leaf, every nonce 0)
    # and an empty cache: both mappings are keyed by epoch, nothing is iterated
```

**Where the new roots come from.** Two cases.

- *Rotation* (lost client record, §4.3 rule 5; precaution; moving to a fresh index space): the keys of epoch `e` are derived from the same chain key,

  ```
  key_0(chain) = key(chain)                                                                    (§3)
  key_e(chain) = HKDF-SHA256(key(chain), salt = ∅, info = "aegis/cchs/epoch/v1" ‖ e as 8-byte BE, 32)    (e ≥ 1)
  ```

  and every tree of epoch `e` (top, bottom subtrees, recovery) and its `pkSeed` are built from `key_e(chain)` with the per-set labels of §3. Epoch 0 is the chain key itself. `newRoot, newRecRoot, newSeed` for the rotation at epoch `e` are the roots and seed of `key_{e+1}`; the recovery signature is made with the recovery tree of `key_e` at leaf `recNonce`. The message is therefore a pure function of `(chainId, account, recNonce, e)`. A device needs only the mnemonic, the chain and the on-chain `epoch` to derive the current keys; it checks the derived roots against the on-chain `root`/`recRoot` before signing with them.
- *Compromise* (the master itself may be exposed): the user supplies a new mnemonic, and `newRoot, newRecRoot, newSeed` are the epoch-0 roots and seed of the new master. The old master's recovery tree signs this once; the new master then runs its own epoch sequence. This path is not deterministic and is subject to §4.3 rule 6.

In both cases the pre-recovery `root` is dead: its signatures are rejected by the epoch-keyed cache and the changed root (C3), as `wallet/scripts/evm-flow.mts` checks after each rotation.

Hybrid deployments (`AegisAccountV3`) may keep ECDSA as the daily path and use CCHS only as the recovery root — replacing the SPHINCS+ verifier of V2 with a ~175 K-gas, 2.5 KB alternative that needs no 15 KB verifier contract.

---

## 9. Parameter sets

| Name | Hash | d | h | Capacity | Sig (amortized) | Use |
|---|---|---|---|---|---|---|
| `CCHS-S-20` | SHA-256 | 2 | 10 | 2^20 | 2.5 KB | canonical; every non-EVM port; EVM when cross-chain byte identity is wanted |
| `CCHS-K-20` | keccak256 | 2 | 10 | 2^20 | 2.5 KB | EVM default; ~173 K total gas cached |
| `CCHS-C-20` | SHA-256/24, w = 256 | 2 | 10 | 2^20 | 864 B | packet-limited chains (Solana); cache fill is its own transaction (§5.5) |
| `CCHS-S-30` | SHA-256 | 3 | 10 | 2^30 | 2.5 KB | institutional; not yet implemented |

Key derivation (HKDF-SHA256 from the 32-byte `key(chain)`, itself derived per chain from the master; §3) uses a distinct label per set (`cchs/sk`, `cchs/sk/k`, `cchs/sk/c`; §3), so one master yields independent secret values and independent trees per set, and no secret value is ever hashed under two different functions. Each set also has its own public-seed label (`cchs/pkseed`, `cchs/pkseed/k`, `cchs/pkseed/c`), so the trees of two sets built from one key differ in every hash call, not only in the hash function.

---

## 10. Reference implementations

- `evm/src/AegisCCHSBase.sol` — hash-agnostic account logic (`execute`, `executeFirst`, `recover`, cache, digests, signer-chosen monotonic index).
- `evm/src/AegisCCHS.sol` — `CCHS-S-20`, SHA-256 precompile from assembly. 7 237 B runtime (deployed build).
- `evm/src/AegisCCHSK.sol` — `CCHS-K-20`, keccak256 opcode. 7 130 B runtime (deployed build).
- `evm/src/AegisCCHSFactory.sol` — CREATE2 factory for both sets. `deploy` is payable and forwards ETH; `deployAndMove` also pulls approved ERC-20s, so creating and funding an account is one transaction. The factory itself is published through the deterministic-deployment proxy (`deploy/deploy-cchs.mjs`, or the wallet's first Protect on a chain where it is missing; the sender does not matter), giving it the address `0x515922E1bf018EA26dA78Dfe1F928Fc01fa8a2c6` on every EVM chain where it has been deployed (the factory of the zero-padded ADRS revision was at `0x7f86A1C9f93A2751Bb83050E4C9529271Eb8817F`; accounts created by it verify under a different hash family and are not compatible with this revision); the wallet artifact (`wallet/src/aegis/cchsArtifacts.json`) carries the exact init code so account addresses can be predicted offline.
- `evm/test/AegisCCHS.t.sol` — Foundry suites for S-20 and K-20 (front-run by target and by value, replay, tampered chain value, tampered auth path, wrong top layer, cache poisoning, recovery, recovery replay, old key after rotation, skip within and across subtrees, redundant top layer on a registered subtree, jump to a fresh subtree without top layer, signature bound to its index, backward index after a skip) plus factory tests (prediction, idempotence, chain independence, ETH forwarding, ERC-20 pull, missing approval). Driven by client-generated vectors.
- `evm/test/fixtures/cchs-s-20.json`, `cchs-k-20.json` — test vectors (master `0x07…07`, chainId 1, account `0x…cc45`): roots, public seed (`seed`, with its HKDF label `seedInfo`), bottom roots 0 and 1, three sequential operations (first-in-subtree with top layer, two cached), a `skip` sequence (index 5 cached, then index 1024 with top layer), one recovery (with `newSeed`). Regenerated with `npm run gen-fixtures` in `wallet/`. The S-20 file is the ground truth for every non-EVM port in §7.
- `wallet/src/aegis/cchs.ts` — TypeScript client, S-20 and K-20 (`cchsS`, `cchsK`, `forVariant`): keygen, sign, local verify, digest construction, ABI helpers, range-based leaf generation for parallel keygen.
- `wallet/src/aegis/cchsCompact.ts` — `CCHS-C-20` client (`cchsC`): keygen, sign, `topLayer` for the split cache fill, `bottomRootOf` / `verifyTopLayer` mirroring the two on-chain operations, recovery, digests with chain tags. `evm/test/fixtures/cchs-c-20.json` is its vector file (master `0x07…07`, tag `solana`).
- `evm/test/fixtures/cchs-derivation.json` — mnemonic → seed → master → `sk(0,0,0,0)`, roots and predicted EVM account for S-20 and K-20 (§3). Replayed by `wallet/scripts/check-vectors.mts`.
- `wallet/src/aegis/cchsAccount.ts` — the client rules of §4.3 and the per-epoch keys of §8: `nextSigningIndex`, `markIndexSigned`, `recordMissing`, `markRecoverySigned`, `epochKey`. `wallet/scripts/check-index-discipline.mts` tests them; `wallet/src/components/ProtectPanel.tsx` uses them (refuses to sign without a record, offers the rotation).
- `wallet/scripts/evm-flow.mts` — the full account life cycle for S-20 and K-20 against the shipped artifacts in an EVM: factory publication through the proxy, account creation, first-in-subtree, cached, skip, rotation to epoch 1 with the deterministic epoch keys, rejection of the old root, withdrawal. Prints the whole-transaction cost table behind §5.2.
- `model/cchs-state.mjs`, `model/cchs-client.mjs` — the bounded model checks of §6.2 with their seeded bugs.
- `proofs/` — the Lean 4 proofs of §6.2 (`Cchs/Verifier.lean`: C3, C4, C5, NF, LI, cache-once; `Cchs/Client.lean`: ONE-MESSAGE with lanes). `lake build` in that directory; `Check.lean` prints the axioms each theorem uses.

**Interop verified** (2026-10-08): for both sets, signatures produced by `cchs.ts` were executed against the compiled contracts in an EVM (`@ethereumjs/vm`, Cancun), with accounts created through the factory (predicted address = deployed address, idempotent). First-in-subtree, cached, front-run to a different target, tampered chain value, recovery rotation, post-rotation rejection of the old key, skipping leaves within a subtree, jumping to a fresh subtree with the top layer and continuing on its cached path, and rejection of index reuse, backward index and cross-subtree jump without top layer all behaved as specified. Client digests matched `digestAt()` byte-for-byte; the gas and calldata figures in §5.2 come from this run.

---

## 11. Open problems

1. **Concurrent signers.** Lanes (§4.3 rule 4) give devices independent counters and nonces on the EVM contracts, so devices in different lanes need no coordination; the remaining open items are lanes on the other adapters (all still single-counter, `ADAPTERS.md`) and a lane assignment that survives device loss without a user action.
2. **Cache eviction.** `cachedRoot` grows by one slot per 1024 signatures. Negligible, but a recovery epoch counter is used so old entries are logically cleared without gas-costly deletion.
3. **Formal verification.** The transition system is proven in Lean (`proofs/`, §6.2). Open: the cryptographic reduction itself (WOTS+ and Merkle security to the hash assumptions), with explicit constants for each set.
4. **Bitcoin.** Nothing binds a hash-based witness to a transaction under current consensus (§7.1); the open problem is the opcode, not the scheme. Once it exists, option (a) forgoes caching and (b) recovers it through UTXO lineage.
5. **C-20 concrete security.** A written reduction with explicit constants for `n = 24`, `w = 256`, 2^20 leaves in the multi-target quantum setting, and a packet-size measurement for the `n = 28` alternative (§5.5). The multi-user term is closed by `pkSeed` (§2.1); the single-tree constants are still to be written down, and until then the set carries the two-level label given there.
6. **Compute units on Solana.** Measured in the `solana-program-test` runtime in CI (§5.5); a measurement on a public cluster with the compute-budget instruction in place is still outstanding.
7. **Wider output.** One evaluated, unimplemented set (§5.6): `n = 36`, the smallest at which the conservative accounting of §5.5 also reaches 2^128 on the chain and node paths (about 1.25× the bytes and an estimated 1.75× the gas of K-20, two hash calls per `F`, no single-packet path on Solana). A 2^192 configuration is not offered; what it would take is listed in §5.6 — `n = 48`, a 384-bit digest built from two SHA-256 calls with a written combiner argument, a 48-byte master, and at least 384 bits of seed entropy, which BIP-39 does not provide — and the seed-search path P4 makes any subset of those pieces worthless. The wallet enforces the 256-bit seed that the default set's label assumes.
8. **The reduction behind the label.** The label 2^128 of the abstract is the FIPS 205 multi-target argument transported to CCHS by hand (§5.5, §5.6); the figure that holds without that argument is 2^113. Writing the reduction out for CCHS specifically — WOTS+ with the per-position ADRS and `pkSeed`, the two Merkle layers, the cached-root check and the signer-chosen index as the usage model — with explicit constants, and having it checked, is what decides which of the two numbers is the formal claim. Until then this document's unconditional claim is 2^113 and 2^128 is conditional on that argument; SECURITY.md says the same.
9. **C-20 keygen cost.** ~15 M hashes: 28 s single-threaded in JS, 5.4 s on the eight-worker WASM pool (`CchsPool.keygen(key, 'C')`). Still an order of magnitude above S-20; a native (Rust/WASM) tree builder would close most of it.
