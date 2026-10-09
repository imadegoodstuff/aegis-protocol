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
| On-chain index for one-time keys | Shelter.cash (flat WOTS) |

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
master ← 32 random bytes, or from a BIP-39 mnemonic exactly as SPEC.md §2:
         seed   = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" ‖ passphrase, 2048)   # BIP-39, 64 B
         master = HKDF-SHA256(seed, salt = ∅, info = "aegis/cchs/master/v1", 32)

key(chain) = HKDF-SHA256(master, salt = ∅, info = "aegis/cchs/chain/v1" ‖ tag(chain), 32)   # one tree per chain
    tag(EVM chain)   = 0x00 ‖ chainId as 8 bytes BE
    tag(other chain) = 0x01 ‖ utf8(label)       # the label of that chain's digest: "solana", "ton", …

label(set) = "cchs/sk" (S-20) | "cchs/sk/k" (K-20) | "cchs/sk/c" (C-20, §5.5)
sk(layer, treeIdx, leafIdx, chainIdx) = HKDF-SHA256(key, salt = ∅, label(set) ‖ layer ‖ treeIdx ‖ leafIdx ‖ chainIdx, 32)
    # key = key(chain) at epoch 0, key_e(chain) after e recoveries (§8)
    # layer: 1 byte, treeIdx: 8 bytes BE, leafIdx: 4 bytes BE, chainIdx: 1 byte

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

All secret material is derived lazily from `master`. Client stores 32 bytes (plus the index record of §4.3).

**One tree per chain.** The digest of §4 contains the chain id, which stops a signature from being *replayed* on another chain. It does not stop the same leaf from being *used* on another chain: if two chains shared one tree, leaf 0 on chain A and leaf 0 on chain B would sign two different digests under one WOTS+ key, which is exactly the reuse a one-time signature forbids, and no on-chain `nextIdx` can prevent it because each chain sees only its own. Deriving `key(chain)` per chain makes leaves of different chains different leaves by construction; nothing has to be coordinated between chains, devices or records. The consequence is that the account address differs per chain: it is still a pure function of the mnemonic, the chain id and the factory init code, and is known before anything is deployed. The CREATE2 *factory* is at the same address on every EVM chain; the *accounts* it creates are not.

There is one derivation path, and it is the one above; an implementation that derives `master` or `key(chain)` any other way produces a different account. Each parameter set has its own secret-key label, so no WOTS+ secret value is ever exposed through two different one-way functions (S-20 hashes with SHA-256, K-20 with keccak256). `evm/test/fixtures/cchs-derivation.json` fixes the whole chain for one mnemonic (`abandon` ×23 `art`, empty passphrase): seed, master, then for chain id 1, chain id 8453 and the label `ton` the tag, the chain key, `sk(0,0,0,0)`, `root`, `recRoot`, `bottomRoot0` and (EVM) the predicted account. A client is compatible with the reference if and only if it reproduces that file. The signature vectors `cchs-s-20.json` / `cchs-k-20.json` / `cchs-c-20.json` start from a given 32-byte key, which plays the role of `key(chain)`.

---

## 4. Signing

Inputs: `master`, chain-read `nextIdx` and `nonce`, the device's own record of the highest index it has signed (`signedMax`, §4.3), transaction `(target, value, data)`.

```
idx     = max(nextIdx, signedMax + 1)   # signer-chosen, monotonic (§4.3)
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

1. **The signer chooses `idx`.** Any `idx ≥ nextIdx` is accepted; `nextIdx` becomes `idx + 1` and every lower leaf is abandoned forever. `idx` is bound into `M`, so only the key holder can skip and nobody can force a skip on them. There is no separate `skipSubtree` operation: a signer that no longer trusts the keys of its current subtree signs its next operation at the first leaf of the following subtree (with that subtree's top layer), and the distrusted subtree is behind `nextIdx`.
2. **Write-ahead record.** The device stores the highest index it has signed per `(chainId, account)` *before* producing the signature. Next index = `max(nextIdx, signedMax + 1)`. A transaction that is dropped, replaced, under-priced, or reverted for an unrelated reason leaves its leaf unused on chain, and the client never signs that leaf again: it is abandoned and the next operation uses a higher one. Re-signing the same leaf for a changed call (new target, amount, or gas) is exactly the two-messages case and is never done.
3. **Pending operations.** `nonce` is also bound into `M`, so two operations prepared from the same chain state cannot both land. A client with one operation in flight waits for it to settle or be dropped before signing the next; a dropped operation does not advance `nonce`, so the next signature reuses the nonce but, by rule 2, a fresh leaf.
4. **Several devices.** Devices sharing a master each keep their own `signedMax`; they are safe only if they never sign the same leaf. The reference wallet is single-signer. A multi-device deployment partitions the index space (device *d* uses subtrees ≡ *d* mod *n*, which rule 1 permits) or routes signing through one device.
5. **Lost or rolled-back record.** A device whose record is missing or may be older than the signatures it produced (new install with the account already in use, storage cleared, restore from a backup) must not sign under the current epoch at all. It cannot know which leaves the lost record covered, and a transaction it signed earlier may still be sitting in a mempool with a leaf above `nextIdx`; "wait until the pool drains, then take `nextIdx` as the lower bound" is not sufficient (the model in §6 produces the counterexample: sign at leaf 0, drop, restore, pool empty, sign a different message at leaf 0). The complete rule is to leave the index space: perform a recovery (§8) to the next epoch, whose keys are a different derivation, and start a fresh record there. The reference wallet refuses to sign when `nextIdx > 0` and no record exists for `(chain, account, epoch)`, and offers the rotation instead. The record is written per epoch.
6. **Recovery messages are deterministic.** The roots of epoch `e + 1` are a pure function of the master and `e + 1` (§8), so the recovery message at `(epoch, recNonce)` is fixed; a dropped rotation that is signed again is the same message under the same recovery leaf, not a second one. The recovery leaf is nevertheless recorded before signing, like any other leaf. A recovery to a *fresh* master (the compromise case) is a different message and must therefore never be attempted at a `recNonce` for which a deterministic rotation has already been signed; the wallet records both under one counter.
7. **Several chains.** Each chain has its own tree (`key(chain)`, §3). A client must never build a tree for chain B from the key of chain A, however convenient a shared address would be; the chain id in the digest does not make that safe. The model (§6) shows the violation in six states for a client that shares one tree between two chains.
8. **Capacity.** Abandoned leaves cost capacity, not security: 2^20 leaves at one operation per minute last about two years even if every other leaf is abandoned. Recovery (§8) opens a fresh index space under a new root.

Rule 1 also settles two races: a transaction prepared with a top layer still succeeds if someone else registered the subtree in the meantime (`executeFirst` ignores a redundant proof), and a cached-path transaction prepared before a recovery fails cleanly (new epoch, empty cache) rather than being replayable.

---

## 5. Verification (on-chain)

Two entry points share the verification; they differ only in whether the top layer is present, so a cached-path transaction carries one layer of calldata.

```
execute(target, value, data, idx, sig_0, auth_0):          # cached subtree
    require idx ≥ nextIdx                                   # IndexUsed
    t_0 = idx >> h ; j_0 = idx & (2^h-1)
    M    = H("AEGIS_CCHS_V1" ‖ chainId ‖ this ‖ nonce ‖ idx ‖ target ‖ value ‖ keccak256(data))
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
    nextIdx = idx + 1 ; nonce += 1                          # effects
    call target                                             # interaction
```

`digestAt(idx, …)` and `needsTopLayerAt(idx)` are the views the client checks before signing; `nextDigest` / `needsTopLayer` are the same at `idx = nextIdx`.

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
| Cached subtree (`execute`) | 2 628 B ≈ 40.2 K | ~209 K | **~270 K** | ~108 K | **~169 K** |
| New subtree (`executeFirst`, first of 1024) | 5 092 B ≈ 79.5 K | ~457 K | ~557 K | ~252 K | ~353 K |
| Recovery | 2 436 B ≈ 39 K | ~201 K | ~261 K | ~117 K | ~177 K |
| Account deploy via factory | — | ~1 457 K | — | ~1 435 K | — |
| Runtime code | | 6 756 B | | 6 644 B | |

Execution gas moves by about ±10 % with the digits of the particular digest (the verifier walks `w − 1 − digit` steps per chain), so the figures are for the fixture's messages, not bounds. Calldata is about a quarter of the cached-path total and is irreducible for a hash-based signature (2 464 B of chain values and path). EIP-7623 (Pectra) prices calldata at a floor of 10 gas per token when execution is small; execution exceeds the floor on every path here, so the floor never binds. Against ECDSA (65 B, ≈ 24 K for a plain transfer) a cached K-20 operation costs about 7× in gas and 40× in bytes. The design optimizes the amortized cost of a hash-based signature; it does not remove that gap, and for high-frequency or very small payments an ECDSA daily path with CCHS as the recovery root (§8, hybrid) is the right configuration.

The account also implements the ERC-721 and ERC-1155 receiver callbacks and ERC-165, so any asset can be sent to it with a safe transfer; those four pure functions account for ~0.9 KB of the runtime. (Without them: 5 296 B / 5 184 B, S-20 cached ~232 K, K-20 cached ~118 K. With optimizer 200 runs and no viaIR the code is 3 831 B / 3 666 B and K-20 cached execution is ~128 K; the deployed build trades code size for ~10 K gas per signature.)

Execution gas includes the outgoing `call` (9 K for value transfer, 25 K if it creates the recipient), one packed SSTORE, and the event — roughly 45 K that is not verification. K-20 verification proper is ~75 K; S-20 ~185 K.

SPHINCS+ C13 on-chain verification is ~190 K compute + 3 688 B calldata (~59 K) + 21 K ≈ 270 K per signature and needs a separate 14.6 KB verifier contract. K-20 is ~1/3 cheaper than that on every signature, S-20 is at parity; both use about 1/3 the code and no external contract.

**Which set to deploy.** `CCHS-K-20` is the EVM default: signatures are bound to a chain ID, so an EVM account never shares a signature with Bitcoin Script, and the keccak opcode is the cheaper primitive. `CCHS-S-20` is the canonical set and the one every non-EVM port implements (each chain still has its own tree, §3). Both are deployed by the same factory (§5.4).

### 5.3 Cache registration is permissionless, not cross-chain

The top-layer message is the bottom subtree root `R_0`, which contains no chain identifier, and the registration `(sig_1, auth_1)` is valid for any account whose `root` is the tree's root. Registering the correct root is harmless wherever it is replayed, so anyone may submit it (a relayer, a sponsor, the user from another device) and the write is idempotent. It is *not* portable between chains: since each chain has its own tree (§3), no two chains share a `root`, and a top-layer signature produced for chain A registers nothing on chain B. The first-in-subtree premium is therefore paid once per subtree *per chain*. An earlier revision of this section described the same `l1` as valid on every chain of a parameter set; that was true of the shared-tree design and was withdrawn together with it, because sharing a tree also shares its one-time leaves (§3, §4.3 rule 7).

### 5.4 Factory and same-address deployment

`evm/src/AegisCCHSFactory.sol` deploys either set with CREATE2, `salt = keccak256(root ‖ recRoot ‖ variant)`. With metadata-free bytecode and the factory itself at the same address on every EVM chain, `(root, recRoot, variant)` maps to one address on all of them; since the roots are derived per chain (§3), each chain's account has its own address. `deploy()` is permissionless and idempotent; `predict()` is pure in the chain ID.

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

Measured (`wallet/src/aegis/cchsCompact.ts`, Node 24): keygen top + recovery 15.6 s and first subtree 12.7 s single-threaded in pure JS, 5.4 s for all three on the eight-worker WASM pool; sign 6.5 ms cached / 12.2 ms with top layer; local verify 6.5 ms / 14.5 ms; a legacy Solana `execute` transaction on the cached path (one signer, seven account keys, the 8-byte signer-chosen `idx`, 12-byte inner instruction) is 1 231 B of 1 232, 1 198 B when the recipient is the payer; because C-20 verification exceeds the 200 K default compute budget the transaction also needs `SetComputeUnitLimit`, which fits only as a v0 message with an address lookup table: 1 090 B, leaving 142 B for inner-instruction data; the `cache_subtree` transaction is 1 174 B (1 214 B with the compute-budget instruction). Compute units are estimated from the syscall cost model (≈ 376 K average, ≈ 722 K worst for the hashes alone; `solana/README.md`), not measured on a cluster. Bit flip, foreign digest, index replay, wrong cached root, and tampered top-layer path were all rejected; recovery accepted once and rejected on replay. Key derivation is domain-separated (`cchs/sk/c`), so a master seed yields independent C-20 keys. The checksum for `w = 256` is `Σ(255 − m_i) ≤ 6 120`, two base-256 digits.

**Security of C-20, with numbers.** The rows above are generic single-target costs of the truncated hash; the scheme is a multi-target object. Two accountings bracket it.

*Target count.* Per epoch a verifier may be shown every intermediate chain value of every leaf: 2^20 leaves × 26 chains × 255 positions ≈ 2^32.7 values at layer 0, plus 2^10 × 26 × 255 ≈ 2^22.7 at layer 1, plus leaf and node hashes (≈ 2^21). Call it T ≈ 2^33. For S-20/K-20 the same count is 2^20 × 67 × 15 ≈ 2^29.9, T ≈ 2^30.

*Conservative accounting* (count targets, give the ADRS tweak no credit): a second preimage on any one of T outputs costs 2^8n / T classically and about 2^(8n − log₂T)/2 with Grover.

| | S-20 / K-20 (n = 32, w = 16) | C-20 (n = 24, w = 256) |
|---|---|---|
| classical | 2^256 / 2^30 ≈ **2^226** | 2^192 / 2^33 ≈ **2^159** |
| quantum (Grover, multi-target) | ≈ **2^113** | ≈ **2^80** |
| AES yardstick | above AES-192 (2^96 quantum) | between AES-128 (2^64) and AES-192 (2^96) |

*Tight accounting* (the SPHINCS+ argument: the address tweak makes every chain position a distinct function, so the adversary must commit to a target before querying; the SM-TCR / SM-DSPR reductions of the SPHINCS+ submission are tight in the random-oracle model and lose only the query count in the quantum ROM): 2^192 / 2^96 for C-20, 2^256 / 2^128 for S-20/K-20, i.e. AES-192 and AES-256 respectively. The Winternitz parameter enters these bounds only through T; `w = 256` costs about 3 bits more of target count than `w = 16` at equal n, not more.

*What this means.* S-20 and K-20 clear the AES-192 yardstick under either accounting. C-20 clears it under the tight accounting and does not under the conservative one; the honest label for C-20 is therefore "NIST level 3 if the SPHINCS+ multi-target argument is accepted for this construction, level 1–2 if it is not". The CCHS-specific parts (the cached subtree root, the signer-chosen index, the epoch-keyed cache) do not add hash targets beyond the hypertree itself, but the written reduction with explicit constants for `(n = 24, w = 256, 2^20)` under the SPHINCS+ framework is still an open item (§11). A design alternative that clears the conservative bar is `n = 28` (classical 2^224 / 2^33 ≈ 2^191, quantum ≈ 2^95.5): the layer grows from 864 B to 1 008 B, which no longer fits a legacy Solana packet on the cached path, and by the current layout misses the v0-with-lookup-table limit by about 2 B (1 090 B measured for n = 24 with a 12-byte inner instruction leaves 142 B; n = 28 needs 144 B more), so it would require trimming the instruction encoding or a two-packet path. Until that measurement and the written bound exist, the parameter set stays at n = 24 and carries the two-level label above.

What C-20 trades: ~6× more verifier compute per layer and ~6× more keygen work for a 2.85× smaller signature. On a chain that meters compute rather than bytes (EVM) it is the wrong trade; on a chain that caps bytes per transaction (Solana) it is the only one that gives a single-transaction hot path without a staging buffer.

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

**C5 — One landed signature per leaf, and signer-controlled skipping.** For every `(epoch, idx)` at most one `execute`/`executeFirst` succeeds, and `nextIdx` only moves to a value the key holder signed.

Sketch. Both entry points require `idx ≥ nextIdx` and set `nextIdx = idx + 1` before the external call, so a second acceptance at the same `idx` is impossible and a lower `idx` is rejected without hashing. `idx` is an input to `M`, so a signature at `idx` is not valid at `idx' ≠ idx` (C1); A cannot therefore move `nextIdx` anywhere the owner did not sign. Recovery resets `nextIdx` under a new `epoch`, and the cache key includes `epoch`, so pre-recovery signatures are not accepted afterwards (their `(layer, t_0, j_0)` keys live under the old `root`; C3). What C5 does not cover is a signature the owner produced that never landed: the chain cannot see it, and §4.3 places that obligation on the client.

**State machine.** The account's authorization state is `(root, recRoot, epoch, nextIdx, nonce, recNonce, cachedRoot)`. `model/cchs-state.mjs` explores every reachable state of an abstracted model (`h = 1`, two subtrees, one recovery, up to six owner signatures; the hash is replaced by "the recomputed root is right exactly when the inputs are the ones signed") under an adversary that may submit any signature it has seen at any index, target or entry point, in any order, and may forge freely with the bottom keys of any subtree that is entirely behind `nextIdx`. C3, C4, C5 and non-forgeability are checked on every one of ~10⁷ submissions, and four deliberately broken verifiers (no index check, cache key without epoch, index not in the digest, top layer not bound to `R_0`) are each caught. It runs in CI. It is a bounded model check of the transition logic, not a proof about the hash function.

**Client model.** `model/cchs-client.mjs` checks the other half: the rules of §4.3 under the events the chain cannot see. Two devices share a master; each keeps a persistent `signedMax` and may back it up and later restore the older copy; signed transactions enter a pool from which they land (verifier rules) or are dropped in any order; recovery to a new epoch is available; every signature ever produced is remembered. The invariant is ONE-MESSAGE: no `(epoch, leaf)` ever signs two different messages. It holds on every reachable state (≈ 1.7 × 10⁵ states, 6.4 × 10⁵ transitions at the model's bounds), and each of five weakened clients is caught with a concrete trace: recording the index after signing (crash in between), restoring a backup and merely waiting for the pool to drain instead of rotating, two devices without partition, no record at all, and recovery with non-deterministic new roots. A second configuration (`--chains=2`) runs two chains with independent on-chain state from one mnemonic; the reference client (one tree per chain, §3) holds, and the mutant `shared-tree`, which signs on both chains from one tree, violates ONE-MESSAGE after two signatures: leaf 0 signs the digest of chain 0 and then the digest of chain 1. `wallet/scripts/check-index-discipline.mts` tests the wallet's implementation of the same rules, and `wallet/scripts/evm-flow.mts` runs the full life cycle including a rotation against the shipped contracts.

### 6.3 Not covered

- Side channels on client key derivation.
- Chain-level failures (reorg past finality, consensus bugs).
- Loss of `master`. See §8 recovery.
- Signatures produced by the client that never landed (§4.3); the chain cannot observe them.
- Formal machine-checked proof. The sketches above reduce to Hülsing 2013 + standard Merkle arguments; a Lean/EasyCrypt formalization is future work, and the model check above is bounded.
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
| Bitcoin | `OP_SHA256` in Tapscript | — | §7.1 |

### 7.1 Bitcoin

Bitcoin has no mutable storage, so the cache cannot be held on-chain, and current Script cannot bind a hash-based signature to the spending transaction: a tapleaf can check WOTS+ chains against hard-coded public values (BitVM, Linus 2023), but the digits it checks are witness data, not the sighash. Without `OP_CAT` (BIP-347) or `OP_CHECKSIGFROMSTACK` the script cannot compute or compare the sighash, so a miner could reuse the WOTS+ witness on a transaction paying elsewhere. BitVM is unaffected because its digits are program state, not transaction data. Consequently there is no hash-only, transaction-binding signature on Bitcoin today; the following describes what becomes possible once either opcode activates.

**(a) Flat Tapscript tree + OP_CAT.** The Taproot script tree *is* a Merkle tree. Use it as the signature tree: one tapleaf per WOTS+ key, each leaf script (i) verifying 67 chains against hard-coded pks (BitVM Winternitz pattern: compute the 16 chain states, `OP_PICK` the one at the claimed digit, `OP_EQUALVERIFY`), (ii) checking the 3 checksum digits arithmetically, (iii) reassembling the 64 message digits with `OP_CAT` and comparing them with the sighash reconstructed in-script from witness-supplied transaction fields (the CAT-covenant technique). Measured from the builder: leaf script 5 752 B for (i)+(ii); witness for a 2^4 test tree 8 116 B (134 WOTS items + script + 161 B control block); a 2^20 tree adds 512 B of control block. Plus the sighash fragment. Under the 4 MB weight limit. No hypertree caching benefit. `wallet/src/aegis/btcTapscript.ts` implements the tree builder, leaf-script generator (i)+(ii), BIP-341 tagged hashing and control-block construction; (iii) is left as a marked insertion point until BIP-347 is active on a network with real value.

**(b) With OP_CAT, hypertree form.** In-script Merkle verification becomes possible; a single tapleaf can verify any of 2^h bottom keys with the auth path in the witness. The cache is replaced by the UTXO itself: a spend from a "subtree UTXO" carries only the bottom layer, and creating the subtree UTXO carries the top layer. This mirrors CCHS exactly, with UTXO lineage as the cache.

**Why no construction under current consensus closes the gap.** The requirement is that a spend be authorized by something a quantum adversary cannot compute, and that the authorization be *bound to the transaction* by rules the network enforces. Every avenue available today fails one of the two:

1. *Key-path or script-path Taproot.* A P2TR output publishes the tweaked key `Q` in the output itself. A discrete-log adversary recovers the key for `Q` without waiting for a spend, so any P2TR UTXO, including one whose internal key is a NUMS point, is spendable by the key path. Script-path restrictions do not help; the key path is always available to whoever holds the key for `Q`.
2. *Hash-locked scripts (P2WSH).* `OP_SHA256 <h> OP_EQUAL` and any WOTS+ chain check reveal preimages in the witness; nothing ties them to the outputs, so the first miner or relayer to see them can rebuild the transaction to pay elsewhere. This is exactly the missing binding, and it is what `OP_CAT`/`OP_CHECKSIGFROMSTACK` supply.
3. *Pre-signed transaction trees with key deletion.* They bind the destination, but the key that signed them is an elliptic-curve key whose public key the adversary learns from the output (P2TR) or from the first spend (P2WPKH). Deletion protects against the owner's own future compromise, not against a key recovered from public data.
4. *Commit-delay-reveal* (publish `H(tx)` first, spend later). Sound as a protocol, but no script can check that a commitment preceded the reveal; enforcement requires a consensus rule, which is why it has only been proposed as a soft fork.
5. *Length-channel constructions.* Proposals exist that extract bits of the sighash from the DER length of ECDSA signatures checked by `OP_CHECKSIG` and sign those bits with Lamport chains. They do not reach the security level of the rest of this document and are not adopted here.

The conclusion is a statement about Bitcoin consensus, not about CCHS: a hash-only, transaction-binding spend condition needs an introspection opcode. BIP-347 (`OP_CAT`) and the quantum-resistant output proposals built on hash-based signatures are the activation paths; when either is live, (a) and (b) above apply as written.

**Posture until then** (what the wallet does for its Bitcoin address). Use outputs that do not expose the key before the spend, P2WPKH (BIP-84) rather than P2TR, never reuse an address, send change to a fresh address, and derive those keys from the same master so that they are rotated by the same backup. This limits a quantum adversary to the window between broadcast and confirmation, which is the strongest guarantee available without consensus changes. It is not post-quantum security and the wallet does not label it as such.

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

**Where the new roots come from.** Two cases.

- *Rotation* (lost client record, §4.3 rule 5; precaution; moving to a fresh index space): the keys of epoch `e` are derived from the same chain key,

  ```
  key_0(chain) = key(chain)                                                                    (§3)
  key_e(chain) = HKDF-SHA256(key(chain), salt = ∅, info = "aegis/cchs/epoch/v1" ‖ e as 8-byte BE, 32)    (e ≥ 1)
  ```

  and every tree of epoch `e` (top, bottom subtrees, recovery) is built from `key_e(chain)` with the per-set labels of §3. Epoch 0 is the chain key itself. `newRoot, newRecRoot` for the rotation at epoch `e` are the roots of `key_{e+1}`; the recovery signature is made with the recovery tree of `key_e` at leaf `recNonce`. The message is therefore a pure function of `(chainId, account, recNonce, e)`. A device needs only the mnemonic, the chain and the on-chain `epoch` to derive the current keys; it checks the derived roots against the on-chain `root`/`recRoot` before signing with them.
- *Compromise* (the master itself may be exposed): the user supplies a new mnemonic, and `newRoot, newRecRoot` are the epoch-0 roots of the new master. The old master's recovery tree signs this once; the new master then runs its own epoch sequence. This path is not deterministic and is subject to §4.3 rule 6.

In both cases the pre-recovery `root` is dead: its signatures are rejected by the epoch-keyed cache and the changed root (C3), as `wallet/scripts/evm-flow.mts` checks after each rotation.

Hybrid deployments (`AegisAccountV3`) may keep ECDSA as the daily path and use CCHS only as the recovery root — replacing the SPHINCS+ verifier of V2 with a ~175 K-gas, 2.5 KB alternative that needs no 15 KB verifier contract.

---

## 9. Parameter sets

| Name | Hash | d | h | Capacity | Sig (amortized) | Use |
|---|---|---|---|---|---|---|
| `CCHS-S-20` | SHA-256 | 2 | 10 | 2^20 | 2.5 KB | canonical; every non-EVM port; EVM when cross-chain byte identity is wanted |
| `CCHS-K-20` | keccak256 | 2 | 10 | 2^20 | 2.5 KB | EVM default; ~169 K total gas cached |
| `CCHS-C-20` | SHA-256/24, w = 256 | 2 | 10 | 2^20 | 864 B | packet-limited chains (Solana); cache fill is its own transaction (§5.5) |
| `CCHS-S-30` | SHA-256 | 3 | 10 | 2^30 | 2.5 KB | institutional; not yet implemented |

Key derivation (HKDF-SHA256 from the 32-byte `key(chain)`, itself derived per chain from the master; §3) uses a distinct label per set (`cchs/sk`, `cchs/sk/k`, `cchs/sk/c`; §3), so one master yields independent secret values and independent trees per set, and no secret value is ever hashed under two different functions.

---

## 10. Reference implementations

- `evm/src/AegisCCHSBase.sol` — hash-agnostic account logic (`execute`, `executeFirst`, `recover`, cache, digests, signer-chosen monotonic index).
- `evm/src/AegisCCHS.sol` — `CCHS-S-20`, SHA-256 precompile from assembly. 6 756 B runtime (deployed build).
- `evm/src/AegisCCHSK.sol` — `CCHS-K-20`, keccak256 opcode. 6 644 B runtime (deployed build).
- `evm/src/AegisCCHSFactory.sol` — CREATE2 factory for both sets. `deploy` is payable and forwards ETH; `deployAndMove` also pulls approved ERC-20s, so creating and funding an account is one transaction. The factory itself is published through the deterministic-deployment proxy (`deploy/deploy-cchs.mjs`, or the wallet's first Protect on a chain where it is missing; the sender does not matter), giving it the address `0xAa6175251D4097f2927126202F04cca4151d0611` on every EVM chain where it has been deployed; the wallet artifact (`wallet/src/aegis/cchsArtifacts.json`) carries the exact init code so account addresses can be predicted offline.
- `evm/test/AegisCCHS.t.sol` — Foundry suites for S-20 and K-20 (front-run by target and by value, replay, tampered chain value, tampered auth path, wrong top layer, cache poisoning, recovery, recovery replay, old key after rotation, skip within and across subtrees, redundant top layer on a registered subtree, jump to a fresh subtree without top layer, signature bound to its index, backward index after a skip) plus factory tests (prediction, idempotence, chain independence, ETH forwarding, ERC-20 pull, missing approval). Driven by client-generated vectors.
- `evm/test/fixtures/cchs-s-20.json`, `cchs-k-20.json` — test vectors (master `0x07…07`, chainId 1, account `0x…cc45`): roots, bottom roots 0 and 1, three sequential operations (first-in-subtree with top layer, two cached), a `skip` sequence (index 5 cached, then index 1024 with top layer), one recovery. The S-20 file is the ground truth for every non-EVM port in §7.
- `wallet/src/aegis/cchs.ts` — TypeScript client, S-20 and K-20 (`cchsS`, `cchsK`, `forVariant`): keygen, sign, local verify, digest construction, ABI helpers, range-based leaf generation for parallel keygen.
- `wallet/src/aegis/cchsCompact.ts` — `CCHS-C-20` client (`cchsC`): keygen, sign, `topLayer` for the split cache fill, `bottomRootOf` / `verifyTopLayer` mirroring the two on-chain operations, recovery, digests with chain tags. `evm/test/fixtures/cchs-c-20.json` is its vector file (master `0x07…07`, tag `solana`).
- `evm/test/fixtures/cchs-derivation.json` — mnemonic → seed → master → `sk(0,0,0,0)`, roots and predicted EVM account for S-20 and K-20 (§3). Replayed by `wallet/scripts/check-vectors.mts`.
- `wallet/src/aegis/cchsAccount.ts` — the client rules of §4.3 and the per-epoch keys of §8: `nextSigningIndex`, `markIndexSigned`, `recordMissing`, `markRecoverySigned`, `epochKey`. `wallet/scripts/check-index-discipline.mts` tests them; `wallet/src/components/ProtectPanel.tsx` uses them (refuses to sign without a record, offers the rotation).
- `wallet/scripts/evm-flow.mts` — the full account life cycle for S-20 and K-20 against the shipped artifacts in an EVM: factory publication through the proxy, account creation, first-in-subtree, cached, skip, rotation to epoch 1 with the deterministic epoch keys, rejection of the old root, withdrawal. Prints the whole-transaction cost table behind §5.2.
- `model/cchs-state.mjs`, `model/cchs-client.mjs` — the bounded model checks of §6.2 with their seeded bugs.

**Interop verified** (2026-10-08): for both sets, signatures produced by `cchs.ts` were executed against the compiled contracts in an EVM (`@ethereumjs/vm`, Cancun), with accounts created through the factory (predicted address = deployed address, idempotent). First-in-subtree, cached, front-run to a different target, tampered chain value, recovery rotation, post-rotation rejection of the old key, skipping leaves within a subtree, jumping to a fresh subtree with the top layer and continuing on its cached path, and rejection of index reuse, backward index and cross-subtree jump without top layer all behaved as specified. Client digests matched `digestAt()` byte-for-byte; the gas and calldata figures in §5.2 come from this run.

---

## 11. Open problems

1. **Concurrent signers.** The signer-chosen index (§4.3) lets several devices partition the index space, but the reference wallet is single-signer and there is no protocol-level coordination between devices sharing a master.
2. **Cache eviction.** `cachedRoot` grows by one slot per 1024 signatures. Negligible, but a recovery epoch counter is used so old entries are logically cleared without gas-costly deletion.
3. **Formal verification.** Reduce §6 sketches to a machine-checked proof.
4. **Bitcoin.** Nothing binds a hash-based witness to a transaction under current consensus (§7.1); the open problem is the opcode, not the scheme. Once it exists, option (a) forgoes caching and (b) recovers it through UTXO lineage.
5. **C-20 concrete security.** A written reduction with explicit constants for `n = 24`, `w = 256`, 2^20 leaves in the multi-target quantum setting, and a packet-size measurement for the `n = 28` alternative (§5.5). Until then the set carries the two-level label given there.
6. **Compute units on Solana.** Measured on a local validator rather than estimated from the syscall cost model.
7. **C-20 keygen cost.** ~15 M hashes: 28 s single-threaded in JS, 5.4 s on the eight-worker WASM pool (`CchsPool.keygen(key, 'C')`). Still an order of magnitude above S-20; a native (Rust/WASM) tree builder would close most of it.
