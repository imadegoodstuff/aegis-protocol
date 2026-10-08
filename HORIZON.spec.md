# AEGIS HORIZON — Hash-Only Post-Quantum Account Protocol

> **Superseded by [`CCHS.spec.md`](./CCHS.spec.md).** Horizon's 32-byte preimage reveal does not bind to the message, which is why it needed a two-phase commit-reveal and a finality wait. CCHS uses WOTS+ (message-binding) under a chain-cached hypertree: single transaction, 2.5 KB amortized, no finality delay. Kept for the record.

**Version**: 1.0.0-draft
**Status**: Superseded.
**Primary assumption**: SHA-256 preimage resistance (Grover: 2^128 classical-equivalent).

---

## 1. Honest framing

Horizon is **not a new cryptographic primitive**. It is a specific **engineering combination** of three primitives, each 10–47 years old and extensively peer-reviewed:

| Primitive | Year | Standard |
|---|---|---|
| Lamport one-time preimage auth | 1979 | Lamport, "Constructing digital signatures from a one way function" |
| Merkle hash tree | 1979 | Merkle, "Secrecy, authentication and public key systems" |
| Commit-reveal front-run defense | 2016 | HTLC (Lightning Network), later ENS registrar |

**What Horizon claims**:

1. A wallet that authorises transactions using **only SHA-256 preimage reveals** — no ECDSA, no lattice, no new assumption.
2. Deployable on **any chain that has SHA-256 and 32-byte storage** — EVM, Bitcoin Script (Taproot), Solana, Cosmos (CosmWasm), Aptos, Sui, NEAR, TON, Cairo, TRON.
3. Security against a full-quantum adversary reduces to **inverting SHA-256**, for which Grover gives ~2^128 operations — infeasible for any projected hardware this century.

**What Horizon does *not* claim**:

- It is not a cryptographic breakthrough. Every underlying mechanism is a standard textbook construction.
- It is not faster or cheaper than ECDSA. Each op costs 2 transactions (commit + reveal) plus a finality delay.
- It is not reviewed by any external cryptographer. Users running real funds should hire one.

**Intended use**:

- As the **recovery / cold path** in `AegisAccountV3` (which keeps ECDSA for daily high-frequency ops).
- As the **sole auth** on chains where ECDSA cannot be bypassed by a quantum attack (Bitcoin + Taproot script path).
- As a **minimal-assumption fallback** when a user believes all elliptic-curve and lattice schemes are compromised.

---

## 2. Notation

- `H(x)` denotes `SHA-256(x)` throughout.
- `H2(a, b) := H(0x01 || a || b)` is the Merkle internal-node hash (domain-separated).
- `Hleaf(x) := H(0x00 || x)` is the Merkle leaf hash (domain-separated).
- `||` is byte concatenation.
- `H(x || "label")` means concatenation with ASCII bytes of `label`.
- Integers are big-endian unless noted.
- `D` = finality delay in blocks, chain-specific (Ethereum: 2; BSC: 15; Bitcoin: 6).
- `E` = commit expiry window in blocks (default 256).

---

## 3. Setup

Given a user BIP-39 mnemonic:

```
master_seed := PBKDF2-HMAC-SHA512(mnemonic, "aegis-horizon-v1-" || passphrase)[0:32]

for i in [0, 2^N):
    ops_secret_i := HKDF-SHA256(master_seed, "ops/" || i_u32_be, 32)
    ops_leaf_i   := Hleaf( H(ops_secret_i || "aegis-h/ops/pub") )

for j in [0, 2^M):
    rec_secret_j := HKDF-SHA256(master_seed, "rec/" || j_u32_be, 32)
    rec_leaf_j   := Hleaf( H(rec_secret_j || "aegis-h/rec/pub") )

ops_root := MerkleRoot(ops_leaf_0, ..., ops_leaf_{2^N-1})
rec_root := MerkleRoot(rec_leaf_0, ..., rec_leaf_{2^M-1})

account_id := H(ops_root || rec_root || "aegis-h/v1")
```

**Recommended parameters**: `N = 20` (1 048 576 daily ops), `M = 8` (256 lifetime recoveries).

Keygen cost: ~1 048 832 × SHA-256 ≈ 300 ms on a modern laptop single-threaded. Fits in a Web Worker without blocking UI.

Secret storage: 32-byte master seed only. All leaves and roots recomputed on demand from `master_seed`.

---

## 4. On-chain state

```
struct Account {
    bytes32 ops_root;         // commitment to all ops leaves
    bytes32 rec_root;         // commitment to all recovery leaves
    uint32  next_ops_index;   // strictly monotonic; prevents reuse
    bytes32 rec_used_bitmap;  // 256-bit bitmap of consumed recovery leaves
    address custody;          // target of execute(); defaults to self
}

mapping(uint256 ops_index => CommitSlot) commits;

struct CommitSlot {
    bytes32 commit;
    uint64  block_number;
}
```

Total state: 5 words per account, plus one word per outstanding commit.

---

## 5. Daily operation flow (two-phase)

### Phase 1 — Commit

User computes locally:

```
tx_payload := abi.encode(chain_id, account_addr, target, value, data, next_ops_index)
tx_hash    := H(tx_payload)
commit     := H(ops_secret_i || tx_hash || "aegis-h/ops/commit")
```

Submits transaction `commit(i, commit)`:

```solidity
function commit(uint32 i, bytes32 c) external {
    require(i == next_ops_index, "stale index");
    require(commits[i].commit == 0, "already committed");
    commits[i] = CommitSlot({ commit: c, block_number: uint64(block.number) });
}
```

Cost: ~22 000 gas (one SSTORE).

### Phase 2 — Reveal + execute

After at least `D` blocks have passed (chain finality), user submits:

```solidity
function reveal(
    uint32 i,
    bytes32 ops_secret,
    bytes32[] calldata merkle_path,
    address target,
    uint256 value,
    bytes calldata data
) external {
    CommitSlot memory slot = commits[i];
    require(slot.commit != 0, "no commit");
    require(block.number >= slot.block_number + FINALITY_DELAY, "wait finality");
    require(block.number <= slot.block_number + EXPIRY_WINDOW, "expired");
    require(i == next_ops_index, "wrong index");

    bytes32 tx_hash = sha256(abi.encode(block.chainid, address(this), target, value, data, i));
    bytes32 expected_commit = sha256(abi.encodePacked(ops_secret, tx_hash, "aegis-h/ops/commit"));
    require(expected_commit == slot.commit, "bad reveal");

    bytes32 leaf = sha256(abi.encodePacked(bytes1(0x00), sha256(abi.encodePacked(ops_secret, "aegis-h/ops/pub"))));
    require(_verifyMerkle(leaf, i, merkle_path, ops_root), "bad proof");

    unchecked { next_ops_index = i + 1; }
    delete commits[i];

    (bool ok, ) = target.call{value: value}(data);
    require(ok, "call failed");
}
```

Cost: ~45 000 gas for the 2 SHA-256 calls + Merkle verify (depth 20 = 20 SHA-256 = 20 × 60 = 1200 gas) + state updates. Total ~70 000 gas.

### Why two phases

- **Phase 1 only** would require the user to reveal `ops_secret` in the same tx as the operation, letting a quantum attacker who sees the mempool invert SHA-256 within one block window and front-run with a different `target`.
- **Phase 2 enforced after finality** means by the time `ops_secret` is public, the chain has committed to the specific `(target, value, data)` tuple from Phase 1. Any alternative execution would require a reorg past finality + a Grover attack within that window — a bound of 2^128.

---

## 6. Recovery flow (rotate roots)

If `master_seed` is lost or compromised, use a recovery secret to install a fresh `ops_root` and `rec_root`.

Phase 1 — commit:

```
new_ops_root := H(new_master_seed || "aegis-h/ops/root")   // precomputed off-chain
new_rec_root := H(new_master_seed || "aegis-h/rec/root")
rec_tx_hash  := H(chain_id || account || new_ops_root || new_rec_root)
rec_commit   := H(rec_secret_j || rec_tx_hash || "aegis-h/rec/commit")
```

Submit `recoverCommit(j, rec_commit)`.

Phase 2 — reveal:

```solidity
function recoverReveal(
    uint8 j,
    bytes32 rec_secret,
    bytes32[] calldata merkle_path,
    bytes32 new_ops_root,
    bytes32 new_rec_root
) external {
    require((rec_used_bitmap & (bytes32(uint256(1)) << j)) == 0, "used");
    require(block.number >= recCommits[j].block_number + FINALITY_DELAY, "wait");
    // verify commit + merkle proof against rec_root
    // ...
    ops_root = new_ops_root;
    rec_root = new_rec_root;
    next_ops_index = 0;
    rec_used_bitmap |= bytes32(uint256(1)) << j;
}
```

With `M = 8`, user has 256 lifetime recoveries. Enough for 1 recovery/year × 256 years, or 1/day × 8 months.

---

## 7. Security analysis (preliminary; needs external review)

### 7.1 Threat model

- Adversary A knows the entire chain state and mempool.
- A has quantum hardware sufficient to break any discrete-log or factoring assumption.
- A can perform up to 2^N Grover queries against SHA-256 (currently ~2^128 for 256-bit output).
- A can mine blocks, but a `D`-block reorg has cost ≥ `D × block_reward + external bribes`.

### 7.2 Claim: An adversary cannot execute a transaction without knowing `master_seed`

Proof sketch:

To execute, A must call `reveal(i, ops_secret_i, path_i, ...)` with:

1. `ops_secret_i` such that `Hleaf(H(ops_secret_i || "aegis-h/ops/pub"))` equals the `i`-th leaf of `ops_root`.
2. A matching `commit` in a prior block at height ≥ `D` ago.

If A does not know `master_seed`, then:

- To produce `ops_secret_i`, A must invert SHA-256 on the public leaf → ~2^128 Grover ops.
- To produce the commit in a prior block without knowing `ops_secret_i`, A must have predicted both `ops_secret_i` and the exact `tx_hash` before block `N - D`. Both require preimage inversion.

### 7.3 Claim: Observing a Phase-2 reveal does not help A steal

After Phase 2, `ops_secret_i` is public. But:

- `next_ops_index` incremented to `i+1`, slot `i` deleted.
- The leaf at index `i+1` is a fresh SHA-256 output; `ops_secret_{i+1}` not derivable from `ops_secret_i` (HKDF).
- To use `ops_secret_i` again A would need to replay the exact same `(target, value, data, i)` tuple, which is already executed; the strict `next_ops_index` check blocks it.

### 7.4 Claim: Front-run attack is bounded by finality

A sees Phase 1 commit `C` in block `N`. A wants to broadcast a competing commit `C'` at block `N' ≤ N` with their own `target'`.

- A must insert `C'` into a block ≤ `N`, which requires reorging the chain.
- Finality delay `D` ensures that by Phase 2, both `C` and all blocks ≤ `N` are economically final.
- Reorg cost ≥ cost of `D` blocks of mining; for Ethereum post-merge, `D = 2` is strong because reorging past 2 slots requires >33% stake.

For high-value accounts, use `D = 32` (Ethereum full epoch) or `D = 100` (BSC conservative).

### 7.5 Grover concretely

Best-known quantum attack on `k`-bit preimage: Grover's algorithm, `O(2^(k/2))` queries. For SHA-256 (k=256), this is 2^128 queries. Each query requires a reversible SHA-256 circuit (~250 000 Toffoli gates, estimates per Amy-Di-Matteo-Gheorghiu-Mosca-Parent-Schanck 2016). Total gate count ~2^128 × 2^18 = 2^146 quantum gates. No projected quantum hardware this century reaches 2^80 gate operations.

Conclusion: 128-bit post-quantum security on SHA-256 preimage is more conservative than NIST Level 1 (which is 2^80 PQ against brute search).

### 7.6 What this analysis does NOT prove

- Formal UC-security proof: not provided.
- Reduction to a standard model primitive: `H` is modelled as a random oracle, which is standard but technically unsound for monolithic constructions.
- Protection against side-channel attacks on `master_seed`.
- Protection against the user's own key-management mistakes (seed leaked, worker memory dumped).
- Protection against chain-level attacks (consensus failure, re-execution).

**You should pay a cryptographer to review this before holding more than $10k in a Horizon account.**

---

## 8. Multi-chain compatibility

| Chain | Primitive used | Status |
|---|---|---|
| EVM (ETH / BSC / Polygon / Arbitrum / Optimism / Base) | `SHA256` precompile (0x02) | 1-contract deploy |
| Bitcoin | OP_SHA256 + Taproot script path (BIP-341) | script-tree spec in §10 |
| Solana | `sha256` syscall | native program, ~500 LOC Rust |
| Cosmos (CosmWasm) | `sha2_256` host fn | ~300 LOC Rust |
| Aptos | `aptos_hash::sha2_256` | ~200 LOC Move |
| Sui | `hash::sha2_256` | ~200 LOC Move |
| NEAR | `env::sha256` | ~250 LOC Rust |
| TON | `HASHEXT_SHA256` | ~400 LOC Func/Tolk |
| Cairo (Starknet) | `core::sha256` | ~300 LOC Cairo |
| TRON | SHA256 EVM-compat precompile | reuses EVM contract |

All implementations verify the exact same byte-level protocol. A commit made from any client is reveal-compatible with any chain-side implementation.

---

## 9. UX & integration

- **Horizon-only accounts**: pure 2-phase cold wallet. Users accept finality delay. Suitable for large holdings.
- **Hybrid V3 accounts**: `AegisAccountV3` has ECDSA primary + Horizon as the pq-recovery root. ECDSA path identical to V2 (fast, free). Horizon path replaces SPHINCS+ with pure hash reveal. No external verifier contract needed, no 15kB bytecode, no 190k-gas verify.

Hybrid gas comparison (recovery op):

| Mechanism | On-chain verify gas | Witness size |
|---|---|---|
| V2 SPHINCS+ C13 | ~190 000 | 3 688 B |
| **V3 Horizon** | **~45 000** | **~700 B (32 B secret + 20 × 32 B path + header)** |

Horizon recovery is 4× cheaper and 5× smaller than SPHINCS+.

---

## 10. Bitcoin Taproot deployment sketch

Horizon fits into a Taproot script leaf as follows (one leaf per `(i, j)` precomputed, or a lazy approach with CHECKSIGADD against OP_RETURN commits):

```
# Taproot leaf script for ops index i
OP_SHA256                       # hash top-of-stack (ops_secret_i)
<ops_pub_i>                     # push expected pub (32 bytes)
OP_EQUALVERIFY                  # fail if mismatch
<32-level Merkle path verifier> # standard pattern using OP_SHA256 + OP_CAT? No — OP_CAT is BIP-347, not yet live.
```

**Honest limit**: full in-script Merkle verification requires OP_CAT (BIP-347) to concatenate hash siblings. Until BIP-347 activates (currently in review), the Bitcoin version uses a **single-leaf-per-script** encoding: user pre-commits each `(i, ops_pub_i)` as its own Taproot leaf (Merkle tree of script leaves, not of pub-key leaves). This is less efficient (one leaf per op) but works TODAY with activated BIP-341.

For post-CAT, a single leaf verifies any `i` with a 20-deep in-script Merkle verify (~700 opcodes, well under the 10 000 limit).

---

## 11. Reference implementations in this repo

- **Solidity**: `evm/src/AegisHorizon.sol` (this PR)
- **Tests**: `evm/test/AegisHorizon.t.sol`
- **TypeScript client** (keygen, commit, reveal): `wallet/src/aegis/horizon.ts` (future)
- **Rust reference** (byte-exact test vectors): `horizon-ref/` (future)

---

## 12. Known open problems

1. **Single-tx auth**: current design requires 2 txs + finality wait. A one-tx variant using VDFs or chain-anchored randomness beacons is possible but adds assumptions.
2. **Mass-adoption keygen cost**: 2^20 leaves = ~300 ms on laptop, ~2 s on low-end phone. Acceptable but noticeable.
3. **Recovery ceiling**: 256 recoveries per lifetime. Could be extended by rotating `rec_root` on each recovery, but adds state.
4. **Cross-chain atomic recovery**: rotating a user's `ops_root` across 10 chains atomically requires an off-chain coordinator or a bridge. Not solved in v1.
5. **State bloat**: outstanding commits accumulate state. A keepalive sweep (anyone can delete expired commits for a gas rebate) is suggested.

---

## 13. Changelog

- 1.0.0-draft (2026-10-08): initial specification. Honest about primitives, no breakthrough claims.
