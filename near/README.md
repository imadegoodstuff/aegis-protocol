# Aegis — NEAR adapter (CCHS-S-20)

**Status**: implemented. The contract compiles to `wasm32-unknown-unknown` in
CI (`build.yml`, job `near`) and uses `../cchs-core`, which is CI-tested
against the shared vectors in `evm/test/fixtures/cchs-s-20.json`.

Spec: `../CCHS.spec.md`. Reference implementation: `../evm/src/AegisCCHS.sol`.

## What it does

A hash-only post-quantum account. Each `execute` is authorized by a WOTS+
signature (SHA-256, w = 16, 67 chains) under a two-layer hypertree of height
10 + 10 (2^20 signatures). The top-layer proof for a bottom subtree is verified
once and cached in `cache[(epoch, tree_idx)]`; the following 1023 signatures
carry only the bottom layer. SHA-256 is the `env::sha256_array` host function.

The signer chooses the leaf index: `execute(idx, ..)` must satisfy
`idx >= next_idx` (otherwise the call panics with `index used`) and sets
`next_idx = idx + 1`, so skipped leaves are abandoned forever (only the signer
can skip, because `idx` is in the digest). The top layer `l1` is required when
the subtree `idx >> 10` is not cached yet and ignored when it already is.

Deploy one contract per user; the contract account is the user's account.

## State

```
root, rec_root: [u8; 32]
epoch, next_idx, nonce, rec_nonce: u64
cache: LookupMap<(u64, u64), [u8; 32]>   (epoch, bottom tree index) → verified bottom root
```

`recover` bumps `epoch`, which logically clears the cache.

## Methods

| Method | Args encoding | Arguments |
|---|---|---|
| `new` (init) | JSON | `root`, `rec_root`: base64 32 bytes; `seed`: base64 16 bytes |
| `execute` | **Borsh** | `idx: u64`, `l0: LayerSig`, `l1: Option<LayerSig>`, `receiver_id: AccountId`, `method: String`, `args: Vec<u8>`, `deposit: u128`, `gas: u64` |
| `recover` | **Borsh** | `new_root: [u8;32]`, `new_rec_root: [u8;32]`, `new_seed: [u8;16]`, `wots: Vec<[u8;32]>` (67), `auth: Vec<[u8;32]>` (8) |
| `get_state` | JSON | — |
| `needs_top_layer` | JSON | — (`idx = next_idx`) |
| `needs_top_layer_at` | JSON | `idx` (string u64) |
| `next_digest` | JSON | `receiver_id`, `method`, `args` (base64), `deposit` (string u128) — `idx = next_idx` |
| `digest_at` | JSON | `idx` (string u64), `receiver_id`, `method`, `args` (base64), `deposit` (string u128) |
| `next_recovery_digest` | JSON | `new_root`, `new_rec_root` (base64 32 B), `new_seed` (base64 16 B) |

`LayerSig` is the Borsh struct `{ wots: Vec<[u8;32]> /*67*/, auth: Vec<[u8;32]> /*10*/ }`.
Borsh is used for `execute` / `recover` so a 2.5 KB signature is not inflated
by JSON. `execute` returns a `Promise` calling `receiver_id.method(args)` with
`deposit` yoctoNEAR and `gas` gas, sent from the contract account.

## Digest

```
inner = sha256(len(receiver_id) u32 BE ‖ receiver_id
             ‖ len(method) u32 BE ‖ method
             ‖ len(args) u32 BE ‖ args
             ‖ deposit u128 BE)

M = sha256("AEGIS_CCHS_V1" ‖ "near" ‖ sha256(current_account_id) ‖ nonce u64 BE ‖ idx u64 BE ‖ inner)

M_rec = sha256("AEGIS_CCHS_RECOVER_V1" ‖ "near" ‖ sha256(current_account_id) ‖ rec_nonce u64 BE
               ‖ new_root ‖ new_rec_root ‖ new_seed)
```

`current_account_id` is the UTF-8 account name of the contract. The
variable-length fields of `inner` are length-prefixed so that a relayer cannot
re-split `(receiver_id, method, args)` into a different call with the same
digest. `gas` is not part of the digest (like gas on EVM). Use the
`next_digest` / `digest_at` view to obtain the exact bytes to sign.

## Layer verification (shared with every chain)

```
ADRS = layer(1) ‖ treeIdx(8 BE) ‖ type(1) ‖ leafIdx(4 BE) ‖ chainIdx(1) ‖ step(1) ‖ pkSeed(16)
F(adrs, x)   = sha256(adrs ‖ x)                      type 0x00
leaf         = sha256(adrs ‖ pk_0 ‖ … ‖ pk_66)        type 0x01
node         = sha256(adrs ‖ left ‖ right)            type 0x02, leafIdx = pos >> 1, chainIdx = level
```

Layer 0: `treeIdx = idx >> 10`, `leafIdx = idx & 1023`, message `M`. Layer 1:
`treeIdx = 0`, `leafIdx = idx >> 10`, message `R_0`; required unless
`cache[(epoch, idx >> 10)]` already holds `R_0`. Recovery: layer `0xFF`,
tree 0, `leafIdx = rec_nonce`, height 8.

`pkSeed` is the 16-byte public seed of the key tree (part of the public key,
rotated by recovery, `CCHS.spec.md` §2.2): every hash call of one tree is a
different function from the same position in any other tree.

## Build

```bash
cargo build --release --target wasm32-unknown-unknown --lib
# or, with cargo-near:
cargo install cargo-near && cargo near build
```

## Deploy

```bash
near deploy <account>.near target/wasm32-unknown-unknown/release/aegis_near.wasm \
    --initFunction new \
    --initArgs '{"root":"<base64>","rec_root":"<base64>","seed":"<base64 16B>"}'
```

## Tests

```bash
cargo test                                  # contract-level index discipline and views
cd ../cchs-core && cargo test --features std   # fixture vectors, including the skip ops
```
