# Aegis — CosmWasm adapter (CCHS-S-20)

**Status**: implemented. The contract compiles to `wasm32-unknown-unknown` in
CI (`build.yml`, job `cosmwasm`) and uses `../cchs-core`, which is CI-tested
against the shared vectors in `evm/test/fixtures/cchs-s-20.json`.

Spec: `../CCHS.spec.md`. Reference implementation: `../evm/src/AegisCCHS.sol`.

## Target chains

Any chain with CosmWasm 2.x: Osmosis, Neutron, Injective, Archway, Juno,
Stargaze, Terra, …

## What it does

A hash-only post-quantum account. Each `Execute` is authorized by a WOTS+
signature (SHA-256, w = 16, 67 chains) under a two-layer hypertree of height
10 + 10 (2^20 signatures). The top-layer proof for a bottom subtree is verified
once and cached in `cache[(epoch, tree_idx)]`; the following 1023 signatures
carry only the bottom layer. SHA-256 is the `sha2` crate compiled into the
wasm.

## Storage

```
state: Item<State>               root, rec_root (Binary 32), epoch, next_idx, nonce, rec_nonce
cache: Map<(u64, u64), Binary>   (epoch, bottom tree index) → verified bottom root
```

`Recover` bumps `epoch`, which logically clears the cache without deleting
entries.

## Messages

```jsonc
// instantiate
{ "root": "<base64 32B>", "rec_root": "<base64 32B>" }

// execute
{ "execute": {
    "l0":  { "wots": ["<base64 32B>" × 67], "auth": ["<base64 32B>" × 10] },
    "l1":  { "wots": [...67], "auth": [...10] },   // or null when the subtree is cached
    "msgs": [ /* CosmosMsg[] */ ] } }

{ "recover": {
    "new_root": "<base64 32B>", "new_rec_root": "<base64 32B>",
    "wots": ["<base64 32B>" × 67], "auth": ["<base64 32B>" × 8] } }

// query
{ "state": {} }
{ "next_digest": { "msgs": [ ... ] } }                        → base64 32B
{ "next_recovery_digest": { "new_root": "...", "new_rec_root": "..." } }
{ "needs_top_layer": {} }                                     → bool
```

Anyone may submit `Execute`; authorization is the signature. On success the
contract returns `msgs` as sub-messages executed with the contract as sender.

## Digest

```
M = sha256("AEGIS_CCHS_V1" ‖ "cosmwasm" ‖ contract_address_utf8 ‖ nonce u64 BE ‖ next_idx u64 BE
           ‖ sha256(to_json_binary(msgs)))

M_rec = sha256("AEGIS_CCHS_RECOVER_V1" ‖ "cosmwasm" ‖ contract_address_utf8 ‖ rec_nonce u64 BE
               ‖ new_root ‖ new_rec_root)
```

`contract_address_utf8` is the bech32 string of `env.contract.address`
(it includes the chain prefix). `to_json_binary(msgs)` is the contract's own
canonical JSON of the `Vec<CosmosMsg>` — use the `next_digest` query to obtain
the exact bytes rather than re-serializing client-side.

## Layer verification (shared with every chain)

```
ADRS = layer(1) ‖ treeIdx(8 BE) ‖ type(1) ‖ leafIdx(4 BE) ‖ chainIdx(1) ‖ step(1) ‖ 16 zero bytes
F(adrs, x)   = sha256(adrs ‖ x)                      type 0x00
leaf         = sha256(adrs ‖ pk_0 ‖ … ‖ pk_66)        type 0x01
node         = sha256(adrs ‖ left ‖ right)            type 0x02, leafIdx = pos >> 1, chainIdx = level
```

Layer 0: `treeIdx = idx >> 10`, `leafIdx = idx & 1023`, message `M`. Layer 1:
`treeIdx = 0`, `leafIdx = idx >> 10`, message `R_0`; required unless
`cache[(epoch, idx >> 10)]` already holds `R_0`. Recovery: layer `0xFF`,
tree 0, `leafIdx = rec_nonce`, height 8.

## Build

```bash
# requires rustup target wasm32-unknown-unknown
cargo wasm           # alias in .cargo/config.toml
# or:
RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown --lib
```

Produces `target/wasm32-unknown-unknown/release/aegis_cosmwasm.wasm`.

## Core tests

```bash
cd ../cchs-core && cargo test --features std
```
