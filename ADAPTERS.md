# Chain Adapters — Status Matrix

Aegis separates a chain-agnostic core (seed → CCHS master, SLH-DSA seed, secp256k1 and ed25519 keys; standard address derivation for 23 chains) from per-chain adapters that implement the account contract in the chain's native language.

The CCHS verifier (`CCHS.spec.md` §5) requires only SHA-256, byte concatenation, integer shifts, and 32-byte storage. Every adapter implements the same byte-level algorithm; a signature produced by the client is valid input to every chain's verifier (the chain ID is bound inside the digest, so it is not replayable across chains).

## Matrix

| # | Chain | Family | Directory | Language | Address derivation | SHA-256 primitive | Account contract | CCHS verify |
|---|---|---|---|---|---|---|---|---|
| 1 | Ethereum | EVM | `evm/` | Solidity | CREATE2 | precompile `0x02` | complete | **complete, interop-tested** |
| 2 | BSC | EVM | `evm/` | Solidity | CREATE2 | precompile | same artifact | same artifact |
| 3 | Polygon | EVM | `evm/` | Solidity | CREATE2 | precompile | same | same |
| 4 | Arbitrum | EVM | `evm/` | Solidity | CREATE2 | precompile | same | same |
| 5 | Optimism | EVM | `evm/` | Solidity | CREATE2 | precompile | same | same |
| 6 | Base | EVM | `evm/` | Solidity | CREATE2 | precompile | same | same |
| 7 | Avalanche | EVM | `evm/` | Solidity | CREATE2 | precompile | same | same |
| 8 | Linea / Scroll / Mantle / Blast / Mode | EVM | `evm/` | Solidity | CREATE2 | precompile | same | same |
| 9 | TRON | TVM | `tron/` | Solidity | `base58check(0x41 ‖ addr)` | precompile | shared with EVM | shared with EVM |
| 10 | Starknet | Cairo VM | `cairo/` | Cairo 1 | class hash + pedersen | `core::sha256` (`compute_sha256_u32_array`) | implemented (`AegisCCHS`: multicall via `call_contract_syscall`, recover, cache map) | **implemented** (`scarb test` replays bottom, top and recovery vectors); not yet deployed |
| 11 | Solana | SVM | `solana/` | Rust / Anchor | `base58(ed25519_pk)` | `sha256` syscall | implemented (`cchs-core` + Anchor program) | implemented (CI-compiled, core verified against vectors) |
| 12 | Cosmos | CosmWasm | `cosmwasm/` | Rust | `bech32(ripemd160(sha256(pk)))` | `sha2` crate | implemented (`cchs-core` + contract) | implemented (CI-compiled, core verified against vectors) |
| 13 | Aptos | Move | `aptos/` | Move | `sha3_256(pk ‖ 0x00)` | `hash::sha2_256` | implemented (APT transfer, v1) | **implemented** (CI-compiled, layer verify tested against vectors) |
| 14 | Sui | Move | `sui/` | Move 2024 | `blake2b_256(0x00 ‖ pk)` | `hash::sha2_256` | implemented (shared object, SUI balance, v1) | **implemented** (CI-compiled, layer verify tested against vectors) |
| 15 | NEAR | WASM | `near/` | Rust / near-sdk | `hex(ed25519_pk)` | `env::sha256_array` | implemented (`cchs-core` + contract) | implemented (CI-compiled, core verified against vectors) |
| 16 | TON | TVM (TON) | `ton/` | FunC | `hash(StateInit)` | `HASHEXT_SHA256` | implemented (internal-message account: `send_raw_message` action, recover, dict cache) | **implemented, sandbox-tested** (fixture roots + full execute/cache/replay/recover flow); not yet deployed |
| 17 | Bitcoin | Script | `bitcoin/` | Tapscript | BIP-86 P2TR | `OP_SHA256` | design (`CCHS.spec.md` §7.1) | flat Tapscript tree today; cached variant needs OP_CAT |

Address derivation for all 23 supported chains is implemented and produces standard, wallet-importable addresses: `wallet/src/aegis/derive.ts`.

## Shared Rust core

`cchs-core/` is a `no_std`, dependency-free crate implementing the whole CCHS-S-20 verifier (ADRS, WOTS+ chain completion, leaf compression, Merkle path, cache state machine, recovery) over an injected SHA-256. Its test suite (`cargo test -p cchs-core --features std`, CI job `cchs-core`) replays `evm/test/fixtures/cchs-s-20.json`: first-in-subtree with top layer, two cached signatures, tampered chain value / auth path / message, and the recovery rotation. The Solana, CosmWasm and NEAR adapters depend on it by path and add only their chain digest, storage and call dispatch.

Per-chain digests (the EVM chain id is replaced by a chain tag):

| Chain | `M` |
|---|---|
| Solana | `sha256("AEGIS_CCHS_V1" ‖ "solana" ‖ account(32) ‖ nonce BE ‖ idx BE ‖ sha256(target_program ‖ ix_data))` |
| CosmWasm | `sha256("AEGIS_CCHS_V1" ‖ "cosmwasm" ‖ contract_address_utf8 ‖ nonce BE ‖ idx BE ‖ sha256(to_json_binary(msgs)))` |
| NEAR | `sha256("AEGIS_CCHS_V1" ‖ "near" ‖ sha256(account_id) ‖ nonce BE ‖ idx BE ‖ sha256(len‖receiver ‖ len‖method ‖ len‖args ‖ deposit u128 BE))` |
| Aptos | `sha256("AEGIS_CCHS_V1" ‖ "aptos" ‖ bcs(account)(32) ‖ nonce BE ‖ idx BE ‖ sha256(bcs(recipient) ‖ amount u64 BE))` (Move, `aptos/`) |
| Sui | `sha256("AEGIS_CCHS_V1" ‖ "sui" ‖ object_id(32) ‖ nonce BE ‖ idx BE ‖ sha256(recipient(32) ‖ amount u64 BE))` (Move, `sui/`) |
| Starknet | `sha256("AEGIS_CCHS_V1" ‖ "starknet" ‖ contract_address(32 BE) ‖ nonce BE ‖ idx BE ‖ sha256(for each call: to(32) ‖ selector(32) ‖ calldata_len u32 BE ‖ calldata[i](32)…))` (Cairo, `cairo/`) |
| TON | `sha256("AEGIS_CCHS_V1" ‖ "ton" ‖ address_hash(32) ‖ nonce BE ‖ idx BE ‖ cell_hash(action))`, `action = { mode:uint8 msg:^Cell }` (FunC, `ton/`) |

## What a scaffold contains

Each remaining non-EVM directory compiles and defines the account's storage layout, entry points, and build commands. The CCHS verification body is the remaining work. Because the algorithm is fixed by `CCHS.spec.md` and the EVM and Rust implementations are complete and tested, each port is a direct translation with shared test vectors.

## Common interface

Every adapter exposes the following semantics (names vary by language):

```
constructor(root, recRoot)
execute(target, value, data, l0, hasL1, l1)
recover(newRoot, newRecRoot, wots, auth)
nextDigest(target, value, data) → bytes32
needsTopLayer() → bool
```

State: `root`, `recRoot`, `epoch`, `nextIdx`, `nonce`, `recNonce`, `cachedRoot[(epoch, treeIdx)]`.

Authoritative definition: `CCHS.spec.md` §4–§5.
