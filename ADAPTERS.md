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
| 10 | Starknet | Cairo VM | `cairo/` | Cairo 1 | class hash + pedersen | `core::sha256` | scaffold | planned (~300 LOC) |
| 11 | Solana | SVM | `solana/` | Rust / Anchor | `base58(ed25519_pk)` | `sha256` syscall | scaffold | planned (~500 LOC) |
| 12 | Cosmos | CosmWasm | `cosmwasm/` | Rust | `bech32(ripemd160(sha256(pk)))` | `sha2_256` | scaffold | planned (~300 LOC) |
| 13 | Aptos | Move | `aptos/` | Move | `sha3_256(pk ‖ 0x00)` | `hash::sha2_256` | scaffold | planned (~200 LOC) |
| 14 | Sui | Move | `sui/` | Move 2024 | `blake2b_256(0x00 ‖ pk)` | `hash::sha2_256` | scaffold | planned (~200 LOC) |
| 15 | NEAR | WASM | `near/` | Rust / near-sdk | `hex(ed25519_pk)` | `env::sha256` | scaffold | planned (~250 LOC) |
| 16 | TON | TVM (TON) | `ton/` | FunC / Tolk | `hash(StateInit)` | `HASHEXT_SHA256` | scaffold | planned (~400 LOC) |
| 17 | Bitcoin | Script | `bitcoin/` | Tapscript | BIP-86 P2TR | `OP_SHA256` | design (`CCHS.spec.md` §7.1) | flat Tapscript tree today; cached variant needs OP_CAT |

Address derivation for all 23 supported chains is implemented and produces standard, wallet-importable addresses: `wallet/src/aegis/derive.ts`.

## What a scaffold contains

Each non-EVM directory compiles and defines the account's storage layout, entry points, and build commands. The CCHS verification body is the remaining work. Because the algorithm is fixed by `CCHS.spec.md` and the EVM implementation is complete and tested, each port is a direct translation with shared test vectors.

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
