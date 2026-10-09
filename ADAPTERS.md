# Chain Adapters — Status Matrix

Aegis separates a chain-agnostic core (seed → CCHS master, SLH-DSA seed, secp256k1 and ed25519 keys; standard address derivation for 23 chains) from per-chain adapters that implement the account contract in the chain's native language.

The CCHS verifier (`CCHS.spec.md` §5) requires only SHA-256, byte concatenation, integer shifts, and 32-byte storage. Every adapter implements the same byte-level algorithm, verified against the same fixture vectors, including the 16-byte public seed of the key tree (`pkSeed`, `CCHS.spec.md` §2.1) that fills the last 16 bytes of every ADRS and is stored next to the roots. Keys are per chain (`CCHS.spec.md` §3): the client derives a separate tree for each chain, so a signature belongs to exactly one chain's account, and the chain ID bound inside the digest makes it non-replayable as well.

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
| 9 | TRON | TVM | `tron/` | Solidity | CREATE2 with prefix `0x41`, shown as `base58check(0x41 ‖ addr)`; factory address per publisher (no deterministic proxy) | precompile `0x02` | same sources, TVM build (`tron/build.mjs`: cancun target, opcode-scanned, init code byte-identical to the EVM artifact); not yet deployed on Nile or mainnet | same bytecode as EVM; `deploy()`/`accountOf` correct on TRON, on-chain `predict()` view uses the EVM `0xff` rule, so predict with `wallet/src/aegis/tronAccount.ts` |
| 10 | Starknet | Cairo VM | `cairo/` | Cairo 1 | class hash + pedersen | `core::sha256` (`compute_sha256_u32_array`) | implemented (`AegisCCHS`: multicall via `call_contract_syscall`, recover, cache map) | **implemented** (`scarb test` replays bottom, top and recovery vectors); not yet deployed |
| 11 | Solana | SVM | `solana/` | Rust / Anchor | `base58(ed25519_pk)` | `sha256` syscall | implemented (`cchs-core::compact` + Anchor program; **CCHS-C-20**, 864-byte layer, `cache_subtree` + `execute` split so every signature is one packet) | implemented (core verified against `cchs-c-20.json` including the skip sequence; program built with `cargo build-sbf` in CI; not deployed on devnet or mainnet) |
| 12 | Cosmos | CosmWasm | `cosmwasm/` | Rust | `bech32(ripemd160(sha256(pk)))` | `sha2` crate | implemented (`cchs-core` + contract) | implemented (CI-compiled, core verified against vectors) |
| 13 | Aptos | Move | `aptos/` | Move | resource account: `sha3_256(bcs(creator) ‖ "AEGIS_CCHS_V1" ‖ root ‖ 0xFF)` | `hash::sha2_256` | implemented: resource account with zeroed auth key, `SignerCapability` held by the module, signer-free `execute_transfer<CoinType>` / `execute_transfer_fa`; module must be published `upgrade_policy = "immutable"` | **implemented** (CI-compiled; fixture vectors plus end-to-end create/fund/execute/cached/recover tests); not published on any network yet |
| 14 | Sui | Move | `sui/` | Move 2024 | shared object id | `hash::sha2_256` | implemented: shared object, no owner signature anywhere, generic `Bag` of `Balance<T>` with `execute_transfer<T>`; package must be made immutable (`sui::package::make_immutable`) after publish | **implemented** (CI-compiled; fixture vectors plus end-to-end `test_scenario` tests); not published on any network yet |
| 15 | NEAR | WASM | `near/` | Rust / near-sdk | `hex(ed25519_pk)` | `env::sha256_array` | implemented (`cchs-core` + contract) | implemented (CI-compiled, core verified against vectors) |
| 16 | TON | TVM (TON) | `ton/` | FunC | `hash(StateInit)` | `HASHEXT_SHA256` | implemented (internal-message account: `send_raw_message` action, recover, dict cache) | **implemented, sandbox-tested** (fixture roots + full execute/cache/replay/recover flow); not yet deployed |
| 17 | Bitcoin | Script | `wallet/src/aegis/btcCchs.ts`, `btcTx.ts` | Tapscript | P2TR per state (NUMS internal key), address changes every spend; wallet receives at BIP-84 P2WPKH until the opcodes are on mainnet | `OP_SHA256` + `OP_CAT` + `OP_CHECKSIGFROMSTACK` | implemented as a UTXO lineage: each UTXO commits to `(root, recRoot, pkSeed, epoch, t, R_t, nextIdx)`, leaves `exec` / `execFirst` / `recover` (`BITCOIN.md` §5) | **implemented, executed on Bitcoin Inquisition signet and on an Inquisition regtest node in CI**; successor signer-enforced until a key-less output (BIP-360) exists; opcodes not active on mainnet |

Address derivation for all 23 supported chains is implemented and produces standard, wallet-importable addresses: `wallet/src/aegis/derive.ts`.

## Shared Rust core

`cchs-core/` is a `no_std`, dependency-free crate implementing the whole CCHS-S-20 verifier (seeded ADRS, WOTS+ chain completion, leaf compression, Merkle path, cache state machine, recovery with seed rotation) over an injected SHA-256. Its test suite (`cargo test -p cchs-core --features std`, CI job `cchs-core`) replays `evm/test/fixtures/cchs-s-20.json`: first-in-subtree with top layer, two cached signatures, tampered chain value / auth path / message, and the recovery rotation. The CosmWasm and NEAR adapters depend on it by path and add only their chain digest, storage and call dispatch.

The same crate carries a second parameter set in `cchs_core::compact`: **CCHS-C-20** — n = 24 (SHA-256 truncated to 24 bytes), w = 256, 24 message chains + 2 checksum chains (LEN = 26), the same two layers of height 10, recovery tree of height 8 and the same 32-byte seeded ADRS. One layer is 26 × 24 + 10 × 24 = 864 bytes, which is what lets a bottom-layer signature fit a 1 232-byte Solana packet. Besides the S-20-shaped API (`verify_layer`, `wots_leaf`, `root_from_path`, `CchsState::execute_verify`, `recover_verify`) it exposes `bottom_root(seed, idx, m, l0)` and `verify_top_layer(seed, root, tree_idx, r0, l1)` so a host can fill the subtree cache in one transaction and execute in another. Test vectors: `evm/test/fixtures/cchs-c-20.json`, replayed by `cchs-core/tests/vectors_compact.rs` (same CI job). Client: `wallet/src/aegis/cchsCompact.ts`. The Solana adapter uses this set; key derivation is domain-separated (`cchs/sk/c`), so one key yields independent S-20, K-20 and C-20 trees. The key itself is per chain (`HKDF-SHA256(master, "aegis/cchs/chain/v1" ‖ tag)`, tag `0x00 ‖ chainId` for EVM chains and `0x01 ‖ label` otherwise, CCHS.spec.md §3): no one-time leaf exists on two chains, which the chain id in the digest alone would not guarantee.

Per-chain digests (the EVM chain id is replaced by a chain tag):

| Chain | Parameter set | `M` |
|---|---|---|
| Solana | CCHS-C-20 | `sha256("AEGIS_CCHS_V1" ‖ "solana" ‖ account(32) ‖ nonce BE ‖ idx BE ‖ sha256(target_program ‖ ix_data))[0..24)` |
| CosmWasm | CCHS-S-20 | `sha256("AEGIS_CCHS_V1" ‖ "cosmwasm" ‖ contract_address_utf8 ‖ nonce BE ‖ idx BE ‖ sha256(to_json_binary(msgs)))` |
| NEAR | CCHS-S-20 | `sha256("AEGIS_CCHS_V1" ‖ "near" ‖ sha256(account_id) ‖ nonce BE ‖ idx BE ‖ sha256(len‖receiver ‖ len‖method ‖ len‖args ‖ deposit u128 BE))` |
| Aptos | CCHS-S-20 | `sha256("AEGIS_CCHS_V1" ‖ "aptos" ‖ bcs(resource_account)(32) ‖ nonce BE ‖ idx BE ‖ sha256(asset ‖ bcs(recipient) ‖ amount u64 BE))`, `asset = sha256(0x00 ‖ type_name<CoinType>)` or `sha256(0x01 ‖ bcs(fa_metadata))` (Move, `aptos/`) |
| Sui | CCHS-S-20 | `sha256("AEGIS_CCHS_V1" ‖ "sui" ‖ object_id(32) ‖ nonce BE ‖ idx BE ‖ sha256(asset ‖ recipient(32) ‖ amount u64 BE))`, `asset = sha256(0x00 ‖ type_name::with_defining_ids<T>)` (Move, `sui/`) |
| Starknet | CCHS-S-20 | `sha256("AEGIS_CCHS_V1" ‖ "starknet" ‖ contract_address(32 BE) ‖ nonce BE ‖ idx BE ‖ sha256(for each call: to(32) ‖ selector(32) ‖ calldata_len u32 BE ‖ calldata[i](32)…))` (Cairo, `cairo/`) |
| TON | CCHS-S-20 | `sha256("AEGIS_CCHS_V1" ‖ "ton" ‖ address_hash(32) ‖ nonce BE ‖ idx BE ‖ cell_hash(action))`, `action = { mode:uint8 msg:^Cell }` (FunC, `ton/`) |

Every recovery digest ends with the 16-byte seed of the new key tree (`‖ new_seed`), after `new_rec_root`. Solana's is likewise truncated: `sha256("AEGIS_CCHS_RECOVER_V1" ‖ "solana" ‖ account(32) ‖ rec_nonce BE ‖ new_root(24) ‖ new_rec_root(24) ‖ new_pk_seed(16))[0..24)`.

## What a scaffold contains

Each remaining non-EVM directory compiles and defines the account's storage layout, entry points, and build commands. The CCHS verification body is the remaining work. Because the algorithm is fixed by `CCHS.spec.md` and the EVM and Rust implementations are complete and tested, each port is a direct translation with shared test vectors.

## Common interface

Every adapter exposes the following semantics (names vary by language):

```
constructor(root, recRoot, pkSeed)
execute(target, value, data, idx, l0)              # subtree already cached
executeFirst(target, value, data, idx, l0, l1)     # registers the subtree; l1 ignored if already cached
recover(newRoot, newRecRoot, newSeed, wots, auth)
digestAt(idx, target, value, data) → bytes32
needsTopLayerAt(idx) → bool
```

State: `root`, `recRoot`, `pkSeed`, `epoch`, `nextIdx`, `nonce`, `recNonce`, `cachedRoot[(epoch, treeIdx)]`.

Index rule, identical on every chain: `idx ≥ nextIdx` is required, `nextIdx` becomes `idx + 1`, lower leaves are abandoned forever. The EVM contracts keep that counter and the nonce *per lane* (16 lanes by the top four bits of `idx`, `CCHS.spec.md` §4.3 rule 4), so devices owning different lanes sign concurrently; the other adapters still keep one counter and one nonce for the whole tree, which is the single-lane case of the same rule, and a multi-device client on those chains must route signing through one device until they adopt lanes. `idx` is part of the digest, so only the key holder can skip. A jump into a subtree that is not cached needs the top layer (`executeFirst`); the same index can never be accepted twice (CCHS.spec.md §4.3, §6 C5). Every adapter in this file (EVM/TRON, Starknet, Solana, CosmWasm, NEAR, Aptos, Sui, TON) implements the explicit `idx` argument with `digestAt` / `needsTopLayerAt` views and a fixture-driven test for index reuse; the rejection code is named in each directory's README (`IndexUsed`, `E_INDEX_USED`, exit code 207 on TON).

Solana (CCHS-C-20) splits `execute` in two because of the packet limit: `cache_subtree(treeIdx, l1, r0)` fills `cachedRoot` and `execute(idx, l0, ixData)` only ever carries the bottom layer. The state and the acceptance condition are the same; see `solana/README.md`.

Authoritative definition: `CCHS.spec.md` §4–§5.
