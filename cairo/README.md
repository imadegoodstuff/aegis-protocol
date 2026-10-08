# Aegis — Starknet adapter (Cairo 1)

**Status**: complete CCHS-S-20 account contract (`AegisCCHS`) with a pure
verifier library (`cchs`) and fixture-driven unit tests. Compiled and tested in
CI with Scarb 2.8.5 (`scarb build`, `scarb test`). Not yet deployed or
gas-profiled on a live network.

Spec: [`../CCHS.spec.md`](../CCHS.spec.md). Byte-exact with
`evm/src/AegisCCHS.sol` and `wallet/src/aegis/cchs.ts`; ground truth is
`evm/test/fixtures/cchs-s-20.json`.

## Layout

```
Scarb.toml
src/lib.cairo          cchs library + IAegisCCHS + AegisCCHS contract + tests
src/test_vectors.cairo fixture vectors as u256 literals (test build only)
```

### `cchs` library (no storage, no state)

| Function | Purpose |
|---|---|
| `adrs_words(layer, tree_idx, typ, leaf_idx, chain_idx, step)` | ADRS as the first four big-endian `u32` words (words 4..7 are zero) |
| `digits(m: u256) -> Array<u32>` | 64 base-16 message digits + 3 checksum digits |
| `wots_leaf(layer, tree_idx, leaf_idx, m, wots) -> [u32; 8]` | complete 67 chains, compress to the leaf |
| `verify_layer(layer, tree_idx, leaf_idx, height, m, wots, auth) -> u256` | leaf + Merkle path → tree root |
| `u256_to_words` / `words_to_u256` | 32-byte value ⇄ eight big-endian `u32` words |

32-byte values cross the API as `u256` (numeric value of the 32 bytes,
big-endian). Internally everything is eight big-endian `u32` words, which is
the native input of `core::sha256::compute_sha256_u32_array`; all hash inputs
in the scheme (64, 96 and 2176 bytes) are whole words, so the partial-word
arguments are always `(0, 0)`.

### `AegisCCHS` contract

Storage: `root: u256`, `rec_root: u256`, `epoch: u64`, `next_idx: u64`,
`nonce: u64`, `rec_nonce: u64`, `cached_root: Map<(u64, u64), u256>` keyed by
`(epoch, bottom_tree_idx)`.

```
constructor(root: u256, rec_root: u256)

execute(calls: Array<Call>,
        l0_wots: Array<u256>, l0_auth: Array<u256>,     // 67 + 10
        l1_wots: Array<u256>, l1_auth: Array<u256>)     // 67 + 10, or both empty
  -> Array<Span<felt252>>

recover(new_root: u256, new_rec_root: u256,
        wots: Array<u256>, auth: Array<u256>)           // 67 + 8

next_digest(calls) -> u256          next_recovery_digest(new_root, new_rec_root) -> u256
needs_top_layer() -> bool           get_root / get_rec_root / get_epoch / get_next_idx /
                                    get_nonce / get_rec_nonce / get_cached_root(epoch, tree_idx)
```

`execute` flow (identical to the Solidity reference):

1. `idx = next_idx` (must be `< 2^20`), `tree_idx = idx >> 10`, `leaf_idx = idx & 1023`.
2. `m = digest(idx, calls)`; `r0 = verify_layer(0, tree_idx, leaf_idx, 10, m, l0)`.
3. If `cached_root[(epoch, tree_idx)] != 0` it must equal `r0`. Otherwise
   `l1_wots` must be present, `verify_layer(1, 0, tree_idx, 10, r0, l1)` must equal
   `root`, and `r0` is cached.
4. `next_idx += 1`, `nonce += 1`, then `call_contract_syscall` for every call in
   order; results are returned.

`recover` verifies the recovery tree (layer `0xFF`, tree 0, leaf `rec_nonce`,
height 8) against `rec_root`, then sets both roots, resets `next_idx` to 0 and
increments `epoch` (which logically clears the cache) and `rec_nonce`.

`Call` is `starknet::account::Call { to, selector, calldata: Span<felt252> }`.

### Digest construction (Starknet)

```
calls_hash = sha256( for each call:
                       to(32 BE) ‖ selector(32 BE) ‖ calldata_len(4 BE) ‖ calldata[i](32 BE)… )

M          = sha256( "AEGIS_CCHS_V1" ‖ "starknet" ‖ contract_address(32 BE)
                     ‖ nonce(8 BE) ‖ idx(8 BE) ‖ calls_hash(32) )

M_rec      = sha256( "AEGIS_CCHS_RECOVER_V1" ‖ "starknet" ‖ contract_address(32 BE)
                     ‖ rec_nonce(8 BE) ‖ new_root(32) ‖ new_rec_root(32) )
```

Felts (`to`, `selector`, calldata elements, the contract address) are encoded
as their numeric value in 32 big-endian bytes. Clients can fetch `next_digest`
and `next_recovery_digest` from the contract instead of re-deriving them.

Note: the digest binds the literal `"starknet"` and the account address, not
the network chain id. Two networks that produce the same account address for
the same class/salt/deployer (e.g. mainnet and a testnet) would therefore share
digests while `nonce`/`next_idx` coincide. Binding
`get_tx_info().chain_id` is a one-line change if that property is required.

## Build and test

```bash
scarb build          # Sierra + CASM for AegisCCHS
scarb test           # cairo-test: fixture-driven unit tests (see below)
```

Tests (`src/lib.cairo`, module `tests`):

| Test | Checks |
|---|---|
| `digits_of_fixture_digest` | nibbles and checksum `0x1ae` of `ops[1].digest` |
| `digits_all_zero_message` | checksum `960 = 0x3c0` for the zero message |
| `adrs_layout` | byte positions of every ADRS field |
| `u256_words_roundtrip` | word order of the `u256` ⇄ words conversion |
| `verify_layer_bottom_fixture` | `ops[1]` (cached path) → `bottomRoot0` |
| `verify_layer_top_fixture` | `ops[0].l1` on `bottomRoot0` at leaf 0 → `root` |
| `verify_layer_recovery_fixture` | recovery vector, layer `0xFF`, height 8 → `recRoot` |
| `verify_layer_rejects_tampered_chain` | a modified chain value changes the root |

## Cost (estimate, not measured on-chain)

Per `verify_layer`: 67 chains × 7.5 steps on average ≈ 500 chain hashes
(64-byte input → 2 SHA-256 blocks each), 10 node hashes (96 bytes → 2 blocks)
and one 2176-byte leaf compression (35 blocks), i.e. about **1,060 SHA-256
compression blocks**, each one `sha256_process_block_syscall`. A cached-subtree
`execute` runs one layer (≈ 1,060 blocks + the two digest hashes); the first
signature in a subtree runs two (≈ 2,120 blocks); `recover` runs one height-8
layer (≈ 1,055 blocks).

On top of the SHA-256 builtin resource, the Cairo overhead is dominated by
packing inputs into `Array<u32>` (16–24 appends per hash plus one `u256` →
words conversion per chain and per sibling), on the order of a few hundred
Cairo steps per hash call, so roughly 0.2–0.4 M steps per layer before the
syscall cost. This is accepted for a post-quantum account on an L2; on
Starknet the SHA-256 builtin is priced per block by the sequencer and dominates
the fee. Measured numbers will be added after a testnet deployment.
