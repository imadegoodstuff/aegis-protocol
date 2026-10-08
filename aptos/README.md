# Aegis — Aptos adapter (CCHS-S-20)

**Status**: implemented. Compiled and unit-tested in CI (`aptos move test`);
`verify_layer` is checked against the shared fixture
`evm/test/fixtures/cchs-s-20.json` (bottom-layer root and top-layer root).
Not yet deployed to a network.

Module: `aptos/sources/aegis_account.move` (`aegis::aegis_account`).
Protocol: `../CCHS.spec.md`. Reference implementations: `evm/src/AegisCCHS.sol`,
`wallet/src/aegis/cchs.ts`.

## Design

A `CchsAccount` resource is published under the owner's address:

| Field | Type | Meaning |
|---|---|---|
| `root` | `vector<u8>` (32) | top-layer tree root; rotated only by `recover` |
| `rec_root` | `vector<u8>` (32) | recovery tree root (height 8) |
| `epoch` | `u64` | bumped on every recovery; namespaces the cache |
| `next_idx` | `u64` | next unused leaf in `[0, 2^20)` |
| `nonce` | `u64` | bound into every digest |
| `rec_nonce` | `u64` | next unused recovery leaf in `[0, 256)` |
| `cached_root` | `Table<u128, vector<u8>>` | `(epoch << 64) \| tree_idx` → verified bottom subtree root |

Entry functions:

```
create(account: &signer, root, rec_root)
execute_transfer(account: &signer, recipient, amount,
                 l0_wots: vector<vector<u8>>, l0_auth: vector<vector<u8>>,
                 has_l1: bool,
                 l1_wots: vector<vector<u8>>, l1_auth: vector<vector<u8>>)
recover(acct_addr, new_root, new_rec_root, wots, auth)
```

Views: `next_digest(acct_addr, recipient, amount)`, `needs_top_layer(acct_addr)`,
plus getters for every state field.

`l*_wots` is 67 × 32 bytes, `l*_auth` is 10 × 32 bytes (8 × 32 for recovery).
`verify_layer(layer, tree_idx, leaf_idx, height, m, wots, auth)` is a public
pure function and is byte-exact with `AegisCCHS._layerRoot`: ADRS layout,
chain step `sha2_256(adrs ‖ x)`, leaf `sha2_256(adrs ‖ pk_0 ‖ … ‖ pk_66)`,
and node `sha2_256(adrs ‖ left ‖ right)` are unchanged from the spec.

### v1 scope

The action is a single APT transfer executed with `aptos_account::transfer`,
which requires the owner's `&signer`. In v1 the CCHS signature is therefore an
additional gate on top of the account's native authenticator, not a
replacement. A signer-free design (resource account holding a
`SignerCapability`, arbitrary Move payloads submitted by a relayer) is the
planned follow-up; `recover` already needs no owner signer and may be
submitted by anyone holding a valid recovery signature.

## Digest construction

All integers big-endian (hand-encoded; BCS is little-endian and is used only
for addresses, where it yields the raw 32 bytes).

```
action  = sha2_256( bcs(recipient) ‖ amount_u64_be )
M       = sha2_256( "AEGIS_CCHS_V1" ‖ "aptos" ‖ bcs(account) ‖ nonce_u64_be ‖ idx_u64_be ‖ action )

M_rec   = sha2_256( "AEGIS_CCHS_RECOVER_V1" ‖ "aptos" ‖ bcs(account) ‖ rec_nonce_u64_be ‖ new_root ‖ new_rec_root )
```

`account` is the address holding the resource. The `"aptos"` tag replaces the
EVM chain id so a signature is never valid on two chains.

## Verification flow (`execute_transfer`)

1. `idx = next_idx` (abort if `≥ 2^20`); `tree_idx = idx >> 10`, `leaf_idx = idx & 1023`.
2. `r0 = verify_layer(0, tree_idx, leaf_idx, 10, M, l0_wots, l0_auth)`.
3. If `cached_root[(epoch, tree_idx)]` exists, require it equals `r0`.
   Otherwise require `has_l1`, compute
   `r1 = verify_layer(1, 0, tree_idx, 10, r0, l1_wots, l1_auth)`, require
   `r1 == root`, and store `r0` in the cache.
4. `next_idx += 1`, `nonce += 1`, then transfer.

`recover` verifies layer `0xFF`, tree 0, leaf `rec_nonce`, height 8 against
`rec_root`, then sets the new roots, resets `next_idx`, and bumps `epoch` and
`rec_nonce`.

## Build and test

```bash
aptos move compile --named-addresses aegis=0x1
aptos move test    --named-addresses aegis=0x1
```

Tests (`#[test]` in the module):

- `test_adrs_layout` — ADRS byte layout.
- `test_digits_fixture_op1` — base-16 digits and checksum for the fixture digest.
- `test_layer0_fixture_op1_matches_bottom_root0` — `ops[1]` (cached path) recomputes `bottomRoot0`.
- `test_layer1_fixture_op0_matches_root` — `ops[0].l1` on `bottomRoot0` recomputes `root`.
- `test_layer0_tampered_chain_fails` — a modified chain value changes the root.

## Framework APIs used

`std::hash::sha2_256`, `std::bcs::to_bytes`, `std::vector`, `std::signer`,
`std::error`, `aptos_std::table`, `aptos_framework::aptos_account::transfer`,
`aptos_framework::event::emit` with `#[event]` structs.
