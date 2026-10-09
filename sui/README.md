# Aegis — Sui adapter (CCHS-S-20)

**Status**: source compiled and unit-tested in CI (`sui move build`,
`sui move test`, `.github/workflows/build.yml`). `verify_layer` is checked
against the shared fixture `evm/test/fixtures/cchs-s-20.json`; the full
create → deposit → execute → cached execute → recover flow is exercised in
`test_scenario` with a test-generated hypertree. **Not published on mainnet,
testnet or devnet by anyone yet.** No audit.

Module: `sui/sources/aegis_account.move` (`aegis::aegis_account`, Move 2024).
Protocol: `../CCHS.spec.md`. Reference implementations: `evm/src/AegisCCHS.sol`,
`wallet/src/aegis/cchs.ts`.

## Two properties this adapter must have

1. **No elliptic-curve key in the authorization path.** `CchsAccount` is a
   shared object. No function takes an owner signature or checks
   `tx_context::sender`; the sender of `deposit`, `execute_transfer` and
   `recover` only pays gas. Funds are inside the object and leave it only
   through `execute_transfer<T>`, gated by the CCHS signature. The tests
   create the object from one address and operate it from another.
2. **The published package must be immutable.** `sui client publish` hands
   the publisher an `UpgradeCap`; while it exists, the publisher's key can
   replace this code and drain every account. It must be destroyed with
   `sui::package::make_immutable` right after publishing. See "Deployment".

What remains outside this module's control: the Sui framework packages
(`0x1`, `0x2`) that this module calls are upgraded through protocol
upgrades decided by validators. That is a property of the chain, not of this
adapter.

## Design

| Field | Type | Meaning |
|---|---|---|
| `id` | `UID` | object id; bound into every digest |
| `root` | `vector<u8>` (32) | top-layer tree root; rotated only by `recover` |
| `rec_root` | `vector<u8>` (32) | recovery tree root (height 8) |
| `epoch` | `u64` | bumped on every recovery; namespaces the cache |
| `next_idx` | `u64` | next unused leaf in `[0, 2^20)` |
| `nonce` | `u64` | bound into every digest |
| `rec_nonce` | `u64` | next unused recovery leaf in `[0, 256)` |
| `cached_root` | `Table<u128, vector<u8>>` | `(epoch << 64) \| tree_idx` → verified bottom subtree root |
| `balances` | `Bag` | `TypeName` of `T` → `Balance<T>`; one entry per coin type held |

Entry functions:

```
create(root, rec_root, ctx)                           -- shares the object; sender keeps nothing
deposit<T>(acct: &mut CchsAccount, coin: Coin<T>)     -- anyone may fund, any coin type
execute_transfer<T>(acct: &mut CchsAccount, recipient, amount,
                 l0_wots: vector<vector<u8>>, l0_auth: vector<vector<u8>>,
                 has_l1: bool,
                 l1_wots: vector<vector<u8>>, l1_auth: vector<vector<u8>>, ctx)
recover(acct: &mut CchsAccount, new_root, new_rec_root, wots, auth)
```

The balance is generic: `deposit<T>` joins into (or creates) the
`Balance<T>` entry keyed by `type_name::with_defining_ids<T>()`, and
`execute_transfer<T>` splits from it with `coin::take` and
`transfer::public_transfer`. SUI is just `T = 0x2::sui::SUI`. The object is
created with no balances; a transfer of a type never deposited aborts with
`ENoBalance`.

Views: `asset_id<T>()`, `next_digest<T>(acct, recipient, amount)`,
`next_recovery_digest(acct, new_root, new_rec_root)`, `needs_top_layer(acct)`,
`balance_value<T>(acct)`, plus getters for every counter and root.

`l*_wots` is 67 × 32 bytes, `l*_auth` is 10 × 32 bytes (8 × 32 for recovery).
`verify_layer(layer, tree_idx, leaf_idx, height, m, wots, auth)` and
`merkle_root(...)` are public pure functions, byte-exact with
`AegisCCHS._layerRoot`: ADRS layout, chain step `sha2_256(adrs ‖ x)`, leaf
`sha2_256(adrs ‖ pk_0 ‖ … ‖ pk_66)`, node `sha2_256(adrs ‖ left ‖ right)`.

## Digest construction

All integers big-endian (hand-encoded; BCS is little-endian and is used only
for addresses, where it yields the raw 32 bytes).

```
asset   = sha2_256( 0x00 ‖ ascii(type_name::with_defining_ids<T>()) )
          -- SUI: "0000000000000000000000000000000000000000000000000000000000000002::sui::SUI"
action  = sha2_256( asset ‖ recipient(32) ‖ amount_u64_be )
M       = sha2_256( "AEGIS_CCHS_V1" ‖ "sui" ‖ object_id(32) ‖ nonce_u64_be ‖ idx_u64_be ‖ action )

M_rec   = sha2_256( "AEGIS_CCHS_RECOVER_V1" ‖ "sui" ‖ object_id(32) ‖ rec_nonce_u64_be ‖ new_root ‖ new_rec_root )
```

`object_id` is the 32-byte address of the shared `CchsAccount`. The type
name is the full-width lowercase hex form produced by `std::type_name` with
defining ids (the id of the package version that introduced the type), so
it is stable across upgrades of the coin's own package. Binding the asset
into `action` means a signature for 400 of one coin cannot be replayed for
400 of another. The `"sui"` tag replaces the EVM chain id so a signature is
never valid on two chains. Vectors for the SUI asset id and both digests are
asserted in the module tests and were recomputed independently.

## Verification flow (`execute_transfer`)

1. `idx = next_idx` (abort if `≥ 2^20`); `tree_idx = idx >> 10`, `leaf_idx = idx & 1023`.
2. `r0 = verify_layer(0, tree_idx, leaf_idx, 10, M, l0_wots, l0_auth)`.
3. If `cached_root[(epoch, tree_idx)]` exists, require it equals `r0`.
   Otherwise require `has_l1`, compute
   `r1 = verify_layer(1, 0, tree_idx, 10, r0, l1_wots, l1_auth)`, require
   `r1 == root`, and store `r0` in the cache.
4. `next_idx += 1`, `nonce += 1`, then split and transfer the coin.

`recover` verifies layer `0xFF`, tree 0, leaf `rec_nonce`, height 8 against
`rec_root`, then sets the new roots, resets `next_idx`, and bumps `epoch` and
`rec_nonce`. Anyone may submit it.

## Deployment

### Immutability is mandatory

Sui has no manifest-level immutable policy; immutability is a second
transaction that burns the `UpgradeCap`. The sequence is:

```bash
# 1. Publish. Note two ids in "Object Changes": the package id and the
#    object of type 0x2::package::UpgradeCap.
sui client publish --gas-budget 200000000

# 2. Burn the UpgradeCap. After this no key can ever change the package.
sui client call \
  --package 0x2 --module package --function make_immutable \
  --args <UPGRADE_CAP_ID> --gas-budget 10000000
```

`make_immutable` is `public entry fun make_immutable(cap: UpgradeCap)` in
`sui::package`; it deletes the capability object. Anyone can check
immutability afterwards: no object of type `0x2::package::UpgradeCap` whose
`package` field equals the package id exists any more (`sui client object
<UPGRADE_CAP_ID>` reports it deleted). Until step 2 has executed, the
package must not be entered into any wallet.

### Who publishes

There is no project deployer. The package id is assigned at publish time
and the module id is `<package_id>::aegis_account`, so identity is per
publisher, and two honest models exist:

**A. Each user publishes their own copy (the wallet does this on first use).**
The user funds an ordinary Sui address once, runs the two commands above,
then calls `create` on the new package. No other key was ever involved. Cost:
the one-time publish storage fee (proportional to bytecode size) plus the
`make_immutable` call plus `create`; the publishing key keeps no power and
may be discarded.

**B. The community publishes once.** One publisher runs the two commands;
every user enters that package id into the wallet, checks that the on-chain
bytecode matches this source (`sui move build --dump-bytecode-as-base64`
compared with `sui client object <PACKAGE_ID> --bcs`, or a source
verification service) and that the `UpgradeCap` is gone, and calls `create`.
Cost per user is only `create`.

Publish and `create` costs have not been measured on a live network.

### Using an account

```bash
sui client call --package <PKG> --module aegis_account --function create --args <ROOT_HEX> <REC_ROOT_HEX> --gas-budget 10000000
sui client call --package <PKG> --module aegis_account --function deposit --type-args 0x2::sui::SUI --args <ACCOUNT_ID> <COIN_ID> --gas-budget 10000000
sui client call --package <PKG> --module aegis_account --function execute_transfer --type-args 0x2::sui::SUI \
  --args <ACCOUNT_ID> <TO> <AMOUNT> '[...]' '[...]' true '[...]' '[...]' --gas-budget 50000000
```

`next_digest<T>` is a plain (non-entry) function; read it with a dev-inspect
call or recompute it client-side from the layout above.

## Build and test

```bash
sui move build
sui move test --gas-limit 100000000000
```

Tests (`#[test]` in the module):

- `test_adrs_layout` — ADRS byte layout.
- `test_digits_fixture_op1` — base-16 digits and checksum for the fixture digest.
- `test_layer0_fixture_op1_matches_bottom_root0` — `ops[1]` (cached path) recomputes `bottomRoot0`.
- `test_layer1_fixture_op0_matches_root` — `ops[0].l1` on `bottomRoot0` recomputes `root`.
- `test_layer0_tampered_chain_fails` — a modified chain value changes the root.
- `test_asset_id_and_digest_vectors` — SUI type name, asset id, transfer and recovery digests against independent vectors.
- `test_create_deposit_execute_first_in_subtree` — created by one address, funded and spent by another; first transfer with top layer; recipient receives the `Coin<SUI>`.
- `test_cached_second_op` — second transfer from the cached subtree (bottom layer only), index and nonce advance, no top layer needed.
- `test_recover_rotates_roots_and_keeps_funds` — recovery rotates roots, bumps the epoch and resets the index while id and balance stay.
- `test_replayed_signature_fails` — resubmitting a used signature aborts with `EBadSubtreeRoot`.
- `test_first_use_without_top_layer_fails` — first use of a subtree without `l1` aborts with `EMissingTopLayer`.
- `test_wrong_amount_fails` — a signature for one amount submitted with another aborts with `EBadTopRoot`.

- `test_precomputed_leaves`, `test_precomputed_root_l0`, `test_precomputed_root_l0_real_sibling`, `test_precomputed_top_root`, `test_precomputed_rec_root` — re-derive the two leaves and four tree roots the end-to-end tests start from.

The end-to-end tests sign with a real WOTS+ hypertree built in `#[test_only]`
code (chain secrets derived from a tag; sibling nodes are the real neighbour
leaf or tagged values), so they exercise signing and verification with the
actual digest the module computes. Tree roots are precomputed constants
because every unit test runs under the Sui computation cap and building three
full trees (67 chains x 15 steps per leaf) inside one test exceeds it; the
four `test_precomputed_*` tests rebuild one root each.

## Framework APIs used

`sui::object::{new, uid_to_address}`, `sui::transfer::{share_object, public_transfer}`,
`sui::table`, `sui::bag::{new, add, borrow, borrow_mut, contains_with_type}`,
`sui::balance::{join, value}`, `sui::coin::{into_balance, take}`,
`sui::event::emit`, `std::type_name::{with_defining_ids, into_string}`,
`std::ascii::into_bytes`, `std::hash::sha2_256`, `std::bcs::to_bytes`,
`std::vector`. Tests also use `sui::sui::SUI`, `sui::test_scenario` and
`sui::coin::{mint_for_testing, burn_for_testing, value}`. Deployment uses
`sui::package::make_immutable`.
