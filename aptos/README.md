# Aegis — Aptos adapter (CCHS-S-20)

**Status**: source compiled and unit-tested in CI (`aptos move compile`,
`aptos move test`, `.github/workflows/build.yml`). `verify_layer` is checked
against the shared fixture `evm/test/fixtures/cchs-s-20.json`; the full
create → fund → execute → cached execute → recover flow is exercised with a
test-generated hypertree. **Not published on mainnet, testnet or devnet by
anyone yet.** No audit.

Module: `aptos/sources/aegis_account.move` (`aegis::aegis_account`).
Protocol: `../CCHS.spec.md`. Reference implementations: `evm/src/AegisCCHS.sol`,
`wallet/src/aegis/cchs.ts`.

## Two properties this adapter must have

1. **No elliptic-curve key in the authorization path.** The funds live in a
   *resource account* whose authentication key is zeroed by the framework at
   creation; the only way to produce its signer is the `SignerCapability`
   stored inside the `CchsAccount` resource, and the module releases that
   signer only after a CCHS signature verified. `execute_transfer*` and
   `recover` take no `&signer` at all. Breaking every ed25519 key on the
   chain gives an attacker nothing against this account.
2. **The published module must be immutable.** `Move.toml` sets
   `upgrade_policy = "immutable"`. Without it, the publisher's key could
   replace the module and move the funds, which reintroduces an
   elliptic-curve key into the trust path. See "Deployment" below.

What remains outside this module's control: the Aptos framework at `0x1`
(which this module calls for account and coin operations) is upgradable by
on-chain governance. That is a property of the chain, not of this adapter.

## Design

### Resource account

`create(creator: &signer, root, rec_root)`:

```
seed          = "AEGIS_CCHS_V1" || root                         (13 + 32 bytes)
account_addr  = sha3_256( bcs(creator_addr) || seed || 0xFF )  -- account::create_resource_address
```

The module calls `account::create_resource_account(creator, seed)`, which
publishes an `Account` at `account_addr`, rotates its authentication key to
all zeros, and returns the `SignerCapability`. The module then publishes
`CchsAccount` **at `account_addr` itself**, with the capability inside. One
address is therefore the CCHS account, the funds holder and the identity
bound into every digest. `derive_address(creator, root)` is a view that
predicts it.

`creator` can be the user's existing Aptos account or any relayer; it pays
the creation gas and then has no authority (it cannot call
`create_resource_account` again for the same seed, and the capability never
leaves the module). Because the seed is the root, one key tree maps to one
account per creator; recovery rotates `root` in place and does **not** change
the address.

### State (`CchsAccount`, stored at `account_addr`)

| Field | Type | Meaning |
|---|---|---|
| `root` | `vector<u8>` (32) | top-layer tree root; rotated only by `recover` |
| `rec_root` | `vector<u8>` (32) | recovery tree root (height 8) |
| `epoch` | `u64` | bumped on every recovery; namespaces the cache |
| `next_idx` | `u64` | next unused leaf in `[0, 2^20)` |
| `nonce` | `u64` | bound into every digest |
| `rec_nonce` | `u64` | next unused recovery leaf in `[0, 256)` |
| `cached_root` | `Table<u128, vector<u8>>` | `(epoch << 64) \| tree_idx` → verified bottom subtree root |
| `signer_cap` | `SignerCapability` | sole source of the resource account's signer; never exposed |
| `creator` | `address` | informational; who derived the address |

### Entry functions

```
create(creator: &signer, root, rec_root)
deposit<CoinType>(payer: &signer, acct_addr, amount)        -- convenience; any transfer to acct_addr works
execute_transfer<CoinType>(acct_addr, recipient, amount,
                 l0_wots: vector<vector<u8>>, l0_auth: vector<vector<u8>>,
                 has_l1: bool,
                 l1_wots: vector<vector<u8>>, l1_auth: vector<vector<u8>>)
execute_transfer_fa(acct_addr, metadata: Object<Metadata>, recipient, amount, l0_*, has_l1, l1_*)
recover(acct_addr, new_root, new_rec_root, wots, auth)
```

`execute_transfer<CoinType>` covers APT (`0x1::aptos_coin::AptosCoin`) and
every legacy `Coin<T>`, including coins that have migrated to a paired
fungible asset (the framework's `coin::withdraw` handles both stores).
`execute_transfer_fa` covers tokens that exist only as fungible assets,
addressed by their `Metadata` object. The asset moves with
`aptos_account::transfer_coins<CoinType>` /
`aptos_account::transfer_fungible_assets`, called with the resource
account's signer obtained from `account::create_signer_with_capability`.
Both create the recipient account if it does not exist.

Views: `derive_address(creator, root)`, `coin_asset_id<CoinType>()`,
`fa_asset_id(metadata_addr)`, `next_digest<CoinType>(acct_addr, recipient, amount)`,
`next_digest_fa(acct_addr, metadata_addr, recipient, amount)`,
`next_recovery_digest(acct_addr, new_root, new_rec_root)`,
`needs_top_layer(acct_addr)`, `creator_of(acct_addr)`, plus getters for
every counter and root.

`l*_wots` is 67 × 32 bytes, `l*_auth` is 10 × 32 bytes (8 × 32 for recovery).
`verify_layer(layer, tree_idx, leaf_idx, height, m, wots, auth)` and
`merkle_root(...)` are public pure functions, byte-exact with
`AegisCCHS._layerRoot`: ADRS layout, chain step `sha2_256(adrs ‖ x)`, leaf
`sha2_256(adrs ‖ pk_0 ‖ … ‖ pk_66)`, node `sha2_256(adrs ‖ left ‖ right)`.

## Digest construction

All integers big-endian (hand-encoded; BCS is little-endian and is used only
for addresses, where it yields the raw 32 bytes). `account` is the resource
account address.

```
asset   = sha2_256( 0x00 ‖ utf8(type_info::type_name<CoinType>()) )   -- Coin<T>; APT: "0x1::aptos_coin::AptosCoin"
asset   = sha2_256( 0x01 ‖ bcs(metadata_address) )                    -- fungible asset
action  = sha2_256( asset ‖ bcs(recipient) ‖ amount_u64_be )
M       = sha2_256( "AEGIS_CCHS_V1" ‖ "aptos" ‖ bcs(account) ‖ nonce_u64_be ‖ idx_u64_be ‖ action )

M_rec   = sha2_256( "AEGIS_CCHS_RECOVER_V1" ‖ "aptos" ‖ bcs(account) ‖ rec_nonce_u64_be ‖ new_root ‖ new_rec_root )
```

Binding the asset id into `action` means a signature for 400 APT cannot be
replayed as 400 units of another coin. The `"aptos"` tag replaces the EVM
chain id so a signature is never valid on two chains. The type-name string
is the one returned by `aptos_std::type_info::type_name<T>()` (short
address form, as shown). Test vectors for the seed, the derived address, the
APT asset id and both digests are asserted in the module tests and were
recomputed independently.

## Verification flow (`execute_transfer*`)

1. `idx = next_idx` (abort if `≥ 2^20`); `tree_idx = idx >> 10`, `leaf_idx = idx & 1023`.
2. `r0 = verify_layer(0, tree_idx, leaf_idx, 10, M, l0_wots, l0_auth)`.
3. If `cached_root[(epoch, tree_idx)]` exists, require it equals `r0`.
   Otherwise require `has_l1`, compute
   `r1 = verify_layer(1, 0, tree_idx, 10, r0, l1_wots, l1_auth)`, require
   `r1 == root`, and store `r0` in the cache.
4. `next_idx += 1`, `nonce += 1`, then obtain the resource signer and move the asset.

`recover` verifies layer `0xFF`, tree 0, leaf `rec_nonce`, height 8 against
`rec_root`, then sets the new roots, resets `next_idx`, and bumps `epoch` and
`rec_nonce`. Anyone may submit it.

## Deployment

### Immutability is mandatory

`Move.toml` carries `upgrade_policy = "immutable"`. The CLI reads this
field from the manifest and writes it into the on-chain `PackageMetadata`;
`0x1::code` then refuses every later publish to the same package name at
that address (`EUPGRADE_IMMUTABLE`), and a policy can only ever be
strengthened. The module depends only on `0x1` packages, which are exempt
from the "dependencies must be at least as strict" rule, so an immutable
publish of this package is accepted.

Before trusting a published copy, check two things:

```bash
# 1. The bytecode matches this source tree.
aptos move verify-package --account <PUBLISHER_ADDR> --named-addresses aegis=<PUBLISHER_ADDR>
# 2. The on-chain policy is immutable (policy == 2).
aptos account list --query resources --account <PUBLISHER_ADDR>   # look at 0x1::code::PackageRegistry
```

### Who publishes

There is no project deployer and no project-owned module address. The
module id is `<publisher_addr>::aegis_account`, so identity is per
publisher, and two honest models exist:

**A. Each user publishes their own copy (the wallet does this on first use).**
The user funds an ordinary Aptos account once, publishes the module under
it with the immutable policy, then calls `create`. Nobody else's key was ever
involved, and the user does not need to verify anyone's bytecode. Cost: the
one-time publish fee (proportional to bytecode plus metadata size; use
`--included-artifacts none` to keep metadata small) plus `create`. The
publishing key keeps no power afterwards; it may be discarded.

**B. The community publishes once.** One publisher runs the command below;
every user then points the wallet at that address, verifies the bytecode
with `verify-package` and the policy as above, and calls `create` against
it. Cost per user is only `create`. Trust required: that the bytecode matches
and the policy is immutable, both of which are checkable on chain.

Publish command (same in both models; the publisher's own address is the
named address):

```bash
aptos move publish \
  --named-addresses aegis=<PUBLISHER_ADDR> \
  --included-artifacts none \
  --profile <PROFILE>
```

### Using an account

```bash
# predicted address
aptos move view --function-id <PUBLISHER_ADDR>::aegis_account::derive_address --args address:<CREATOR> hex:<ROOT>
# create (creator signs once; it keeps no authority)
aptos move run --function-id <PUBLISHER_ADDR>::aegis_account::create --args hex:<ROOT> hex:<REC_ROOT>
# fund: any transfer to the derived address
aptos account transfer --account <ACCOUNT_ADDR> --amount <OCTAS>
# spend: submitted by any payer, no owner key
aptos move view --function-id <PUBLISHER_ADDR>::aegis_account::next_digest --type-args 0x1::aptos_coin::AptosCoin --args address:<ACCOUNT_ADDR> address:<TO> u64:<AMOUNT>
aptos move run  --function-id <PUBLISHER_ADDR>::aegis_account::execute_transfer --type-args 0x1::aptos_coin::AptosCoin --args address:<ACCOUNT_ADDR> address:<TO> u64:<AMOUNT> 'hex:[...]' 'hex:[...]' bool:true 'hex:[...]' 'hex:[...]'
```

Publish and `create` costs have not been measured on a live network; the
numbers above are left out on purpose rather than guessed.

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
- `test_derive_address_vector` — seed bytes and `sha3_256` resource address against an independently computed vector.
- `test_asset_ids_and_digest_vectors` — APT type name, coin and FA asset ids, transfer and recovery digests against independent vectors.
- `test_create_fund_execute_cached_recover` — resource account created, funded with APT, first transfer with top layer (no signer), second transfer from the cached subtree, recovery rotates roots and resets the cache while the address and balance stay.
- `test_replayed_signature_fails` — resubmitting a used signature aborts with `E_BAD_SUBTREE_ROOT`.
- `test_first_use_without_top_layer_fails` — first use of a subtree without `l1` aborts with `E_MISSING_TOP_LAYER`.
- `test_wrong_amount_fails` — a signature for one amount submitted with another aborts with `E_BAD_TOP_ROOT`.
- `test_create_twice_same_root_fails` — the framework rejects a second resource account for the same seed.

The end-to-end tests build a real WOTS+ hypertree in `#[test_only]` code
(chain secrets derived from a tag; sibling nodes are the real neighbour leaf
or tagged values), so they exercise signing and verification with the actual
digest the module computes.

## Framework APIs used

`aptos_framework::account::{create_resource_account, create_resource_address,
create_signer_with_capability, SignerCapability}`,
`aptos_framework::aptos_account::{transfer_coins, transfer_fungible_assets, deposit_coins (tests)}`,
`aptos_framework::object::{Object, object_address}`,
`aptos_framework::fungible_asset::Metadata`,
`aptos_framework::event::emit` with `#[event]` structs,
`aptos_std::table`, `aptos_std::type_info::type_name`,
`std::hash::sha2_256`, `std::bcs::to_bytes`, `std::string`, `std::vector`,
`std::signer`, `std::error`. Tests also use
`aptos_framework::aptos_coin::{initialize_for_test, AptosCoin}` and
`aptos_framework::coin::{mint, balance, destroy_burn_cap, destroy_mint_cap}`.
