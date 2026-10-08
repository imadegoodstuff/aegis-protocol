# Aegis — TON adapter (FunC)

**Status**: complete CCHS-S-20 account contract in FunC
(`contracts/aegis_account.fc`), compiled with func 0.4.6 and exercised in the
TON sandbox against the shared fixture: bottom-layer, top-layer and recovery
vectors reproduce the fixture roots, and a full execute (new subtree, cached
subtree, replay rejection) + recover flow passes with client-generated
signatures. Not yet deployed to testnet/mainnet.

Spec: [`../CCHS.spec.md`](../CCHS.spec.md). Byte-exact with
`evm/src/AegisCCHS.sol` and `wallet/src/aegis/cchs.ts`; ground truth is
`evm/test/fixtures/cchs-s-20.json`.

## Layout

```
contracts/aegis_account.fc   the account (verifier + state machine + get methods)
contracts/imports/stdlib.fc  FunC standard library (vendored from ton-blockchain/ton)
scripts/compile.mjs          func-js compile → build/aegis_account.{fif,code.boc}
tests/cchs.test.mjs          sandbox tests driven by the shared fixture
```

```bash
npm install
npm run build     # compiles with @ton-community/func-js (func + fift in WebAssembly)
npm test          # @ton/sandbox: fixture roots, execute, cache, replay, recover
```

## Storage

One cell, 769 bits + optional dictionary root:

```
root:uint256 rec_root:uint256 epoch:uint64 next_idx:uint64 nonce:uint64 rec_nonce:uint64
cache:(HashmapE 128 uint256)        key = epoch << 64 | bottom_tree_idx, value = bottom root
```

Deploy with an internal message carrying the StateInit (code + initial data
with `epoch = next_idx = nonce = rec_nonce = 0` and an empty dictionary). The
account address is `hash(StateInit)`, so it is a function of the two roots.

## Messages

All operations are **internal messages**. Any wallet or relayer may submit
them; the CCHS signature, not the sender, authorizes the action. External
messages are refused (`exit 206`): verification costs ~3·10^5 gas, far above the
10k gas credit available before `accept_message()`, and accepting first would let
anyone drain the balance with invalid messages.

Plain transfers (empty body or `op = 0` text comment) and bounced messages are
accepted silently so the account can receive TON.

### `op::execute = 0x41455845`

```
body:   op:uint32 query_id:uint64 has_l1:uint1
        ref[0] = l0  value stream   67 wots ‖ 10 auth   (bottom layer, leaf next_idx)
        ref[1] = action             { mode:uint8  msg:^Cell }
        ref[2] = l1  value stream   67 wots ‖ 10 auth   (top layer; present iff has_l1)
```

`msg` is a complete outgoing message cell (`MessageRelaxed`), sent with
`send_raw_message(msg, mode)` after the state update. The send mode is inside
the signed `action` cell, so a relayer cannot change it.

### `op::recover = 0x41455243`

```
body:   op:uint32 query_id:uint64 new_root:uint256 new_rec_root:uint256
        ref[0] = recovery value stream   67 wots ‖ 8 auth   (layer 0xFF, leaf rec_nonce)
```

### Value stream (signature cell layout)

A layer signature is a stream of 256-bit values: the 67 WOTS+ chain values
followed by the authentication path, leaf to root. Values are packed **three per
cell** (768 bits) and each cell references the cell holding the next three:

```
cell_0 = v0 v1 v2 → cell_1 = v3 v4 v5 → … → cell_25 = v75 v76
```

77 values → 26 cells (bottom/top layer), 75 values → 25 cells (recovery). The
reader (`next_val`) moves to the referenced cell whenever fewer than 256 bits
remain, so any packing in which every cell holds whole values is accepted; the
3-per-cell packing is canonical and the one the tests produce. A cached-subtree
execute carries ~2.5 KB of signature in 26 cells; a first-in-subtree execute
carries ~5 KB in 52 cells.

### Digests (TON)

```
M      = sha256( "AEGIS_CCHS_V1" ‖ "ton" ‖ my_address.hash(32)
                 ‖ nonce(8 BE) ‖ idx(8 BE) ‖ cell_hash(action)(32) )          96 bytes

M_rec  = sha256( "AEGIS_CCHS_RECOVER_V1" ‖ "ton" ‖ my_address.hash(32)
                 ‖ rec_nonce(8 BE) ‖ new_root(32) ‖ new_rec_root(32) )        128 bytes
```

`my_address.hash` is the 256-bit hash part of the account's standard address.
`cell_hash(action)` is the representation hash of the `action` cell, which
commits to both the send mode and the full outgoing message. Get methods
`get_next_digest(cell_hash(action))` and `get_recovery_digest(new_root,
new_rec_root)` return the digest the client must sign.

Note: the digest binds the account address, not the workchain or network;
testnet and mainnet deployments with identical StateInit share the address and
therefore digests while their `nonce`/`next_idx` coincide.

## Get methods

| Method | Returns |
|---|---|
| `get_account_state()` | `(root, rec_root, epoch, next_idx, nonce, rec_nonce)` |
| `get_cached_root(epoch, tree_idx)` | cached bottom root or 0 |
| `needs_top_layer()` | `-1` if the next execute must carry the top layer, else `0` |
| `get_next_digest(action_hash)` | digest for the next execute |
| `get_recovery_digest(new_root, new_rec_root)` | digest for the next recover |
| `compute_layer_root(layer, tree_idx, leaf_idx, height, m, sig_cell)` | pure verifier; used by the tests |

## Exit codes

| Code | Meaning |
|---|---|
| 200 | index space exhausted (`next_idx ≥ 2^20` or `rec_nonce ≥ 256`) |
| 201 | bottom root differs from the cached root for this subtree |
| 202 | subtree not cached and no top layer supplied |
| 203 | top layer does not reach `root` |
| 204 | recovery signature does not reach `rec_root` |
| 205 | zero root in `recover` |
| 206 | external message (always refused) |
| 0xffff | unknown op |

## Hashing on TVM

`HASHEXT_SHA256` (TVM 2023.07) is used for every hash. It pops `n` and then `n`
slices or builders and hashes their concatenation as one SHA-256 stream; the
deepest stack entry is hashed first, so FunC argument order equals byte order.

| Input | Size | Call |
|---|---|---|
| chain step `F(ADRS, x)` | 64 B | `1 PUSHINT HASHEXT_SHA256` over one builder |
| Merkle node `T_node(ADRS, l, r)` | 96 B | same |
| execute digest | 96 B | same |
| recovery digest | 128 B = 1024 bits | `2 PUSHINT HASHEXT_SHA256` over two 512-bit builders (one builder holds at most 1023 bits) |
| leaf `T_leaf(ADRS, pk_0‖…‖pk_66)` | 2176 B | `255 PUSHINT EXPLODEVAR HASHEXT_SHA256` over a tuple of 23 builders (3 × 256 bits each) |

`EXPLODEVAR` unpacks a tuple `t` of length `m ≤ 255` to `x_1 … x_m m`, which is
exactly the operand layout `HASHEXT` expects, so the 68-slot leaf input is
hashed in one call without creating any cell. `SHA256U` (`string_hash`) would
also work for the 64/96-byte inputs but is limited to a single slice of at most
127 bytes and offers no advantage, so it is not used. No cells are created in
the hot loop: ADRS is stored as one 256-bit integer, and HASHEXT accepts
builders directly.

## Gas (measured in @ton/sandbox, func 0.4.6)

| Transaction | Compute gas |
|---|---|
| `execute`, first in subtree (two layers, cache write) | ~598 k |
| `execute`, cached subtree (one layer) | ~301 k |
| `recover` (height-8 layer) | ~304 k |
| `compute_layer_root` get method, one height-10 layer | ~280–300 k |

HASHEXT itself is cheap (1 gas per entry + 1 gas per 33 bytes); the cost is
dominated by builder construction (`NEWC`, `STU`) and loop control for the
~500 chain steps per layer. All cases fit the 1 M gas limit of a basechain
transaction with margin. At the current basechain gas price this is on the
order of 0.1–0.25 TON per transaction, amortized to ~0.12 TON over a 1024-leaf
subtree. Forwarded-message fees and the ~2.5–5 KB message body are extra.

Because the state is written before `send_raw_message`, a failed action phase
(e.g. insufficient balance for the requested value with mode 0) still consumes
the leaf and nonce; this mirrors a reverted call on EVM consuming the nonce.
