# Aegis — Solana adapter (CCHS-C-20)

**Status**: implemented, not yet built or run on-chain. The verification core
(`../cchs-core`, module `compact`) is CI-tested against the shared vectors in
`evm/test/fixtures/cchs-c-20.json`; the Anchor program adds only the Solana
digest, PDA layout and CPI dispatch. Anchor builds are not part of
`build.yml` yet (toolchain install is slow); see "Before deployment".

Spec: `../CCHS.spec.md`. Client reference: `../wallet/src/aegis/cchsCompact.ts`.

## Why a second parameter set

The canonical set CCHS-S-20 (n = 32, w = 16, 67 chains) has a 2 464-byte
bottom layer, twice the 1 232-byte Solana packet. CCHS-C-20 keeps the tree
shape (two layers of height 10, recovery tree of height 8, identical ADRS)
and changes two numbers:

| | S-20 | C-20 |
|---|---|---|
| Hash output `n` | 32 (SHA-256) | 24 (SHA-256 truncated to the first 24 bytes) |
| Winternitz `w` | 16 | 256 |
| Chains | 64 + 3 = 67 | 24 + 2 = 26 |
| One layer | 67 × 32 + 10 × 32 = 2 464 B | 26 × 24 + 10 × 24 = **864 B** |
| Hash calls per layer | ≈ 500 | ≈ 3 330 average, 6 386 worst case |

Digits are the 24 message bytes themselves; the checksum
`csum = Σ (255 − m_i) ≤ 6 120` is appended as 2 big-endian bytes. Chain step
`x = sha256(ADRS(step s) ‖ x)[0..24)`; leaf
`sha256(ADRS type 1 ‖ pk_0 ‖ … ‖ pk_25)[0..24)` (656-byte input); node
`sha256(ADRS type 2 ‖ left ‖ right)[0..24)`. Roots are 24 bytes.

The price is compute (w = 256 means up to 255 steps per chain), which buys a
2.9× smaller signature and, with the cache split below, a one-packet hot path.

## How the client splits a signature

Verifying the top layer and the bottom layer in one instruction would need
1 728 bytes of signature. Instead the hypertree cache that CCHS already
relies on is filled by its own instruction:

1. `cache_subtree(tree_idx, l1_wots, l1_auth, r0)` — once per bottom subtree
   (every 1 024 signatures). The client computes `r0 = bottomRootOf(...)`
   (the root of bottom tree `tree_idx`) and `l1 = topLayer(key, tree_idx, r0)`
   (`cchsCompact.ts`), and sends both. The program verifies the top-layer
   WOTS+ signature on `r0` at top leaf `tree_idx` against `account.root` and
   stores `r0` in the cache PDA. Anyone can pay for this transaction; the
   proof authenticates itself, and the same `l1` registers the same subtree
   on every chain running C-20 with the same root (`CCHS.spec.md` §5.3).
2. `execute(l0_wots, l0_auth, ix_data)` — every signature. The client reads
   `next_idx` and `nonce` from the `CchsAccount`, builds the digest, signs
   with `sign(key, idx, m, subtreeCached = true)` and sends only `l0`. The
   program recomputes `r0` from `l0` and requires it to equal the cache PDA
   for `(epoch, next_idx >> 10)`. No top layer is accepted here, so the
   instruction always fits one packet.

The client decides which to send by checking whether the cache PDA for the
current subtree exists and is non-zero (`needs_top_layer` in the core).
Both can be sent back-to-back; `execute` fails with `MissingTopLayer` until
the cache transaction has landed.

Soundness is unchanged from the one-shot verifier: a cache slot can only be
written through a valid top-layer signature on exactly the stored value, is
never overwritten with a different value, and `execute` accepts only the
bottom root that was so registered (`CCHS.spec.md` §6.2 C3, C4).

## Accounts

| PDA | Seeds | Contents | Size |
|---|---|---|---|
| `CchsAccount` | `["cchs", initial_root(24)]` | `seed, root, rec_root` (24 B each), `epoch, next_idx, nonce, rec_nonce` (u64), `bump, vault_bump` | 8 + 106 = 114 B |
| `SubtreeCache` | `["cache", account, epoch LE u64, tree_idx LE u64]` | `root` — verified bottom subtree root, zero = not cached | 8 + 24 = 32 B |
| vault | `["vault", account]` | data-less system account; holds SOL / token authority | 0 |

`recover` bumps `epoch`, so every existing cache PDA becomes unreachable
without being deleted.

## Instructions

```
create(root: [u8;24], rec_root: [u8;24])
    accounts: account (init), payer (signer), system_program

cache_subtree(tree_idx: u64, l1_wots: [[u8;24];26], l1_auth: [[u8;24];10], r0: [u8;24])
    accounts: account, cache (init_if_needed, PDA for (epoch, tree_idx)), payer (signer), system_program
    rejects: ZeroRoot (r0 = 0), Exhausted (tree_idx >= 1024), BadTopRoot,
             CacheConflict (slot holds a different non-zero root; re-sending the same r0 is a no-op)

execute(l0_wots: [[u8;24];26], l0_auth: [[u8;24];10], ix_data: Vec<u8>)
    accounts: account (mut), cache (PDA for (epoch, next_idx >> 10), must exist),
              target_program, then as remaining_accounts every account of the
              inner instruction (not the target program itself)
    rejects: MissingTopLayer (cache zero / absent), BadSubtreeRoot, Exhausted, TargetNotExecutable
    effect:  next_idx += 1, nonce += 1, then CPI target_program(ix_data) signed by
             the account PDA and the vault PDA wherever they appear

recover(new_root: [u8;24], new_rec_root: [u8;24], wots: [[u8;24];26], auth: [[u8;24];8])
    accounts: account (mut)
    effect:  root/rec_root replaced, next_idx = 0, epoch += 1, rec_nonce += 1
```

`execute` takes no index argument: the leaf is `account.next_idx`, so a
signature can be used exactly once and only in order. No payer or system
program is needed because `execute` never creates an account.

## Digest

The client signs the 24-byte message

```
M = sha256("AEGIS_CCHS_V1" ‖ "solana" ‖ account_pubkey(32) ‖ nonce u64 BE ‖ next_idx u64 BE
           ‖ sha256(target_program(32) ‖ ix_data))[0..24)
```

and for recovery

```
M_rec = sha256("AEGIS_CCHS_RECOVER_V1" ‖ "solana" ‖ account_pubkey(32) ‖ rec_nonce u64 BE
               ‖ new_root(24) ‖ new_rec_root(24))[0..24)
```

`"solana"` replaces the EVM chain id, so a signature is never valid on another
chain. The `digest` fields of `cchs-c-20.json` are exactly these values for
`account = 0xcc…cc`, `callHash = sha256(target_program ‖ ix_data)` as given.

## Layer verification (shared with every chain)

```
ADRS = layer(1) ‖ treeIdx(8 BE) ‖ type(1) ‖ leafIdx(4 BE) ‖ chainIdx(1) ‖ step(1) ‖ 16 zero bytes
F(adrs, x)   = sha256(adrs ‖ x)[0..24)                   type 0x00
leaf         = sha256(adrs ‖ pk_0 ‖ … ‖ pk_25)[0..24)     type 0x01
node         = sha256(adrs ‖ left ‖ right)[0..24)         type 0x02, leafIdx = pos >> 1, chainIdx = level
```

Layer 0: `treeIdx = idx >> 10`, `leafIdx = idx & 1023`, message `M`. Layer 1:
`treeIdx = 0`, `leafIdx = idx >> 10`, message `R_0` (checked in
`cache_subtree`). Recovery: layer `0xFF`, tree 0, `leafIdx = rec_nonce`,
height 8.

## Byte budget

Instruction data (8-byte Anchor discriminator included; fixed arrays carry
no length prefix, `Vec<u8>` carries a 4-byte one):

| Instruction | Data bytes |
|---|---|
| `create` | 8 + 24 + 24 = **56** |
| `cache_subtree` | 8 + 8 + 624 + 240 + 24 = **904** |
| `execute` | 8 + 624 + 240 + 4 + `ix_data.len()` = **876 + len** (888 for a 12-byte SOL transfer) |
| `recover` | 8 + 24 + 24 + 624 + 192 = **872** |

Whole transaction, one fee-payer signature, legacy message
(`65 + 3 + 1 + 32·keys + 32 + 1 + Σ(1 + 1 + accounts + 2 + data)`), computed
from the layouts above (not yet measured against a built program):

| Transaction | Keys | Bytes of 1 232 |
|---|---|---|
| `execute`, SOL transfer vault → recipient (12-byte inner ix), no compute-budget ix | payer, program, account, cache, system, vault, recipient = 7 | **1 223** |
| same, recipient = payer (6 keys), no compute-budget ix | 6 | 1 190 |
| same, 6 keys, plus `SetComputeUnitLimit` (adds the ComputeBudget key and an 8-byte ix) | 7 | 1 230 |
| same, 7 keys, plus `SetComputeUnitLimit` | 8 | 1 263 — **does not fit** |
| `execute` as a v0 message, payer static, 7 keys through one address lookup table, plus `SetComputeUnitLimit` | 1 + 7 | **1 082** (room for 162 bytes of `ix_data`) |
| `cache_subtree` | payer, program, account, cache, system = 5 (6 with compute budget) | 1 174 (1 214) |
| `recover` | payer, program, account = 3 (4 with compute budget) | 1 075 (1 115) |
| `create` | 4 | 292 |

The bottom-layer instruction itself fits a legacy packet. Because the
verification needs more than the 200 K CU default (next section), a real
transaction also carries a `SetComputeUnitLimit` instruction, and a vault
transfer to a third party then needs 8 keys, 31 bytes too many for a legacy
message. The client therefore sends `execute` as a v0 transaction with an
address lookup table holding the program, account, cache, vault, system and
ComputeBudget keys: 1 082 bytes for a 12-byte inner instruction, 150 bytes to
spare. The lookup table is created once per account alongside `create`.

## Compute units (estimate, not yet measured on-chain)

Each `sol_sha256` call costs `85 + max(10, len / 2)` CU for a single slice:
113 CU per chain step (56-byte input), 413 CU per leaf (656 bytes), 125 CU
per Merkle node (80 bytes). A layer on a message with digits `d_c` does

```
steps(m) = Σ_c (255 − d_c)         c over 26 chains (24 message bytes + 2 checksum bytes)
CU_syscall(m) = 113 · steps(m) + 413 + 10 · 125
```

`steps` is 3 315 on average (uniform digest bytes), 6 375 at worst
(all-zero message, checksum digits 0x17 0xE8). Syscalls alone:
≈ 376 K CU average, 722 K worst case. The program's own work per step
(ADRS update, 56-byte copy, loop) is not measured; at 50–100 CU per step
the total is **≈ 540–710 K CU average, 1.04–1.36 M worst case**. The
fixture layers need 2 805–3 570 steps (319–405 K syscall CU).

Plan: request 1.4 M CU (the per-transaction maximum) for `execute` and
`cache_subtree`. The worst-case message is a hash output, so it is
astronomically unlikely, but a client can evaluate `verifySteps(m)`
(`cchsCompact.ts`) before signing and the measured overhead must confirm
that even 6 375 steps stay under 1.4 M. `recover` is one layer of height 8
with the same chain cost. If the measured overhead is too high, the fallback
is a `w = 128` variant (28 message chains + 2 checksum chains, 30 × 24 +
10 × 24 = 960 bytes per layer, about half the chain steps), which still fits
the packet.

## Before deployment

* Anchor build in CI (`anchor build`, `anchor test`) with the vectors of
  `cchs-c-20.json` replayed through `create` → `cache_subtree(0, l1, r0 =
  bottomRoot0)` → `execute` × 3 → `recover`, plus the negative cases
  (tampered chain value, missing cache, cache conflict, replay).
* Measure CU for `execute` on the fixture ops and on an all-zero message;
  confirm the stack budget of the fixed-array instruction arguments
  (~900 bytes) inside the 4 KB BPF frame.
* Devnet run with a real vault transfer through a v0 transaction and an
  address lookup table; record the exact transaction sizes.
* `anchor keys sync` to replace the placeholder program id.

## Build

```bash
# requires: rustup, solana-cli 1.18.17, anchor 0.30.1
anchor build
```

## Core tests

```bash
cd ../cchs-core && cargo test --features std
```

`tests/vectors_compact.rs` replays `cchs-c-20.json`: ops[0] bottom root
equals `bottomRoot0` and its top layer reaches `root`; ops[1] and ops[2]
verify against the cached root; tampered chain value, auth path and message
are rejected; the recovery vector is accepted once and its replay rejected.
