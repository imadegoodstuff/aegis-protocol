# Aegis — Solana adapter (CCHS-C-20)

**Status**: implemented, built and exercised in CI, deployable from CI. The
verification core (`../cchs-core`, module `compact`) is CI-tested against the
shared vectors in `evm/test/fixtures/cchs-c-20.json`; the Anchor program adds
only the Solana digest, PDA layout and CPI dispatch. The `solana` job of
`build.yml` builds the SBF program, uploads the ELF as an artifact and replays
the fixture life cycle through it in the BanksClient runtime, reporting
compute units per instruction (`cu-test/tests/compute_units.rs`).

Program id: `AoQ7c3GuxiF7nshFnM872FoxUz7oUDhygdhoRX6jMQKr` on every cluster
(`declare_id!`, `Anchor.toml`). The manual workflow
`.github/workflows/solana-deploy.yml` builds the ELF at the chosen commit and
runs `solana program deploy` with the program and deployer keypairs held as
repository secrets (`SOLANA_PROGRAM_KEYPAIR`, `SOLANA_DEPLOYER_KEYPAIR`); on
devnet it funds the deployer from the faucet, on mainnet-beta the deployer
must already hold the rent (about twice the ELF size in lamports). Mainnet-beta
is not deployed. The wallet's Solana panel reads `getAccountInfo(program)` on
the selected cluster and refuses to act where the program is absent.

Client: `../wallet/src/aegis/solana.ts` (keys, PDAs, legacy/v0 messages,
JSON-RPC, Wallet Standard connector, no Solana library) and
`../wallet/src/aegis/solanaAccount.ts` (instruction encoding, state decoding,
index records, the protect / spend / recover flows). `../wallet/scripts/solana-flow.mts`
runs the whole life cycle against a live cluster with a local payer
(`SOLANA_PAYER=keypair.json npm run solana-flow`): create + lookup table,
SOL and SPL deposits (it mints a throwaway token), `cache_subtree`, three
`execute`s including a token transfer to a recipient without a token
account, `recover`, and an `execute` under the new epoch, printing every
transaction's size and signature.

Spec: `../CCHS.spec.md`. Signature client: `../wallet/src/aegis/cchsCompact.ts`.

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
   proof authenticates itself (it is bound to this account's `root`, which
   belongs to this chain's tree only; `CCHS.spec.md` §3, §5.3).
2. `execute(idx, l0_wots, l0_auth, ix_data)` — every signature. The client
   reads `next_idx` and `nonce` from the `CchsAccount`, picks a leaf
   `idx >= next_idx` (normally `next_idx` itself), builds the digest, signs
   with `sign(key, idx, m, subtreeCached = true)` and sends only `l0`. The
   program recomputes `r0` from `l0` and requires it to equal the cache PDA
   for `(epoch, idx >> 10)`. No top layer is accepted here, so the
   instruction always fits one packet.

The signer chooses the leaf index: `idx` below `next_idx` is rejected with
`IndexUsed`, and a successful `execute` sets `next_idx = idx + 1`, so the
skipped leaves are abandoned forever (only the signer can skip, because `idx`
is in the digest). The client decides whether a `cache_subtree` is needed by
checking whether the cache PDA for the subtree of `idx` exists and is
non-zero (`needs_top_layer` in the core). Both can be sent back-to-back;
`execute` fails with `MissingTopLayer` until the cache transaction has
landed. Re-sending `cache_subtree` for an already registered subtree is a
no-op, the split-flow counterpart of a redundant top layer being ignored.

Soundness is unchanged from the one-shot verifier: a cache slot can only be
written through a valid top-layer signature on exactly the stored value, is
never overwritten with a different value, and `execute` accepts only the
bottom root that was so registered (`CCHS.spec.md` §6.2 C3, C4).

## Accounts

| PDA | Seeds | Contents | Size |
|---|---|---|---|
| `CchsAccount` | `["cchs", initial_root(24)]` | `seed, root, rec_root` (24 B each; `seed` is the PDA seed = initial root), `pk_seed` (16 B, public seed of the current key tree), `epoch, next_idx, nonce, rec_nonce` (u64), `bump, vault_bump` | 8 + 122 = 130 B |
| `SubtreeCache` | `["cache", account, epoch LE u64, tree_idx LE u64]` | `root` — verified bottom subtree root, zero = not cached | 8 + 24 = 32 B |
| vault | `["vault", account]` | data-less system account; holds SOL / token authority | 0 |

`recover` bumps `epoch`, so every existing cache PDA becomes unreachable
without being deleted.

## Instructions

```
create(root: [u8;24], rec_root: [u8;24], pk_seed: [u8;16])
    accounts: account (init), payer (signer), system_program

cache_subtree(tree_idx: u64, l1_wots: [[u8;24];26], l1_auth: [[u8;24];10], r0: [u8;24])
    accounts: account, cache (init_if_needed, PDA for (epoch, tree_idx)), payer (signer), system_program
    rejects: ZeroRoot (r0 = 0), Exhausted (tree_idx >= 1024), BadTopRoot,
             CacheConflict (slot holds a different non-zero root; re-sending the same r0 is a no-op)

execute(idx: u64, l0_wots: [[u8;24];26], l0_auth: [[u8;24];10], ix_data: Vec<u8>)
    accounts: account (mut), cache (PDA for (epoch, idx >> 10), must exist),
              target_program, then as remaining_accounts every account of the
              inner instruction (not the target program itself)
    rejects: IndexUsed (idx < next_idx), Exhausted (idx >= 2^20),
             MissingTopLayer (cache zero / absent), BadSubtreeRoot, TargetNotExecutable
    effect:  next_idx = idx + 1, nonce += 1, then CPI target_program(ix_data) signed by
             the account PDA and the vault PDA wherever they appear

recover(new_root: [u8;24], new_rec_root: [u8;24], new_pk_seed: [u8;16], wots: [[u8;24];26], auth: [[u8;24];8])
    accounts: account (mut)
    effect:  root/rec_root/pk_seed replaced, next_idx = 0, epoch += 1, rec_nonce += 1
```

`idx` is bound into the digest and checked against `next_idx` before any
hashing, so a signature can be used exactly once and never at a lower leaf
than the account has already advanced to. No payer or system program is
needed because `execute` never creates an account.

## Digest

The client signs the 24-byte message

```
M = sha256("AEGIS_CCHS_V1" ‖ "solana" ‖ account_pubkey(32) ‖ nonce u64 BE ‖ idx u64 BE
           ‖ sha256(target_program(32) ‖ ix_data))[0..24)
```

and for recovery

```
M_rec = sha256("AEGIS_CCHS_RECOVER_V1" ‖ "solana" ‖ account_pubkey(32) ‖ rec_nonce u64 BE
               ‖ new_root(24) ‖ new_rec_root(24) ‖ new_pk_seed(16))[0..24)
```

`"solana"` replaces the EVM chain id, so a signature is never valid on another
chain. The `digest` fields of `cchs-c-20.json` are exactly these values for
`account = 0xcc…cc`, `callHash = sha256(target_program ‖ ix_data)` as given.

## Layer verification (shared with every chain)

```
ADRS = layer(1) ‖ treeIdx(8 BE) ‖ type(1) ‖ leafIdx(4 BE) ‖ chainIdx(1) ‖ step(1) ‖ pkSeed(16)
F(adrs, x)   = sha256(adrs ‖ x)[0..24)                   type 0x00
leaf         = sha256(adrs ‖ pk_0 ‖ … ‖ pk_25)[0..24)     type 0x01
node         = sha256(adrs ‖ left ‖ right)[0..24)         type 0x02, leafIdx = pos >> 1, chainIdx = level
```

Layer 0: `treeIdx = idx >> 10`, `leafIdx = idx & 1023`, message `M`. Layer 1:
`treeIdx = 0`, `leafIdx = idx >> 10`, message `R_0` (checked in
`cache_subtree`). Recovery: layer `0xFF`, tree 0, `leafIdx = rec_nonce`,
height 8.

`pkSeed` (`pk_seed`) is the 16-byte public seed of the key tree (part of the public key,
rotated by recovery, `CCHS.spec.md` §2.2): every hash call of one tree is a
different function from the same position in any other tree.

## Byte budget

Instruction data (8-byte Anchor discriminator included; fixed arrays carry
no length prefix, `Vec<u8>` carries a 4-byte one):

| Instruction | Data bytes |
|---|---|
| `create` | 8 + 24 + 24 = **56** |
| `cache_subtree` | 8 + 8 + 624 + 240 + 24 = **904** |
| `execute` | 8 + 8 (`idx`) + 624 + 240 + 4 + `ix_data.len()` = **884 + len** (896 for a 12-byte SOL transfer) |
| `recover` | 8 + 24 + 24 + 624 + 192 = **872** |

The explicit `idx` argument costs 8 bytes per `execute` compared with the
earlier implicit-index layout; every row below includes it.

Whole transaction, one fee-payer signature, legacy message
(`65 + 3 + 1 + 32·keys + 32 + 1 + Σ(1 + 1 + accounts + 2 + data)`), computed
from the layouts above. Rows marked *measured* are the serialized sizes of
the transactions `cu-test/tests/compute_units.rs` sends (each carries one
instruction and no compute-budget instruction):

| Transaction | Keys | Bytes of 1 232 |
|---|---|---|
| `execute`, SOL transfer vault → recipient (12-byte inner ix), no compute-budget ix | payer, program, account, cache, system, vault, recipient = 7 | **1 231** |
| same, recipient = payer (6 keys), no compute-budget ix | 6 | 1 199 (measured) |
| same, 6 keys, plus `SetComputeUnitLimit` (adds the ComputeBudget key and an 8-byte ix) | 7 | 1 239 — **does not fit** |
| same, 7 keys, plus `SetComputeUnitLimit` | 8 | 1 271 — **does not fit** |
| `execute` as a v0 message, payer static, 7 keys through one address lookup table, plus `SetComputeUnitLimit` | 1 + 7 | **1 090** (room for 142 bytes of `ix_data`) |
| `cache_subtree` | payer, program, account, cache, system = 5 (6 with compute budget) | 1 174 (measured) (1 214) |
| `recover` | payer, program, account = 3 (4 with compute budget) | 1 075 (measured) (1 115) |
| `create` | 4 | 292 (measured) |

The bottom-layer instruction itself still fits a legacy packet (1 byte to
spare in the 7-key case). Because the verification needs more than the
200 K CU default (next section), a real transaction also carries a
`SetComputeUnitLimit` instruction, and with `idx` on board even the 6-key
variant then exceeds the legacy limit by 7 bytes. The client therefore sends
`execute` as a v0 transaction with an address lookup table holding the
program, account, cache, vault, system and ComputeBudget keys: 1 090 bytes
for a 12-byte inner instruction, 142 bytes to spare. The lookup table is
created once per account alongside `create`.

## Compute units (measured in CI)

`cu-test/tests/compute_units.rs` runs the SBF build of the
program in the BanksClient runtime (`solana-program-test`, the same
instruction metering as a validator) and replays the fixture life cycle:
`create`, `cache_subtree(0)`, `execute` at leaves 0, 1, 2 and 5,
`cache_subtree(1)`, `execute` at leaf 1024, `recover`. Every transaction
carries one instruction, so the `compute_units_consumed` of the transaction
is the cost of that instruction. The test prints a markdown table (chain
steps, compute units, instruction and transaction bytes per instruction), a
linear fit `CU ≈ a + b · steps` over the `execute` rows with its
extrapolation to the 6 375-step worst case, and fails if any instruction
exceeds 1 400 000 CU. The numbers are in the log and the job summary of the
`Solana (CCHS-C-20 program, SBF)` job of `build.yml`, step "Compute units
per instruction"; they are not copied here because they move with the
toolchain that builds the program.

The fixture's `execute` and `recovery` digests bind the placeholder account
`0xcc…cc`, while the program binds the real `CchsAccount` PDA, so the
fixture's bottom-layer and recovery chain values cannot be sent as they are.
The test derives the WOTS+ secret keys from the fixture's `master` seed (the
HKDF of `cchsCompact.ts`) and re-signs the on-chain digest; roots,
authentication paths and both top-layer proofs (`cache_subtree` payloads)
are the fixture bytes, and every re-signed layer is checked against the
fixture root before it is sent. Chain steps are always a multiple of 255
(`Σ (255 − d_c) = 255 · (csum_hi + 2)`), so the fixture ops cover 3 315,
3 570 and 3 825 steps.

### Estimate (kept for comparison)

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
(ADRS update, 56-byte copy, loop) is not part of this estimate; at 50–100 CU
per step the total is **≈ 540–710 K CU average, 1.04–1.36 M worst case**.
The fixture layers replayed by the CI test need 3 315–3 825 steps
(376–434 K syscall CU); compare with the measured column.

Plan: request 1.4 M CU (the per-transaction maximum) for `execute` and
`cache_subtree`. The worst-case message is a hash output, so it is
astronomically unlikely, but a client can evaluate `verifySteps(m)`
(`cchsCompact.ts`) before signing, and the CI extrapolation must confirm
that even 6 375 steps stay under 1.4 M. `recover` is one layer of height 8
with the same chain cost. If the measured overhead is too high, the fallback
is a `w = 128` variant (28 message chains + 2 checksum chains, 30 × 24 +
10 × 24 = 960 bytes per layer, about half the chain steps), which still fits
the packet.

## Open items

* The positive life cycle (`create` → `cache_subtree(0)` → `execute` × 3 →
  skip to leaf 5 → `cache_subtree(1)` → leaf 1024 → `recover`) runs against
  the SBF build in CI (`cu-test/tests/compute_units.rs`). Still to add on the
  BanksClient side: the negative cases (tampered chain value, missing
  cache, cache conflict, index reuse, replay), currently covered host-side
  only (`src/lib.rs` tests, `cchs-core/tests/vectors_compact.rs`).
* CU on an all-zero message cannot be measured directly (the message is a
  hash output); the CI table extrapolates from the fixture ops. Confirm the
  stack budget of the fixed-array instruction arguments (~900 bytes) inside
  the 4 KB BPF frame (the CI run exercises it).
* A recorded devnet run of `wallet/scripts/solana-flow.mts` (real vault
  transfers through the v0 transaction and the lookup table) with its
  signatures pasted here. The client computes `execute` at 1 089 bytes for a
  12-byte inner instruction and 1 239 as a legacy message, matching the table
  above; `cache_subtree` with a compute-budget instruction stays legacy.
* The lookup table is owned by the wallet that created the account (its
  authority); a second wallet finds it from the account's first transaction
  (`findTable`) or creates another one.

## Build

```bash
# requires: rustup, Agave (solana-cli) 2.3.6, anchor 0.31.1 (the versions CI builds and measures with)
anchor build
```

`Cargo.lock` in this directory is committed, unlike the rest of the
repository: the cargo inside the Agave 2.3 platform tools is 1.84 and cannot
parse edition-2024 manifests, so the lock holds every dependency at a version
that toolchain can read (blake3 1.5, proc-macro-crate 3.2, zeroize 1.8.1,
indexmap 2.10, unicode-segmentation 1.11). To refresh it, run
`cargo generate-lockfile` with `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback`
and pin those five again; `cargo metadata` lists `rust_version` per package
to confirm nothing above 1.84 remains. `cu-test/` is a separate package with
its own, uncommitted lock: it runs on the host toolchain.

## Tests

```bash
cargo test -p aegis_account --lib      # host-side replay of cchs-c-20.json through the handler logic
cd ../cchs-core && cargo test --features std

# compute units per instruction on the built program (what CI runs)
cargo build-sbf --manifest-path programs/aegis_account/Cargo.toml
SBF_OUT_DIR=$PWD/target/deploy cargo test --manifest-path cu-test/Cargo.toml --test compute_units -- --nocapture
```

`tests/vectors_compact.rs` replays `cchs-c-20.json`: ops[0] bottom root
equals `bottomRoot0` and its top layer reaches `root`; ops[1] and ops[2]
verify against the cached root; tampered chain value, auth path and message
are rejected; the recovery vector is accepted once and its replay rejected.
The `skip` ops cover the signer-chosen index: leaf 5 on the cached path,
leaf 1024 after `cache_subtree(1, l1, bottomRoot1)`, `IndexUsed` for any
lower leaf afterwards, `MissingTopLayer` for a jump into an unregistered
subtree, and a leaf-5 signature rejected at leaf 6. The program's own test
module (`programs/aegis_account/src/lib.rs`) runs the same ops through the
`cache_subtree` / `execute` ordering with the program's `SolSha256`.
