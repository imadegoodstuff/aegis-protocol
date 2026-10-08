# Aegis — Solana adapter (CCHS-S-20)

**Status**: implemented. The verification core (`../cchs-core`) is CI-tested
against the shared vectors in `evm/test/fixtures/cchs-s-20.json`; the Anchor
program compiles against it and adds only the Solana digest, PDA layout and
CPI dispatch. Anchor builds run in a dedicated workflow (toolchain install is
slow), not in `build.yml`.

Spec: `../CCHS.spec.md`. Reference implementation: `../evm/src/AegisCCHS.sol`.

## What it does

A hash-only post-quantum account. Each `execute` is authorized by a WOTS+
signature (SHA-256, w = 16, 67 chains) under a two-layer hypertree of height
10 + 10 (2^20 signatures). The top-layer proof for a bottom subtree is verified
once and cached; the following 1023 signatures carry only the bottom layer
(77 × 32 = 2464 bytes). Only SHA-256 is used, through the `sol_sha256`
syscall.

## Accounts

| PDA | Seeds | Contents |
|---|---|---|
| `CchsAccount` | `["cchs", initial_root]` | `seed, root, rec_root, epoch, next_idx, nonce, rec_nonce, bump, vault_bump` |
| `SubtreeCache` | `["cache", account, epoch LE u64, tree_idx LE u64]` | `root` — verified bottom subtree root, zero = not cached |
| vault | `["vault", account]` | data-less system account; holds SOL / token authority |

Because Solana accounts are fixed-size, the `cachedRoot[(epoch, treeIdx)]`
mapping of the EVM contract becomes one small PDA per bottom subtree, created
(`init_if_needed`) on the first signature of that subtree. `recover` bumps
`epoch`, so every existing cache PDA becomes unreachable without being
deleted.

## Instructions

```
initialize(root: [u8;32], rec_root: [u8;32])
execute(l0_wots: Vec<[u8;32]>  // 67
        l0_auth: Vec<[u8;32]>  // 10
        has_l1: bool,
        l1_wots: Vec<[u8;32]>, // 67 or empty
        l1_auth: Vec<[u8;32]>, // 10 or empty
        target_program: Pubkey,
        ix_data: Vec<u8>)
recover(new_root: [u8;32], new_rec_root: [u8;32], wots: Vec<[u8;32]> /*67*/, auth: Vec<[u8;32]> /*8*/)
```

`execute` accounts: `account` (mut), `cache` (mut, PDA for the current
`(epoch, next_idx >> 10)`), `payer` (signer, pays for a new cache PDA),
`system_program`, then as `remaining_accounts` every account of the inner
instruction including the target program. The account PDA and the vault PDA
are marked as signers wherever they appear and co-sign the CPI.

## Digest

The client signs the 32-byte message

```
M = sha256("AEGIS_CCHS_V1" ‖ "solana" ‖ account_pubkey(32) ‖ nonce u64 BE ‖ next_idx u64 BE
           ‖ sha256(target_program(32) ‖ ix_data))
```

and for recovery

```
M_rec = sha256("AEGIS_CCHS_RECOVER_V1" ‖ "solana" ‖ account_pubkey(32) ‖ rec_nonce u64 BE
               ‖ new_root ‖ new_rec_root)
```

`"solana"` replaces the EVM chain id, so a signature is never valid on another
chain. `nonce` and `next_idx` are read from the `CchsAccount`.

## Layer verification (shared with every chain)

```
ADRS = layer(1) ‖ treeIdx(8 BE) ‖ type(1) ‖ leafIdx(4 BE) ‖ chainIdx(1) ‖ step(1) ‖ 16 zero bytes
F(adrs, x)   = sha256(adrs ‖ x)                      type 0x00
leaf         = sha256(adrs ‖ pk_0 ‖ … ‖ pk_66)        type 0x01
node         = sha256(adrs ‖ left ‖ right)            type 0x02, leafIdx = pos >> 1, chainIdx = level
```

Layer 0: `treeIdx = idx >> 10`, `leafIdx = idx & 1023`, message `M`. Layer 1:
`treeIdx = 0`, `leafIdx = idx >> 10`, message `R_0`; required unless the cache
PDA already holds `R_0`. Recovery: layer `0xFF`, tree 0, `leafIdx = rec_nonce`,
height 8.

## Transaction size and compute

* A bottom-layer signature is 2464 bytes and a first-in-subtree transaction
  carries 4928 bytes. Both exceed the 1232-byte Solana packet limit, so a
  production deployment needs a staging buffer account filled over several
  transactions (or a client that splits the signature) before `execute` reads
  it. The instruction interface above is the verifier contract; the staging
  path is not yet implemented.
* One layer costs about 500 SHA-256 syscalls (≈ 100–200 K CU); request a
  compute budget of ~400 K CU for cached signatures and ~800 K CU for
  first-in-subtree ones.

## Build

```bash
# requires: rustup, solana-cli 1.18.17, anchor 0.30.1
anchor build
```

## Core tests

```bash
cd ../cchs-core && cargo test --features std
```
