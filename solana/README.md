# Aegis — Solana adapter

**Status**: skeleton compiles with Anchor 0.30.1; SPHINCS+ verify is TODO.

## Address derivation

```
seeds = [b"aegis-v1", pq_pk_hash (32), guardian_pubkey (32)]
PDA = Pubkey::find_program_address(seeds, PROGRAM_ID)
```

Same seed → same PDA globally. Different from EVM address (SVM uses ed25519-shape 32-byte pubkeys).

## Build

```bash
# requires: rustup, solana-cli 1.18.17, anchor 0.30.1
anchor build
anchor test --skip-deploy
```

## Why SPHINCS+ verify is stubbed

Solana BPF has a ~200K compute unit budget per instruction and a ~4KB stack. A
plain `sphincsshake192ssimple` verify costs ~5M hashes — infeasible in one tx.

Three paths considered (ADAPTERS.md tracks the decision):

1. **SIMD-0152** user-defined precompiles (if/when activated on mainnet)
2. **SHRINCS** (Kudinov & Nick, 2025) — 324 B sigs, ~10× fewer hashes
3. **Chunked verifier** — split hyper-tree evaluation across many txs with commit scheme

v0.2 will pick one and implement.

## Interface parity with EVM

| Function        | EVM | Solana |
|-----------------|-----|--------|
| execute         | `AegisAccount.execute()`              | `aegis_account::execute()` |
| initiate_exit   | `AegisAccount.initiateEmergencyExit()`| `aegis_account::initiate_emergency_exit()` |
| cancel_exit     | `AegisAccount.cancelEmergencyExit()`  | `aegis_account::cancel_emergency_exit()` |
| finalize_exit   | `AegisAccount.finalizeEmergencyExit()`| `aegis_account::finalize_emergency_exit()` |
