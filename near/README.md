# Aegis — NEAR adapter

**Status**: skeleton; builds with `cargo near build`; SPHINCS+ verify is TODO.

## Address derivation

NEAR uses human-readable account names. We derive a deterministic subaccount:

```
near_subaccount = format!("{}.aegis.near", hex(sha256(pq_pk))[..16])
```

User owns `0a1b…9f.aegis.near`; the contract code deployed there IS the user's
AegisAccount.

For NEAR's "implicit accounts" model (addresses == hex of ed25519 pubkey), we
emit a parallel implicit address:

```
near_implicit = hex(sha256(pq_pk))      # 64-char hex
```

Users with existing NEAR assets can migrate by sending to either form.

## Build

```bash
# cargo-near installs the full toolchain the first time
cargo install cargo-near
cd near
cargo near build
# produces target/near/aegis_near.wasm
```

## Deploy

```bash
near create-account 0a1b…9f.aegis.near --masterAccount aegis.near --initialBalance 2
near deploy 0a1b…9f.aegis.near target/near/aegis_near.wasm \
    --initFunction new \
    --initArgs '{"pq_pk_hash":"...","guardian":"cold.near","fallback_pubkey":"...","fee_collector":"fees.aegis.near"}'
```

## SPHINCS+ cost on NEAR

NEAR txs have 300 TGas (= 300e12 units) per receipt. SPHINCS+-192s verify is
~5M hash ops ≈ well within this. The verify will fit in a single receipt.
Precise cost benchmarking is a v0.2 task.
