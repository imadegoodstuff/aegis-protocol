# Aegis — CosmWasm adapter

**Status**: skeleton compiles with CosmWasm 2.1; SPHINCS+ verify is TODO.

## Target chains

Any chain supporting CosmWasm 2.x: Osmosis, Neutron, Injective, Archway, Juno, Stargaze, Terra, Secret, …

## Address derivation (Cosmos SDK bech32)

Contract instantiation address is chain-defined (hash of code_id + instance id).
Users derive a stable **account address**:

```
cosmos_address = bech32(prefix, sha256(pq_pk)[:20])
```

Prefix is per-chain (`osmo1…`, `neutron1…`, `inj1…`, …). The contract
instance per-user is a `MsgInstantiateContract2` with a deterministic
`salt = sha256(pq_pk)` for predictable addresses.

## Build

```bash
# requires rustup target wasm32-unknown-unknown
cargo wasm           # alias in .cargo/config.toml below
# or:
RUSTFLAGS='-C link-arg=-s' cargo build --release --target wasm32-unknown-unknown --lib
```

Produces `target/wasm32-unknown-unknown/release/aegis_cosmwasm.wasm`.

## SPHINCS+ verification path

CosmWasm has unlimited gas (metered) and no stack size restrictions beyond host
limits — plain SPHINCS+-192s verify should fit, but costs millions of gas.
Decision for v0.2: use `cosmwasm_crypto_v2`'s `host_sphincs_verify` if the
host chain enables it; otherwise ship an in-contract SHRINCS verifier.

## Interface parity

Same `execute / initiate_exit / cancel_exit / finalize_exit` state machine as
EVM. See `src/lib.rs::ExecuteMsg`.
