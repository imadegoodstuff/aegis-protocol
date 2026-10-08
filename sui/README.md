# Aegis — Sui adapter

**Status**: skeleton; `sui move build` should compile; SPHINCS+ verify is TODO.

## Address derivation

Sui addresses are 32 bytes = `blake2b_256(flag_byte || pubkey)[..32]`. We'll
register a dedicated flag byte for SPHINCS+:

```
sui_address = blake2b_256(0xFE || pq_pk)[..32]   # 0xFE = aegis-sphincs provisional flag
```

(Sui multisig schemes use flags 0x00=ed25519, 0x01=secp256k1, 0x02=secp256r1, 0x03=multisig,
0x05=zkLogin. 0xFE is our provisional slot pending governance.)

## Build

```bash
sui move build
sui move test
```

## Object model

Each user's AegisAccount is a **shared object**. No one owns it; authorization
is purely by PQ sig. Transfers of owned Coin objects into/out of the account
happen via normal Sui object ownership flows.

## v0.2 TODO

- Implement signer-free coin sweeping in `finalize_emergency_exit`
  (iterate dynamic fields on the account; split-and-transfer owned `Coin<T>`)
- Replace stub verify with native SPHINCS+ once `std::crypto::sphincs` exists,
  or ship SHRINCS Move impl
