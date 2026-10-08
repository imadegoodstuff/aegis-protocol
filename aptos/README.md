# Aegis — Aptos adapter

**Status**: skeleton; `aptos move compile` should succeed; SPHINCS+ verify is TODO.

## Address derivation

Aptos uses 32-byte account addresses. We derive the user's Aegis address via
Aptos's standard pubkey → address rule, but with our hash of pq_pk substituted:

```
auth_key = sha3_256(pq_pk || 0x02)        # 0x02 = multi-ed25519 scheme byte stand-in
address  = auth_key                        # Aptos address == auth_key (32 bytes)
```

(For v0.2 we'll register a custom auth-scheme byte to disambiguate SPHINCS+-controlled
accounts from Ed25519/MultiEd25519 ones. 0x02 is a placeholder here.)

## Build

```bash
aptos move compile --named-addresses aegis=0x1   # adjust address at deploy
aptos move test
```

## SPHINCS+ in Move

Aptos Move has a gas limit per tx (~2M units for user txs on mainnet). A full
SPHINCS+-192s verify is heavy but technically doable in native-call form. v0.2
will add a native function to `aptos-framework` or use the hypothetical
`aptos_std::sphincs` once it lands.

Alternative: use SHRINCS (Kudinov–Nick) which fits comfortably within one tx.

## Resource model note

Finalizing an emergency exit requires a `SignerCapability` because resources
cannot be removed without a signer. The current skeleton omits this; the real
implementation needs to store a `SignerCapability` at `initialize` time (produced
via `aptos_framework::account::create_resource_account`), gated by the PQ sig.
