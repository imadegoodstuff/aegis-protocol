# Aegis — TON adapter

**Status**: FunC skeleton with full state machine; `send_raw_message` sweep
scaffolded; SPHINCS+ verify is TODO.

## Address derivation

TON addresses are derived from the hash of the initial contract state (StateInit).
Thus different `pq_pk_hash` → different StateInit → different TON address.

```
addr = sha256(StateInit(code, initial_data(pq_pk_hash, guardian, fallback_pubkey_hash)))
```

Same pq_pk + guardian + fallback across installations always yields the same
TON address (deterministic deploy).

## Build

```bash
# requires func-js (TON FunC compiler) and fift
npm i -g @ton/func-js
func -o aegis_account.fif -SPA contracts/aegis_account.fc
fift -s aegis_account.fif
```

Produces `aegis_account.cell`, deployable via `@ton/blueprint` or `tonweb`.

## SPHINCS+ in TVM

TVM has a per-tx gas limit around 1M gas. SPHINCS+-192s verify (~5M hash ops)
exceeds this. Three options for v0.2:

1. Split verify across multiple messages with on-chain commitment of
   intermediate state (true parallel evaluation won't fit either way).
2. Deploy SHRINCS variant (~324B sigs) — much cheaper, probably fits.
3. Lobby for a dedicated TVM instruction for FIPS 205 verify.

v0.1 ships without actual verification; the state machine is wired so the real
verify slots in with no interface change.

## Minimum viable test

```bash
# in TON Sandbox (Blueprint)
npx blueprint create
# drop contracts/aegis_account.fc into contracts/
# write wrappers/AegisAccount.ts + tests/AegisAccount.spec.ts
npx blueprint test
```
