# Aegis — Bitcoin adapter

**Status**: design-doc only. Blocked on BIP-360 (Pay-to-Merkle-Root) activation.

Bitcoin has no smart contract VM, so the Aegis state machine cannot be
reproduced directly. What *is* possible today vs. after BIP-360:

## Today (pre BIP-360)

The best we can do without a soft fork is a **Taproot script path** that
commits to:
- A SPHINCS+ public-key hash (as `OP_HASH256` of the pubkey)
- An ECDSA fallback pubkey (secp256k1) gated by `OP_CHECKSEQUENCEVERIFY 1008`
  (~7 days of blocks)

But Taproot's **key path** still uses secp256k1 and would be the cheap, default
spend path — defeating the "no EC in user signing" goal. We would need users
to **always** use the script path, which is wasteful (larger witness).

Verdict: not shipping a Bitcoin adapter today is the correct call.

## After BIP-360 (Pay-to-Merkle-Root)

Bitcoin BIP-360 proposes `P2MR` outputs — a 32-byte commitment to a Merkle root
of scripts, **without** a key-path spend. This is exactly the primitive Aegis
needs: your output is bound only to a script tree, so you can commit to a
SPHINCS+ script path exclusively.

Timeline: BIP merged to the repo in Feb 2026 but **not activated**. No ETA.

## Planned Aegis-on-Bitcoin design (post BIP-360 activation)

```
output = P2MR(merkle_root([
    script_pq:        <sphincs_pk> OP_SPHINCSVERIFY
                      // requires companion BIP for OP_SPHINCSVERIFY opcode
    script_fallback:  <7 days> OP_CSV OP_DROP <ecdsa_pk> OP_CHECKSIG
                      // 7-day timelock to guardian via pre-signed PSBT
]))
```

Spend path = either (a) PQ sig over tx-sighash via `OP_SPHINCSVERIFY`, or
(b) classical ECDSA signature after 7-day relative timelock.

No AegisAccount contract exists; the account IS the UTXO. The "state machine"
collapses to the two tapscript branches above.

## Why we're waiting

A Bitcoin adapter without BIP-360 would either:
- Expose a working key-path spend (defeats PQ goal), or
- Require users to always use the script path (bad UX)

Neither is honest. We'd rather ship nothing than ship something that doesn't
materially help.

Tracking:
- https://github.com/bitcoin/bips/pull/1670 (BIP-360 P2MR)
- Companion PQ-signature opcode BIP: not yet drafted
