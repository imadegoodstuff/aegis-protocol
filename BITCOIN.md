# Bitcoin and quantum resistance

What current Bitcoin consensus allows, what it does not, and the design that
Aegis holds ready for the day it changes. Everything here is either a statement
about Bitcoin Script that can be checked against BIP-141/143/341/342, a
measurement from `wallet/src/aegis/btcTapscript.ts`, or an estimate marked as
such. Nothing in this file is live on a network with value.

---

## 0. Summary

A Bitcoin UTXO is exposed to a discrete-log adversary in two ways. *Long
exposure*: the public key is visible in the output itself (P2PK, P2TR, reused
P2PKH/P2WPKH). *Short exposure*: the key becomes visible when the spend is
broadcast and stays attackable until the spend is buried.

Long exposure is solved today by key hygiene, and the wallet does that
(§6). Short exposure cannot be solved by any script under current consensus:
§2 lists what a script can observe about its spending transaction, and §3
shows that every observable is either controlled by the spender, depends on
discrete-log hardness, or leaks only through the DER length of ECDSA
signatures, which is the basis of the known no-fork constructions and the
reason they do not reach the security level of the rest of this project.

Once Bitcoin has (i) an output type without a key path and (ii) an opcode
that lets a script see its own sighash, a hash-only account is possible, and
§5 specifies one: the CCHS state machine carried by the UTXO lineage itself,
with a universal code tree and a per-account state leaf, so that every Aegis
Bitcoin account shares one script and differs only in 32 bytes of state.
BIP-360 (P2MR) supplies (i); BIP-347 (`OP_CAT`) or BIP-348
(`OP_CHECKSIGFROMSTACK`) supplies (ii). Neither alone is sufficient (§4).

---

## 1. Threat model

A *cryptographically relevant quantum computer* (CRQC) computes discrete
logarithms on secp256k1. Nothing else is assumed to break: SHA-256 and
RIPEMD-160 keep their preimage and collision resistance up to the Grover
square root, which is why every construction below is hash-only.

| Exposure | When the key is public | Adversary's window | Status today |
|---|---|---|---|
| Long | from the moment the output is created (P2PK, P2TR, any reused address) | unbounded | avoidable by the owner (§6) |
| Short | from broadcast of the spend until the spend is final | minutes to hours: the adversary must recover the key *and* win the fee race before confirmation, or reorganise the chain afterwards | not avoidable by any script (§3) |

"Quantum protection for Bitcoin" therefore has two different meanings. The
first is a wallet discipline. The second needs a consensus change. This file
is careful to say which one it is talking about.

---

## 2. What a script can observe about its spending transaction

Bitcoin Script has no general transaction introspection. The complete list of
ways a script's result depends on the transaction that spends it:

| Mechanism | What it observes | Spender control |
|---|---|---|
| `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` / `OP_CHECKSIGADD` | whether a witness-supplied signature is valid for a public key over the sighash of this transaction | the spender chooses the signature; for a key whose private key is known (to the spender or to a CRQC) a valid signature exists for every sighash |
| `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY` | lower bounds on `nLockTime` / `nSequence` | the spender sets both fields |
| `OP_SIZE` applied to an ECDSA signature (SegWit v0 and legacy only) | the DER length of `(r, s)`, which depends on the sighash once the nonce is fixed | the spender chooses the nonce; fixing it can only be enforced through the same length check |
| `OP_SIZE` applied to a Schnorr signature (Tapscript) | 64 or 65 bytes | entirely the spender's choice (sighash-type byte) |
| the Taproot annex, the output amount, the other inputs and outputs | nothing: no opcode reads them | — |

Everything else a script does (`OP_SHA256`, `OP_EQUAL`, arithmetic, stack
manipulation, hard-coded constants) is a function of the witness and the
script alone, both of which the spender supplies.

---

## 3. Why no spend condition under current consensus is both hash-only and transaction-binding

A post-quantum spend condition must satisfy two things at once: authorisation
depends on a secret a CRQC cannot compute, and the authorisation is bound to
*this* transaction by rules the network enforces. Three observations close
every avenue.

**L1 (key path).** A P2TR output publishes its tweaked key `Q`. A CRQC
recovers `log Q` from the output alone and spends by the key path, whatever
the internal key is: a NUMS internal key makes the owner unable to use the
key path, not the adversary. So any design on P2TR has unbounded long
exposure regardless of what its leaves do. The only key-less containers are
P2SH/P2WSH, which cannot receive new opcodes (no `OP_SUCCESSx`), and the
proposed P2MR.

**L2 (circularity).** A script could bind a spend to one transaction by
hard-coding a *signature* and checking it with `OP_EQUALVERIFY` before
`OP_CHECKSIG`: for a fixed `(R, s, P)` the Schnorr equation
`s·G = R + H(R‖P‖m)·P` holds for exactly one `m` up to a SHA-256 collision,
so the pin would rest on hashing, not on discrete logs, even with `P = G`.
But every sighash mode, legacy, BIP-143 and BIP-341, commits to the outpoint
being spent, the outpoint commits to the txid, and the txid commits to the
scriptPubKey that would contain the signature. The signature would have to
sign a hash of itself. The pin is impossible without `SIGHASH_ANYPREVOUT`
(BIP-118), `OP_CHECKTEMPLATEVERIFY` (BIP-119) or introspection. This is the
precise reason pre-signed "vault" transactions must live off-chain, where a
recovered key defeats them (the key is learned from the output or from the
first spend, and the vault UTXO is still unspent at that moment).

**L3 (reduction of no-fork schemes).** Combine §2 with L1 and L2: the only
transaction-dependent, spender-uncontrollable quantity a script can obtain
without relying on discrete logs is the DER length of an ECDSA signature
whose nonce has been forced by a length bound. Therefore every hash-only,
transaction-binding construction expressible today extracts bits of the
sighash through that channel and signs them with hash chains. This is
exactly the family in the literature: Heilman et al., "Signing a Bitcoin
transaction with Lamport signatures" (bitcoin-dev, 2024); Linus, *Binohash*;
and the 2025–26 "Quantum-Safe Bitcoin transactions without soft forks"
paper, which replaces the length puzzle with a hash-to-valid-DER puzzle after
the first variant was shown to fail against an adversary that can compute
the nonce for `r = 1`. These schemes need hundreds to a thousand `CHECKSIG`
evaluations per spend, rest on puzzle assumptions outside the standard
hash-function model, and deliver tens of bits of binding per signature.
Aegis does not adopt them: the rest of the protocol is argued at 2^128 /
2^256 under plain (second-)preimage resistance, and a Bitcoin leg that falls
short of that would be labelled in a way the wallet refuses to label anything.

Consequence: *today*, protection against short exposure on Bitcoin is
operational, not cryptographic. The owner can shorten the window (adequate
fee, broadcast directly to miners rather than to the public mempool), not
close it. The wallet says so (§6).

---

## 4. What each proposed change would add

| Proposal | Status (2026-10) | Gives | Does not give |
|---|---|---|---|
| BIP-360 P2MR (formerly P2QRH / P2TSH) | merged into the BIPs repository as a draft, 2026-02; not activated, no timeline | a Taproot-style output that commits to a script tree only: no key path, so L1 disappears; Tapscript (BIP-342) unchanged | any post-quantum signature; the mempool window (short exposure) is untouched, as the BIP itself states |
| BIP-347 `OP_CAT` | draft, Tapscript only | byte concatenation; with the "Schnorr trick" (`P = G`, `R = G`, so `s = 1 + e`) a script can reconstruct the BIP-341 sighash from witness-supplied fields and have `OP_CHECKSIG` confirm it, binding the transaction with hashing alone | a key-less output: in P2TR the key path remains (L1) |
| BIP-348 `OP_CHECKSIGFROMSTACK` | draft, Tapscript only | the same binding without the grinding step of the Schnorr trick | a key-less output |
| BIP-118 / BIP-119 | drafts | covenants (pin the outputs) | the ability to verify a hash signature over an arbitrary message |

Hence the dependency for a hash-only Bitcoin account is a conjunction:

> **a key-less container** (P2MR, or `OP_CAT`/`OP_CHECKSIGFROMSTACK` deployed
> under a witness version without key path) **and an introspection opcode**
> (`OP_CAT` or `OP_CHECKSIGFROMSTACK`).

`OP_CAT` alone leaves L1 open; P2MR alone leaves the signature to ECDSA /
Schnorr. The pairing is noted in passing in the BIP-360 discussion
("disable the key path and activate OP_CAT"); the design below is what it
takes to turn the pairing into an account rather than a one-shot Lamport
leaf.

---

## 5. Design: CCHS carried by the UTXO lineage

Bitcoin has no mutable storage, so the EVM contract's `nextIdx` and
`cachedRoot[epoch, t]` cannot be stored anywhere. The UTXO model offers a
substitute that is in one respect better: a UTXO is consumed when it is
spent, so the *successor* output can carry the updated state, and a covenant
can force the successor to be well-formed. The account is therefore not an
address but a lineage of UTXOs, each committing to the state after the last
spend.

### 5.1 State and code

```
state   = root ‖ recRoot ‖ epoch (1 B) ‖ nextIdx (3 B) ‖ R_t (32 B) ‖ t (2 B)
```

`root`, `recRoot`, `epoch`, `nextIdx` have the meaning of `CCHS.spec.md`
§4–§5 and §8. `R_t` is the cached bottom-subtree root for subtree `t`
(the EVM contract caches one root per subtree; the UTXO carries one, for the
subtree currently in use, which is all a monotone index ever needs).

```
stateLeaf = OP_RETURN <state>                       # never spendable, 72 B + overhead
codeRoot  = TapTree( exec, execFirst, recover )     # the same for every account
spk       = P2MR( TapBranch(codeRoot, TapLeafHash(stateLeaf)) )
```

The three code leaves are universal: they contain no per-account constant.
They learn the account's state from the witness, which supplies
`stateLeaf` and `codeRoot`, and they authenticate both against the
scriptPubKey being spent, which is part of the sighash
(`sha_scriptpubkeys`; a single-input transaction makes it
`SHA256(len ‖ spk)`). A leaf cannot contain its own hash (quine), and
`codeRoot` depends on all three leaves, so neither can be hard-coded; the
scriptPubKey in the sighash is what breaks the circle, and it is available
exactly because the introspection opcode is.

Consequences: the protocol has one `codeRoot`, publishable and auditable
once; an account is identified by 72 bytes of state; the address is
`P2MR(TapBranch(codeRoot, H(stateLeaf)))` and changes after every spend,
which is also the normal Bitcoin practice of never receiving twice at one
address.

### 5.2 `exec` (cached path, every spend)

Witness: WOTS+ signature at leaf `idx` (67 × 32 B), the 64 message digits,
the bottom-layer authentication path (10 × 32 B), the BIP-341 sighash fields
of this transaction, `stateLeaf`, `codeRoot`, the control block, and the
successor's `nextIdx'`.

Script, in order:

1. Reconstruct `sighash` from the supplied fields with `OP_CAT` and
   `OP_SHA256` (tagged hash `TapSighash`), and prove it is this
   transaction's sighash: `OP_CHECKSIGFROMSTACK` directly, or the Schnorr
   trick under `OP_CAT`. From here on every supplied transaction field is
   trusted.
2. From `sha_scriptpubkeys` (or the specific `scriptPubKey` field) recover
   the spent `spk`; compute `TapBranch(codeRoot, TapLeafHash(stateLeaf))`
   and check it equals the program in `spk`. From here on `state` is
   trusted.
3. Parse `nextIdx`, `R_t`, `t` out of `state` (fixed offsets, `OP_CAT` with
   witness-supplied pieces and equality, since Script has no substring).
   Check `idx ≥ nextIdx` and `idx >> 10 == t`.
4. Verify the 67 WOTS+ chains against the leaf's public values, the
   checksum digits arithmetically, and that the 64 message digits reassemble
   to `sighash` (this is `CCHS.spec.md` §4 with `M = sighash`; the chain id
   of §4 is unnecessary because the sighash already commits to the chain
   through the outpoint, and the per-chain key of §3 still applies: the
   Bitcoin tree is derived from `key(label "bitcoin")`).
5. Compute the leaf's WOTS+ public key hash, climb the 10-level
   authentication path, compare with `R_t`.
6. Form `state' = state` with `nextIdx' ≥ idx + 1` (witness-chosen, see
   5.5) and require `sha_outputs` to be consistent with output 0 having
   `spk' = P2MR(TapBranch(codeRoot, TapLeafHash(stateLeaf')))` and the
   remaining outputs free (destination, change, an anchor for fee bumping).
   The amount of output 0 is also in the covenant: at least the input amount
   minus the amounts the signer authorises to leave, which the digits of the
   WOTS+ signature already fix because they cover the whole sighash.

### 5.3 `execFirst` (first spend in a subtree)

Same as `exec` with, before step 5, the top layer: the WOTS+ signature of
top leaf `t'` on `R_{t'}` and its authentication path to `root`
(`CCHS.spec.md` §5, `executeFirst`). The successor state carries
`R_{t'}` and `t'`. The premium of the top layer is paid once per subtree per
lineage, as on every other chain.

### 5.4 `recover`

Verifies a WOTS+ signature of recovery leaf `epoch` under `recRoot` on the
new `root'` (deterministic from the mnemonic, `CCHS.spec.md` §8) and the
sighash, and forces the successor state
`(root', recRoot, epoch + 1, 0, ∅, ∅)`.

### 5.5 Rules that the UTXO model adds

- **Signer-chosen successor index.** The covenant requires `nextIdx' ≥ idx
  + 1`, not equality. Two UTXOs of the same lineage can then be spent in one
  transaction: their sighashes differ (input index, outpoint), so they use
  two leaves `idx_1 < idx_2`, and both covenants are satisfied by
  `nextIdx' = idx_2 + 1`. Burning leaves is the signer's choice, as on the
  EVM.
- **Several UTXOs at one state.** Anyone can pay twice to the same address,
  producing two UTXOs with identical state. Each lineage enforces
  monotonicity on its own; nothing on-chain stops the owner from using one
  leaf on both. This is the same situation as several devices or several
  pending operations in `CCHS.spec.md` §4.3, and the same client rule
  covers it: the write-ahead record of the highest signed index is per
  account, never per UTXO. The wallet treats all UTXOs that carry the same
  `(root, epoch)` as one account.
- **Fees.** Output 0 is pinned, so the fee is paid from the free outputs or
  by a child transaction spending an anchor output; the signer sets both
  when signing, because the sighash covers them.
- **Receiving.** Payments to a superseded address still arrive at a UTXO
  whose state is old; it is spendable with any leaf `≥` its `nextIdx`, which
  the client picks above its own record. Old addresses are never unsafe,
  only stale.

### 5.6 Size and cost (one measurement, the rest estimates)

| Item | Bytes | Source |
|---|---|---|
| Leaf script, 67-chain WOTS+ check + checksum | 5 752 | measured, `btcTapscript.ts` |
| WOTS+ signature + digits | 2 144 + 64 | arithmetic |
| Bottom authentication path | 320 | arithmetic |
| Sighash fields + reconstruction code | ≈ 250 + ≈ 400 | estimate from BIP-341 field list |
| Digit → byte reassembly code | ≈ 700 | estimate (BitVM-style gadgets, ~11 B per byte) |
| State leaf, code root, control block | 72 + 32 + 97 | arithmetic (depth 2 within codeRoot + 1) |
| Covenant: successor state and output hash | ≈ 300 | estimate |
| **`exec` witness, total** | **≈ 10 100** | → ≈ 2 530 vB |
| `execFirst`, additional top layer | ≈ + 7 000 | one more layer of script and signature |

At 5 sat/vB an `exec` spend costs about 12 700 sat and a block holds about
390 of them; this is the price of hash-only authorisation on Bitcoin and it
is why the design keeps `w = 16`. On Bitcoin the Winternitz parameter cuts
the other way from Solana: a chain check is an unrolled sequence of
`w − 1` hash steps, so script size grows linearly in `w` while the
signature shrinks only logarithmically: with the leaf layout of
`btcTapscript.ts` a chain costs about `82` B of script at `w = 16` and about
`682` B at `w = 256`, so the 5.8 KB leaf would become roughly 23 KB to save
1 KB of signature.

### 5.7 What is built and what is not

`wallet/src/aegis/btcTapscript.ts` implements, for the flat variant of
`CCHS.spec.md` §7.1(a): key derivation from `key(label "bitcoin")`, the leaf
script of step 4 without message binding, the BIP-341 tree, control blocks
and spend witnesses. `wallet/scripts/check-btc.mts` (CI, `npm run btc`)
executes that leaf in an interpreter for the BIP-342 opcodes it uses:
the wallet's witness is accepted with a clean stack, and foreign digits,
advanced chain values, another leaf's signature and non-minimal numbers are
rejected; it also pins the sizes above. Steps 1–3 and 6 are the
`binding` insertion point in that file and are not implemented, because no
network with value can execute them and a mock interpreter would prove only
that the mock agrees with itself. The hypertree form of this section (state
leaf, universal code root, covenant) is specified here so that it can be
reviewed before either opcode activates; it will be implemented against a
signet that enforces the required opcodes, and the first measurement will
replace the estimates above.

---

## 6. What the wallet does for Bitcoin today

- Receives to BIP-84 P2WPKH, never P2TR (L1), never reuses an address, sends
  change to a fresh address. Public keys appear only at spend time: long
  exposure is zero.
- Derives those keys from the same master as everything else, so the same
  mnemonic and the same backup rotate them.
- Labels the Bitcoin address as *not* post-quantum, because §3 is a
  statement about consensus, not about effort.
- Has the hash-only account precomputed: `key(label "bitcoin")`, the WOTS+
  tree and its root exist at the same time as the EVM roots, so migration
  is one transaction once §4's conjunction holds.

Operational reduction of short exposure (direct-to-miner submission, fee
choice) is outside the wallet: it requires trusting a miner not to be the
adversary, and the wallet does not make trust decisions on the user's
behalf.

---

## 7. References

BIP-141 (SegWit), BIP-143 (v0 sighash), BIP-341/342 (Taproot, Tapscript),
BIP-118 (`SIGHASH_ANYPREVOUT`), BIP-119 (`OP_CHECKTEMPLATEVERIFY`), BIP-347
(`OP_CAT`), BIP-348 (`OP_CHECKSIGFROMSTACK`), BIP-360 (P2MR). Heilman,
Sabouri, Narula, "Signing a Bitcoin transaction with Lamport signatures (no
changes needed)", bitcoin-dev, 2024. Linus, *BitVM* (2023) for the
Winternitz leaf pattern. Poelstra, "CAT and Schnorr tricks" (2021) for the
`P = G` binding. The CCHS verifier and client rules referenced throughout
are `CCHS.spec.md` §3–§8.
