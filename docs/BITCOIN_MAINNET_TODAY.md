# Post-quantum spending on Bitcoin mainnet today: what Script can and cannot bind

Status: analysis, with two small numerical checks. Nothing here is deployed.
The CCHS-UTXO leaves in `bitcoin/` need `OP_CAT` and `OP_CHECKSIGFROMSTACK`
and run on the Inquisition signet only. This note is the result of asking,
carefully, whether the same guarantee can be had on mainnet with the opcodes
that exist now. The short answer is no, and the reasons are sharper than
"there is no covenant opcode". We write them down so that nobody, including
us, ships a construction that only looks post-quantum.

Terminology. A spend is *bound* when a valid witness for transaction T cannot
be replayed on a different transaction T′ that pays somebody else. Hash-based
signatures (Lamport, WOTS+, CCHS) bind a *message*; Bitcoin Script must
therefore be able to present something that depends on T — on its outputs — to
the hash checks. Everything below is about whether that is possible.

## 1. Tapscript: the only transaction-dependent observable is signature validity

In Tapscript (BIP 342) the opcodes that read anything about the spending
transaction are:

- `OP_CHECKSIG`, `OP_CHECKSIGVERIFY`, `OP_CHECKSIGADD`: a boolean (or a count)
  that is true iff the 64/65-byte Schnorr signature is valid for the sighash
  *m* of T under the given key.
- `OP_CHECKLOCKTIMEVERIFY`, `OP_CHECKSEQUENCEVERIFY`: lower bounds on
  `nLockTime` / `nSequence`. These fields are chosen by whoever builds T; a
  forger copies them. They say nothing about outputs.

Schnorr signatures have fixed length, so `OP_SIZE` reveals nothing. There is
no byte-slicing (`OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT` are gone),
numeric opcodes accept at most 4-byte values, and there is no way to parse a
32-byte item into chunks. Hence:

> **Lemma 1 (observability).** In Tapscript, the only output-dependent value
> a script can compute is the truth of `OP_CHECKSIG` for a signature it is
> handed.

Two cases. If the signing key is **unknown** to attackers, the script is a
normal Schnorr check: it is bound, and it is exactly as Shor-exposed as any
Bitcoin spend (the public key appears when the leaf is spent). If the key is
**public** (a known private key, so a hash-based layer could sit on top),
anyone can produce a valid signature for any T′, so validity carries no
binding at all. What *is* transaction-dependent is the signature's bytes: with
public key x and a fixed nonce k the signature is a deterministic function
σ(m) = (R, k + H(R‖P‖m)·x). A script can hash it — `OP_SHA256` on the
64-byte item works without `OP_CAT` — and so compute a 32-byte digest
D = SHA-256(σ(m)) that depends on T. But by Lemma 1 it can then only compare D
for **equality** against a constant. That is a precommitted transaction, not a
signature.

## 2. Precommitment through a known key is circular

Suppose we accept precommitment: a vault leaf

```
<σ> OP_DUP <P> OP_CHECKSIGVERIFY OP_SHA256 <H> OP_EQUALVERIFY  <y> OP_SHA256 <Y> OP_EQUAL
```

spends only via the one transaction T with SHA-256(σ(m_T)) = H, and the
one-time preimage y authorises it. Front-running is harmless because T's
outputs are fixed. This looks like a hash-only vault with a menu of
destinations (sweep to cold, roll to the next state). It cannot be created:

> **Lemma 2 (circularity).** Every sighash mode, including
> `SIGHASH_ANYONECANPAY`, commits to the outpoint (txid, index) of the input
> being signed. The txid commits to the output's `scriptPubKey`, which
> commits to H = SHA-256(σ(m_T)), which commits to the txid. The vault's
> address is a fixed point of a hash; nobody can compute it.

Moving the equality check to a second "template" input does not help:
`ANYONECANPAY` still commits to *that* input's own outpoint. Pre-signed vaults
avoid the loop only because a secret key stands between the script and the
signature, and that key is Shor-exposed the moment its leaf is revealed.
Removing the loop is precisely what `OP_CTV` (BIP 119, the template hash
excludes the input txid) or `SIGHASH_ANYPREVOUT` (BIP 118) would do.

A related trap: a leaf containing `OP_CAT` or `OP_CHECKSIGFROMSTACK` cannot be
pre-installed "for when the soft fork activates". In Tapscript today those
bytes are `OP_SUCCESSx`; the whole leaf is anyone-can-spend the moment it is
revealed. Upgrade paths must move coins.

## 3. Segwit v0: the `OP_SIZE` channel carries log₂(4N) bits

Legacy and segwit-v0 scripts verify ECDSA, whose DER encoding has variable
length, and Heilman (bitcoin-dev, April 2024) observed that `OP_SIZE` of a
*fixed-nonce* ECDSA signature leaks whether the s-value lost a leading byte,
and that a Lamport signature over those lengths binds the spend. The nonce is
pinned by using k = 1/2 mod n, whose r has 88 leading zero bits (21 bytes), so
`OP_SIZE(sig) ≤ 59` forces that r; finding another short r costs 2⁹⁶ work.
We confirm r(1/2) = `0x…3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63` (21
bytes) with `@noble/curves`.

What does the channel carry? With k = 1/2 the s-value is
s = 2·(z + r·x) mod n, where z is the sighash. Low-S is enforced by the size
check (a high-S signature is 60 bytes), so the only event visible to Script is
*s < 2²⁴⁸*, i.e. the s-value is 31 bytes instead of 32. As a predicate on
u = z + r·x mod n, this is u ∈ [0, 2²⁴⁷) ∪ [(n+1)/2, (n+1)/2 + 2²⁴⁷) — two
intervals (checked numerically at the six boundary points). Each of N
signatures therefore adds at most four boundary points on the circle ℤ_n, so
the N indicators are constant on at most 4N arcs:

> **Lemma 3 (information bound).** With the only pinnable nonce, N fixed-nonce
> ECDSA signatures expose at most log₂(4N) bits of the sighash to Script.
> For N = 46 that is under 8 bits.

Security in Heilman's scheme does not come from information; it comes from
*rarity*: the signer grinds her transaction until M of the N signatures are
short (probability 256⁻ᴹ each), and a forger must reproduce that pattern.
The signer's advantage is C(N, M), the number of ways the M short positions
can fall. Three things erode it:

1. **Per-signature `SIGHASH` freedom.** Each of the N signatures carries its
   own sighash byte, which Script cannot read. A forger may try all six types
   per position, raising the per-position match probability from 1/256 to
   about 6/256. Ten short positions give ≈ 2⁵⁴ rather than 2⁸⁰; restoring
   2⁸⁰ needs M ≈ 15, and then C(N, M) no longer makes the signer's grinding
   feasible within the next constraint.
2. **Script limits.** Segwit v0 keeps the 201 non-push-opcode limit, 3 600
   standard script bytes and 100 standard witness items. N `CHECKSIGVERIFY`
   plus a Lamport check per short position is already near 201 for N ≈ 46;
   WOTS over the position vector does not fit at all (each chain step is an
   unrolled `OP_IF`).
3. **Grover.** The forger's problem is a search over transaction variants, so
   a quantum forger needs about the square root of the classical trials. A
   pattern worth 2⁸⁰ classical trials is 2⁴⁰ Grover iterations.

Point 3 is also where the honest nuance lives. The Lamport preimages are
revealed only in the spending transaction, so the forger's window is the
mempool interval — minutes, not years. 2⁴⁰ Grover iterations of
"hash the transaction, run ECDSA" in ten minutes requires a sub-nanosecond
error-corrected iteration; no projected machine does that. In that narrow
sense `OP_SIZE`-Lamport at 80 classical bits would be *time-bounded safe*. It
is still not something we would ship: it is P2WSH only, it needs the signer to
grind on the order of 2³²–2⁴⁶ ECDSA operations per spend, the per-signature
sighash freedom has to be re-analysed for every parameter set, and the whole
argument is "the attacker is slow", which is the argument post-quantum
cryptography exists to retire.

## 4. What this means, stated plainly

- Arbitrary-destination spending that depends on **no** elliptic-curve secret
  is not expressible on Bitcoin mainnet today. Not in Tapscript (Lemma 1 + 2),
  and only in a time-bounded, grinding-based sense in segwit v0 (Lemma 3).
- The minimal change that makes it expressible is **`OP_CAT`** (BIP 347):
  Poelstra's trick (the Schnorr signature with fixed nonce and `OP_CAT`
  reconstruction) puts the sighash on the stack *in pieces*, which is exactly
  what a WOTS+ verifier needs. `OP_CHECKSIGFROMSTACK` alone is not enough: it
  can prove that a 32-byte item equals the sighash, but without slicing, the
  item still cannot be fed to per-chunk hash chains. This is why CCHS-UTXO
  uses both and why it lives on the Inquisition signet.
- Until then, the two threats separate cleanly. **Shor at rest** (an exposed
  public key sitting in a UTXO for years) is avoidable now: never hold coins
  under a Taproot key path or a reused address; P2WPKH, or P2TR with an
  unspendable internal key and a hidden single-use leaf key, reveals the key
  only when spending. **Shor in the mempool** (deriving the key between
  broadcast and confirmation) is not avoidable by any mainnet script; it can
  only be shortened — a transaction handed directly to a miner never sits in
  the public mempool at all. Anyone claiming "quantum-safe Bitcoin wallet" on
  mainnet today is offering at most the first of these.

## 5. What Aegis does with this

The Bitcoin line of this repository is unchanged: CCHS-UTXO on signet, with
the measured sizes in `README.md`, waiting for `OP_CAT`. On mainnet the
wallet can offer — and labels as — *exposure reduction*, not post-quantum
security: single-use hidden-key addresses derived from the same mnemonic, a
migration path for coins whose public key is already on chain, and direct
miner submission for the spend. The same seed derives the CCHS-UTXO account,
so the move to a hash-only output is one transaction on the day the opcodes
arrive.

## Checks

```sh
cd wallet && node -e "
const { secp256k1 } = require('@noble/curves/secp256k1');
const n = secp256k1.CURVE.n, inv2 = (n + 1n) / 2n;
const R = secp256k1.ProjectivePoint.BASE.multiply(inv2).toAffine();
console.log(R.x.toString(16).padStart(64, '0'));                 // 21-byte r
const T = 1n << 248n, short = (u) => ((2n * u) % n) < T;
console.log([0n, (1n << 247n) - 1n, 1n << 247n, (n + 1n) / 2n,
  (n + 1n) / 2n + (1n << 247n) - 1n, (n + 1n) / 2n + (1n << 247n)].map(short));
// true true false true true false: two intervals of width 2^247
"
```

## References

- E. Heilman, "Signing a Bitcoin Transaction with Lamport Signatures (no
  changes needed)", bitcoin-dev, April 2024, and the follow-up thread
  (position-vector variant, SIGHASH and length mix-and-match concerns).
- A. Poelstra, "CAT and Schnorr Tricks I/II", 2021.
- BIP 118 (`SIGHASH_ANYPREVOUT`), BIP 119 (`OP_CHECKTEMPLATEVERIFY`),
  BIP 342 (Tapscript), BIP 347 (`OP_CAT`).
