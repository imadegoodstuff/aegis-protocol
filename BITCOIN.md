# Bitcoin and quantum resistance

What current Bitcoin consensus allows, what it does not, and the design that
Aegis holds ready for the day it changes. Everything here is either a statement
about Bitcoin Script that can be checked against BIP-141/143/341/342, a
measurement from `wallet/src/aegis/btcCchs.ts` on a Bitcoin Inquisition
node, or an estimate marked as such. Nothing in this file is live on a
network with value.

---

## 0. Summary

A Bitcoin UTXO is exposed to a discrete-log adversary in two ways. *Long
exposure*: the public key is visible in the output itself (P2PK, P2TR, reused
P2PKH/P2WPKH). *Short exposure*: the key becomes visible when the spend is
broadcast and stays attackable until the spend is buried.

Long exposure is solved today by key hygiene, and the wallet does that
(§6). Short exposure has no *practical* solution under current consensus:
§2 lists what a script can observe about its spending transaction, and §3
shows that every observable is either controlled by the spender, depends on
discrete-log hardness, or is a yes/no answer about the sighash that must be
*searched for* with proof of work rather than read. That bound is what the
no-fork constructions (Binohash, QSB; §3.1) work inside: they are hash-only
and transaction-binding, and they cost a 10 KB legacy output, GPU grinding
per spend and a miner who accepts non-standard transactions, for 2^118 of
second-preimage resistance against Shor and about 2^60–70 against Grover.
§3.1 gives the numbers and the one lever that reaches the security level of
the rest of this project (several such inputs in one transaction).

Once Bitcoin has (i) an output type without a key path and (ii) an opcode
that lets a script see its own sighash, a hash-only account is possible, and
§5 builds one: the CCHS state machine carried by the UTXO lineage itself.
Each UTXO commits to the account state after the previous spend; its three
spend paths verify a WOTS+ signature over the transaction's own sighash,
enforce the index rule against the cached subtree root, and bind the
message to the transaction with `OP_CHECKSIG` + `OP_CHECKSIGFROMSTACK` on a
key everybody knows. This runs today on Bitcoin Inquisition signet, where
`OP_CAT` and `OP_CHECKSIGFROMSTACK` are active, and §5.6 records the
transactions. What signet cannot give is (i): the output is P2TR, so the
successor is built by the signer rather than forced by a covenant, and the
key path remains (NUMS). BIP-360 (P2MR) supplies (i); BIP-347 (`OP_CAT`) or
BIP-348 (`OP_CHECKSIGFROMSTACK`) supplies (ii). Neither alone is sufficient
(§4).

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
| `OP_SIZE` applied to an ECDSA signature (SegWit v0 and legacy only) | the DER length of `(r, s)`, which depends on the sighash once the nonce is fixed | the spender chooses the nonce; fixing it can only be enforced through the same length check, and a CRQC can compute the nonce of the shortest possible `r` |
| `OP_CHECKSIG` with a *hard-coded* ECDSA signature and a witness-supplied public key | passes iff the key equals the key recovered from `(r, s)` and the sighash: the key is a pseudo-random function of the transaction that the spender cannot choose (two candidates, by the parity of `R`) | none beyond the parity bit; but the script can only hash the key, compare it for equality, or feed it to another `OP_CHECKSIG` |
| `OP_CHECKSIG` with a *hash output* in the signature position | passes iff the 20- or 32-byte hash parses as a DER signature (probability ≈ 2^−46 for a random string); the key is recoverable for any such string | the spender chooses what is hashed, so the check is a proof of work on the hashed value, not a reading of it |
| `OP_CHECKMULTISIG` in legacy scripts (`FindAndDelete`) | the sighash depends on which signatures the witness passed, because they are deleted from the script before hashing: one transaction yields `C(n, t)` different sighashes | the spender picks the subset; this is a way to *iterate* candidates inside the script, which is what makes the proof of work above affordable |
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

**L3 (the sensing bound).** Combine §2 with L1 and L2. Without relying on
discrete logs, a script learns about its transaction only through
`OP_CHECKSIG` returning true or false, and the only transaction-dependent
quantities that the spender cannot choose are (i) the key recovered from a
hard-coded signature and (ii) whether a hash of something transaction-bound
parses as a signature. Neither can be *read*: the recovered key is 33 bytes
that legacy script cannot split, and the parse test is a 2^−46 event. So the
digits that a hash-based signature would sign cannot be extracted from the
sighash; they can only be found by searching candidates until the parse test
succeeds, and the success itself (which candidate) is what gets signed.
Every hash-only, transaction-binding construction expressible today
therefore has the shape *proof-of-work sensing + one-time hash signature on
the search result*, and its binding strength is the number of search bits
the opcode and size limits allow. That is the family in the literature:
Heilman, Sabouri, Narula (bitcoin-dev, 2024: bits through DER length; broken
by a CRQC that computes the nonce of the shortest `r`); Linus, *Binohash*
(2026: `FindAndDelete` as the in-script iterator, length puzzle; same CRQC
weakness); Levy, *QSB* (2026: the hash-to-DER parse test as the puzzle, so
that only hash preimage resistance remains). §3.1 gives what QSB delivers
and what it costs. An earlier revision of this section said the only channel
was the DER length; the parse oracle is a second channel and it is the one
that survives a CRQC.

Consequence: *today*, protection against short exposure on Bitcoin is either
operational (adequate fee, direct-to-miner submission; the owner shortens
the window, not closes it) or bought with the construction of §3.1, which no
standard node relays. The wallet uses neither (§6) and says why.

### 3.1 What the no-fork frontier gives, with numbers

QSB (Levy, 2026, building on Binohash) as published: a *bare* legacy
scriptPubKey of about 9,500–9,650 bytes and 197 of the 201 permitted
non-push opcodes (P2SH's 520-byte redeem script cannot hold it; SegWit and
Tapscript lack `FindAndDelete` and the `SIGHASH_SINGLE` bug it relies on).
Spending: a pinning puzzle (2^46 RIPEMD-160 evaluations of transaction
variants) and two digest rounds, each a search over `C(150, 8..9)` subsets of
dummy signatures until the key recovered from the resulting sighash hashes to
a valid DER string; the winning subsets (≈ 84 bits) are signed by revealing
HORS preimages committed in the script. Published figures: second preimage
2^118 against an adversary with Shor but not Grover, about 2^59–69 with
Grover; collision 2^78–88; honest cost 2^47.7 candidates, estimated
$75–200 of GPU time per spend; the transaction is consensus-valid but
non-standard and must be handed to a miner directly (Slipstream-type
services; three pools have committed to mining BitVM's non-standard
transactions). The HORS key is one-time, which matches the UTXO model: one
output, one key, no state beyond the UTXO set. Funding such an output costs
about 9.6 KB of *non-witness* bytes, roughly 38 kWU, about 1 % of a block,
paid by whoever creates it.

What is and is not proven there. The binding rests on RIPEMD-160 (or
SHA-256) preimage resistance and on counting: an attacker who wants another
transaction accepted under the revealed HORS preimages must find one whose
pinned sighash and both digest rounds land on the same subsets, at 2^46 per
attempt. The assumptions are the standard ones; the *level* is what falls
short: 2^59–69 under Grover is below every NIST category, whereas the rest
of this project is argued at 2^96 (C-20) and 2^128.

**Composition closes the level gap, at linear cost.** Each input of a
transaction runs its own script over the same `SIGHASH_ALL` sighash (the
sighash commits to all inputs and outputs), and the pinning puzzle is a
property of the transaction, shared by all inputs. A spend from `k` QSB
outputs at once therefore requires an attacker's substitute transaction to
pass the pinning puzzle and *all* `2k` digest rounds with the same subsets:
second-preimage cost ≈ 2^(46 + 72k) classically and ≈ 2^(23 + 36k) under
Grover, against an honest cost that grows linearly (`k` times the grinding,
`k` outputs funded). Two inputs give ≈ 2^95 under Grover, the C-20 level of
`CCHS.spec.md` §5.5; three give ≈ 2^131, above AES-128's 2^128 quantum
yardstick. The owner chooses `k` per spend; nothing in the outputs
changes. This observation is not in the two papers as read on 2026-10-09; it
has not been implemented or measured here, and the cost that makes it
unattractive is the same one that makes a single QSB spend unattractive:
hundreds of dollars of GPU work and tens of kilobytes of non-witness block
space per transaction, plus a miner relationship. It is recorded because it
is the only route under current consensus that reaches this project's
security level, and so that the statement "nothing without a fork" is made
precisely: *nothing standard, cheap, or below 2^47 of work per spend*.

Aegis does not ship it. The wallet cannot run a 2^47 search, cannot relay a
non-standard transaction, and will not label a Bitcoin leg post-quantum on a
construction whose spend depends on a private mempool. The design that this
project does contribute, §5, needs the two consensus changes of §4 and then
costs about 2,500 vB per spend with no grinding.

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
spent, so the *successor* output can carry the updated state. The account is
therefore not an address but a lineage of UTXOs, each committing to the
state after the last spend:

```
state = (root, recRoot, pkSeed, epoch, t, R_t, nextIdx)
```

`root`, `recRoot`, `pkSeed`, `epoch`, `nextIdx` have the meaning of
`CCHS.spec.md` §2–§5 and §8. `R_t` is the cached root of bottom subtree
`t` (the EVM contract caches one root per subtree; the UTXO carries one, for
the subtree in use, which is all a monotone index ever needs). A fresh
account, and the first UTXO after a recovery, cache nothing (`t = ∅`).

This section is implemented in `wallet/src/aegis/btcCchs.ts` (hashing,
trees, the three leaf scripts, witnesses, state machine) and
`wallet/src/aegis/btcTx.ts` (transactions, BIP-341 sighash), executed by
`wallet/scripts/check-btc.mts` in a Tapscript interpreter and by
`wallet/scripts/btc-flow.mts` against Bitcoin Inquisition nodes (regtest in
CI, signet for the record in §5.6). Where the text below says "the script
checks", that is a statement about code that runs.

### 5.1 Two forms: what runs today and what the covenant needs

The three spend paths are the same in both forms; they differ in where the
state lives and in who enforces the successor.

| | P2TR form (runs on Inquisition signet today) | P2MR form (needs BIP-360) |
|---|---|---|
| Where the state is | hard-coded in the three leaves; the leaves are regenerated from a template for every state | one 32-byte state leaf beside a universal code tree, `spk = P2MR(TapBranch(codeRoot, H(stateLeaf)))` |
| How the input side is authenticated | the control block proves the executed leaf is in the tree the output committed to (BIP-341) | the same, plus the script re-derives the output's program from `codeRoot` and `stateLeaf` and compares it with `sha_scriptpubkeys` |
| Who enforces the successor | the signer: output 0 is built by the wallet and covered by the WOTS+ signature (the sighash commits to it) | the script: it forms `state'` and requires `sha_outputs` to put `P2MR(TapBranch(codeRoot, H(stateLeaf')))` at output 0 |
| Why | a P2TR output key is `P + H(P ‖ root)·G`; Script has no curve arithmetic, so no script can check what tree an output commits to | P2MR commits to the tree root directly, so `SHA256` and `OP_CAT` suffice |
| Key path | the NUMS point: unspendable classically, spendable by a discrete-log adversary (L1 of §3) | none |

The difference matters less than it looks. Only the holder of the WOTS+
secrets can produce a valid spend, so the covenant protects the lineage
against the signer's own software, not against an adversary; and the index
rule and the cached root *are* consensus-checked in both forms. What the
P2TR form cannot give is the two things §4 said it cannot: a key-less output
and a successor that no wallet bug can malform.

### 5.2 Hashing

Every hash call is `SHA-256` over an address prefix and the data, with the
tree's 16-byte public seed in every prefix (`CCHS.spec.md` §2.2). The
prefixes are laid out so a script can assemble them by concatenation from
numbers the spender puts on the stack:

```
tag(x)               = LE32(2^24 + x)                      the minimal Script number of 2^24 + x
SP(layer, tree)      = pkSeed(16) ‖ layer(1) ‖ tag(tree)
A(layer, tree, leaf) = SP ‖ tag(leaf)
chain   s_i          = SHA256(A ‖ chain(1) ‖ s_{i-1})                           i = 1..15
group   g_j          = SHA256(A ‖ 0xf0 ‖ j ‖ e_hi ‖ … ‖ e_lo)                   chains 60–66, 45–59, 30–44, 15–29, 0–14
leaf                 = SHA256(A ‖ 0xf1 ‖ g_4 ‖ g_3 ‖ g_2 ‖ g_1 ‖ g_0)
node(parent, level)  = SHA256(SP ‖ tag(parent) ‖ 0xf2 ‖ level ‖ left ‖ right)
```

`tag` turns a Script number into a fixed 4-byte field with one `OP_ADD`,
so the leaf index, the subtree index and every node position chosen by the
spender enter the hashes they belong to. The leaf is compressed in five
groups because `OP_CAT` caps a stack element at 520 bytes (15 × 32 + 26 =
506). The one departure from `CCHS.spec.md` §2.1 is that the chain address
has no step index: the script evaluates all sixteen positions of a chain
from the witness value and picks the one the digit selects, so it does not
know the step it is at, and carrying the digit into every step would cost
about 5 KB per leaf. Omitting it leaves at most 15 targets per chain
position, a factor below 2^4 in the multi-target term; separation by seed,
layer, tree, leaf and chain is intact. Bottom subtrees have 2^10 leaves and
the recovery tree 2^8 as in the spec; the top-tree height `HT` is a build
parameter (16 subtrees in the signet build, 1 024 in the spec), not a
protocol constant: it changes `root` and the length of one path.

### 5.3 The three leaves

Each leaf is a straight-line Tapscript (no loops exist) over the witness it
names. `B_j` are the 32 bytes of the message, `b_k` the bits of a leaf
index, `sib_k` a Merkle sibling, `(sig_c, d_c)` a WOTS+ chain value and
its digit. `sig_B m P` is the binding triple of §5.4.

**exec** (cached path; witness `sig_B m P  B_0…B_31  sib_9…sib_0
(sig_66 d_66)…(sig_0 d_0)  b_0…b_9`):

1. Rebuild `idx` from its ten bits, saving the bits and the ten ancestor
   positions `p_k` for step 5; require `idx ≥ nextIdx`.
2. `A = SP(0, t) ‖ tag(idx)`.
3. For each of the 67 chains: `0 ≤ d < 16`; compute `s_0 = sig, …, s_15`;
   keep `s_{15−d}` (the chain end if and only if `sig = F^d(sk)`).
4. Hash the 67 ends in groups into the leaf.
5. Climb ten levels: the saved bit orders `(node, sib_k)`, the saved
   `p_{k+1}` and the level enter the prefix; require the result to equal
   `R_t`.
6. Checksum: `256·d_64 + 16·d_65 + d_66 + Σ d_0..63 = 960`.
7. Bytes: for each `j`, `16·d_{2j} + d_{2j+1} + 256` as a Script number is
   the two-byte string `B_j ‖ 0x01`; require equality; `M = B_0 ‖ … ‖
   B_31`.
8. Binding (§5.4): `M = m`, `CHECKSIGVERIFY(sig_B, P)`,
   `CHECKSIGFROMSTACK(sig_B, m, P)`.

**execFirst** (first spend in a new subtree; witness adds, below the above,
the top layer: `RB_0…RB_31`, the top path, 67 top chain pairs, and on top
the bits `c` of `t'`): rebuild `t'`, require `t' > t`; run steps 2–7 of
`exec` for subtree `t'` with `SP(0, t')` built from `tag(t')` on the
stack, but keep the computed root `R` instead of comparing it; run steps
2–7 again for the top layer at `A(1, 0, t')` with message bytes `RB`,
climb `HT` levels to `root`; require `RB_0 ‖ … ‖ RB_31 = R`; bind.

**recover** (witness like `exec` without bits; the recovery leaf is
`epoch`, so its address and path directions are constants of the leaf): run
steps 3–8 at `A(0xff, 0, epoch)` with an 8-level climb to `recRoot`. The
new public key `(root', recRoot', pkSeed')` of epoch + 1 is in the
successor output, hence under the signature; the message is the sighash
itself.

Successor states: `exec` → `nextIdx = idx + 1`; `execFirst` → `(t', R_{t'},
idx + 1)`; `recover` → `(root', recRoot', pkSeed', epoch + 1, ∅, –, 0)`. The
script tree of a state is `TapBranch(TapBranch(exec, execFirst), recover)`,
or `TapBranch(execFirst, recover)` when nothing is cached; the address
changes after every spend.

### 5.4 Binding the sighash without a secret

Let `P = 1·G`. The spender signs the transaction's BIP-341 sighash `m`
with the private key 1 and supplies `(sig_B, m, P)`. The script requires
`OP_CHECKSIGVERIFY` on `(sig_B, P)` and `OP_CHECKSIGFROMSTACK` on
`(sig_B, m, P)`. A BIP-340 signature `(R, s)` satisfies `s·G = R +
e(R, P, msg)·P`; if it verifies for two messages then `e(R, P, m) = e(R, P,
sighash)`, so `m = sighash` unless the challenge hash collided. The WOTS+
digits are then checked against the bytes of `m` (step 7), which is what
makes the hash signature a signature *of the transaction*. The key 1 is
public; the construction has no secret and a discrete-log adversary gains
nothing from it. Under `OP_CAT` alone the same binding is obtained by the
Schnorr trick (`R = P = G`, `s = 1 + e`, which requires grinding the
transaction so the addition has no carry); the implementation uses
`OP_CHECKSIGFROMSTACK` because the Inquisition network enforces it and it
removes the grinding.

### 5.5 Rules that the UTXO model adds

- **Signer-chosen successor index.** The wallet sets `nextIdx' = idx + 1`;
  the leaf only requires `idx ≥ nextIdx`. Two UTXOs of the same lineage can
  therefore be spent in one transaction with leaves `idx_1 < idx_2` (their
  sighashes differ by input index and outpoint), both successors carrying
  `idx_2 + 1`. Burning leaves is the signer's choice, as on the EVM.
- **Several UTXOs at one state.** Anyone can pay twice to one address,
  producing two UTXOs with identical state. Each lineage enforces
  monotonicity on its own; nothing on-chain stops the owner from using one
  leaf on both. This is the several-devices situation of `CCHS.spec.md`
  §4.3 and the same client rule covers it: the write-ahead record of the
  highest signed index is per account, never per UTXO.
- **Fees.** The successor's amount is the input minus the payment outputs
  and the fee, all fixed before signing; a leaf is never signed twice, so
  the fee is computed from an upper bound of the witness (every digit and
  bit one byte) and the transaction pays slightly above the target rate.
- **Receiving.** Payments to a superseded address arrive at a UTXO whose
  state is old; it is spendable with any leaf `≥` its `nextIdx`, which the
  client picks above its own record. Old addresses are never unsafe, only
  stale.
- **Successor on P2TR.** Until a key-less output exists, the successor is
  the wallet's responsibility (§5.1). A malformed successor is a loss of
  the lineage's *convenience* (the funds remain spendable by whatever the
  malformed output allows), not a theft vector: no spend exists without
  the WOTS+ secrets.

### 5.6 Measurements

Spends of one lineage on Bitcoin Inquisition signet (block-signed test
network; `OP_CAT` active since 2024-04, `OP_CHECKSIGFROMSTACK` since
2025-10), built at `HT = 4`, fee rate 1.1 sat/vB, one 2 000 sat payment
output to the faucet's return address in every spend:

| step | signet txid | vB | WU | fee (sat) | leaf script (B) | witness (B) | successor state |
|---|---|---|---|---|---|---|---|
| `execFirst` | [`6f7145ee7d530266…`](https://mempool.space/signet/tx/6f7145ee7d5302669b0279355a50cc702b5861a26895fe63b176551d6701e21a) | 6 336 | 25 341 | 6 976 | 19 350 | 24 837 | epoch 0, t 0, nextIdx 1 |
| `exec` | [`f87840b8695efd22…`](https://mempool.space/signet/tx/f87840b8695efd22d89faf246cddd363b71f8fe289996e7bb192c2de4efd0237) | 3 300 | 13 198 | 3 634 | 9 718 | 12 696 | epoch 0, t 0, nextIdx 2 |
| `exec` | [`06d82ae3468d7801…`](https://mempool.space/signet/tx/06d82ae3468d7801649e833b9fe31e8ed5f8d8d903946f273aabb3bb1a4e3f23) | 3 300 | 13 200 | 3 634 | 9 718 | 12 698 | epoch 0, t 0, nextIdx 3 |
| `recover` | [`7400ea6e21b47bf2…`](https://mempool.space/signet/tx/7400ea6e21b47bf271866d527b6a93f97463cabbd50a51fa49c0b48ebc412ab6) | 3 207 | 12 828 | 3 529 | 9 454 | 12 326 | epoch 1, t ∅, nextIdx 0 |
| `execFirst` | [`765cb6b4c7f78bb3…`](https://mempool.space/signet/tx/765cb6b4c7f78bb35f8716c1137271c322e7406c46d6fbb89c235f7e3a57d0a5) | 6 334 | 25 336 | 6 976 | 19 350 | 24 832 | epoch 1, t 0, nextIdx 1 |
| `exec` | [`4963ebf78a6b540a…`](https://mempool.space/signet/tx/4963ebf78a6b540a457722e9aa30f5df4a327a4c4d63cf31a9e88522b8ac8586) | 3 269 | 13 074 | 14 070 | 9 718 | 12 696 | epoch 1, t 0, nextIdx 2 |

Funding output: [`tb1p0e85juwrcgztj52ytssg652tw8xx4yvmfhr8nnmdu539a2l5wmkq8wezc3`](https://mempool.space/signet/address/tb1p0e85juwrcgztj52ytssg652tw8xx4yvmfhr8nnmdu539a2l5wmkq8wezc3). The
first five transactions have one input (the account UTXO) and two outputs
(successor, payment); the successor of each row is the input of the next.
All six confirmed in block 325 621. The signet block producer was skipping
1.1 sat/vB at the time, so the sixth spend (no payment output, 4.3 sat/vB)
was added as a child to lift the package to 1.5 sat/vB; it is an ordinary
`exec` spend of the lineage, resumed from the master key alone
(`BTC_RESUME`), and shows that a lineage can be continued by any holder of
the key without state other than the current UTXO.

Leaf scripts are a function of the state only; the witness varies by a few
bytes with the digits (a digit of 0 is an empty push). For comparison the
flat variant of `CCHS.spec.md` §7.1(a) (`btcTapscript.ts`, one hard-coded
WOTS+ key per leaf, no binding) is 5 752 B of script; the account's `exec`
leaf pays about 4 KB more for the index rule, the cached root, the path,
the byte reassembly and the binding, and in return the same script template
serves every spend of every account.

At 5 sat/vB an `exec` spend costs about 16 500 sat and a block holds about
300 of them; this is the price of hash-only authorisation on Bitcoin and it
is why the design keeps `w = 16`. On Bitcoin the Winternitz parameter cuts
the other way from Solana: a chain check is an unrolled sequence of `w − 1`
hash steps, so script size grows linearly in `w` while the signature
shrinks only logarithmically.

The same lineage runs in CI against an Inquisition regtest node with
standardness enforced (`.github/workflows/build.yml`, job *Bitcoin*), and
the leaves are executed independently in a Tapscript interpreter
(`npm run btc`) that also pins the script sizes.

### 5.7 What is built and what is not

Built and executed on a network: everything in §5.2–§5.4 in the P2TR form,
with real transactions (§5.6). Not built: the P2MR form, because no network
has P2MR; its differences from the running code are the universal
`codeRoot`, the state leaf and the `sha_outputs` covenant of §5.1, each a
concatenation-and-compare over data already in the sighash. Not safe on
mainnet: any output of the P2TR form, for the two reasons of §4: the opcodes
are not active and the key path exists. The signet build uses a top tree of
16 subtrees (16 384 one-time keys per epoch); the spec's 1 024 subtrees are
a keygen-time choice.

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
  trees and their roots exist at the same time as the EVM roots, so
  migration is one transaction once §4's conjunction holds; the account
  itself is the §5 lineage, running on signet.

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
Winternitz leaf pattern. Linus, *Binohash: Transaction Introspection Without
Softforks* (2026). Levy, *Quantum-Safe Bitcoin Transactions Without
Softforks* (QSB, 2026). Poelstra, "CAT and Schnorr tricks" (2021) for the
`P = G` binding. The CCHS verifier and client rules referenced throughout
are `CCHS.spec.md` §3–§8.
