# CCHS invariants, machine-checked

Lean 4 proofs of the transition-system properties that `CCHS.spec.md` §6 claims
and that `model/cchs-state.mjs` / `model/cchs-client.mjs` check by bounded
exploration. The proofs hold for every parameter choice and every reachable
state; the model checks hold for small bounds but additionally run an explicit
adversary and seeded bugs. Both are kept.

```
cd proofs
lake build                 # ~5 s, core Lean only (no Mathlib)
lake env lean Check.lean   # axioms used by each theorem
```

Toolchain pinned in `lean-toolchain` (installed by `elan`). CI runs both
commands and fails on `sorry` or on any axiom beyond `propext`,
`Classical.choice`, `Quot.sound`.

## What is proven

`Cchs/Verifier.lean` — the account verifier (`execute`, `executeFirst`,
`recover`) as a transition system with lanes:

| Name | Statement | Spec |
|---|---|---|
| `cache_genuine` | every cache entry of epoch `e` at tree `t` is the owner's bottom root for `(e, t)` | C4 |
| `cache_once` | a cache entry never changes once written | §5 |
| `accept_inputs` | an accepted signature was made in the current epoch over exactly the accepted `(idx, lane nonce, target)` | NF, C3 |
| `register_not_leaked` | only an owner's top layer registers a subtree | NF |
| `leaked_rejected` | if every leaf of a subtree is behind its lane's counter, the index check alone rejects every submission there | §4.3 |
| `nextIdx_mono`, `accept_sets_nextIdx` | lane counters never decrease; an acceptance at `idx` sets its lane's counter to `idx + 1` | C5 |
| `no_double_accept` | no `(epoch, idx)` is accepted twice along any execution | C5 |
| `lane_independence` | a state update in lane `l` leaves the verdict on every submission for another lane unchanged; needs only that lanes are unions of whole subtrees | LI |

`Cchs/Client.lean` — the signer's one-time-key discipline:

| Name | Statement | Spec |
|---|---|---|
| `one_message` | along any trace, two signatures over the same `(epoch, idx)` are the same signature — for any number of devices with pairwise distinct lanes, write-ahead records, backup restores (device stale until recovery) and recoveries | §4.3 ONE-MESSAGE |

## What is abstracted or not covered

- **The hash.** A signature object remembers its inputs; recomputing over any
  other inputs yields `Root.garbage`, which matches nothing. That is the
  second-preimage assumption on the chaining and tree hashes, stated as a
  definition, not proven. Nothing here is about SHA-256 or keccak.
- **WOTS+ two-message exposure.** Enters as the hypothesis of
  `leaked_rejected` (keys exposed only for fully abandoned subtrees), not as a
  theorem about WOTS+.
- **Recovery leaf messages** (deterministic by key derivation) and **several
  chains** (one tree per chain by derivation) are derivation facts, not
  transition facts, and are outside these files.
- **A client that records after signing** is excluded by construction (the
  record and the signature are one step); the bounded model catches that
  mutant with a crash in between.
- The signer model picks *any* index at or above its record in its lane; the
  reference client's `max(nextIdx, record)` is a special case.
