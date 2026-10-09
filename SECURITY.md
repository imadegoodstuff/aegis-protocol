# Security

Aegis has **not** been audited. Nothing in this repository is deployed on a mainnet. This file states what the code claims, what it does not, what has been checked and how, and what an external review would have to cover. It is written for a reviewer, and it is the document we would hand to an auditor.

## 1. Claims

1. **Unforgeability.** Without the master secret, producing a signature that an Aegis account accepts for a message of the attacker's choosing requires a (second) preimage or collision on the underlying hash at the cost given in `CCHS.spec.md` §5.5 (S-20 / K-20: AES-192 yardstick or better under either accounting; C-20: see the two-level label there).
2. **One-time-key discipline.** No WOTS+ leaf of any epoch ever signs two different messages, under crashes, dropped or reordered transactions, backup restores, several devices and several chains, provided the client follows `CCHS.spec.md` §3 (one key tree per chain) and §4.3, and the verifier §5.
3. **Replay resistance.** A valid signature is bound to `(chainId, account, epoch, idx, target, value, data)`; it is accepted at most once by one account on one chain.
4. **Cache soundness.** A cached bottom-subtree root is only ever accepted for the `(epoch, treeIdx)` it was proven for, and the proof bound it to the root current at that time.
5. **Recovery.** The holder of the master can move the account to a new root (same master, next epoch; or a fresh master) using a one-time key that is never used for spending, and the previous root is dead afterwards.

Not claimed: anonymity, resistance to a compromised client device while it holds the master, anything about the chains' own cryptography (account addresses derived with ECDSA/Ed25519 are not post-quantum, and the wallet labels them as such), or availability under censorship.

## 2. Threat model

- The attacker sees every transaction, every signature and every cached root; controls ordering and dropping of transactions within the chain's rules; may run arbitrary contracts; has quantum computation at the cost model of Grover's algorithm.
- The attacker does not hold the master secret or any per-epoch key derived from it.
- The chain's consensus, its `sha256` / `keccak256` primitives and its storage semantics are correct.
- The client's persistent storage is reliable *or* the client follows §4.3 rule 5 (missing or possibly stale record ⇒ rotate before signing). Plain data loss is in scope; a storage that lies (returns a stale record claiming to be current) is out of scope except through the backup-restore event the model covers.

## 3. What is checked, and how

| Property | Check | Where | In CI |
|---|---|---|---|
| Verifier logic (claims 2–4 on the chain side) | bounded model check, 4 seeded bugs caught | `model/cchs-state.mjs` | yes |
| Client rules (claim 2 on the device side) | bounded model check, 6 seeded rule violations caught (incl. one tree shared between two chains) | `model/cchs-client.mjs` | yes |
| Wallet implements the client rules | unit tests over a storage shim | `wallet/scripts/check-index-discipline.mts` | yes |
| Contract behaviour per set | Foundry, 20 tests × 3 sets incl. index reuse, backward index after skip, stale root, wrong chain | `evm/test/AegisCCHS.t.sol` | yes |
| Full life cycle with costs | create → first → cached → skip → rotation → old root rejected → withdraw, in an EVM | `wallet/scripts/evm-flow.mts` | yes |
| Cross-implementation agreement | shared fixtures replayed by Solidity, Rust, Cairo, FunC, Move, TypeScript | `evm/test/fixtures/`, each chain directory | yes |
| Key derivation is pinned | mnemonic → master → roots → addresses vector | `evm/test/fixtures/cchs-derivation.json`, `wallet/scripts/check-vectors.mts` | yes |
| Hash security numbers | hand analysis, two accountings | `CCHS.spec.md` §5.5 | n/a |

Bounded model checks explore every state up to the stated bounds; they are not proofs. The hash-level analysis is a derivation from published bounds, not a machine-checked reduction.

## 4. Known gaps

- No independent audit of any component.
- No machine-checked proof; no written reduction with explicit constants for `(n = 24, w = 256, 2^20 leaves)` (C-20).
- No mainnet deployment; gas and compute figures come from local EVMs and estimates, and Solana compute units have not been measured on a cluster.
- The wallet is a reference implementation: single signer by default, browser `localStorage` for the index record, no hardware-key support.
- Side channels in the client's hash chains (timing of WOTS+ chain lengths) are not addressed; the signer runs in a browser or a user's own process.

## 5. Audit scope we propose

1. `evm/src/AegisCCHSBase.sol` and the three set contracts: verification, index and cache state machine, recovery, factory and CREATE2 determinism, asset handling in `execute`.
2. `CCHS.spec.md` §3–§5, §8: whether the specification's security argument is correct and whether the contracts implement it.
3. `model/*.mjs`: whether the models faithfully abstract the contracts and the client, and whether the bounds are meaningful.
4. `wallet/src/aegis/`: key derivation, per-epoch keys, signing, the index record, and `ProtectPanel`'s use of them.
5. `cchs-core` and the non-EVM verifiers against the fixtures and against the Solidity reference.
6. The C-20 parameter choice.

## 6. Reporting

Report vulnerabilities privately to the repository owner through the hosting platform's private vulnerability reporting, or open an issue marked `security` for anything that is already public. There is no bug bounty; there are no funds at risk because nothing is deployed.
