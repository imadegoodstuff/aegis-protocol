# Security

Aegis has **not** been audited. Nothing in this repository is deployed on a mainnet. This file states what the code claims, what it does not, what has been checked and how, and what an external review would have to cover. It is written for a reviewer, and it is the document we would hand to an auditor.

## 1. Claims

1. **Unforgeability.** Without the master secret, producing a signature that an Aegis account accepts for a message of the attacker's choosing requires a (second) preimage or collision on the underlying hash at the cost given in `CCHS.spec.md` §5.5 (S-20 / K-20: 2^113 quantum unconditionally, 2^128 under the FIPS 205 multi-target argument — the first is the claim, the second is conditional on that argument until the reduction of §11 item 8 is written for CCHS; C-20: see the two-level label there). §5.6 defines the forgery game and shows that every winning transcript contains one of five events and costs each: the 16-byte public seed is not a path (an adversary gains nothing by copying it), the 32-byte master *is* one — a Grover search over the seed checked against a single public chain value, ≈ 2^133 hash-equivalents from a 256-bit seed and ≈ 2^76 from a 12-word mnemonic in the document's cost model (Grover queries × classical work per candidate; not a quantum resource estimate) — and it is the path no hash-width change moves. The claim therefore assumes a 256-bit seed, which the wallet enforces where it creates accounts. The cost does not decrease with the number of accounts attacked at once: every hash call of a key tree carries the tree's 16-byte public seed (`pkSeed`, `CCHS.spec.md` §2.1), so no two trees share a hash function at any position.
2. **One-time-key discipline.** No WOTS+ leaf of any epoch ever signs two different messages, under crashes, dropped or reordered transactions, backup restores, several devices and several chains, provided the client follows `CCHS.spec.md` §3 (one key tree per chain) and §4.3, and the verifier §5.
3. **Replay resistance.** A valid signature is bound to `(chainId, account, epoch, idx, target, value, data)` and, through the seed in every hash, to its own key tree; it is accepted at most once by one account on one chain.
4. **Cache soundness.** A cached bottom-subtree root is only ever accepted for the `(epoch, treeIdx)` it was proven for, and the proof bound it to the root current at that time.
5. **Recovery.** The holder of the master can move the account to a new public key (`root`, `recRoot`, `pkSeed`; same master, next epoch; or a fresh master) using a one-time key that is never used for spending, and the previous root is dead afterwards.
6. **Lane independence (EVM contracts).** The index space is split into 16 lanes with independent on-chain `nextIdx` and `nonce`; an accepted operation in one lane changes the verifier's verdict on no signature made for another lane (`CCHS.spec.md` §6, LI). Devices that own distinct lanes therefore sign concurrently without coordination. Which device owns which lane is a client assignment and is not checked on chain.

Not claimed: anonymity, resistance to a compromised client device while it holds the master, anything about the chains' own cryptography (account addresses derived with ECDSA/Ed25519 are not post-quantum, and the wallet labels them as such), or availability under censorship.

## 2. Threat model

- The attacker sees every transaction, every signature and every cached root; controls ordering and dropping of transactions within the chain's rules; may run arbitrary contracts; has quantum computation at the cost model of Grover's algorithm.
- The attacker does not hold the master secret or any per-epoch key derived from it, and the master comes from at least 256 bits of seed entropy (a 24-word BIP-39 mnemonic or 32 random bytes; `CCHS.spec.md` §3). The reference wallet refuses to create or fund a CCHS account from a shorter mnemonic (`CCHS_MIN_SEED_BITS`; Spend stays open so that nothing is stranded). The verifier cannot check this: the label applies to accounts created under the specification, not to every root a contract will accept.
- The chain's consensus, its `sha256` / `keccak256` primitives and its storage semantics are correct.
- The client's persistent storage is reliable *or* the client follows §4.3 rule 5 (missing or possibly stale record ⇒ rotate before signing). Plain data loss is in scope; a storage that lies (returns a stale record claiming to be current) is out of scope except through the backup-restore event the model covers.

## 3. What is checked, and how

| Property | Check | Where | In CI |
|---|---|---|---|
| Verifier transition logic (claims 2–4, 6), all parameters and reachable states, hash abstracted | Lean 4 proofs: cache genuine and write-once, acceptance only over the signed inputs in the current epoch, no `(epoch, idx)` accepted twice, lane independence; no `sorry`, standard axioms only | `proofs/Cchs/Verifier.lean` | yes |
| Client ONE-MESSAGE with lanes (claim 2 on the device side), any number of devices, backup restores, recoveries | Lean 4 proof | `proofs/Cchs/Client.lean` | yes |
| Verifier logic (claims 2–4 and lane independence on the chain side) | bounded model check, 6 seeded bugs caught (incl. a nonce shared across lanes) | `model/cchs-state.mjs` | yes |
| Client rules (claim 2 on the device side) | bounded model check, 6 seeded rule violations caught (incl. one tree shared between two chains) | `model/cchs-client.mjs` | yes |
| Wallet implements the client rules | unit tests over a storage shim | `wallet/scripts/check-index-discipline.mts` | yes |
| Contract behaviour per set | Foundry, 26 tests × 2 sets incl. index reuse, backward index after skip, stale root, lanes (independence, replay, reset by recovery) | `evm/test/AegisCCHS.t.sol` | yes |
| Full life cycle with costs | create → first → cached → skip → second lane → rotation → old root rejected → withdraw, in an EVM | `wallet/scripts/evm-flow.mts` | yes |
| Cross-implementation agreement | shared fixtures replayed by Solidity, Rust, Cairo, FunC, Move, TypeScript | `evm/test/fixtures/`, each chain directory | yes |
| Key derivation is pinned | mnemonic → master → roots → addresses vector | `evm/test/fixtures/cchs-derivation.json`, `wallet/scripts/check-vectors.mts` | yes |
| Hash security numbers | hand analysis, two accountings; multi-user term removed by `pkSeed` | `CCHS.spec.md` §5.5 | n/a |
| Per-tree seed is enforced by every verifier | fixture signatures replayed under another seed are rejected (Foundry, Rust, Cairo, FunC, Move tests) | each chain directory | yes |

The Lean proofs cover the transition system only: the hash is an abstraction ("a signature over other inputs matches nothing") and the WOTS+ two-message exposure enters as a hypothesis, not a theorem. Bounded model checks explore every state up to the stated bounds and additionally exercise an explicit adversary and seeded bugs; they are not proofs. The hash-level analysis is a derivation from published bounds, not a machine-checked reduction.

### 3.1 Automated scanners (2026-10-09, `main`)

Five off-the-shelf scanners were run over `evm/src` (13 files, ~1 500 lines; Solidity 0.8.28, via-ir) and, for PostQuant, over every JavaScript, Rust, Go, Java and Python source in the repository. None of them is an audit; the table records what each one reported and what we make of it. Raw outputs are not committed; the public reports are linked.

| Tool | Run | Headline | Reading |
|---|---|---|---|
| Slither 0.11.6 | local, per root contract, 102 detectors | 75 unique findings: 5 High, 4 Medium, 21 Low, 45 Informational | Every High and Medium is triaged below; none is a loss of funds. |
| MIESC 6.0.0 | local, 32 of its 50 adapters available (Slither, Semgrep, Solhint, Wake, SMTChecker, solcmc, pattern and ML detectors; no Mythril, Foundry or LLM backends) | 114 findings after its ML severity re-weighting | Its "critical" bucket is Slither's `assembly`, `reentrancy-events` and `calls-loop` re-labelled, plus two pattern detectors firing on "external call before state update" in `UpgradeHelper.upgrade` and `AegisCCHSFactory.deployAndMove`. SMTChecker and solcmc produced no counterexample. Nothing beyond the Slither set. |
| PostQuant | local, source only | grade C+; 1 critical, 7 informational | The critical is ECDSA in `core/src/lib.rs` (`ecdsa_sign_eth`), which is the secp256k1 half of the hybrid `AegisAccountV2` and exists so that account can be reached from a classical wallet; the CCHS path has no ECDSA. The informational items are SHA-256 uses, which the tool itself classifies as quantum-safe. The grade is driven by the one ECDSA symbol. |
| [Audit Forge](https://auditforge.org/r/181317fd-76dd-4992-91b8-a7939e57c09d) | web, repository mode, entry `evm/src/AegisCCHSFactory.sol` | 100/100, 0 critical/high/medium/low, 4 informational | Only Mythril, Semgrep and Solhint completed; Slither and Aderyn failed because repository mode fetches the entry file alone and the relative imports were not resolved. Treat as three engines over the factory and its transitive sources, not six. |
| [SolidityScan QuickScan](https://solidityscan.com/qs-report/eeaa23c580a482b3eeafc73ca5ec159d/c76e1c4771f84d75/2c22791fa8419b88) | web, repository mode, `main`, `.sol` only | security score 53.20/100, threat score 68/100; 590 findings: 7 critical, 8 high, 56 medium, 51 low, 356 informational, 112 gas | Per-instance locations are behind a paywall; only the category counts are public. The categories are assessed below. |

**Why the SolidityScan score is low.** The score is a weighted count of pattern matches per line of code, with no notion of what the contract is for. Three properties of an account contract are penalised by construction:

1. *It forwards arbitrary calls.* `execute` and `executeFirst` do `target.call{value}(data)` to an address chosen by the signer. QuickScan files each such site under CONTROLLED LOW-LEVEL CALL (critical, 6 instances); Slither files the same sites under `arbitrary-send-eth`. Forwarding a signed call is the whole purpose of the contract; the control is the CCHS signature, verified before the call, with the lane's `nextIdx` and nonce written before the call (`_finish`). Removing the finding would mean removing the account.
2. *It is hash-and-bit heavy.* The ADRS word is assembled with shifts (`_adrs`), the WOTS+ chains and Merkle nodes run in inline assembly, and the digest is `abi.encodePacked` over fixed-width fields plus `keccak256(data)`. That yields INCORRECT SHIFT ASSEMBLY (35), IN-LINE ASSEMBLY, ABI.ENCODEPACKED collision warnings (11 + 11) and ERROR-PRONE TYPECASTING (17). The encodePacked inputs are all fixed width except the trailing hash, so no two field layouts collide; the shifts are the documented ADRS layout (`CCHS.spec.md` §2.2) and are checked bit-for-bit by the cross-implementation fixtures.
3. *It is small and the tool counts per line.* 1 500 lines with 468 informational and gas items (NatSpec tags, `uint48` for timestamps, `++i`, constructor events) dominate the denominator.

The remaining high and medium categories, by name: ABSENCE OF NONCE IN SIGNATURE (1) — the CCHS digest binds the lane nonce and the leaf index, and `AegisAccount` binds `nonce`; without the instance we cannot say which site tripped it, and we would like to know. MISSING MODIFIER IN INITIALIZE (1) — `_init` is `internal`, called from the constructor, and reverts with `AlreadyInitialized`. USE OF TX.GASPRICE (2) — the fee formula of the legacy `AegisAccount`/`AegisAccountV2`, intentional. MERKLE LEAF CAN BE REUSED (3) — the lane rule forbids it; this is the property the Lean proof and the model check establish. REENTRANCY (3) and UNCHECKED TRANSFER (1) — see the Slither triage. INCORRECT ACCESS CONTROL (1) — most likely `finalizeEmergencyExit`, which is deliberately permissionless after the timelock.

**Slither High and Medium, triaged.**

| Detector | Site | Assessment |
|---|---|---|
| `arbitrary-send-eth` ×3 | `AegisCCHSBase._finish`, `AegisAccount.execute`, `executeBatch` | By design (item 1 above). |
| `reentrancy-balance` | `AegisCCHSFactory.deployAndMove` | `balanceOf(msg.sender)` is read, then `transferFrom` is called on a token the caller named. Only the caller's own tokens move, into the caller's own account; a malicious token can only harm its own caller. |
| `reentrancy-eth` | `AegisAccount.finalizeEmergencyExit` (legacy V1 account, not CCHS) | ETH reaches GUARDIAN before `exitTimestamp` is cleared. A re-entering guardian sees a zero balance and tokens already moved; the only effect is a second nonce increment. Would be fixed by moving the state writes above the transfers. |
| `incorrect-equality` ×3 | `bal == 0`, `exitTimestamp == 0` | Sentinel comparisons; false positive. |
| `uninitialized-local` | `moved` in `finalizeEmergencyExit` | Defaults to zero and is only incremented; false positive. |

What these tools cannot see is the part that matters for a hash-based signature: whether the WOTS+ chain and Merkle arithmetic is correct and whether the index discipline holds. That is what the Lean proofs, the model checks, the Foundry tests and the cross-implementation fixtures above are for, and what the audit scope in §5 asks a human to check.

## 4. Known gaps

- No independent audit of any component.
- No machine-checked proof of the cryptographic reductions (the Lean proofs stop at the hash); no written reduction with explicit constants for `(n = 24, w = 256, 2^20 leaves)` (C-20). The multi-user term of that analysis is closed by construction (`pkSeed`); the single-tree constants are not written down.
- No mainnet deployment; gas figures come from a local EVM and Solana compute units from the `solana-program-test` runtime in CI, not from a public cluster.
- The wallet is a reference implementation: browser `localStorage` for the index record and the device lane, no hardware-key support; lane assignment between devices is a user action that the protocol cannot check.
- The signer runs in a browser or a user's own process, with the mnemonic and every derived key in page memory for the session (nothing secret is ever written to `localStorage`); malware with access to that memory holds the account, and a hardware-isolated signer is not implemented. The timing of WOTS+ signing reveals only the digits of the public digest; what the JavaScript runtime leaks about the secret itself is the compromised-device case, which is out of scope (§1).

## 5. Audit scope we propose

1. `evm/src/AegisCCHSBase.sol` and the three set contracts: verification, index and cache state machine, recovery, factory and CREATE2 determinism, asset handling in `execute`.
2. `CCHS.spec.md` §3–§5, §8: whether the specification's security argument is correct and whether the contracts implement it.
3. `model/*.mjs`: whether the models faithfully abstract the contracts and the client, and whether the bounds are meaningful.
4. `wallet/src/aegis/`: key derivation, per-epoch keys, signing, the index record, and `ProtectPanel`'s use of them.
5. `cchs-core` and the non-EVM verifiers against the fixtures and against the Solidity reference.
6. The parameter choices: the C-20 set, and the attack-path accounting of `CCHS.spec.md` §5.6 that keeps `n = 32` as the default (in particular whether the 32-byte digest and master really cap every wider-output variant at 2^128, and whether the conservative 2^113 figure for the chain and node paths should be the one quoted).

## 6. Reporting

Report vulnerabilities privately to the repository owner through the hosting platform's private vulnerability reporting, or open an issue marked `security` for anything that is already public. There is no bug bounty; there are no funds at risk because nothing is deployed.
