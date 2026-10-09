# Aegis

**Hash-only post-quantum accounts, one seed, every chain.**

Aegis is a smart-account protocol whose authorization layer reduces to a single assumption: SHA-256 preimage resistance. No elliptic curves, no lattices, no trusted setup, no admin keys, no pools, no protocol token.

Site: [aegisprotocol.si](https://aegisprotocol.si) · X: [@aegisprotocolon](https://x.com/aegisprotocolon) · Community token (Solana, Token-2022, mint and freeze authority disabled): **AEGIS** `5BHTmt8bnEizr5tcokZTWoHjMmptR29Me6MqLrVWpump`. The token plays no role in the protocol: no fees, no governance, no staking; holding it grants nothing in any contract here. It is an SPL token like any other and can itself be held in a CCHS vault.

Its core is **CCHS — Chain-Cached Hypertree Signatures**, a hash-based signature architecture that uses the one property on-chain verifiers have and classical verifiers do not: persistent storage.

---

## CCHS in one paragraph

Hash-based hypertree signatures (XMSS^MT, SPHINCS+) carry the full authentication path through every tree layer in every signature, because the verifier is assumed to be memoryless. A smart contract is not. CCHS verifies the upper-layer proof for each bottom subtree once, caches the subtree root on-chain, and lets the next 1023 signatures carry only the bottom layer.

| At 2^20 signatures | Keygen | Signature (amortized) | Client state | Assumption |
|---|---|---|---|---|
| Flat XMSS (h=20) | ~10^9 hashes | 2.8 KB | stateful | SHA-256 |
| XMSS^MT (d=2, h=10) | ~10^6 hashes | 4.9 KB | stateful | SHA-256 |
| SPHINCS+-128s | ~10^6 hashes | 7.8 KB | stateless | SHA-256 |
| **CCHS (d=2, h=10)** | **~10^6 hashes** | **2.5 KB** | **index on chain + write-ahead record** | SHA-256 |

Single transaction, no commit-reveal, no finality wait. Two parameter sets share one account contract: `CCHS-K-20` (keccak256, EVM default) and `CCHS-S-20` (SHA-256, canonical for every other chain). Measured in an EVM, whole transaction (intrinsic + calldata + execution): K-20 ~177 K gas on the cached path (2 628 B calldata) and ~368 K for the first signature in a subtree; S-20 ~261 K / ~558 K. That is about 7× an ECDSA transfer; the cached path is the amortized floor for a hash-based signature, not a way around it. Runtime code 7.2 KB, no external verifier contract. The account holds any asset (ETH, ERC-20, ERC-721, ERC-1155) and spends any of them through one `execute` call (`executeFirst` when the subtree is new). The signer chooses the leaf index (monotonic, bound into the digest), so a dropped transaction never leads to a second signature under the same one-time key. Accounts are created and funded in one transaction through a CREATE2 factory that lives at the same address on every EVM chain. One mnemonic derives an independent key tree per chain (a one-time leaf must never sign on two chains, and the chain id in the digest only prevents replay, not reuse), so the account address differs per chain; each is a pure function of the mnemonic and the chain id and is known before anything is deployed. Signatures produced by the TypeScript client were executed against the compiled contracts; front-running, replay, tampering, cache poisoning, and post-recovery use of the old key are all rejected.

Full specification: [`CCHS.spec.md`](CCHS.spec.md).

---

## Why

On 2026-10-07 Vitalik Buterin and Justin Drake warned publicly that AI-accelerated mathematics may weaken lattice cryptography within two years and break ECDSA sooner than expected. Ethereum's own post-quantum infrastructure targets 2029.

Users need a signature layer with the weakest possible assumption, today. Hash functions are that layer. Aegis makes them practical for accounts.

## Trust assumptions

1. SHA-256 preimage and second-preimage resistance: 2^128 quantum under the tight multi-target accounting of FIPS 205, 2^113 under the conservative one; `CCHS.spec.md` §5.5 gives both and §5.6 costs every attack path and the wider-output alternatives.
2. The user's own device and seed handling.

There is no trusted setup, committee, admin key, treasury, upgrade path, or governance that can alter account logic.

## Two deployment modes

**Hash-only (`AegisCCHS`)** — every operation is a CCHS signature. For holdings whose owner wants zero reliance on elliptic curves.

**Hybrid (`AegisAccountV2`)** — daily operations use ECDSA (instant, works with every wallet); an immutable post-quantum commitment allows a one-shot recovery that rotates the ECDSA owner if ECDSA is ever broken. V2 ships with a SPHINCS+ (FIPS 205) verifier; CCHS is the planned replacement for the recovery path (≈ 4× cheaper, 1/3 the code, no external contract).

## Chains

The CCHS verifier needs one 256-bit hash, byte concatenation, and 32-byte storage, so the same verification algorithm runs on every chain below. Keys are not shared between chains: one mnemonic yields an independent key tree, root and account per chain (`CCHS.spec.md` §3), because a one-time leaf must never sign on two chains; the chain ID inside each digest additionally makes operations non-replayable. Subtree registration (`cache_subtree`) is permissionless but chain-specific (§5.3).

| Chain | Hash primitive | Status |
|---|---|---|
| EVM (Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche, Linea, Scroll, Mantle, Blast, Mode, …) | `keccak256` (K-20) or precompile `0x02` (S-20) | contracts + factory complete, interop-tested |
| TRON | same opcodes (TVM, cancun) | same sources, TVM build byte-identical to the EVM artifact (`tron/`); CREATE2 prefix `0x41` predictor; not yet published on Nile or mainnet |
| Solana | `sha256` syscall | `CCHS-C-20` Anchor program: `cache_subtree` + single-packet `execute` (`solana/`); wallet path for SOL and any SPL / Token-2022 token (`wallet/src/aegis/solanaAccount.ts`, Solana panel); program id `AoQ7c3GuxiF7nshFnM872FoxUz7oUDhygdhoRX6jMQKr`, **live on mainnet-beta** (deployed from CI, slot 454 874 054, ELF identical to the CI artifact; upgrade authority = deployer key) |
| Cosmos (CosmWasm) | `sha2_256` | verifier contract on `cchs-core`, fixture-tested, not deployed |
| Aptos / Sui | `hash::sha2_256` | Move modules: resource account with zeroed auth key (Aptos), `Bag<Balance<T>>` any-coin vault (Sui), immutable publication documented; fixture + end-to-end tests, not published |
| NEAR | `env::sha256` | verifier contract on `cchs-core`, fixture-tested, not deployed |
| TON | `HASHEXT_SHA256` | FunC verifier, fixture-tested, not deployed |
| Starknet | `core::sha256` | Cairo verifier, fixture-tested, not deployed |
| Bitcoin | `OP_SHA256` + `OP_CAT` + `OP_CHECKSIGFROMSTACK` in Tapscript (BIP-347/348, active on Bitcoin Inquisition signet, not on mainnet); the covenant form needs a key-less output (BIP-360 P2MR, draft) | CCHS account carried by the UTXO lineage: `execFirst → exec → exec → recover → execFirst` executed on Inquisition signet (3 300 vB per cached spend, 6 336 vB first-in-subtree, 3 207 vB recovery; txids in [`BITCOIN.md`](BITCOIN.md) §5.6) and on an Inquisition regtest node in CI; successor enforced by the signer until P2MR |

**Tokenised real-world assets.** An Aegis account is an ordinary contract address (EVM) or PDA vault (Solana), so tokenised treasuries, money-market funds and gold are held and spent like any other token. The wallet knows the issuers' contracts for BUIDL, USDY, OUSG, USTB, BENJI, PAXG and XAUt (`wallet/src/data/rwa.ts`, addresses from the issuers' own publications) and handles the one thing that differs: most of these contracts refuse holders their issuer has not registered. Before moving anything in, the Protect panel simulates `transfer(aegisAccount, …)` and reports what the token answered (BUIDL on Ethereum: "Wallet not in registry service" until Securitize registers the address); before signing a Spend, it simulates the transfer from the account, so a gated recipient costs no leaf. Registration with the issuer is the holder's step, exactly as for any new wallet address; the account address is known offline before deployment, so it can be registered first.

Standard mainnet address derivation for 23 chains (importable into Phantom, Keplr, Petra, etc.) is implemented in `wallet/src/aegis/derive.ts`. Those are ordinary ed25519 / secp256k1 addresses from the same seed; they are not post-quantum. The post-quantum account on a chain is the CCHS verifier listed above, at the stage listed above. See [`ADAPTERS.md`](ADAPTERS.md).

## Repository

```
aegis/
├── CCHS.spec.md          protocol specification
├── SPEC.md               account model, key and address derivation, V2 interface
├── ADAPTERS.md           per-chain adapter matrix
├── evm/                  Solidity: AegisCCHS, AegisAccountV2, factories, SPHINCS+ C13 verifier, tests
├── wallet/               Vite + React client: CCHS client, 23-chain derivation, Web Worker crypto
├── sdk/                  @aegis-protocol/sdk: the wallet's client as a library (EVM, Solana, Bitcoin signet, derivation)
├── deploy/               Node deployment (solc-js + viem), no Foundry required
├── model/                bounded model check of the CCHS state machine (runs in CI)
├── proofs/               Lean 4 proofs of the verifier and client invariants (runs in CI)
├── core/                 Rust core (seed → keys)
├── solana/ cosmwasm/ aptos/ sui/ near/ ton/ cairo/ tron/ bitcoin/
│                         chain adapters
└── docs/                 user verification guide, testnet notes
```

## Build

```bash
# Solidity (Foundry)
cd evm && forge build && forge test

# Solidity without Foundry (solc-js)
cd deploy && npm i && node deploy.mjs --compile-only

# Wallet, then the checks CI runs: pinned vectors, index discipline, full life cycle in an EVM with costs
cd wallet && npm i && npm run build
npm run vectors && npm run index-discipline && npm run evm-flow && npm run btc

# SDK for integrators (same sources as the wallet): build, type-check, offline smoke
cd sdk && npm i && npm run build && npm run smoke

# Bounded model checks (verifier and client), each with its seeded bugs
node model/cchs-state.mjs && node model/cchs-client.mjs

# Machine-checked invariants (Lean 4 via elan; no Mathlib, builds in seconds)
cd proofs && lake build && lake env lean Check.lean

# CCHS factory: build the deterministic artifact, check or publish it per chain
cd deploy && node deploy-cchs.mjs --build
node deploy-cchs.mjs --status
AEGIS_DEPLOYER_KEY=0x… node deploy-cchs.mjs sepolia base arbitrum
```

The factory is published through the deterministic-deployment proxy (`0x4e59b44847b379578588920cA78FbF26c0B4956C`) with a fixed salt, so it has the address `0x515922E1bf018EA26dA78Dfe1F928Fc01fa8a2c6` on every chain where it has been published. Anyone can publish it; the result does not depend on who sends the transaction, and there is no project deployer key. `--status` reports where it is live. The wallet's **Protect** panel predicts the user's account address offline from `wallet/src/aegis/cchsArtifacts.json`, shows live per-chain state, publishes the factory itself as one extra transaction on a chain where it is still missing (the user pays about 3.7 M gas once per chain), and creates + funds the account in one transaction.

## Honest limits

- The underlying primitives (WOTS+, Merkle trees, hypertrees) date from 1979–2015 and are extensively studied. The CCHS contribution is the verifier-side caching architecture and the trade-off point it reaches; it is not a new primitive.
- Keygen is ~2.3 M hashes (top tree, recovery tree, first subtree). Single-threaded JS: ~3 s. The wallet splits leaves across a Web Worker pool with WASM hash cores (`wallet/src/aegis/cchsPool.ts`): ~0.7 s on a 6-core laptop, byte-identical output. Getting under 100 ms requires running the WOTS+ chain loop inside WASM rather than calling a WASM hash per step; that is the planned use of the Rust `cchs-core` crate compiled to wasm32.
- Chain consensus security is outside the protocol's scope.
- No external audit, and the machine-checked part stops at the hash. The security argument is a reduction sketch (CCHS.spec.md §6) plus Lean 4 proofs of the transition logic (`proofs/`: cache genuineness, one acceptance per index, acceptance only over the signed inputs, lane independence, and the client's ONE-MESSAGE with lanes — for all parameters and all reachable states, with the hash abstracted as "a signature over other inputs matches nothing"), bounded model checks that additionally exercise the adversary and seeded bugs (`model/cchs-state.mjs`, six caught, including a shared nonce across lanes; `model/cchs-client.mjs`, six rule violations caught under crashes, dropped transactions, backup restores, two devices and two chains), Foundry, a full life-cycle run in an EVM (`wallet/scripts/evm-flow.mts`) and cross-language fixture tests. None of this proves anything about SHA-256, keccak or the WOTS+ reduction; those are assumptions stated in the spec. SECURITY.md lists the claims, the threat model and the audit scope we propose.
- Signatures are 2.5 KB and ~177 K gas end to end on the cached path; this is the amortized floor for a hash-based signature on an EVM, about 7x an ECDSA transfer. Small or frequent payments belong on the hybrid account (ECDSA daily, CCHS recovery).
- One-time keys depend on the client never signing two messages under one leaf. The verifier enforces one landed signature per index; the client enforces the rest with a write-ahead record of the highest signed index per epoch and lane (CCHS.spec.md §4.3). A device whose record is missing or restored from a backup must move to an unused lane or rotate to the next epoch (same mnemonic, deterministic keys) before signing again; the wallet enforces this and offers both. Several devices: the index space has 16 lanes with independent on-chain counters and nonces, one device per lane; devices then sign concurrently with no coordination (invariant LI in the spec), and the only client obligation is never to put two devices in one lane. Across chains the question does not arise: each chain has its own key tree, so no leaf exists on two chains (an earlier design shared one tree across EVM chains for a common address; that would have let leaf 0 sign two different digests, and was changed).
- `CCHS-C-20` (Solana) truncates SHA-256 to 24 bytes and uses w = 256. Every hash call of a key tree carries a 16-byte public seed in its address (`pkSeed`, the role of `PK.seed` in SLH-DSA), so the multi-target count is that of one tree however many accounts exist. Within one tree, the SPHINCS+ argument that places SLH-DSA-192 at NIST level 3 puts C-20 at the AES-192 yardstick (2^192 / 2^96); counting the ≈ 2^33 published chain values with no credit for the address tweak gives 2^159 / 2^80, between AES-128 and AES-192. Both numbers are in CCHS.spec.md §5.5 with the reasoning; the written reduction with explicit constants for (n = 24, w = 256) is an open item. S-20 / K-20 (n = 32, w = 16) clear AES-192 under either accounting.
- Bitcoin: the wallet's Bitcoin address is a plain P2WPKH address and is not post-quantum. Under current consensus a script can only *search* for facts about its transaction with proof of work, not read them; the one hash-only, transaction-binding family that exists today on mainnet (Binohash / QSB, 2026) costs a 10 KB non-standard legacy output, about 2^47 of GPU work per spend and a miner that accepts it, for 2^118 against Shor and about 2^60–70 against Grover. With `OP_CAT` and `OP_CHECKSIGFROMSTACK` the account of [`BITCOIN.md`](BITCOIN.md) §5 runs: each UTXO commits to the CCHS state after the last spend, its leaves verify a WOTS+ signature over the transaction's own sighash against the cached subtree root and the index rule, and the message is bound to the transaction with `OP_CHECKSIG` + `OP_CHECKSIGFROMSTACK` on a public key everybody knows (3 300 vB per spend). It is live on Bitcoin Inquisition signet, where those opcodes are active, with the two limits §5.1 states: the successor output is built by the signer rather than forced by a covenant (a P2TR commitment is an elliptic-curve tweak Script cannot check), and the key path exists. Mainnet needs the opcodes and a key-less output type (BIP-360 P2MR); nothing here is post-quantum on mainnet today.
- Chain status: EVM contracts are built, tested against client-produced signatures and deployable by anyone; the factory has no mainnet deployment yet. Non-EVM adapters are at the stages listed in ADAPTERS.md; none is live on a mainnet.

## License

MIT (protocol, contracts, core) · GPL-3.0 (wallet UI). Vendored SPHINCS+ C13 verifier: see `evm/src/vendor/LICENSE.nconsigny`.
