# Aegis

**Hash-only post-quantum accounts, one seed, every chain.**

Aegis is a smart-account protocol whose authorization layer reduces to a single assumption: SHA-256 preimage resistance. No elliptic curves, no lattices, no trusted setup, no admin keys, no pools, no token.

Its core is **CCHS — Chain-Cached Hypertree Signatures**, a hash-based signature architecture that uses the one property on-chain verifiers have and classical verifiers do not: persistent storage.

---

## CCHS in one paragraph

Hash-based hypertree signatures (XMSS^MT, SPHINCS+) carry the full authentication path through every tree layer in every signature, because the verifier is assumed to be memoryless. A smart contract is not. CCHS verifies the upper-layer proof for each bottom subtree once, caches the subtree root on-chain, and lets the next 1023 signatures carry only the bottom layer.

| At 2^20 signatures | Keygen | Signature (amortized) | Client state | Assumption |
|---|---|---|---|---|
| Flat XMSS (h=20) | ~10^9 hashes | 2.8 KB | stateful | SHA-256 |
| XMSS^MT (d=2, h=10) | ~10^6 hashes | 4.9 KB | stateful | SHA-256 |
| SPHINCS+-128s | ~10^6 hashes | 7.8 KB | stateless | SHA-256 |
| **CCHS (d=2, h=10)** | **~10^6 hashes** | **2.5 KB** | **stateless (chain-held)** | SHA-256 |

Single transaction, no commit-reveal, no finality wait. Two parameter sets share one account contract: `CCHS-K-20` (keccak256, EVM default) and `CCHS-S-20` (SHA-256, canonical for every other chain). Measured in an EVM: K-20 ~128 K gas on the cached path and ~284 K for the first signature in a subtree; S-20 ~235 K / ~465 K. Runtime code 3.7 KB, no external verifier contract. Accounts are created through a CREATE2 factory, so one key gives the same address on every EVM chain. Signatures produced by the TypeScript client were executed against the compiled contracts; front-running, replay, tampering, cache poisoning, and post-recovery use of the old key are all rejected.

Full specification: [`CCHS.spec.md`](CCHS.spec.md).

---

## Why

On 2026-10-07 Vitalik Buterin and Justin Drake warned publicly that AI-accelerated mathematics may weaken lattice cryptography within two years and break ECDSA sooner than expected. Ethereum's own post-quantum infrastructure targets 2029.

Users need a signature layer with the weakest possible assumption, today. Hash functions are that layer. Aegis makes them practical for accounts.

## Trust assumptions

1. SHA-256 preimage and second-preimage resistance (Grover bound: 2^128).
2. The user's own device and seed handling.

There is no trusted setup, committee, admin key, treasury, upgrade path, or governance that can alter account logic.

## Two deployment modes

**Hash-only (`AegisCCHS`)** — every operation is a CCHS signature. For holdings whose owner wants zero reliance on elliptic curves.

**Hybrid (`AegisAccountV2`)** — daily operations use ECDSA (instant, works with every wallet); an immutable post-quantum commitment allows a one-shot recovery that rotates the ECDSA owner if ECDSA is ever broken. V2 ships with a SPHINCS+ (FIPS 205) verifier; CCHS is the planned replacement for the recovery path (≈ 4× cheaper, 1/3 the code, no external contract).

## Chains

The CCHS verifier needs one 256-bit hash, byte concatenation, and 32-byte storage. With `CCHS-S-20` the same key and the same top-layer proof are valid on every chain (the chain ID is bound inside each operation digest, so operations are not replayable; the subtree registration is portable by design, see `CCHS.spec.md` §5.3).

| Chain | Hash primitive | Status |
|---|---|---|
| EVM (Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche, Linea, Scroll, Mantle, Blast, Mode, …) | `keccak256` (K-20) or precompile `0x02` (S-20) | contracts + factory complete, interop-tested |
| TRON | same opcodes (EVM-compatible) | same artifacts |
| Solana | `sha256` syscall | adapter scaffold |
| Cosmos (CosmWasm) | `sha2_256` | adapter scaffold |
| Aptos / Sui | `hash::sha2_256` | adapter scaffold |
| NEAR | `env::sha256` | adapter scaffold |
| TON | `HASHEXT_SHA256` | adapter scaffold |
| Starknet | `core::sha256` | adapter scaffold |
| Bitcoin | `OP_SHA256` + `OP_CAT` (BIP-347, not active) | tree/leaf-script builder in `wallet/src/aegis/btcTapscript.ts`; sighash binding needs OP_CAT, see `CCHS.spec.md` §7.1 |

Standard mainnet address derivation for 23 chains (importable into Phantom, Keplr, Petra, etc.) is implemented in `wallet/src/aegis/derive.ts`. See [`ADAPTERS.md`](ADAPTERS.md).

## Repository

```
aegis/
├── CCHS.spec.md          protocol specification
├── SPEC.md               account model, key and address derivation, V2 interface
├── ADAPTERS.md           per-chain adapter matrix
├── evm/                  Solidity: AegisCCHS, AegisAccountV2, factories, SPHINCS+ C13 verifier, tests
├── wallet/               Vite + React client: CCHS client, 23-chain derivation, Web Worker crypto
├── deploy/               Node deployment (solc-js + viem), no Foundry required
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

# Wallet
cd wallet && npm i && npm run build
```

## Honest limits

- The underlying primitives (WOTS+, Merkle trees, hypertrees) date from 1979–2015 and are extensively studied. The CCHS contribution is the verifier-side caching architecture and the trade-off point it reaches; it is not a new primitive.
- Keygen is ~2.3 M hashes (top tree, recovery tree, first subtree). Single-threaded JS: ~3 s. The wallet splits leaves across a Web Worker pool with WASM hash cores (`wallet/src/aegis/cchsPool.ts`): ~0.7 s on a 6-core laptop, byte-identical output. Getting under 100 ms requires running the WOTS+ chain loop inside WASM rather than calling a WASM hash per step; that is the planned use of the Rust `cchs-core` crate compiled to wasm32.
- Chain consensus security is outside the protocol's scope.
- Not yet externally audited.

## License

MIT (protocol, contracts, core) · GPL-3.0 (wallet UI). Vendored SPHINCS+ C13 verifier: see `evm/src/vendor/LICENSE.nconsigny`.
