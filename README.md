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

Single transaction, no commit-reveal, no finality wait. Measured on the EVM with the SHA-256 precompile: ~275 K gas total on the cached path, ~580 K for the first signature in a subtree, 4 750 B of runtime code, no external verifier contract. Signatures produced by the TypeScript client were executed against the compiled contract in an EVM; front-running, replay, tampering, cache poisoning, and post-recovery use of the old key are all rejected.

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

The CCHS verifier needs SHA-256, byte concatenation, and 32-byte storage. Signatures are byte-identical across chains (the chain ID is bound inside the digest, so they are not replayable).

| Chain | Hash primitive | Status |
|---|---|---|
| EVM (Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche, Linea, Scroll, Mantle, Blast, Mode, …) | precompile `0x02` | contract complete, interop-tested |
| TRON | SHA-256 precompile (EVM-compatible) | same artifact |
| Solana | `sha256` syscall | adapter scaffold |
| Cosmos (CosmWasm) | `sha2_256` | adapter scaffold |
| Aptos / Sui | `hash::sha2_256` | adapter scaffold |
| NEAR | `env::sha256` | adapter scaffold |
| TON | `HASHEXT_SHA256` | adapter scaffold |
| Starknet | `core::sha256` | adapter scaffold |
| Bitcoin | `OP_SHA256` in Tapscript (BIP-341) | design in `CCHS.spec.md` §7.1 |

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
- Pure-JS keygen is ~5 s for 1.3 M hashes; WASM/native is 20–100× faster. The wallet runs it in a Web Worker.
- Chain consensus security is outside the protocol's scope.
- Not yet externally audited.

## License

MIT (protocol, contracts, core) · GPL-3.0 (wallet UI). Vendored SPHINCS+ C13 verifier: see `evm/src/vendor/LICENSE.nconsigny`.
