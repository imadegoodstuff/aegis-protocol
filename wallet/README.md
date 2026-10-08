# Aegis Wallet

Browser client for Aegis accounts. Vite + React 19 + TypeScript. All cryptography runs in the browser; nothing leaves the device.

## What it does

- Generates or imports a 24-word BIP-39 mnemonic.
- Derives, in a Web Worker: the CCHS master and tree roots, an SLH-DSA-SHAKE-192s (FIPS 205) key pair, secp256k1 and ed25519 keys.
- Shows standard, wallet-importable addresses for 23 chains (`src/aegis/derive.ts`).
- CCHS client (`src/aegis/cchs.ts`): both parameter sets (`cchsS`, `cchsK`), keygen, sign, local verify, digest construction, ABI encoding — byte-exact with `evm/src/AegisCCHS.sol` and `AegisCCHSK.sol`.
- Parallel keygen (`src/aegis/cchsPool.ts`): leaf ranges spread across a Web Worker pool using WASM hash cores (`hash-wasm`), folded into trees on the main thread. Output is identical to the single-threaded path; ~0.7 s for public key + first subtree on a 6-core machine.
- Protect panel (`src/components/ProtectPanel.tsx`): derives the CCHS identity, predicts the account address offline (`src/aegis/cchsAccount.ts`, same address on every EVM chain), reads live per-chain state over public RPC, and sends one `AegisCCHSFactory.deploy{value}` transaction per chain through the injected wallet.
- Bitcoin WOTS+ Taproot tree builder (`src/aegis/btcTapscript.ts`); transaction binding awaits OP_CAT.
- On-device bench (`src/components/LabBench.tsx`): runs the real protocol in the page — keygen through the worker pool, a first-in-subtree and a cached signature, local verification, and two attacks (bit flip, front-run) that must be rejected. Every number shown is measured on the visitor's machine; nothing is scripted.
- Figures: an animated hypertree showing the cache filling signature by signature (`src/components/HypertreeFigure.tsx`), the parameter table for both sets (`src/components/ParamsTable.tsx`), and the chain matrix with truthful per-chain status (`src/components/ChainDashboard.tsx`).
- Responsive layout down to 360 px: full-screen menu, stacked Protect rows, 44 px touch targets, safe-area insets, horizontally scrolling tables, no pointer effects on touch devices.
- Live FIPS 205 sign + verify demo.
- One-click hybrid account deployment via `viem` and the injected EVM provider (`src/components/SwapPanel.tsx`).

## Stack

- React 19, Vite 6, TypeScript 5
- `viem` (EVM), `@noble/hashes`, `hash-wasm`, `@noble/curves`, `@noble/post-quantum`, `@scure/bip39`, `@scure/base`
- Self-hosted WOFF2 fonts (Inter, Inter Tight, JetBrains Mono), Latin subsets
- Served by `serve` with immutable cache headers for `/assets` and `/fonts` (`serve.json`)

## Commands

```bash
npm i
npm run dev        # http://localhost:5173
npm run build      # type-check + production build to dist/
npm run preview
```

## Deployment

`Dockerfile` builds a static bundle and serves it on port 8080. `fly.toml` targets a `performance-1x` machine with `auto_stop = off` in `iad` and `sin`.
