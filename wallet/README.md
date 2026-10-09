# Aegis Wallet

Browser client for Aegis accounts. Vite + React 19 + TypeScript. All cryptography runs in the browser; nothing leaves the device.

## What it does

- Generates or imports a 24-word BIP-39 mnemonic.
- Derives, in a Web Worker: the CCHS master and tree roots, an SLH-DSA-SHAKE-192s (FIPS 205) key pair, secp256k1 and ed25519 keys.
- Shows standard, wallet-importable addresses for 23 chains (`src/aegis/derive.ts`).
- CCHS client (`src/aegis/cchs.ts`): both parameter sets (`cchsS`, `cchsK`), keygen, sign, local verify, digest construction, ABI encoding — byte-exact with `evm/src/AegisCCHS.sol` and `AegisCCHSK.sol`.
- Parallel keygen (`src/aegis/cchsPool.ts`): leaf ranges spread across a Web Worker pool using WASM hash cores (`hash-wasm`), folded into trees on the main thread. Output is identical to the single-threaded path; ~0.7 s for public key + first subtree on a 6-core machine.
- Protect panel (`src/components/ProtectPanel.tsx`): derives the CCHS master and one key tree per EVM chain, predicts each account address offline (`src/aegis/cchsAccount.ts`; addresses differ per chain because a one-time leaf never signs on two chains), reads live per-chain state over public RPC (factory, account, native balance, balances of any ERC-20s you list), and protects a chain in one transaction: `AegisCCHSFactory.deployAndMove{value}(root, recRoot, false, erc20s)` after the approvals it needs, or plain transfers into an existing account. 14 EVM chains are listed (12 mainnets + Sepolia, Base Sepolia).
- Spend (same panel): moves any asset back out of the hash-only account. The index is chosen as `max(nextIdx, signedMax + 1)` and recorded in `localStorage` before anything is signed, so a dropped or replaced transaction never leads to a second signature under the same leaf. The digest is computed locally with `cchsK.executeDigest`, cross-checked against the contract's `digestAt`, signed with the CCHS key (the bottom tree for that index comes from the worker pool), verified locally, and `execute` (or `executeFirst` when the subtree is new on chain) is relayed through the injected wallet, which pays gas and holds no authority over the account. ERC-721 / ERC-1155 arrive through the account's receiver callbacks and leave through the same `execute`.
- Bitcoin WOTS+ Taproot tree builder (`src/aegis/btcTapscript.ts`); transaction binding awaits OP_CAT.
- On-device bench (`src/components/LabBench.tsx`): runs the real protocol in the page — keygen through the worker pool, a first-in-subtree and a cached signature, local verification, and two attacks (bit flip, front-run) that must be rejected. Every number shown is measured on the visitor's machine; nothing is scripted.
- Figures: an animated hypertree showing the cache filling signature by signature (`src/components/HypertreeFigure.tsx`), the parameter table for both sets (`src/components/ParamsTable.tsx`), and the chain matrix with truthful per-chain status (`src/components/ChainDashboard.tsx`).
- Responsive layout down to 360 px: full-screen menu, stacked Protect rows, 44 px touch targets, safe-area insets, horizontally scrolling tables, no pointer effects on touch devices.
- Live FIPS 205 sign + verify demo.
- Hybrid account card (`src/components/SwapPanel.tsx`): states the position of the `AegisAccountV2` line (source and tests in `evm/`, not deployed on any chain) and shows the post-quantum commitment the mnemonic would carry. It deploys nothing.
- Source excerpts (`src/components/CodeShowcase.tsx`): `AegisCCHSBase.sol`, `cchs-core/src/lib.rs`, `cairo/src/lib.cairo`, `cchsAccount.ts`, kept in step with the files by hand.

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

The public origin is `https://aegisprotocol.si`; `index.html` forwards `aegis-wallet.fly.dev` and `www.aegisprotocol.si` to it, and the canonical, Open Graph, `robots.txt` and `sitemap.xml` URLs point there. Binding the domain is two steps outside the repository:

```sh
fly certs add aegisprotocol.si -a aegis-wallet
fly certs add www.aegisprotocol.si -a aegis-wallet
fly ips list -a aegis-wallet          # the A and AAAA records below
```

At the registrar: `A @ → <v4 address>`, `AAAA @ → <v6 address>`, `CNAME www → aegis-wallet.fly.dev`, plus the `_acme-challenge` CNAME that `fly certs show aegisprotocol.si` prints if the certificate does not issue on its own. `fly certs check aegisprotocol.si` confirms issuance.
