# @aegis-protocol/sdk

Everything the site at [aegisprotocol.si](https://aegisprotocol.si) does, as a
TypeScript library for node and the browser: hash-only post-quantum accounts
(CCHS, [`CCHS.spec.md`](../CCHS.spec.md)) on EVM chains, Solana and Bitcoin
signet, and the per-chain address derivation of the Derive panel.

The SDK does not reimplement anything. It bundles the wallet's own client
(`wallet/src/aegis`) behind a small API, so the SDK and the site can never
disagree about a byte.

## Install

```bash
npm i @aegis-protocol/sdk
```

`viem`, `@noble/*`, `@scure/*` and `hash-wasm` are ordinary dependencies,
left external to the bundle so a host shares one copy with its own code.
From a clone of the repository: `cd wallet && npm i && cd ../sdk && npm i &&
npm run build` (the sources resolve their imports from `wallet/node_modules`).
The package is not yet published to npm; install it from the built `sdk/`
directory (`npm pack`, or `"@aegis-protocol/sdk": "file:../aegis/sdk"`).

## Three things to know

**One secret.** `masterFromMnemonic(mnemonic)` is the only secret; every
chain gets an independent key tree from it. Nothing in the SDK sends it
anywhere.

**A fee payer is not an owner.** On every chain some ordinary key relays the
transaction and pays gas, rent or fees: a viem `WalletClient` on EVM, a Wallet
Standard wallet or `keypairFeePayer` on Solana. It holds no authority over
the account. The account's authority is the WOTS+ leaf signed by the device
holding the master.

**Persist the index records.** A WOTS+ leaf is signed once. Before signing,
the client records the leaf it is about to use; that record is what prevents
a second signature with the same leaf. In a browser the records go to
`localStorage`. In node you must install a store:

```ts
import fs from "node:fs";
import { JsonFileRecordStore, setRecordStore } from "@aegis-protocol/sdk";
setRecordStore(new JsonFileRecordStore("./aegis-records.json", fs));
```

Without one, records live in process memory: fine for one run, unsafe across
restarts. Two signers of the same EVM account must use different `lane`s
(0–15); a host that finds a lane used with no record of it refuses to sign.

## EVM (CCHS-K-20)

```ts
import { createWalletClient, http, parseEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import { EvmAccount, makePublicClient, masterFromMnemonic } from "@aegis-protocol/sdk";

const master = masterFromMnemonic(process.env.AEGIS_MNEMONIC!);
const publicClient = makePublicClient(base);   // any viem PublicClient works
const walletClient = createWalletClient({ account: privateKeyToAccount("0x…"), chain: base, transport: http() });

const acct = await EvmAccount.derive({ master, chain: base, publicClient });   // ~1–2 s in-process keygen
acct.address;                              // fixed before anything is deployed
await acct.status();                       // factory / proxy / account present, balance, epoch, nextIdx
await acct.protect(walletClient, { value: parseEther("0.01"), tokens: [USDC] });
await acct.execute(walletClient, EvmAccount.erc20Transfer(USDC, to, 1_000_000n));
await acct.execute(walletClient, { to, value: parseEther("0.001") });
await acct.recover(walletClient);          // rotate to the next epoch
```

`protect` publishes the factory on a chain where it is still absent (one
extra transaction, about 3.7 M gas, same address on every chain), approves
tokens, and deploys + funds the account in one transaction; on an existing
account it is plain transfers. `execute` checks the local digest against the
contract's `digestAt` before signing and verifies the signature locally with
the reference verifier before sending.

`PROTECT_CHAINS` is the chain list the site offers; `makePublicClient(chain)`
its read client. In a browser, `requestAccounts()`, `switchChain(id)` and
`makeWalletClient(chain, from)` give the fee payer from the injected wallet.

## Solana (CCHS-C-20, program `AoQ7c3GuxiF7nshFnM872FoxUz7oUDhygdhoRX6jMQKr`)

```ts
import { Rpc, SolanaAccount, keypairFeePayer, masterFromMnemonic } from "@aegis-protocol/sdk";

const rpc = new Rpc("https://api.mainnet-beta.solana.com");
const payer = keypairFeePayer(secretKeyBytes, rpc);        // node; browsers: connectSolanaWallet()
const acct = await SolanaAccount.derive({ master, rpc, cluster: "mainnet-beta" });

acct.account; acct.vault;                                  // PDAs, fixed before creation
await acct.create(payer);                                  // account + address lookup table, one tx
await acct.depositSol(payer, 5_000_000n);
const t = (await acct.feePayerTokens(payer)).find(...);    // any SPL or Token-2022 token
await acct.depositToken(payer, t, t.amount);
await acct.holdings();                                     // SOL and token balances of the vault
await acct.spend(payer, { kind: "sol", to, amount: 1_000_000n });
await acct.spend(payer, { kind: "token", to, amount, token: vaultHolding });
await acct.recover(payer);
```

The program is live on mainnet-beta (not on devnet). `spend` sends
`cache_subtree` first when the leaf is the first of its subtree, then a
single-packet v0 `execute` through the account's lookup table. Lower-level
pieces (`solanaIx.*`, `compileMessage`, `findProgramAddress`,
`associatedTokenAddress`) are exported for hosts that build their own
transactions.

## Bitcoin signet (CCHS-UTXO)

```ts
import { BitcoinAccount, recommendedFeerate } from "@aegis-protocol/sdk";

const btc = BitcoinAccount.derive({ master });
btc.address0;                                   // first address of the lineage (P2TR)
const lin = await btc.sync();                   // state, current address, UTXOs, history (mempool.space)
const p = btc.prepare(lin, { to, sat: 5_000n, feerate: await recommendedFeerate() });
await btc.broadcast(p, relayUrl);               // relay in front of a Bitcoin Inquisition node
```

Each spend pays the recipient and re-creates the account at its successor
state in one transaction. Ordinary nodes do not relay OP_CAT spends, so
broadcasting goes through a relay (`bitcoin/relay` in the repository) or
`p.hex` is carried to an Inquisition node by hand. Signet only: mainnet has
neither OP_CAT nor OP_CHECKSIGFROMSTACK.

## Address derivation (the Derive panel)

```ts
import { derive, identity, pqSign, pqVerify } from "@aegis-protocol/sdk";

derive(mnemonic);              // standard addresses: EVM, TRON, Solana, Cosmos family, NEAR, Aptos, Sui, TON, Bitcoin
const id = identity(mnemonic); // also the SLH-DSA-SHAKE-192s (FIPS 205) key pair and the ed25519 / secp256k1 secrets
pqVerify(id.slhPublicKey, digest, pqSign(id, digest));
```

These are the chains' native addresses for the same mnemonic (importable into
each chain's wallet); they are separate from the CCHS accounts above. TRON
helpers (`toTronBase58`, `predictTronAccount`, …) are exported as well.

## Key generation in parallel

In-process keygen of one 1 024-leaf tree takes about a second. Browsers can
spread it over workers:

```ts
// cchs.worker.ts
import { handleLeaves } from "@aegis-protocol/sdk";
self.onmessage = async (e) => self.postMessage(await handleLeaves(e.data));

// app
const pool = createPool({ size: 8, spawn: () => new Worker(new URL("./cchs.worker.ts", import.meta.url), { type: "module" }) });
EvmAccount.derive({ master, chain, publicClient, pool });
```

## Status

The SDK is the same code the site runs, with the same limits
([`README.md`](../README.md#honest-limits), [`SECURITY.md`](../SECURITY.md)):
no external audit; the Solana program's upgrade authority is a single key;
the EVM factory must be present on a chain before an account can be created
there (`protect` publishes it when it is not); Bitcoin is signet only. The
other adapters in the repository (Move, CosmWasm, NEAR, Starknet, TON) are
source only and have no SDK path yet.

## Examples and checks

`examples/` holds runnable node scripts for EVM, Solana and Bitcoin and a
browser sketch. `npm run smoke` runs the offline checks CI runs: addresses on
all three chains, a K-20 signature and an SLH-DSA signature verified locally,
and the size of a Solana execute transaction.

MIT.
