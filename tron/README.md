# Aegis - TRON adapter

**Status (2026-10-08):** compiled for the TVM and opcode-checked (`tron/build.mjs`);
address prediction implemented and tested against documented vectors
(`tron/predict.mjs`, `wallet/src/aegis/tronAccount.ts`); factory publisher
written but **not run** (`tron/deploy-factory.mjs`). Nothing is deployed on
Nile or mainnet yet. No factory address exists for TRON.

## What is identical to the EVM chains

- **Contract sources.** `evm/src/AegisCCHSBase.sol`, `AegisCCHS.sol`,
  `AegisCCHSK.sol`, `AegisCCHSFactory.sol` are compiled unchanged.
- **Bytecode.** With the same compiler and settings (solc 0.8.37, optimizer
  1 000 000 runs, viaIR, evmVersion `cancun`, no metadata) the TVM build is
  byte-identical to `wallet/src/aegis/cchsArtifacts.json`; `build.mjs` checks
  and records this (`identicalToEvmArtifact: true`). One audit covers both.
- **Signatures and parameter set.** CCHS-K-20 (keccak256) is the default,
  CCHS-S-20 (SHA-256 precompile at `0x02`) is also deployable. The TVM
  precompile set `0x01`-`0x0a` matches the EVM except RIPEMD-160 and Blake2F,
  which CCHS does not use. The client digest is
  `keccak/sha256("AEGIS_CCHS_V1" || chainid || account || nonce || idx || ...)`,
  so a TRON signature is bound to TRON's `CHAINID` and cannot be replayed on
  an EVM chain or vice versa.
- **Storage layout, events, errors, ABI.** Same artifact, same ABI.

## What differs

| Topic | EVM | TRON |
|---|---|---|
| CREATE2 address | `keccak256(0xff || sender || salt || keccak256(initCode))[12..]` | `keccak256(0x41 || sender || salt || keccak256(initCode))[12..]` |
| Factory address | one address on every chain via the deterministic-deployment proxy `0x4e59b44847b379578588920cA78FbF26c0B4956C` | the proxy is **absent** on mainnet and Nile (`wallet/getcontract` returns `{}`); the factory is published with a plain CREATE from a key, so its address depends on the publisher and the transaction id |
| Account address | same on every EVM chain | a different 20 bytes, different per factory; shown as `base58check(0x41 || addr20)`, 34 characters starting with `T` |
| `AegisCCHSFactory.predict()` on chain | correct | **wrong** - it hard-codes `0xff`. `deploy()` is unaffected: it creates the account at the TRON CREATE2 address (the `new{salt}` opcode is what the TVM derives from), records it in `accountOf(salt)`, and decides idempotence from that record, so a second `deploy()` returns the existing account. Predict off-chain (`predict.mjs`, `tronAccount.ts`) or read `accountOf` |
| `CHAINID` | fixed per network (1, 56, ...) | last 4 bytes of the genesis block id: mainnet `728126428`, Shasta `2494104990`, Nile `3448148188` |
| Fee model | gas, EIP-1559 fee market | **Energy** (compute) and **Bandwidth** (bytes). Energy comes from staked TRX or is burned at `getEnergyFee` = 100 sun per unit (0.0001 TRX; lowered from 210 on 2025-08-29); Bandwidth at 1 000 sun per byte beyond the 600/day free quota. Every contract call carries `fee_limit` in sun (max `getMaxFeeLimit` = 15 000 TRX). `GASPRICE` and `BASEFEE` both return the energy price. No priority fee |
| Per-transaction CPU cap | none (gas only) | `getMaxCpuTimeOfOneTx` = 80 ms wall clock, independent of energy; a transaction over it fails with `OUT_OF_TIME` |
| Opcode gating | by hard fork | by SR-voted chain parameters (`getAllowTvm*`), independent per network |
| Browser wallet | `window.ethereum` (EIP-1193) | TronLink injects `window.tronLink` / `window.tronWeb`; transactions are protobuf, signed with `tronWeb.trx.sign`, broadcast with `sendRawTransaction`. TronGrid also exposes an Ethereum-style JSON-RPC (`/jsonrpc`) that is read-only for our purposes |
| Compiler | upstream solc | TronBox / TronIDE bundle a TRON fork of solc (adds `trcToken`, `trx`/`sun` units); upstream solc output deploys fine when none of those extensions are used. Tronscan source verification expects the TRON compiler version, which may not reproduce upstream 0.8.37 bytecode exactly |

## TVM capabilities today

Live values read from `wallet/getchainparameters` on 2026-10-08 (mainnet
`https://api.trongrid.io`, Nile `https://nile.trongrid.io`): both networks
return `1` for `getAllowTvmConstantinople`, `getAllowTvmIstanbul`,
`getAllowTvmLondon`, `getAllowTvmShangHai`, `getAllowTvmCancun`,
`getAllowTvmBlob`, `getAllowTvmPrague`, `getAllowTvmOsaka`,
`getAllowTvmSelfdestructRestriction`; `getEnergyFee` = 100,
`getMaxFeeLimit` = 15 000 000 000 sun. Shasta was not queried.

| Feature | TVM status | Source |
|---|---|---|
| `PUSH0` (0x5f) | implemented in GreatVoyage-v4.7.2, enabled by proposal 76 (2023) | https://github.com/tronprotocol/tips/blob/master/tip-543.md, https://github.com/tronprotocol/tips/issues/578 |
| `TLOAD`/`TSTORE` (0x5c/0x5d), `MCOPY` (0x5e) | implemented in v4.8.0 (TIP-650, TIP-651), enabled on mainnet by committee proposal 103 (parameter 83) on 2025-06-26 | https://tronprotocol.github.io/documentation-en/releases/versions/v4.8.0/, https://github.com/tronprotocol/tips/issues/763, https://github.com/tronprotocol/tips/tree/master/proposal |
| `BLOBHASH`/`BLOBBASEFEE` (0x49/0x4a) | stubs returning 0, enabled with parameter 89 in the same proposal | https://developers.tron.network/docs/opcodes |
| `SELFDESTRUCT` | EIP-6780 semantics, 5 000 energy (TIP-6780) | https://github.com/tronprotocol/tips/blob/master/tip-6780.md |
| `CLZ` (0x1e), `P256VERIFY` | Osaka set, parameter 96 (`getAllowTvmOsaka`), active on mainnet and Nile per the live query | https://developers.tron.network/docs/opcodes |
| SHA-256 precompile `0x02` | present, EVM-compatible | https://developers.tron.network/docs/tvm-vs-evm |
| Hard-fork gate table, CREATE2 prefix, energy model, 80 ms cap | reference page | https://developers.tron.network/docs/tvm-vs-evm |
| Energy, `fee_limit`, resource burning | reference pages | https://developers.tron.network/docs/set-feelimit, https://developers.tron.network/docs/paying-for-resources, https://developers.tron.network/docs/network-parameters |
| Address encoding and documented vectors | `418840E6C55B9ADA326D211D818C34A994AECED808` = `TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL` | https://developers.tron.network/docs/account, https://developers.tron.network/docs/encoding |
| TronBox compilers | TRON solc 0.8.x up to 0.8.31 (default for new projects); `evmVersion` is a plain solc setting in `tronbox-config.js` | https://github.com/tronprotocol/tronbox/releases, https://tronbox.io/docs/reference/configuration |
| TronWeb | 6.5.1 (2026-09-16) | https://www.npmjs.com/package/tronweb, https://tronweb.network/docu/docs/API%20List/contract/tronweb.contract().new |

### Chosen evmVersion: `cancun`

- Every opcode solc emits for `cancun` (`PUSH0`, `MCOPY`; it never emits
  `TLOAD`/`TSTORE` without the `transient` keyword, and we use none) is live
  on TRON mainnet and Nile, verified above.
- It is the setting of the EVM artifact, so the TRON init code is the same
  bytes; nothing new to audit and the account creation code the wallet already
  ships (`cchsArtifacts.json`) is valid for TRON prediction.
- `prague` adds no legacy-bytecode opcodes over `cancun`; `osaka` may emit
  `CLZ`, which depends on a gate (96) that the Shasta testnet has not been
  checked for. A trial `--evm osaka` build of these sources emitted no `CLZ`
  and the same required gates, so neither target buys anything.
- If a network lacks the Cancun gate, `node build.mjs --evm shanghai` produces
  a build without `MCOPY` (sizes below); the scanner then rejects any Cancun
  opcode. Upstream solc 0.8.37 compiled these sources for `paris`,
  `shanghai`, `cancun` and `osaka` without complaint, so no compiler change
  is needed either way.

### Opcode scan (`node build.mjs`, 2026-10-08)

A linear walker that skips PUSH immediates classifies every byte of both the
creation and the runtime bytecode against the TVM opcode table and the gate
each opcode needs. Unassigned opcodes, TRON-only opcodes (0xd0-0xdf, which
solc never emits) and opcodes behind a gate above the target are failures.

| Contract | creation | runtime | gated opcodes used | unassigned |
|---|---|---|---|---|
| `AegisCCHSFactory` | 14 503 B | 14 477 B | PUSH0 x178, MCOPY x5, SHL/SHR, CREATE2 x2, CHAINID x4 | 0 |
| `AegisCCHS` (S-20) | 6 347 B | 6 184 B | PUSH0 x72, MCOPY x2, SHL/SHR, CHAINID x2 | 0 |
| `AegisCCHSK` (K-20) | 6 235 B | 6 072 B | PUSH0 x62, MCOPY x1, SHL/SHR, CHAINID x2 | 0 |

No `TLOAD`, `TSTORE`, `BLOBHASH`, `BLOBBASEFEE`, `CLZ` or `SELFDESTRUCT`.
Required chain parameters, recorded in the artifact:
`getAllowTvmConstantinople`, `getAllowTvmIstanbul`, `getAllowTvmShangHai`,
`getAllowTvmCancun`. The `--evm shanghai` build is 14 593 / 14 567 B,
6 384 / 6 221 B and 6 261 / 6 098 B with no Cancun opcodes.

Artifact: `tron/artifacts/cchs-tvm.json` (abi, bytecode, runtime, runtime
keccak and settings for the three contracts, plus the scan summary).

## Files

| File | Purpose |
|---|---|
| `build.mjs` | compile the four sources for the TVM, scan opcodes, write the artifact; `--evm <target>` to change the target |
| `predict.mjs` | TRON CREATE2 prediction for accounts and for a CREATE2-published factory; CREATE address from `(txid, owner)`; base58check helpers; `--self-test` |
| `deploy-factory.mjs` | publish the factory from `TRON_PRIVATE_KEY` to Nile or mainnet with TronWeb; refuses to run without the key |
| `package.json` | `tronweb` dependency (`npm install` here; `node_modules` is ignored) |
| `../wallet/src/aegis/tronAccount.ts` | the same derivations for the wallet, using its existing dependencies (viem, `@noble/hashes`, `@scure/base`); `TRON_CHAIN_IDS`, `TRON_FULL_HOSTS` |

`build.mjs` and `predict.mjs` reuse `solc` and `viem` from
`deploy/node_modules` (run `npm install` in `deploy/` once).

## Publishing the factory and creating an account

```powershell
cd tron
npm install                                     # tronweb
node build.mjs                                  # -> artifacts/cchs-tvm.json, must print no FAIL lines
node predict.mjs --self-test                    # base58check and CREATE2 vectors

# 1. Publish the factory. Fund the key on Nile from https://nileex.io/join/getJoinPage
#    (mainnet: real TRX). Dry run first: builds the unsigned transaction and
#    prints the address it would get, without signing or broadcasting.
$env:TRON_PRIVATE_KEY = "<64 hex>"
node deploy-factory.mjs nile --dry-run
node deploy-factory.mjs nile                    # prints "deployed T..."; record it
Remove-Item Env:TRON_PRIVATE_KEY

# 2. Predict the account for your CCHS roots (K-20 is the default variant).
node predict.mjs account --factory <T... factory> --root 0x<root> --rec-root 0x<recRoot> --variant K
```

Energy for publishing: java-tron charges a code deposit of 200 energy per
runtime byte (`EnergyCost.CREATE_DATA`, same figure as the EVM; not
re-measured here), so the factory is roughly 14 477 x 200 = 2.9 M energy
plus execution, about 3 M energy = 300 TRX if burned at 100 sun, or free
against staked energy. An account creation through the factory is roughly
1.3 M energy (EVM measurement, `CCHS.spec.md` 5.2) = 130 TRX if burned.
These are estimates; the dry run does not estimate energy. Use
`tronWeb.transactionBuilder.estimateEnergy` or Nile for a real figure.

3. Create the account (TronWeb, any funded key; the factory is permissionless):

```js
import { TronWeb } from "tronweb";
const tronWeb = new TronWeb({ fullHost: "https://nile.trongrid.io", privateKey: process.env.TRON_PRIVATE_KEY });
const { transaction } = await tronWeb.transactionBuilder.triggerSmartContract(
  factoryBase58, "deploy(bytes32,bytes32,bool)", { feeLimit: 300_000_000, callValue: 0 },
  [{ type: "bytes32", value: root }, { type: "bytes32", value: recRoot }, { type: "bool", value: false }]);
const signed = await tronWeb.trx.sign(transaction);
await tronWeb.trx.sendRawTransaction(signed);
```

The `AccountDeployed` event carries the real address; it must equal the
`predict.mjs account` output. `callValue` may fund the account in the same
transaction (TRX is forwarded by the factory). Call `deploy` once per
`(root, recRoot, variant)`; a repeat reverts on TRON (see the table above).

4. Signing from the wallet: the CCHS client is unchanged; pass TRON's chain id
(`TRON_CHAIN_IDS` in `tronAccount.ts`) and the TRON account address into the
digest, then call `execute(...)` through TronLink or TronWeb with a
`fee_limit` sized from the EVM gas numbers (cached K-20 signature ~177 K gas
on the EVM; TVM energy costs match except cheaper `SLOAD`/`CALL`).

## Open items and risks

- **Not deployed.** No Nile or mainnet run has happened. The tronweb calls in
  `deploy-factory.mjs` were checked against the 6.5.1 type definitions only;
  the CREATE address formula `keccak256(txid || 0x41 || owner20)[12..]`
  mirrors java-tron `WalletUtil.generateContractAddress` and is cross-checked
  against the node's `contract_address` field at dry-run time, but has not
  been exercised yet.
- **Factory address is per publisher.** The wallet must be given the TRON
  factory address (and chain id) explicitly; it cannot derive it as on the
  EVM chains. A TRON CREATE2 deployer contract would make it salt-determined
  per deployer, which is what `predict.mjs factory` computes; none is in this
  repository.
- **`predict()` on chain is wrong on TRON** (EVM `0xff` rule). `deploy()`
  and `accountOf` are correct; a TRON-aware `predict()` would need a separate
  factory source and end bytecode identity with the EVM artifact, so the
  client-side predictor is used instead.
- **80 ms CPU cap.** A first-in-subtree S-20 verification is ~450 K gas worth
  of hashing on the EVM. It has not been timed on a TVM node; if it exceeds
  80 ms the transaction fails with `OUT_OF_TIME` regardless of `fee_limit`.
  Test on Nile before mainnet.
- **TRC-20 pulls.** `deployAndMove` uses `transferFrom` and `balanceOf`;
  TRC-20 tokens follow the same ABI. Not tested on TRON.
- **TRX sent by `TransferContract`** reaches the account without running
  `receive()`; that is fine for an account that only needs to hold balance.
- **Source verification on Tronscan** may require recompiling with the TRON
  solc fork; the bytecode may then differ from the upstream build (metadata
  is already disabled, which removes the usual source of mismatch).
