// Protect ETH and one ERC-20 on Base with a CCHS-K-20 account, then send
// some of it out, from node with a private-key fee payer.
//
//   AEGIS_MNEMONIC="…" FEE_PAYER_KEY=0x… npx tsx examples/evm-protect.mts
//
// The fee payer pays gas and holds no authority over the account. The
// mnemonic (the only secret) never leaves this process; index records go to
// ./aegis-records.json so a leaf is never signed twice across runs.

import fs from "node:fs";
import { createWalletClient, http, parseEther, parseUnits } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";
import { EvmAccount, JsonFileRecordStore, makePublicClient, masterFromMnemonic, setRecordStore } from "@aegis-protocol/sdk";

setRecordStore(new JsonFileRecordStore("./aegis-records.json", fs));

const master = masterFromMnemonic(process.env.AEGIS_MNEMONIC!);
const publicClient = makePublicClient(base);   // or createPublicClient({ chain: base as Chain, transport: http() })
const feePayer = privateKeyToAccount(process.env.FEE_PAYER_KEY as `0x${string}`);
const walletClient = createWalletClient({ account: feePayer, chain: base, transport: http() });

const acct = await EvmAccount.derive({ master, chain: base, publicClient });
console.log("account", acct.address, await acct.status());

const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
await acct.protect(walletClient, {
  value: parseEther("0.01"),
  tokens: [USDC],                       // the fee payer's whole USDC balance
  onStep: (s, tx) => console.log(s, tx ?? ""),
});

const r = await acct.execute(walletClient, EvmAccount.erc20Transfer(USDC, feePayer.address, parseUnits("1", 6)));
console.log(`sent 1 USDC back: ${r.hash} (leaf ${r.idx}, ${r.layers} layer(s), ${r.signatureBytes} signature bytes)`);
