// Protect SOL and an SPL / Token-2022 token (a memecoin, say) in a CCHS-C-20
// vault on Solana mainnet-beta, then spend some of it, from node with a
// keypair fee payer.
//
//   AEGIS_MNEMONIC="…" SOLANA_PAYER=~/.config/solana/id.json npx tsx examples/solana-protect.mts
//
// The fee payer pays rent and fees; it has no authority over the vault.

import fs from "node:fs";
import { JsonFileRecordStore, Rpc, SolanaAccount, keypairFeePayer, masterFromMnemonic, setRecordStore, toBase58 } from "@aegis-protocol/sdk";

setRecordStore(new JsonFileRecordStore("./aegis-records.json", fs));

const master = masterFromMnemonic(process.env.AEGIS_MNEMONIC!);
const rpc = new Rpc(process.env.SOLANA_RPC ?? "https://api.mainnet-beta.solana.com");
const payer = keypairFeePayer(new Uint8Array(JSON.parse(fs.readFileSync(process.env.SOLANA_PAYER!, "utf8"))), rpc);

const acct = await SolanaAccount.derive({ master, rpc, cluster: "mainnet-beta" });
console.log("account", acct.account, "vault", acct.vault);

if (!(await acct.state())) {
  const c = await acct.create(payer);                    // account + lookup table, one transaction
  console.log("created", c.signature, "table", c.table);
}

await acct.depositSol(payer, 5_000_000n);                 // 0.005 SOL into the vault
const tokens = await acct.feePayerTokens(payer);
const meme = tokens.find((t) => toBase58(t.mint) === process.env.MINT);   // MINT=<base58 mint address>
if (meme) await acct.depositToken(payer, meme, meme.amount);

const held = await acct.holdings();
console.log("vault holds", held);

// Send 0.001 SOL back to the fee payer: one WOTS+ leaf (cache_subtree first when the subtree is new).
const r = await acct.spend(payer, { kind: "sol", to: payer.address, amount: 1_000_000n }, (s) => console.log(s));
console.log("executed", r);
