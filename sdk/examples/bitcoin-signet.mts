// Bitcoin signet: read the CCHS-UTXO account's lineage, send a payment and
// re-create the account at its successor state, broadcast through a relay in
// front of a Bitcoin Inquisition node.
//
//   AEGIS_MNEMONIC="…" BTC_RELAY=https://… TO=tb1q… SATS=5000 npx tsx examples/bitcoin-signet.mts
//
// Signet coins have no value. Mainnet lacks OP_CAT and OP_CHECKSIGFROMSTACK.

import fs from "node:fs";
import { BitcoinAccount, JsonFileRecordStore, SIGNET_EXPLORER, masterFromMnemonic, recommendedFeerate, setRecordStore } from "@aegis-protocol/sdk";

setRecordStore(new JsonFileRecordStore("./aegis-records.json", fs));

const btc = BitcoinAccount.derive({ master: masterFromMnemonic(process.env.AEGIS_MNEMONIC!) });
console.log("first address", btc.address0, `${SIGNET_EXPLORER}/address/${btc.address0}`);

const lin = await btc.sync();                         // follows every spend from the first address
const balance = lin.utxos.reduce((a, u) => a + u.value, 0n);
console.log("current address", lin.address, "balance", balance, "sat", "next leaf", lin.nextLeaf, "spends left", btc.spendsLeft(lin.state));

if (process.env.TO && balance > 0n) {
  const p = btc.prepare(lin, { to: process.env.TO, sat: BigInt(process.env.SATS ?? "5000"), feerate: await recommendedFeerate() });
  console.log(`prepared ${p.txid}: ${p.vsize} vB, ${p.fee} sat fee, leaf ${p.leaf}, successor ${p.nextAddress}`);
  const relay = process.env.BTC_RELAY;
  if (relay) console.log("broadcast", await btc.broadcast(p, relay));
  else console.log("no BTC_RELAY set; submit this to a Bitcoin Inquisition node:\n" + p.hex);
}
