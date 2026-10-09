// Publish AegisCCHSFactory on TRON from a user-supplied key.
//
//   TRON_PRIVATE_KEY=<64 hex>  node deploy-factory.mjs nile
//   TRON_PRIVATE_KEY=<64 hex>  node deploy-factory.mjs mainnet
//   TRON_PRIVATE_KEY=<64 hex>  node deploy-factory.mjs nile --dry-run    (estimate only, no broadcast)
//
// Optional env: TRON_PRO_API_KEY (TronGrid API key header), TRON_FULL_HOST (override endpoint),
//               TRON_FEE_LIMIT_SUN (default 2 000 000 000 = 2 000 TRX ceiling; unused energy is not charged).
//
// There is no deterministic-deployment proxy on TRON, so this is a plain
// CREATE from the key's account. The resulting address depends on the
// transaction id and the owner; it is printed at the end and must be recorded
// by whoever publishes (every publisher gets a different factory address).
//
// Reads tron/artifacts/cchs-tvm.json (run build.mjs first). Never run against
// a network you did not intend: the network name is a required positional
// argument and the script exits before doing anything if the key is missing.

import { readFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { TronWeb } from "tronweb";
import { tronCreateFromTx, formatAddress, parseAddress20 } from "./predict.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ARTIFACT = resolve(__dirname, "artifacts", "cchs-tvm.json");

const NETWORKS = {
  nile: { fullHost: "https://nile.trongrid.io", explorer: "https://nile.tronscan.org/#/contract/" },
  mainnet: { fullHost: "https://api.trongrid.io", explorer: "https://tronscan.org/#/contract/" },
};

// Energy is paid entirely by the caller of each factory function, as on Ethereum,
// so the publisher's stake is never drained by third-party account creation.
const USER_FEE_PERCENTAGE = 100;
const ORIGIN_ENERGY_LIMIT = 10_000_000;

function hexToBytes(h) { return Uint8Array.from(Buffer.from(h.replace(/^0x/, ""), "hex")); }

async function main() {
  const args = process.argv.slice(2);
  const network = args.find((a) => !a.startsWith("--"));
  const dryRun = args.includes("--dry-run");
  if (!network || !NETWORKS[network]) {
    console.error(`usage: node deploy-factory.mjs <${Object.keys(NETWORKS).join("|")}> [--dry-run]`);
    process.exit(2);
  }
  const pk = (process.env.TRON_PRIVATE_KEY || "").trim().replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{64}$/.test(pk)) {
    console.error("TRON_PRIVATE_KEY is not set (expected 64 hex characters). Refusing to run.");
    process.exit(2);
  }
  if (!existsSync(ARTIFACT)) throw new Error("tron/artifacts/cchs-tvm.json missing; run node build.mjs first");
  const artifact = JSON.parse(readFileSync(ARTIFACT, "utf8"));

  const fullHost = process.env.TRON_FULL_HOST || NETWORKS[network].fullHost;
  const headers = process.env.TRON_PRO_API_KEY ? { "TRON-PRO-API-KEY": process.env.TRON_PRO_API_KEY } : undefined;
  const tronWeb = new TronWeb({ fullHost, headers, privateKey: pk });
  const owner = tronWeb.defaultAddress.base58;

  // Refuse to publish bytecode that needs a chain parameter this network has not enabled.
  const params = await tronWeb.trx.getChainParameters();
  const enabled = new Set(params.filter((p) => p.value === 1).map((p) => p.key));
  const missing = artifact.requiredChainParameters.filter((k) => !enabled.has(k));
  if (missing.length) throw new Error(`network ${network} has not enabled ${missing.join(", ")}; rebuild with a lower --evm target`);

  const balanceSun = await tronWeb.trx.getBalance(owner);
  const energyFee = params.find((p) => p.key === "getEnergyFee")?.value ?? 100;
  const feeLimit = Number(process.env.TRON_FEE_LIMIT_SUN || 2_000_000_000);
  const bytes = (artifact.factory.bytecode.length - 2) / 2;
  console.log(`network      ${network} (${fullHost})`);
  console.log(`publisher    ${owner}   balance ${(balanceSun / 1e6).toFixed(6)} TRX`);
  console.log(`factory      ${bytes} B init code, solc ${artifact.solc}, evmVersion ${artifact.settings.evmVersion}`);
  console.log(`fee limit    ${feeLimit} sun (${feeLimit / 1e6} TRX) at ${energyFee} sun per energy -> up to ${Math.floor(feeLimit / energyFee)} energy`);
  console.log(`energy split caller ${USER_FEE_PERCENTAGE}% / publisher ${100 - USER_FEE_PERCENTAGE}%`);

  // Build the unsigned deployment so the address can be derived before broadcast.
  const tx = await tronWeb.transactionBuilder.createSmartContract({
    abi: artifact.factory.abi,
    bytecode: artifact.factory.bytecode.replace(/^0x/, ""),
    feeLimit,
    callValue: 0,
    userFeePercentage: USER_FEE_PERCENTAGE,
    originEnergyLimit: ORIGIN_ENERGY_LIMIT,
    name: "AegisCCHSFactory",
  }, owner);
  const predicted = formatAddress(tronCreateFromTx(hexToBytes(tx.txID), parseAddress20(owner)));
  const nodeSays = tx.contract_address ? formatAddress(parseAddress20(tx.contract_address)) : null;
  console.log(`txid         ${tx.txID}`);
  console.log(`address      ${predicted.base58} (${predicted.hex21})${nodeSays ? (nodeSays.base58 === predicted.base58 ? "  [node agrees]" : `  [node says ${nodeSays.base58}]`) : ""}`);

  if (dryRun) { console.log("dry run: not signed, not broadcast"); return; }
  if (balanceSun < feeLimit) console.log("warning: balance is below the fee limit; the transaction may fail with OUT_OF_ENERGY");

  const signed = await tronWeb.trx.sign(tx);
  const res = await tronWeb.trx.sendRawTransaction(signed);
  if (!res.result) throw new Error(`broadcast rejected: ${JSON.stringify(res)}`);
  console.log("broadcast ok; waiting for the transaction to be included");

  let info = null;
  for (let i = 0; i < 40 && (!info || !info.receipt); i++) {
    await new Promise((r) => setTimeout(r, 3000));
    info = await tronWeb.trx.getTransactionInfo(tx.txID);
  }
  if (!info || !info.receipt) throw new Error("transaction not confirmed after 120 s; check the explorer with the txid above");
  if (info.receipt.result !== "SUCCESS") throw new Error(`deployment failed: ${info.receipt.result} ${info.resMessage ? Buffer.from(info.resMessage, "hex").toString() : ""}`);

  const deployed = formatAddress(parseAddress20(info.contract_address));
  const code = await tronWeb.trx.getContract(deployed.base58);
  const runtimeHex = "0x" + (code.bytecode || "");
  const matches = runtimeHex.toLowerCase() === artifact.factory.runtime.toLowerCase();
  console.log(`deployed     ${deployed.base58} (${deployed.hex21})  energy used ${info.receipt.energy_usage_total}`);
  console.log(`runtime      ${matches ? "matches artifact" : "DOES NOT MATCH artifact runtime"}`);
  console.log(`explorer     ${NETWORKS[network].explorer}${deployed.base58}`);
  console.log(`\nRecord this factory address; the wallet needs it to predict account addresses on ${network}.`);
}

main().catch((e) => { console.error(e.message || e); process.exit(1); });
