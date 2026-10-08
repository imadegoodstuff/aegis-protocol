// Compiles + deploys the Aegis V2 stack to a public testnet.
// Pure Node: solc-js + viem. No Foundry required.
//
// Usage:
//   AEGIS_DEPLOYER_KEY=0x...  (fresh EOA, nonce 0)
//   AEGIS_FEE_COLLECTOR=0x... (any address)
//   AEGIS_RPC=https://sepolia.rpc...
//   node deploy.mjs sepolia

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import solc from "solc";
import { createPublicClient, createWalletClient, http, parseAbi, encodeDeployData, parseEther, formatEther } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { sepolia, baseSepolia, optimismSepolia, arbitrumSepolia } from "viem/chains";

const __dirname = dirname(fileURLToPath(import.meta.url));
const EVM_DIR   = resolve(__dirname, "..", "evm");

const CHAINS = { sepolia, "base-sepolia": baseSepolia, "op-sepolia": optimismSepolia, "arb-sepolia": arbitrumSepolia };

// ---------- source resolver (handles our relative imports) ----------
function findSource(importPath, parent) {
  const base = parent ? dirname(parent) : resolve(EVM_DIR, "src");
  const abs = resolve(base, importPath);
  if (existsSync(abs)) return { path: abs, contents: readFileSync(abs, "utf8") };
  // try evm/src/
  const alt = resolve(EVM_DIR, "src", importPath);
  if (existsSync(alt)) return { path: alt, contents: readFileSync(alt, "utf8") };
  throw new Error(`cannot resolve import ${importPath} from ${parent}`);
}

function compile(entryFile) {
  const sources = {};
  const seen = new Set();

  function load(path) {
    if (seen.has(path)) return;
    seen.add(path);
    const content = readFileSync(path, "utf8");
    sources[path] = { content };
    // parse imports
    const re = /import\s+(?:\{[^}]*\}\s+from\s+)?["']([^"']+)["']/g;
    let m;
    while ((m = re.exec(content)) !== null) {
      const resolved = findSource(m[1], path);
      load(resolved.path);
    }
  }
  load(entryFile);

  const input = {
    language: "Solidity",
    sources,
    settings: {
      optimizer: { enabled: true, runs: 1_000_000 },
      viaIR: true,
      evmVersion: "cancun",
      metadata: { bytecodeHash: "none" },
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  if (output.errors) {
    const fatal = output.errors.filter(e => e.severity === "error");
    if (fatal.length) {
      for (const e of fatal) console.error(e.formattedMessage);
      throw new Error("Solidity compilation failed");
    }
  }
  return output;
}

function get(output, filePath, contractName) {
  const file = output.contracts[filePath];
  if (!file || !file[contractName]) throw new Error(`${contractName} not found in ${filePath}`);
  const c = file[contractName];
  return { abi: c.abi, bytecode: ("0x" + c.evm.bytecode.object) };
}

// ---------- main ----------
async function main() {
  const chainKey = process.argv[2] || "sepolia";
  const chain = CHAINS[chainKey];
  if (!chain) { console.error(`Unknown chain '${chainKey}'. Known: ${Object.keys(CHAINS).join(", ")}`); process.exit(1); }

  let pk = process.env.AEGIS_DEPLOYER_KEY;
  if (!pk) {
    // generate a fresh key and save it. The user is NOT in the loop — we show the address.
    pk = generatePrivateKey();
    const outFile = resolve(__dirname, ".deployer-key.local");
    writeFileSync(outFile, pk, { mode: 0o600 });
    console.log(`[genkey] fresh deployer key written to ${outFile}`);
  }
  const account = privateKeyToAccount(pk);

  const feeCollector = process.env.AEGIS_FEE_COLLECTOR || account.address;
  const rpc = process.env.AEGIS_RPC || chain.rpcUrls.default.http[0];

  console.log("─ Aegis V2 deploy ─────────────────────────────");
  console.log("chain          :", chain.name, `(${chain.id})`);
  console.log("rpc            :", rpc);
  console.log("deployer       :", account.address);
  console.log("fee collector  :", feeCollector);

  const publicClient = createPublicClient({ chain, transport: http(rpc) });
  const walletClient = createWalletClient({ chain, transport: http(rpc), account });

  const bal = await publicClient.getBalance({ address: account.address });
  console.log("deployer bal   :", formatEther(bal), chain.nativeCurrency.symbol);
  if (bal < parseEther("0.005")) {
    console.log("\n❌ Deployer has <0.005 ETH. Please send some test ETH to:");
    console.log("   " + account.address);
    console.log("\n   Faucets:");
    console.log("   https://www.alchemy.com/faucets/ethereum-sepolia");
    console.log("   https://sepolia-faucet.pk910.de/   (PoW, no login)");
    console.log("   https://cloud.google.com/application/web3/faucet/ethereum/sepolia");
    process.exit(2);
  }

  // ---------- compile ----------
  console.log("\n[1/4] compiling …");
  const stubOut    = compile(resolve(EVM_DIR, "src/SphincsVerifierStub.sol"));
  const factoryOut = compile(resolve(EVM_DIR, "src/AegisAccountV2Factory.sol"));
  const helperOut  = compile(resolve(EVM_DIR, "src/UpgradeHelper.sol"));

  const stub    = get(stubOut,    resolve(EVM_DIR, "src/SphincsVerifierStub.sol"),  "SphincsVerifierStub");
  const factory = get(factoryOut, resolve(EVM_DIR, "src/AegisAccountV2Factory.sol"),"AegisAccountV2Factory");
  const helper  = get(helperOut,  resolve(EVM_DIR, "src/UpgradeHelper.sol"),        "UpgradeHelper");
  console.log("compiled: SphincsVerifierStub, AegisAccountV2Factory, UpgradeHelper");

  // ---------- deploy ----------
  async function deploy(name, abi, bytecode, args = []) {
    const hash = await walletClient.deployContract({ abi, bytecode, args });
    console.log(`[deploy] ${name}  tx=${hash}`);
    const r = await publicClient.waitForTransactionReceipt({ hash });
    console.log(`[deploy] ${name}  @  ${r.contractAddress}  (gas=${r.gasUsed})`);
    return r.contractAddress;
  }

  console.log("\n[2/4] deploying SphincsVerifierStub (nonce 0) …");
  const verifier = await deploy("verifier", stub.abi, stub.bytecode);

  console.log("\n[3/4] deploying AegisAccountV2Factory (nonce 1) …");
  const factoryAddr = await deploy("factory",  factory.abi, factory.bytecode, [verifier, feeCollector]);

  console.log("\n[4/4] deploying UpgradeHelper (nonce 2) …");
  const helperAddr = await deploy("helper",  helper.abi, helper.bytecode, [factoryAddr]);

  // ---------- persist deployment artifact ----------
  const outDir = resolve(EVM_DIR, "deployments");
  mkdirSync(outDir, { recursive: true });
  const outFile = resolve(outDir, `${chainKey}.json`);
  const artifact = {
    chain: { key: chainKey, name: chain.name, id: chain.id, rpc },
    deployer: account.address,
    feeCollector,
    verifier,
    factory: factoryAddr,
    upgradeHelper: helperAddr,
    abis: { factory: factory.abi, helper: helper.abi, verifier: stub.abi },
    deployedAt: new Date().toISOString(),
  };
  writeFileSync(outFile, JSON.stringify(artifact, null, 2));
  console.log(`\n✓ deployment saved: ${outFile}`);
  console.log("\n────────── summary ──────────");
  console.log(`chain:    ${chain.name} (${chain.id})`);
  console.log(`verifier: ${verifier}`);
  console.log(`factory:  ${factoryAddr}`);
  console.log(`helper:   ${helperAddr}`);

  // Also emit a compact config the wallet can import
  const walletCfg = resolve(__dirname, "..", "wallet", "src", "aegis", `deployment.${chainKey}.json`);
  mkdirSync(dirname(walletCfg), { recursive: true });
  writeFileSync(walletCfg, JSON.stringify({
    chainId: chain.id, verifier, factory: factoryAddr, upgradeHelper: helperAddr,
  }, null, 2));
  console.log(`✓ wallet config:  ${walletCfg}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
