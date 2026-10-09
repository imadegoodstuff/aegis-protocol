// Build and deploy AegisCCHSFactory at one deterministic address on every EVM chain.
// Pure Node: solc-js + viem. No Foundry required.
//
//   node deploy-cchs.mjs --build            compile, write wallet/src/aegis/cchsArtifacts.json
//   node deploy-cchs.mjs <chain> [<chain>…] deploy the built artifact through the
//                                           deterministic-deployment proxy on each chain
//   node deploy-cchs.mjs --status           report factory presence on all known chains
//
// Env: AEGIS_DEPLOYER_KEY=0x… (any funded EOA; nonce does not matter), AEGIS_RPC_<CHAINKEY>=https://…
//
// The factory is created with CREATE2 through the proxy at
// 0x4e59b44847b379578588920cA78FbF26c0B4956C, so its address is a function of
// (salt, init code) only. Identical compiler settings give identical init code,
// hence identical factory and account addresses on every chain.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import solc from "solc";
import {
  createPublicClient, createWalletClient, http, keccak256, concatHex, getContractAddress,
  encodeAbiParameters, formatEther, stringToHex, pad,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import * as chains from "viem/chains";

const __dirname = dirname(fileURLToPath(import.meta.url));
const EVM_DIR = resolve(__dirname, "..", "evm");
const ARTIFACT = resolve(__dirname, "..", "wallet", "src", "aegis", "cchsArtifacts.json");

export const DETERMINISTIC_PROXY = "0x4e59b44847b379578588920cA78FbF26c0B4956C";
export const FACTORY_SALT = keccak256(stringToHex("aegis-cchs-factory/1"));

export const CHAINS = {
  mainnet: chains.mainnet, base: chains.base, arbitrum: chains.arbitrum, optimism: chains.optimism,
  polygon: chains.polygon, bsc: chains.bsc, avalanche: chains.avalanche, linea: chains.linea,
  scroll: chains.scroll, mantle: chains.mantle, blast: chains.blast, mode: chains.mode,
  gnosis: chains.gnosis, celo: chains.celo, // zkSync Era derives CREATE2 differently and is excluded
  sepolia: chains.sepolia, "base-sepolia": chains.baseSepolia,
  "arb-sepolia": chains.arbitrumSepolia, "op-sepolia": chains.optimismSepolia,
};

// ---------- compile ----------
function compileFactory() {
  // Source unit names are paths relative to evm/src with forward slashes, so
  // the contracts' relative imports resolve inside solc without a callback.
  const SRC = resolve(EVM_DIR, "src");
  const unitName = (abs) => relative(SRC, abs).split("\\").join("/");
  const sources = {};
  const seen = new Set();
  const load = (path) => {
    if (seen.has(path)) return;
    seen.add(path);
    const content = readFileSync(path, "utf8");
    sources[unitName(path)] = { content };
    const re = /import\s+(?:\{[^}]*\}\s+from\s+)?["']([^"']+)["']/g;
    let m;
    while ((m = re.exec(content)) !== null) {
      const abs = resolve(dirname(path), m[1]);
      if (!existsSync(abs)) throw new Error(`cannot resolve ${m[1]} from ${path}`);
      load(abs);
    }
  };
  load(resolve(SRC, "AegisCCHSFactory.sol"));
  const input = {
    language: "Solidity",
    sources,
    settings: {
      optimizer: { enabled: true, runs: 1_000_000 },
      viaIR: true,
      evmVersion: "cancun",
      metadata: { bytecodeHash: "none", appendCBOR: false },
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const fatal = (out.errors || []).filter((e) => e.severity === "error");
  if (fatal.length) { for (const e of fatal) console.error(e.formattedMessage); throw new Error("compilation failed"); }
  const pick = (file, name) => {
    const c = out.contracts[file][name];
    return { abi: c.abi, bytecode: "0x" + c.evm.bytecode.object, runtime: "0x" + c.evm.deployedBytecode.object };
  };
  return {
    factory: pick("AegisCCHSFactory.sol", "AegisCCHSFactory"),
    s: pick("AegisCCHS.sol", "AegisCCHS"),
    k: pick("AegisCCHSK.sol", "AegisCCHSK"),
    solc: solc.version(),
  };
}

export function factoryAddressFor(initCode) {
  return getContractAddress({ opcode: "CREATE2", from: DETERMINISTIC_PROXY, salt: FACTORY_SALT, bytecode: initCode });
}

/** Mirrors AegisCCHSFactory.predict. */
export function predictAccount(artifact, root, recRoot, seed, sha256Variant) {
  const creation = sha256Variant ? artifact.account.S.creationCode : artifact.account.K.creationCode;
  const initCode = concatHex([creation, encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes16" }], [root, recRoot, seed])]);
  const salt = keccak256(concatHex([root, recRoot, seed, sha256Variant ? "0x01" : "0x00"]));
  return getContractAddress({ opcode: "CREATE2", from: artifact.factory.address, salt, bytecode: initCode });
}

function build() {
  const c = compileFactory();
  const address = factoryAddressFor(c.factory.bytecode);
  const artifact = {
    solc: c.solc,
    settings: "optimizer 1e6 runs, viaIR, cancun, no metadata",
    proxy: DETERMINISTIC_PROXY,
    salt: FACTORY_SALT,
    factory: { address, abi: c.factory.abi, initCode: c.factory.bytecode, runtimeHash: keccak256(c.factory.runtime) },
    account: {
      S: { creationCode: c.s.bytecode, runtimeBytes: (c.s.runtime.length - 2) / 2 },
      K: { creationCode: c.k.bytecode, runtimeBytes: (c.k.runtime.length - 2) / 2 },
    },
    accountAbi: c.k.abi,
  };
  writeFileSync(ARTIFACT, JSON.stringify(artifact, null, 2));
  console.log(`factory address (all chains): ${address}`);
  console.log(`artifact written: ${ARTIFACT}`);
  return artifact;
}

function loadArtifact() {
  if (!existsSync(ARTIFACT)) throw new Error("run --build first");
  return JSON.parse(readFileSync(ARTIFACT, "utf8"));
}

// Public endpoints used when a chain's viem default is unreliable.
const PUBLIC_RPC = { polygon: "https://1rpc.io/matic" };
function rpcFor(key, chain) {
  return process.env[`AEGIS_RPC_${key.toUpperCase().replace(/-/g, "_")}`] || PUBLIC_RPC[key] || chain.rpcUrls.default.http[0];
}

async function status(artifact) {
  for (const [key, chain] of Object.entries(CHAINS)) {
    const pub = createPublicClient({ chain, transport: http(rpcFor(key, chain)) });
    try {
      const [proxy, fac] = await Promise.all([
        pub.getCode({ address: DETERMINISTIC_PROXY }),
        pub.getCode({ address: artifact.factory.address }),
      ]);
      const facOk = fac && fac !== "0x" ? (keccak256(fac) === artifact.factory.runtimeHash ? "deployed" : "DIFFERENT CODE") : "absent";
      console.log(`${key.padEnd(12)} proxy ${proxy && proxy !== "0x" ? "yes" : "NO "}   factory ${facOk}`);
    } catch (e) {
      console.log(`${key.padEnd(12)} rpc error: ${e.shortMessage || e.message}`);
    }
  }
}

async function deployTo(key, artifact) {
  const chain = CHAINS[key];
  if (!chain) throw new Error(`unknown chain '${key}'`);
  let pk = process.env.AEGIS_DEPLOYER_KEY;
  const local = resolve(__dirname, ".deployer-key.local");
  if (!pk && existsSync(local)) pk = readFileSync(local, "utf8").trim();
  if (!pk) throw new Error("AEGIS_DEPLOYER_KEY not set");
  const account = privateKeyToAccount(pk);
  const rpc = rpcFor(key, chain);
  const pub = createPublicClient({ chain, transport: http(rpc) });
  const wc = createWalletClient({ chain, transport: http(rpc), account });

  console.log(`\n── ${chain.name} (${chain.id}) ── deployer ${account.address}`);
  const existing = await pub.getCode({ address: artifact.factory.address });
  if (existing && existing !== "0x") {
    console.log(keccak256(existing) === artifact.factory.runtimeHash ? "factory already deployed, bytes match" : "address occupied by DIFFERENT code; aborting");
    return;
  }
  const proxyCode = await pub.getCode({ address: DETERMINISTIC_PROXY });
  if (!proxyCode || proxyCode === "0x") { console.log("deterministic-deployment proxy absent on this chain; skip"); return; }

  const bal = await pub.getBalance({ address: account.address });
  console.log(`deployer balance ${formatEther(bal)} ${chain.nativeCurrency.symbol}`);
  const data = concatHex([FACTORY_SALT, artifact.factory.initCode]);
  const gas = await pub.estimateGas({ account, to: DETERMINISTIC_PROXY, data });
  const price = await pub.getGasPrice();
  console.log(`estimated gas ${gas} (~${formatEther(gas * price)} ${chain.nativeCurrency.symbol})`);
  if (bal < gas * price) { console.log("insufficient balance; fund the deployer and rerun"); return; }

  const hash = await wc.sendTransaction({ to: DETERMINISTIC_PROXY, data, gas: (gas * 12n) / 10n });
  console.log(`tx ${hash}`);
  const r = await pub.waitForTransactionReceipt({ hash });
  const code = await pub.getCode({ address: artifact.factory.address });
  const ok = r.status === "success" && code && keccak256(code) === artifact.factory.runtimeHash;
  console.log(ok ? `factory live at ${artifact.factory.address} (gas ${r.gasUsed})` : "deployment did not produce the expected code");
}

async function main() {
  const args = process.argv.slice(2);
  if (!args.length || args.includes("--build")) { build(); if (args.length <= 1) return; }
  const artifact = loadArtifact();
  if (args.includes("--status")) { await status(artifact); return; }
  for (const key of args.filter((a) => !a.startsWith("--"))) await deployTo(key, artifact);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
