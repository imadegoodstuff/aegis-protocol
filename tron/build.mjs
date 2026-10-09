// TVM build of the CCHS account + factory.
//
//   node build.mjs                 compile for evmVersion "cancun" (default, see README)
//   node build.mjs --evm shanghai  compile for an older target and reject Cancun opcodes
//
// Compiles the same four sources as deploy/deploy-cchs.mjs (AegisCCHSBase,
// AegisCCHS, AegisCCHSK, AegisCCHSFactory) with the solc-js that the deploy
// folder already carries, using the same optimizer settings, then walks the
// bytecode of every contract and refuses to write an artifact that contains
// an opcode the TRON Virtual Machine does not execute at the chosen target.
//
// Output: tron/artifacts/cchs-tvm.json
//
// Nothing here touches the EVM build or wallet/src/aegis/cchsArtifacts.json.

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const SRC = resolve(ROOT, "evm", "src");
const OUT_DIR = resolve(__dirname, "artifacts");
const OUT = resolve(OUT_DIR, "cchs-tvm.json");
const EVM_ARTIFACT = resolve(ROOT, "wallet", "src", "aegis", "cchsArtifacts.json");

// solc-js and viem live in deploy/node_modules; reuse them instead of adding a copy.
const deployRequire = createRequire(resolve(ROOT, "deploy", "package.json"));
const solc = deployRequire("solc");
const { keccak256 } = deployRequire("viem");

// ---------- TVM opcode table ----------
// Source: https://developers.tron.network/docs/opcodes and
// https://developers.tron.network/docs/tvm-vs-evm (hardfork gate table).
// Each entry: name and the chain-parameter gate that must be enabled for the
// opcode to execute. "base" means part of the original TVM.
const GATE_ORDER = ["base", "constantinople", "istanbul", "london", "shanghai", "cancun", "blob", "prague", "osaka"];
const GATE_PARAM = {
  constantinople: "getAllowTvmConstantinople",
  istanbul: "getAllowTvmIstanbul",
  london: "getAllowTvmLondon",
  shanghai: "getAllowTvmShangHai",
  cancun: "getAllowTvmCancun",
  blob: "getAllowTvmBlob",
  prague: "getAllowTvmPrague",
  osaka: "getAllowTvmOsaka",
};
// Highest gate each solc evmVersion may rely on. Solidity's "prague" target
// emits no new legacy opcodes over "cancun"; "osaka" may use CLZ (0x1e).
const EVM_TO_GATES = {
  paris: ["base", "constantinople", "istanbul", "london"],
  shanghai: ["base", "constantinople", "istanbul", "london", "shanghai"],
  cancun: ["base", "constantinople", "istanbul", "london", "shanghai", "cancun", "blob"],
  prague: ["base", "constantinople", "istanbul", "london", "shanghai", "cancun", "blob", "prague"],
  osaka: ["base", "constantinople", "istanbul", "london", "shanghai", "cancun", "blob", "prague", "osaka"],
};

const OPCODES = new Map();
const def = (op, name, gate = "base") => OPCODES.set(op, { name, gate });
// 0x00 - 0x0b arithmetic
["STOP", "ADD", "MUL", "SUB", "DIV", "SDIV", "MOD", "SMOD", "ADDMOD", "MULMOD", "EXP", "SIGNEXTEND"].forEach((n, i) => def(i, n));
// 0x10 - 0x1d comparison and bitwise
["LT", "GT", "SLT", "SGT", "EQ", "ISZERO", "AND", "OR", "XOR", "NOT", "BYTE"].forEach((n, i) => def(0x10 + i, n));
def(0x1b, "SHL", "constantinople"); def(0x1c, "SHR", "constantinople"); def(0x1d, "SAR", "constantinople");
def(0x1e, "CLZ", "osaka");
def(0x20, "KECCAK256");
// 0x30 - 0x3f environment
["ADDRESS", "BALANCE", "ORIGIN", "CALLER", "CALLVALUE", "CALLDATALOAD", "CALLDATASIZE", "CALLDATACOPY",
  "CODESIZE", "CODECOPY", "GASPRICE", "EXTCODESIZE", "EXTCODECOPY", "RETURNDATASIZE", "RETURNDATACOPY"].forEach((n, i) => def(0x30 + i, n));
def(0x3f, "EXTCODEHASH", "constantinople");
// 0x40 - 0x4a block
["BLOCKHASH", "COINBASE", "TIMESTAMP", "NUMBER", "DIFFICULTY", "GASLIMIT"].forEach((n, i) => def(0x40 + i, n));
def(0x46, "CHAINID", "istanbul"); def(0x47, "SELFBALANCE", "istanbul"); def(0x48, "BASEFEE", "london");
def(0x49, "BLOBHASH", "blob"); def(0x4a, "BLOBBASEFEE", "blob");
// 0x50 - 0x5f stack, memory, storage, flow
["POP", "MLOAD", "MSTORE", "MSTORE8", "SLOAD", "SSTORE", "JUMP", "JUMPI", "PC", "MSIZE", "GAS", "JUMPDEST"].forEach((n, i) => def(0x50 + i, n));
def(0x5c, "TLOAD", "cancun"); def(0x5d, "TSTORE", "cancun"); def(0x5e, "MCOPY", "cancun"); def(0x5f, "PUSH0", "shanghai");
for (let i = 1; i <= 32; i++) def(0x5f + i, `PUSH${i}`);
for (let i = 1; i <= 16; i++) def(0x7f + i, `DUP${i}`);
for (let i = 1; i <= 16; i++) def(0x8f + i, `SWAP${i}`);
for (let i = 0; i <= 4; i++) def(0xa0 + i, `LOG${i}`);
// 0xd0 - 0xdf TRON-specific (TRC-10, staking, voting). solc never emits these;
// their presence in solc output means the walker drifted into a data region.
["CALLTOKEN", "TOKENBALANCE", "CALLTOKENVALUE", "CALLTOKENID", "ISCONTRACT", "FREEZE", "UNFREEZE", "FREEZEEXPIRETIME",
  "VOTEWITNESS", "WITHDRAWREWARD", "FREEZEBALANCEV2", "UNFREEZEBALANCEV2", "CANCELALLUNFREEZEV2", "WITHDRAWEXPIREUNFREEZE",
  "DELEGATERESOURCE", "UNDELEGATERESOURCE"].forEach((n, i) => def(0xd0 + i, n, "tron-only"));
// 0xf0 - 0xff system
["CREATE", "CALL", "CALLCODE", "RETURN", "DELEGATECALL"].forEach((n, i) => def(0xf0 + i, n));
def(0xf5, "CREATE2", "constantinople"); def(0xfa, "STATICCALL"); def(0xfd, "REVERT"); def(0xfe, "INVALID"); def(0xff, "SELFDESTRUCT");

/**
 * Linear opcode walk that skips PUSH immediates. Returns a histogram of
 * opcodes seen plus the list of problems for the given set of allowed gates.
 */
export function scanBytecode(hex, allowedGates) {
  const code = Buffer.from(hex.replace(/^0x/, ""), "hex");
  const seen = new Map();
  const problems = [];
  const allowed = new Set(allowedGates);
  for (let pc = 0; pc < code.length; pc++) {
    const op = code[pc];
    const info = OPCODES.get(op);
    const key = info ? info.name : `0x${op.toString(16).padStart(2, "0")}`;
    seen.set(key, (seen.get(key) || 0) + 1);
    if (!info) {
      problems.push(`pc ${pc}: unassigned opcode 0x${op.toString(16).padStart(2, "0")}`);
    } else if (info.gate === "tron-only") {
      problems.push(`pc ${pc}: TRON-only opcode ${info.name} (0x${op.toString(16)}) in solc output`);
    } else if (!allowed.has(info.gate)) {
      problems.push(`pc ${pc}: ${info.name} (0x${op.toString(16)}) needs gate ${GATE_PARAM[info.gate]} beyond the chosen target`);
    }
    if (op >= 0x60 && op <= 0x7f) pc += op - 0x5f; // skip PUSH1..PUSH32 immediates
  }
  return { bytes: code.length, seen, problems };
}

/** Which gated opcodes a bytecode actually uses, as { gate: [names] }. */
function gatedUsage(seen) {
  const out = {};
  for (const [name, count] of seen) {
    const entry = [...OPCODES.values()].find((o) => o.name === name);
    if (!entry || entry.gate === "base") continue;
    (out[entry.gate] ||= []).push(`${name} x${count}`);
  }
  return out;
}

// ---------- compile ----------
function compile(evmVersion) {
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
  const settings = {
    optimizer: { enabled: true, runs: 1_000_000 },
    viaIR: true,
    evmVersion,
    metadata: { bytecodeHash: "none", appendCBOR: false },
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } },
  };
  const out = JSON.parse(solc.compile(JSON.stringify({ language: "Solidity", sources, settings })));
  const fatal = (out.errors || []).filter((e) => e.severity === "error");
  if (fatal.length) { for (const e of fatal) console.error(e.formattedMessage); throw new Error("compilation failed"); }
  const pick = (file, name) => {
    const c = out.contracts[file][name];
    return { abi: c.abi, bytecode: "0x" + c.evm.bytecode.object, runtime: "0x" + c.evm.deployedBytecode.object };
  };
  return {
    sources: Object.keys(sources).sort(),
    settings,
    solc: solc.version(),
    contracts: {
      AegisCCHSFactory: pick("AegisCCHSFactory.sol", "AegisCCHSFactory"),
      AegisCCHS: pick("AegisCCHS.sol", "AegisCCHS"),
      AegisCCHSK: pick("AegisCCHSK.sol", "AegisCCHSK"),
    },
  };
}

function main() {
  const args = process.argv.slice(2);
  const evmIdx = args.indexOf("--evm");
  const evmVersion = evmIdx >= 0 ? args[evmIdx + 1] : "cancun";
  const gates = EVM_TO_GATES[evmVersion];
  if (!gates) throw new Error(`unsupported --evm '${evmVersion}'; one of ${Object.keys(EVM_TO_GATES).join(", ")}`);

  console.log(`solc ${solc.version()}  evmVersion ${evmVersion}  optimizer 1e6 runs, viaIR, no metadata`);
  const c = compile(evmVersion);

  let failed = false;
  const report = {};
  for (const [name, { bytecode, runtime }] of Object.entries(c.contracts)) {
    for (const [kind, hex] of [["creation", bytecode], ["runtime", runtime]]) {
      const r = scanBytecode(hex, gates);
      const usage = gatedUsage(r.seen);
      const usageStr = Object.entries(usage).map(([g, ops]) => `${g}: ${ops.join(", ")}`).join("; ") || "none";
      console.log(`${name.padEnd(17)} ${kind.padEnd(8)} ${String(r.bytes).padStart(6)} B  gated opcodes -> ${usageStr}`);
      for (const p of r.problems) console.log(`   FAIL ${p}`);
      if (r.problems.length) failed = true;
      if (kind === "runtime") report[name] = { runtimeBytes: r.bytes, creationBytes: (bytecode.length - 2) / 2, gatedOpcodes: usage };
    }
  }
  if (failed) {
    console.error("\nopcode scan failed; artifact not written");
    process.exit(1);
  }

  // Required chain-parameter gates = union of gates actually used.
  const requiredGates = [...new Set(Object.values(report).flatMap((r) => Object.keys(r.gatedOpcodes)))]
    .sort((a, b) => GATE_ORDER.indexOf(a) - GATE_ORDER.indexOf(b));

  // Cross-check against the EVM artifact: identical settings must give identical init code.
  let sameAsEvm = null;
  if (existsSync(EVM_ARTIFACT)) {
    const evm = JSON.parse(readFileSync(EVM_ARTIFACT, "utf8"));
    sameAsEvm = evm.factory.initCode === c.contracts.AegisCCHSFactory.bytecode
      && evm.account.S.creationCode === c.contracts.AegisCCHS.bytecode
      && evm.account.K.creationCode === c.contracts.AegisCCHSK.bytecode;
    console.log(`\ninit code identical to wallet/src/aegis/cchsArtifacts.json: ${sameAsEvm ? "yes" : "no (different evmVersion or solc)"}`);
  }

  const artifact = {
    target: "tron-tvm",
    solc: c.solc,
    settings: { optimizer: c.settings.optimizer, viaIR: true, evmVersion, metadata: c.settings.metadata },
    sources: c.sources,
    create2Prefix: "0x41",
    requiredChainParameters: requiredGates.map((g) => GATE_PARAM[g]),
    identicalToEvmArtifact: sameAsEvm,
    opcodeScan: report,
    factory: {
      abi: c.contracts.AegisCCHSFactory.abi,
      bytecode: c.contracts.AegisCCHSFactory.bytecode,
      runtime: c.contracts.AegisCCHSFactory.runtime,
      runtimeKeccak: keccak256(c.contracts.AegisCCHSFactory.runtime),
    },
    account: {
      S: {
        abi: c.contracts.AegisCCHS.abi,
        bytecode: c.contracts.AegisCCHS.bytecode,
        runtime: c.contracts.AegisCCHS.runtime,
        runtimeKeccak: keccak256(c.contracts.AegisCCHS.runtime),
      },
      K: {
        abi: c.contracts.AegisCCHSK.abi,
        bytecode: c.contracts.AegisCCHSK.bytecode,
        runtime: c.contracts.AegisCCHSK.runtime,
        runtimeKeccak: keccak256(c.contracts.AegisCCHSK.runtime),
      },
    },
  };
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(OUT, JSON.stringify(artifact, null, 2));
  console.log(`required chain parameters: ${artifact.requiredChainParameters.join(", ") || "none beyond base TVM"}`);
  console.log(`artifact written: ${relative(ROOT, OUT)}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (e) { console.error(e); process.exit(1); }
}
