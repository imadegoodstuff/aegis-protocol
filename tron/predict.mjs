// TRON address prediction for the CCHS factory and accounts.
//
//   node predict.mjs account --factory <T...|41..|0x..> --root 0x.. --rec-root 0x.. --seed 0x.. [--variant K|S]
//   node predict.mjs factory --deployer <T...|41..|0x..> --salt 0x..
//   node predict.mjs factory-from-tx --txid <hex32> --owner <T...|41..|0x..>
//   node predict.mjs to-base58 <41..|0x..>        node predict.mjs to-hex <T...>
//   node predict.mjs --self-test
//
// TRON derives CREATE2 addresses with prefix byte 0x41 instead of 0xff:
//   addr20 = keccak256(0x41 || sender20 || salt32 || keccak256(initCode))[12..32)
// Source: https://developers.tron.network/docs/tvm-vs-evm ("CREATE2 prefix differs").
//
// "factory" applies only when the factory is published by a CREATE2-capable
// deployer contract. A factory published directly from a key (deploy-factory.mjs)
// gets a CREATE address derived from the transaction id and the owner; use
// "factory-from-tx" to recompute that one after the fact.
//
// Account salt and init code mirror AegisCCHSFactory._salt / predict:
//   salt     = keccak256(root || recRoot || seed16 || variantByte)   (0x01 = S, 0x00 = K)
//   initCode = creationCode || abi.encode(root, recRoot, seed)      (seed: bytes16, left-aligned word)
//
// Reads tron/artifacts/cchs-tvm.json (run build.mjs first). keccak256 comes
// from the viem copy in deploy/node_modules; sha256 and base58 are local.

import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const ARTIFACT = resolve(__dirname, "artifacts", "cchs-tvm.json");
const { keccak256 } = createRequire(resolve(ROOT, "deploy", "package.json"))("viem");

export const TRON_PREFIX = 0x41;
/** CHAINID values returned inside the TVM (last 4 bytes of the genesis block id). */
export const TRON_CHAIN_IDS = { mainnet: 728126428, shasta: 2494104990, nile: 3448148188 };

// ---------- byte helpers ----------
const strip0x = (h) => h.replace(/^0x/i, "");
const hexToBytes = (h) => Uint8Array.from(Buffer.from(strip0x(h), "hex"));
const bytesToHex = (b) => Buffer.from(b).toString("hex");
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};
const sha256 = (b) => Uint8Array.from(createHash("sha256").update(b).digest());
const keccak = (b) => hexToBytes(keccak256(Buffer.from(b)));

// ---------- base58check ----------
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = "1" + out; }
  return out;
}

export function base58Decode(str) {
  let n = 0n;
  for (const ch of str) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error(`invalid base58 character '${ch}'`);
    n = n * 58n + BigInt(v);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const ch of str) { if (ch !== "1") break; bytes.unshift(0); }
  return Uint8Array.from(bytes);
}

/** 21-byte (0x41 || addr20) -> "T..." */
export function toTronBase58(raw21) {
  if (raw21.length !== 21 || raw21[0] !== TRON_PREFIX) throw new Error("expected 21 bytes starting with 0x41");
  const check = sha256(sha256(raw21)).subarray(0, 4);
  return base58Encode(concat(raw21, check));
}

/** "T..." -> 21 bytes, checksum verified. */
export function fromTronBase58(str) {
  const full = base58Decode(str);
  if (full.length !== 25) throw new Error("base58check payload must be 25 bytes");
  const raw21 = full.subarray(0, 21);
  const check = sha256(sha256(raw21)).subarray(0, 4);
  if (bytesToHex(check) !== bytesToHex(full.subarray(21))) throw new Error("bad base58check checksum");
  if (raw21[0] !== TRON_PREFIX) throw new Error("not a 0x41-prefixed TRON address");
  return raw21;
}

/** Accepts "T...", "41<40 hex>" or "0x<40 hex>"; returns the 20 address bytes. */
export function parseAddress20(s) {
  const str = s.trim();
  if (str.startsWith("T") && str.length === 34) return fromTronBase58(str).subarray(1);
  const h = strip0x(str);
  if (h.length === 42 && h.toLowerCase().startsWith("41")) return hexToBytes(h.slice(2));
  if (h.length === 40) return hexToBytes(h);
  throw new Error(`unrecognised address '${s}'`);
}

export function formatAddress(addr20) {
  const raw21 = concat(Uint8Array.of(TRON_PREFIX), addr20);
  return { hex20: "0x" + bytesToHex(addr20), hex21: bytesToHex(raw21), base58: toTronBase58(raw21) };
}

// ---------- derivations ----------
/** TRON CREATE2: keccak256(0x41 || sender20 || salt32 || keccak256(initCode))[12..] */
export function tronCreate2(sender20, salt32, initCode) {
  if (sender20.length !== 20) throw new Error("sender must be 20 bytes");
  if (salt32.length !== 32) throw new Error("salt must be 32 bytes");
  const h = keccak(concat(Uint8Array.of(TRON_PREFIX), sender20, salt32, keccak(initCode)));
  return h.subarray(12);
}

/**
 * TRON CREATE from a deployment transaction: keccak256(txid || owner21)[12..].
 * Mirrors java-tron WalletUtil.generateContractAddress(Transaction). Not yet
 * checked against a live deployment from this repository.
 */
export function tronCreateFromTx(txid32, owner20) {
  if (txid32.length !== 32) throw new Error("txid must be 32 bytes");
  const owner21 = concat(Uint8Array.of(TRON_PREFIX), owner20);
  return keccak(concat(txid32, owner21)).subarray(12);
}

export function accountSalt(root32, recRoot32, seed16, variant) {
  return keccak(concat(root32, recRoot32, seed16, Uint8Array.of(variant === "S" ? 1 : 0)));
}

export function accountInitCode(artifact, root32, recRoot32, seed16, variant) {
  const creation = hexToBytes(variant === "S" ? artifact.account.S.bytecode : artifact.account.K.bytecode);
  const seedWord = new Uint8Array(32); seedWord.set(seed16, 0); // abi.encode(bytes16): left-aligned in its word
  return concat(creation, root32, recRoot32, seedWord);
}

export function predictAccount(artifact, factory20, root32, recRoot32, seed16, variant) {
  return tronCreate2(factory20, accountSalt(root32, recRoot32, seed16, variant), accountInitCode(artifact, root32, recRoot32, seed16, variant));
}

function loadArtifact() {
  if (!existsSync(ARTIFACT)) throw new Error("tron/artifacts/cchs-tvm.json missing; run node build.mjs first");
  return JSON.parse(readFileSync(ARTIFACT, "utf8"));
}

// ---------- self test ----------
function selfTest() {
  // Hex / base58 pair published in the TRON documentation:
  // https://developers.tron.network/docs/account and https://developers.tron.network/docs/encoding
  const vectors = [
    ["418840E6C55B9ADA326D211D818C34A994AECED808", "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL"],
    ["415CBDD86A2FA8DC4BDDD8A8F69DBA48572EEC07FB", "TJRabPrwbZy45sbavfcjinPJC18kjpRTv8"],
  ];
  for (const [hex21, b58] of vectors) {
    const got = toTronBase58(hexToBytes(hex21));
    if (got !== b58) throw new Error(`base58check mismatch for ${hex21}: got ${got}, want ${b58}`);
    if (bytesToHex(fromTronBase58(b58)).toUpperCase() !== hex21) throw new Error(`decode mismatch for ${b58}`);
    console.log(`ok  ${hex21} <-> ${b58}`);
  }
  // CREATE2 with prefix 0xff must reproduce the EVM factory address from cchsArtifacts.json;
  // swapping the prefix to 0x41 is the only change for TRON.
  const evmPath = resolve(ROOT, "wallet", "src", "aegis", "cchsArtifacts.json");
  if (existsSync(evmPath)) {
    const evm = JSON.parse(readFileSync(evmPath, "utf8"));
    const proxy20 = hexToBytes(evm.proxy);
    const h = keccak(concat(Uint8Array.of(0xff), proxy20, hexToBytes(evm.salt), keccak(hexToBytes(evm.factory.initCode))));
    const got = "0x" + bytesToHex(h.subarray(12));
    if (got.toLowerCase() !== evm.factory.address.toLowerCase()) throw new Error(`EVM CREATE2 cross-check failed: ${got}`);
    console.log(`ok  CREATE2 formula with 0xff reproduces the EVM factory ${evm.factory.address}`);
  }
  console.log("self-test passed");
}

// ---------- CLI ----------
function arg(args, name, required = true) {
  const i = args.indexOf(name);
  if (i < 0 || i + 1 >= args.length) { if (required) throw new Error(`missing ${name}`); return undefined; }
  return args[i + 1];
}

function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];
  if (!cmd || cmd === "--help") {
    console.log(readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(0, 8).map((l) => l.replace(/^\/\/ ?/, "")).join("\n"));
    return;
  }
  if (cmd === "--self-test") return selfTest();
  if (cmd === "to-base58") return console.log(formatAddress(parseAddress20(args[1])).base58);
  if (cmd === "to-hex") return console.log(formatAddress(parseAddress20(args[1])).hex21);

  let addr20;
  if (cmd === "account") {
    const artifact = loadArtifact();
    const factory20 = parseAddress20(arg(args, "--factory"));
    const root = hexToBytes(arg(args, "--root"));
    const rec = hexToBytes(arg(args, "--rec-root"));
    const seed = hexToBytes(arg(args, "--seed"));
    const variant = (arg(args, "--variant", false) || "K").toUpperCase();
    if (root.length !== 32 || rec.length !== 32) throw new Error("root and rec-root must be 32 bytes");
    if (seed.length !== 16) throw new Error("seed must be 16 bytes");
    if (variant !== "K" && variant !== "S") throw new Error("variant must be K or S");
    addr20 = predictAccount(artifact, factory20, root, rec, seed, variant);
    console.log(`variant   CCHS-${variant}-20   salt ${bytesToHex(accountSalt(root, rec, seed, variant))}`);
  } else if (cmd === "factory") {
    const artifact = loadArtifact();
    const deployer20 = parseAddress20(arg(args, "--deployer"));
    const salt = hexToBytes(arg(args, "--salt"));
    if (salt.length !== 32) throw new Error("salt must be 32 bytes");
    addr20 = tronCreate2(deployer20, salt, hexToBytes(artifact.factory.bytecode));
    console.log("note      valid only if the deployer is a contract that runs CREATE2 with this salt and the artifact init code");
  } else if (cmd === "factory-from-tx") {
    const txid = hexToBytes(arg(args, "--txid"));
    const owner20 = parseAddress20(arg(args, "--owner"));
    addr20 = tronCreateFromTx(txid, owner20);
  } else {
    throw new Error(`unknown command '${cmd}'`);
  }
  const f = formatAddress(addr20);
  console.log(`hex20     ${f.hex20}`);
  console.log(`hex21     ${f.hex21}`);
  console.log(`base58    ${f.base58}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (e) { console.error(e.message || e); process.exit(1); }
}
