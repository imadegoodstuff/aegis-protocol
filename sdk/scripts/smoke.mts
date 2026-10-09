// Offline check of the built package: keys, addresses on EVM, Solana and
// Bitcoin, signatures verified locally, the size of a Solana execute
// transaction, and the Derive panel's addresses.
// No network, no funds. `npm run smoke` (after `npm run build`).

import {
  masterFromMnemonic, evmChainKey, labelledChainKey, createPool, predictAccount, cchsK, cchsC, toHex,
  compileMessage, unsignedTransaction, solanaIx, setRecordStore, MemoryRecordStore, findProgramAddress, PACKET_SIZE, fromBase58, toBase58,
  BitcoinAccount, derive, identity, pqSign, pqVerify,
} from "@aegis-protocol/sdk";
import { sha256 } from "@noble/hashes/sha256";

setRecordStore(new MemoryRecordStore());
let failures = 0;
const check = (ok: boolean, what: string) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}`); if (!ok) failures++; };

const master = masterFromMnemonic("test test test test test test test test test test test junk");
const pool = createPool();

// EVM: K-20 tree for chain 8453 (Base), address predicted offline.
const t0 = performance.now();
const kBase = evmChainKey(master, 8453);
const pubK = await pool.keygen(kBase, "K", new Map(), { firstSubtree: false });
const addr = predictAccount(toHex(pubK.root), toHex(pubK.recRoot), toHex(pubK.seed), "K");
console.log(`EVM (Base) account ${addr} · keygen ${Math.round(performance.now() - t0)} ms`);
check(/^0x[0-9a-fA-F]{40}$/.test(addr), "EVM address predicted");
const kOther = evmChainKey(master, 1);
check(toHex(kOther.master) !== toHex(kBase.master), "one key tree per chain");

// A K-20 signature at leaf 0 with the top layer, verified locally.
const trees = new Map();
const pubK2 = cchsK.keygen(kBase, trees);
const m = cchsK.executeDigest({ chainId: 8453n, account: new Uint8Array(20), nonce: 0n, idx: 0n, target: new Uint8Array(20), value: 0n, dataHash: sha256(new Uint8Array(0)) });
const sig = cchsK.sign(kBase, 0, m, false, trees);
check(toHex(pubK2.root) === toHex(pubK.root), "pool keygen equals single-threaded keygen");
let ok = true; try { cchsK.verify(pubK2, 0, m, sig); } catch { ok = false; }
check(ok, "K-20 signature verifies (2 layers)");

// Solana: C-20 tree, account and vault PDAs, execute transaction size with the lookup table.
const kSol = labelledChainKey(master, "solana");
const pubC = await pool.keygen(kSol, "C", new Map(), { firstSubtree: false });
const [account] = findProgramAddress([new TextEncoder().encode("cchs"), pubC.root], solanaIx.SOLANA_PROGRAM_ID);
const [vault] = findProgramAddress([new TextEncoder().encode("vault"), account], solanaIx.SOLANA_PROGRAM_ID);
console.log(`Solana account ${toBase58(account)} · vault ${toBase58(vault)}`);
const treesC = new Map();
cchsC.keygen(kSol, treesC);
const payer = fromBase58("5eRrJufmYNrXEdBNyhSBpGy6LS39u3atZCsFfWTU9TMC");
const inner = solanaIx.innerInstruction(vault, { kind: "sol", to: payer, amount: 1n });
const mC = solanaIx.executeMessage(account, 0n, 0, inner);
const sigC = cchsC.sign(kSol, 0, mC, true, treesC);
const ix = solanaIx.executeIx(account, 0n, 0, sigC.l0, inner);
const table = { address: new Uint8Array(32), addresses: solanaIx.TABLE_KEYS(account, vault) };
const tx = unsignedTransaction(compileMessage(payer, new Uint8Array(32), [ix], table));
console.log(`Solana execute (v0, lookup table, 12-byte inner ix, no compute-budget ix): ${tx.length} bytes`);
check(tx.length <= PACKET_SIZE, `execute fits one packet (${tx.length} ≤ ${PACKET_SIZE})`);

// Bitcoin signet: the lineage's first address (top and recovery trees only), no network.
const tB = performance.now();
const btc = BitcoinAccount.derive({ master });
console.log(`Bitcoin (signet) address 0 ${btc.address0} · ${Math.round(performance.now() - tB)} ms`);
check(/^tb1p[0-9a-z]{58}$/.test(btc.address0), "Bitcoin P2TR signet address derived");

// Derive panel: per-chain standard addresses and an SLH-DSA signature.
const d = derive("test test test test test test test test test test test junk");
console.log(`Derive: EVM ${d.evmAddress} · Solana ${d.solanaAddress} · TRON ${d.tronBase58}`);
check(/^0x[0-9a-fA-F]{40}$/.test(d.evmAddress) && d.tronBase58.startsWith("T") && d.btcSegwit.startsWith("bc1q"), "standard addresses derived");
const id = identity("test test test test test test test test test test test junk");
const digest = sha256(new TextEncoder().encode("aegis"));
const pq = pqSign(id, digest);
check(pq.length === 16_224 && pqVerify(id.slhPublicKey, digest, pq) && !pqVerify(id.slhPublicKey, sha256(digest), pq), "SLH-DSA-SHAKE-192s sign/verify");

pool.terminate();
if (failures) { console.log(`${failures} check(s) failed`); process.exit(1); }
console.log("smoke passed");

