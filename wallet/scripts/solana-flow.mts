// The Solana account end to end on a live cluster (devnet by default), with the
// same client code the wallet runs in the browser (src/aegis/solana.ts,
// src/aegis/solanaAccount.ts). A local ed25519 keypair plays the fee-paying
// wallet.
//
//   create + lookup table → deposit SOL → mint a throwaway SPL token and move
//   it into the vault → execute: SOL out (first leaf: cache_subtree + execute)
//   → execute: token out to a recipient without a token account (created
//   first) → execute again (cached path) → recover to epoch 1 → execute under
//   the new epoch. Prints the signature and the size of every transaction.
//
//   SOLANA_PAYER=/path/to/keypair.json [SOLANA_RPC=https://api.devnet.solana.com] \
//   [SOLANA_CLUSTER=devnet] [SOLANA_MNEMONIC="…"] npm run solana-flow
//
// The payer needs about 0.05 SOL. Without SOLANA_PAYER the script exits 0 and
// prints what it would have needed, so CI without a funded key stays green.

import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { cchsMaster } from '../src/aegis/cchsAccount.ts';
import { CchsPool, type WorkerLike } from '../src/aegis/cchsPool.ts';
import { handleLeaves, type LeavesRequest } from '../src/aegis/cchsWorkerCore.ts';
import {
  Rpc, SYSTEM_PROGRAM, TOKEN_PROGRAM, associatedTokenAddress, compactArray, compileMessage, concat, createAtaIdempotent, fromBase58,
  meta, toBase58, u32le, u64le, u8, utf8, type Cluster, type ConnectedSolanaWallet, type Instruction, type Pubkey,
} from '../src/aegis/solana.ts';
import {
  SOLANA_PROGRAM_ID, createAccount, decodeAccount, decodeTable, depositSol, depositToken, deriveSolanaIdentity, epochSigner, findTable,
  recover, spend, vaultHoldings, type Flow, type Signer,
} from '../src/aegis/solanaAccount.ts';

const payerPath = process.env.SOLANA_PAYER;
if (!payerPath) { console.log('SOLANA_PAYER not set: skipping the live devnet flow (needs a keypair with ~0.05 devnet SOL).'); process.exit(0); }
const cluster = (process.env.SOLANA_CLUSTER ?? 'devnet') as Cluster;
const rpc = new Rpc(process.env.SOLANA_RPC ?? (cluster === 'devnet' ? 'https://api.devnet.solana.com' : 'https://api.mainnet-beta.solana.com'));

// ------------------------------------------------------------ local signer
type Keypair = { seed: Uint8Array; pub: Pubkey };
const loadKeypair = (p: string): Keypair => { const a = Uint8Array.from(JSON.parse(fs.readFileSync(p, 'utf8'))); return { seed: a.slice(0, 32), pub: a.slice(32, 64) }; };
const newKeypair = (): Keypair => { const seed = randomBytes(32); return { seed, pub: ed25519.getPublicKey(seed) }; };
const payer = loadKeypair(payerPath);
const extraSigners = new Map<string, Keypair>(); // other signers a transaction may need (the mint keypair)

const wallet: ConnectedSolanaWallet = {
  name: 'local', address: toBase58(payer.pub), publicKey: payer.pub,
  async signAndSend(tx) {
    // tx = compact(sigs, all zero) ‖ message; re-sign with every required signer.
    const nSigs = tx[0];
    const msg = tx.slice(1 + nSigs * 64);
    const header = msg[0] & 0x80 ? 1 : 0;
    const numSigners = msg[header];
    const keysOff = header + 3 + 1; // header(3) + compact len (1 byte for < 128 keys)
    const sigs: Uint8Array[] = [];
    for (let i = 0; i < numSigners; i++) {
      const key = toBase58(msg.slice(keysOff + i * 32, keysOff + (i + 1) * 32));
      const kp = key === wallet.address ? payer : extraSigners.get(key);
      if (!kp) throw new Error(`no key for signer ${key}`);
      sigs.push(ed25519.sign(msg, kp.seed));
    }
    return rpc.send(concat(compactArray(sigs), msg));
  },
};
const flow: Flow = { rpc, cluster, wallet };

// A pool that runs the leaf generation in-process (no Web Workers in node).
const pool = new CchsPool({ size: 1, spawn: () => {
  const w: WorkerLike = { onmessage: null, postMessage(req) { void handleLeaves(req as LeavesRequest).then((r) => w.onmessage?.({ data: r })); }, terminate() {} };
  return w;
} });

// ------------------------------------------------------------------ helpers
const rows: { step: string; signature: string; bytes: number }[] = [];
const log = (step: string, r: { signature: string; bytes: number }) => { rows.push({ step, ...r }); console.log(`${step.padEnd(44)} ${String(r.bytes).padStart(5)} B  ${r.signature}`); };
let failures = 0;
const check = (ok: boolean, what: string) => { if (!ok) { failures++; console.log(`FAIL ${what}`); } else console.log(`ok   ${what}`); };
const sendLegacy = async (ixs: Instruction[]) => {
  const { blockhash, lastValidBlockHeight } = await rpc.latestBlockhash();
  const tx = concat(compactArray([new Uint8Array(64)]), compileMessage(payer.pub, blockhash, ixs).bytes);
  // compileMessage puts every signer first; signAndSend re-derives the count from the header.
  const signature = await wallet.signAndSend(tx, cluster);
  await rpc.confirm(signature, lastValidBlockHeight);
  return { signature, bytes: tx.length };
};

// SPL Token instructions the wallet itself never needs: create a mint and mint to the payer.
const initializeMint2 = (mint: Pubkey, decimals: number, authority: Pubkey): Instruction =>
  ({ programId: TOKEN_PROGRAM, keys: [meta.w(mint)], data: concat(u8(20), u8(decimals), authority, u8(0)) });
const mintTo = (mint: Pubkey, dest: Pubkey, authority: Pubkey, amount: bigint): Instruction =>
  ({ programId: TOKEN_PROGRAM, keys: [meta.w(mint), meta.w(dest), meta.r(authority, true)], data: concat(u8(7), u64le(amount)) });
const systemCreateAccount = (from: Pubkey, to: Pubkey, lamports: bigint, space: number, owner: Pubkey): Instruction =>
  ({ programId: SYSTEM_PROGRAM, keys: [meta.w(from, true), meta.w(to, true)], data: concat(u32le(0), u64le(lamports), u64le(space), owner) });

// --------------------------------------------------------------------- flow
const prog = await rpc.accountInfo(SOLANA_PROGRAM_ID);
if (!prog?.executable) { console.log(`program ${toBase58(SOLANA_PROGRAM_ID)} is not deployed on ${cluster} (${rpc.url}); nothing to run`); process.exit(1); }
const payerBal = await rpc.balance(payer.pub);
console.log(`cluster ${cluster} · payer ${wallet.address} · ${Number(payerBal) / 1e9} SOL`);
if (payerBal < 50_000_000n) { console.log('payer needs at least 0.05 SOL'); process.exit(1); }

const mnemonic = process.env.SOLANA_MNEMONIC ?? generateMnemonic(wordlist, 128);
const id = await deriveSolanaIdentity(cchsMaster(mnemonic), pool);
console.log(`account ${toBase58(id.account)} · vault ${toBase58(id.vault)} · key tree in ${Math.round(id.tookMs)} ms`);

const existing = await rpc.accountInfo(id.account);
if (!existing) log('create + lookup table', await createAccount(flow, id));
else console.log('account exists; continuing with its state');
let tableAddr = await findTable(rpc, cluster, id.account);
check(!!tableAddr, 'lookup table found from the account\'s first transaction / local record');
const tableInfo = await rpc.accountInfo(tableAddr!);
const table = { address: tableAddr!, addresses: decodeTable(tableInfo!.data) };
check(table.addresses.length === 9, `lookup table holds ${table.addresses.length} keys`);

log('deposit 0.02 SOL', await depositSol(flow, id.vault, 20_000_000n));

// A throwaway SPL mint (6 decimals), 1 000 000 units to the payer, 600 000 into the vault.
const mint = newKeypair();
extraSigners.set(toBase58(mint.pub), mint);
const rent = await rpc.rentExempt(82);
const payerAta = associatedTokenAddress(payer.pub, mint.pub);
log('mint a test token to the payer', await sendLegacy([
  systemCreateAccount(payer.pub, mint.pub, rent, 82, TOKEN_PROGRAM),
  initializeMint2(mint.pub, 6, payer.pub),
  createAtaIdempotent(payer.pub, payer.pub, mint.pub, TOKEN_PROGRAM),
  mintTo(mint.pub, payerAta, payer.pub, 1_000_000n),
]));
const holding = { address: payerAta, mint: mint.pub, amount: 1_000_000n, decimals: 6, tokenProgram: TOKEN_PROGRAM };
log('move 0.6 of the token into the vault', await depositToken(flow, id.vault, holding, 600_000n));

let v = await vaultHoldings(rpc, id.vault);
check(v.lamports === 20_000_000n || existing !== null, `vault holds ${Number(v.lamports) / 1e9} SOL`);
check(v.tokens.some((t) => toBase58(t.mint) === toBase58(mint.pub) && t.amount === 600_000n), 'vault holds 0.6 of the token');

const recipient = newKeypair().pub;
const signers = new Map<string, Signer>();
const state = async () => decodeAccount((await rpc.accountInfo(id.account))!.data);
const step = (s: string) => process.stdout.write(`   … ${s}\n`);

let st = await state();
let r = await spend(flow, id, st, epochSigner(id, st.epoch, pool, signers), table, { kind: 'sol', to: recipient, amount: 5_000_000n }, step);
if (r.cacheSignature) log(`cache_subtree (epoch ${st.epoch}, subtree 0)`, { signature: r.cacheSignature, bytes: r.cacheBytes! });
log(`execute: 0.005 SOL out (leaf ${r.idx})`, r);
check((await rpc.balance(recipient)) === 5_000_000n, 'recipient received 0.005 SOL');

st = await state();
const vaultToken = (await vaultHoldings(rpc, id.vault)).tokens.find((t) => toBase58(t.mint) === toBase58(mint.pub))!;
r = await spend(flow, id, st, epochSigner(id, st.epoch, pool, signers), table, { kind: 'token', to: recipient, amount: 250_000n, token: vaultToken }, step);
log(`execute: 0.25 token out, ATA created first (leaf ${r.idx})`, r);
check(r.cached, 'second leaf used the cached subtree root');
const recTok = await rpc.tokenAccounts(recipient, TOKEN_PROGRAM);
check(recTok.some((t) => t.amount === 250_000n), 'recipient received 0.25 of the token');

st = await state();
r = await spend(flow, id, st, epochSigner(id, st.epoch, pool, signers), table, { kind: 'sol', to: recipient, amount: 1_000_000n }, step);
log(`execute: 0.001 SOL out (leaf ${r.idx})`, r);

st = await state();
const rec = await recover(flow, id, st, pool);
log(`recover → epoch ${rec.epoch}`, rec);
st = await state();
check(st.epoch === rec.epoch && st.nextIdx === 0n, `epoch ${st.epoch}, next leaf reset to ${st.nextIdx}`);

r = await spend(flow, id, st, epochSigner(id, st.epoch, pool, signers), table, { kind: 'sol', to: recipient, amount: 1_000_000n }, step);
if (r.cacheSignature) log(`cache_subtree (epoch ${st.epoch}, subtree 0)`, { signature: r.cacheSignature, bytes: r.cacheBytes! });
log(`execute under epoch ${st.epoch} (leaf ${r.idx})`, r);
check((await rpc.balance(recipient)) === 7_000_000n, 'recipient received 0.007 SOL in total');

v = await vaultHoldings(rpc, id.vault);
console.log(`\nvault now ${Number(v.lamports) / 1e9} SOL · token ${v.tokens[0] ? Number(v.tokens[0].amount) / 1e6 : 0}`);
console.log('\n| Step | Bytes | Signature |\n|---|---:|---|');
for (const row of rows) console.log(`| ${row.step} | ${row.bytes} | ${row.signature} |`);
console.log(`\nexplorer: https://explorer.solana.com/address/${toBase58(id.account)}${cluster === 'devnet' ? '?cluster=devnet' : ''}`);
pool.terminate();
if (failures) { console.log(`\n${failures} check(s) failed`); process.exit(1); }
console.log('\nall checks passed');
