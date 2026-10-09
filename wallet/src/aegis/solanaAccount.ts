// The CCHS-C-20 account on Solana (solana/programs/aegis_account), driven from
// the browser.
//
//   mnemonic ─▶ chain key for tag "solana" ─▶ C-20 tree (epoch 0)
//   account PDA  = ["cchs", root24]            holds the state
//   vault PDA    = ["vault", account]           holds SOL and signs token CPIs
//   cache PDA    = ["cache", account, epoch, k] root of bottom subtree k
//
// Protect: the connected Solana wallet (Phantom, …) pays for `create`, makes an
// address lookup table for the account's fixed keys, and moves SOL / SPL tokens
// into the vault (tokens into the vault's associated token accounts). Spend:
// the device signs the WOTS+ leaf, the wallet merely pays the fee of the
// `execute` transaction; the wallet's own key has no authority over the vault.
//
// One program id on every cluster; it is deployed on devnet. The panel reads
// whether the program exists on the selected cluster and says so.

import { sha256 } from '@noble/hashes/sha256';
import type { CchsKey, CchsPublic, LayerSig, Tree } from './cchs';
import { cchsC, H, LEN, REC_H } from './cchsCompact';
import { chainKey, epochKey, labelChainTag } from './cchsAccount';
import type { CchsPool } from './cchsPool';
import {
  ASSOCIATED_TOKEN_PROGRAM, COMPUTE_BUDGET_PROGRAM, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
  associatedTokenAddress, compileMessage, concat, createAtaIdempotent, createLookupTable, extendLookupTable,
  findProgramAddress, fromBase58, keyEq, meta, readU64le, setComputeUnitLimit, systemTransfer, toBase58,
  tokenTransferChecked, u32le, u64le, unsignedTransaction, utf8,
  type Cluster, type ConnectedSolanaWallet, type Instruction, type Pubkey, type Rpc, type TokenHolding,
} from './solana';

export const SOLANA_PROGRAM_ID = fromBase58('AoQ7c3GuxiF7nshFnM872FoxUz7oUDhygdhoRX6jMQKr');
export const SOLANA_TAG = 'solana';
/** Compute-unit limits per instruction, from the CI measurement (execute 616–708 K, worst case 1.17 M). */
export const CU_EXECUTE = 1_400_000;
export const CU_CACHE = 1_400_000;
export const CU_RECOVER = 1_000_000;
const ACCOUNT_SPACE = 8 + 24 + 24 + 24 + 16 + 8 * 4 + 2;

const discriminator = (name: string) => sha256(utf8(`global:${name}`)).slice(0, 8);
const DISC = { create: discriminator('create'), cache_subtree: discriminator('cache_subtree'), execute: discriminator('execute'), recover: discriminator('recover') };

export const PROGRAM_ERRORS = ['Exhausted', 'IndexUsed', 'MissingTopLayer', 'BadSubtreeRoot', 'BadTopRoot', 'BadRecovery', 'ZeroRoot', 'BadLength', 'CacheConflict', 'TargetNotExecutable'];
/** Turn a simulation / send error into the program's own error name when it is one. */
export function describeError(err: unknown, logs: string[] = []): string {
  const s = typeof err === 'string' ? err : JSON.stringify(err);
  const m = /Custom":\s*(\d+)|custom program error: 0x([0-9a-f]+)/i.exec(s + ' ' + logs.join(' '));
  if (m) {
    const code = m[1] ? Number(m[1]) : parseInt(m[2], 16);
    if (code >= 6000 && code - 6000 < PROGRAM_ERRORS.length) return PROGRAM_ERRORS[code - 6000];
    return `program error ${code}`;
  }
  const line = logs.find((l) => /Error|failed/i.test(l));
  return line ?? s;
}

// ------------------------------------------------------------------- keys
export function solanaChainKey(master: CchsKey): CchsKey { return chainKey(master, labelChainTag(SOLANA_TAG)); }

export interface SolanaIdentity {
  key: CchsKey;          // epoch-0 chain key
  pub: CchsPublic;       // epoch-0 public key (root, recRoot, 16-byte seed)
  trees: Map<string, Tree>;
  account: Pubkey;
  vault: Pubkey;
  tookMs: number;
}
export async function deriveSolanaIdentity(master: CchsKey, pool: CchsPool): Promise<SolanaIdentity> {
  const key = solanaChainKey(master);
  const trees = new Map<string, Tree>();
  const t0 = performance.now();
  const pub = await pool.keygen(key, 'C', trees, { firstSubtree: false });
  const [account] = findProgramAddress([utf8('cchs'), pub.root], SOLANA_PROGRAM_ID);
  const [vault] = findProgramAddress([utf8('vault'), account], SOLANA_PROGRAM_ID);
  return { key, pub, trees, account, vault, tookMs: performance.now() - t0 };
}
export function cachePda(account: Pubkey, epoch: bigint, treeIdx: bigint): Pubkey {
  return findProgramAddress([utf8('cache'), account, u64le(epoch), u64le(treeIdx)], SOLANA_PROGRAM_ID)[0];
}

// ------------------------------------------------------------------ state
export interface AccountState {
  seed: Uint8Array; root: Uint8Array; recRoot: Uint8Array; pkSeed: Uint8Array;
  epoch: bigint; nextIdx: bigint; nonce: bigint; recNonce: bigint;
}
export function decodeAccount(data: Uint8Array): AccountState {
  if (data.length < ACCOUNT_SPACE) throw new Error('not a CchsAccount');
  let o = 8;
  const take = (n: number) => { const v = data.slice(o, o + n); o += n; return v; };
  const seed = take(24), root = take(24), recRoot = take(24), pkSeed = take(16);
  const epoch = readU64le(data, o), nextIdx = readU64le(data, o + 8), nonce = readU64le(data, o + 16), recNonce = readU64le(data, o + 24);
  return { seed, root, recRoot, pkSeed, epoch, nextIdx, nonce, recNonce };
}
export const CAPACITY = 1 << (2 * H);
export const RECOVERIES = 1 << REC_H;

// ------------------------------------------------------- index discipline
// Same rule as the EVM wallet (cchsAccount.ts): a leaf is recorded as used
// before it is signed, and a device that finds the account used (nextIdx > 0)
// without holding a record for the epoch must rotate instead of guessing.
// There are no lanes on Solana: one device signs an epoch.
const idxKey = (cluster: Cluster, account: string, epoch: bigint) => `aegis/cchs/solana/${cluster}/signed/${account}/${epoch}`;
const recKey = (cluster: Cluster, account: string) => `aegis/cchs/solana/${cluster}/rec-signed/${account}`;
export function highestSigned(cluster: Cluster, account: string, epoch: bigint): number | null {
  const v = globalThis.localStorage?.getItem(idxKey(cluster, account, epoch));
  return v === null || v === undefined ? null : Number(v);
}
export function recordMissing(cluster: Cluster, account: string, st: AccountState): boolean {
  return st.nextIdx > 0n && highestSigned(cluster, account, st.epoch) === null;
}
export function nextIndex(cluster: Cluster, account: string, st: AccountState): number {
  const rec = highestSigned(cluster, account, st.epoch);
  const idx = Math.max(Number(st.nextIdx), (rec ?? -1) + 1);
  if (idx >= CAPACITY) throw new Error('this epoch is exhausted; rotate keys');
  return idx;
}
export function markSigned(cluster: Cluster, account: string, epoch: bigint, idx: number): void {
  const rec = highestSigned(cluster, account, epoch);
  if (rec === null || idx > rec) globalThis.localStorage?.setItem(idxKey(cluster, account, epoch), String(idx));
}
export function highestRecoverySigned(cluster: Cluster, account: string): number {
  const v = globalThis.localStorage?.getItem(recKey(cluster, account));
  return v === null || v === undefined ? -1 : Number(v);
}
export function markRecoverySigned(cluster: Cluster, account: string, recNonce: number): void {
  if (recNonce > highestRecoverySigned(cluster, account)) globalThis.localStorage?.setItem(recKey(cluster, account), String(recNonce));
}

// ------------------------------------------------------- lookup table
// The v0 `execute` transaction needs the account's fixed keys in a lookup
// table (solana/README.md, "Transaction sizes"). The table is created in the
// same transaction as the account, so it can always be found again from the
// account's first transaction; the address is also kept locally.
export const TABLE_KEYS = (account: Pubkey, vault: Pubkey): Pubkey[] =>
  [SOLANA_PROGRAM_ID, account, vault, SYSTEM_PROGRAM, COMPUTE_BUDGET_PROGRAM, TOKEN_PROGRAM, TOKEN_2022_PROGRAM, ASSOCIATED_TOKEN_PROGRAM, cachePda(account, 0n, 0n)];
const tableKey = (cluster: Cluster, account: string) => `aegis/cchs/solana/${cluster}/table/${account}`;
export function rememberTable(cluster: Cluster, account: string, table: Pubkey): void { globalThis.localStorage?.setItem(tableKey(cluster, account), toBase58(table)); }
export async function findTable(rpc: Rpc, cluster: Cluster, account: Pubkey): Promise<Pubkey | null> {
  const local = globalThis.localStorage?.getItem(tableKey(cluster, toBase58(account)));
  if (local) return fromBase58(local);
  // Oldest transaction of the account: page back through its signatures.
  let before: string | undefined, oldest: string | undefined;
  for (let i = 0; i < 50; i++) {
    const page = await rpc.signaturesFor(account, before);
    if (!page.length) break;
    oldest = page[page.length - 1].signature; before = oldest;
    if (page.length < 1000) break;
  }
  if (!oldest) return null;
  const tx = await rpc.transaction(oldest);
  const ix = tx?.transaction.message.instructions.find((i) => i.program === 'address-lookup-table' && i.parsed?.type === 'createLookupTable');
  const addr = ix?.parsed?.info.lookupTableAccount as string | undefined;
  if (!addr) return null;
  const table = fromBase58(addr);
  rememberTable(cluster, toBase58(account), table);
  return table;
}
/** Addresses stored in a lookup table account (header is 56 bytes). */
export function decodeTable(data: Uint8Array): Pubkey[] {
  const out: Pubkey[] = [];
  for (let o = 56; o + 32 <= data.length; o += 32) out.push(data.slice(o, o + 32));
  return out;
}

// --------------------------------------------------------- instructions
export function createIx(payer: Pubkey, account: Pubkey, pub: CchsPublic): Instruction {
  return { programId: SOLANA_PROGRAM_ID, keys: [meta.w(account), meta.w(payer, true), meta.r(SYSTEM_PROGRAM)], data: concat(DISC.create, pub.root, pub.recRoot, pub.seed) };
}
const flat = (rows: Uint8Array[]) => concat(...rows);
export function cacheSubtreeIx(payer: Pubkey, account: Pubkey, epoch: bigint, treeIdx: bigint, l1: LayerSig, r0: Uint8Array): Instruction {
  if (l1.wots.length !== LEN || l1.auth.length !== H) throw new Error('bad top-layer proof shape');
  return {
    programId: SOLANA_PROGRAM_ID,
    keys: [meta.r(account), meta.w(cachePda(account, epoch, treeIdx)), meta.w(payer, true), meta.r(SYSTEM_PROGRAM)],
    data: concat(DISC.cache_subtree, u64le(treeIdx), flat(l1.wots), flat(l1.auth), r0),
  };
}
/** `execute(idx, l0, ix_data)`: the inner instruction's accounts follow as remaining accounts; the vault/account among them need not be marked signers (the program does). */
export function executeIx(account: Pubkey, epoch: bigint, idx: number, l0: LayerSig, inner: Instruction): Instruction {
  if (l0.wots.length !== LEN || l0.auth.length !== H) throw new Error('bad signature shape');
  const remaining = inner.keys.map((k) => ({ ...k, isSigner: false }));
  return {
    programId: SOLANA_PROGRAM_ID,
    keys: [meta.w(account), meta.r(cachePda(account, epoch, BigInt(idx >> H))), meta.r(inner.programId), ...remaining],
    data: concat(DISC.execute, u64le(idx), flat(l0.wots), flat(l0.auth), u32le(inner.data.length), inner.data),
  };
}
export function recoverIx(account: Pubkey, next: CchsPublic, sig: LayerSig): Instruction {
  if (sig.wots.length !== LEN || sig.auth.length !== REC_H) throw new Error('bad recovery proof shape');
  return { programId: SOLANA_PROGRAM_ID, keys: [meta.w(account)], data: concat(DISC.recover, next.root, next.recRoot, next.seed, flat(sig.wots), flat(sig.auth)) };
}
/** The 24-byte message `execute` verifies: binds account, nonce, leaf, target program and instruction data. */
export function executeMessage(account: Pubkey, nonce: bigint, idx: number, inner: Instruction): Uint8Array {
  return cchsC.executeDigest({ tag: SOLANA_TAG, account, nonce, idx: BigInt(idx), callHash: sha256(concat(inner.programId, inner.data)) });
}

// ------------------------------------------------------------------ flows
export interface Flow { rpc: Rpc; cluster: Cluster; wallet: ConnectedSolanaWallet; }

async function sendLegacy(f: Flow, ixs: Instruction[]): Promise<{ signature: string; bytes: number }> {
  const { blockhash, lastValidBlockHeight } = await f.rpc.latestBlockhash();
  const tx = unsignedTransaction(compileMessage(f.wallet.publicKey, blockhash, ixs));
  const signature = await f.wallet.signAndSend(tx, f.cluster);
  await f.rpc.confirm(signature, lastValidBlockHeight);
  return { signature, bytes: tx.length };
}

/** `create` + lookup table (create and extend) in one transaction paid by the wallet. */
export async function createAccount(f: Flow, id: SolanaIdentity): Promise<{ signature: string; table: Pubkey; bytes: number }> {
  const slot = BigInt(await f.rpc.slot());
  const payer = f.wallet.publicKey;
  const { ix: mk, table } = createLookupTable(payer, payer, slot);
  const ext = extendLookupTable(table, payer, payer, TABLE_KEYS(id.account, id.vault));
  const r = await sendLegacy(f, [createIx(payer, id.account, id.pub), mk, ext]);
  rememberTable(f.cluster, toBase58(id.account), table);
  return { ...r, table };
}

/** Lookup table alone, for an account that was created without one. */
export async function createTable(f: Flow, id: SolanaIdentity): Promise<{ signature: string; table: Pubkey; bytes: number }> {
  const slot = BigInt(await f.rpc.slot());
  const payer = f.wallet.publicKey;
  const { ix: mk, table } = createLookupTable(payer, payer, slot);
  const r = await sendLegacy(f, [mk, extendLookupTable(table, payer, payer, TABLE_KEYS(id.account, id.vault))]);
  rememberTable(f.cluster, toBase58(id.account), table);
  return { ...r, table };
}

/** Move SOL from the wallet into the vault. */
export function depositSol(f: Flow, vault: Pubkey, lamports: bigint) {
  return sendLegacy(f, [systemTransfer(f.wallet.publicKey, vault, lamports)]);
}
/** Move tokens from the wallet's token account into the vault's associated token account (created if needed). */
export function depositToken(f: Flow, vault: Pubkey, h: TokenHolding, amount: bigint) {
  const payer = f.wallet.publicKey;
  const dest = associatedTokenAddress(vault, h.mint, h.tokenProgram);
  return sendLegacy(f, [createAtaIdempotent(payer, vault, h.mint, h.tokenProgram), tokenTransferChecked(h.tokenProgram, h.address, h.mint, dest, payer, amount, h.decimals)]);
}

/** Vault holdings: SOL plus every token account the vault owns under both token programs. */
export async function vaultHoldings(rpc: Rpc, vault: Pubkey): Promise<{ lamports: bigint; tokens: TokenHolding[] }> {
  const [lamports, a, b] = await Promise.all([rpc.balance(vault), rpc.tokenAccounts(vault, TOKEN_PROGRAM), rpc.tokenAccounts(vault, TOKEN_2022_PROGRAM)]);
  return { lamports, tokens: [...a, ...b].filter((t) => t.amount > 0n) };
}

export interface SpendRequest {
  kind: 'sol' | 'token';
  to: Pubkey;
  amount: bigint;
  token?: TokenHolding; // vault's token account when kind === 'token'
}
/** The inner instruction `execute` will run, signed by the vault PDA. */
export function innerInstruction(vault: Pubkey, req: SpendRequest): Instruction {
  if (req.kind === 'sol') return systemTransfer(vault, req.to, req.amount);
  const t = req.token!;
  const destAta = associatedTokenAddress(req.to, t.mint, t.tokenProgram);
  return tokenTransferChecked(t.tokenProgram, t.address, t.mint, destAta, vault, req.amount, t.decimals);
}

export interface Signer {
  key: CchsKey;         // key of the current epoch
  trees: Map<string, Tree>;
  pool: CchsPool;
}
/** Key and tree cache of `epoch` (epoch 0 is the identity's own). */
export function epochSigner(id: SolanaIdentity, epoch: bigint, pool: CchsPool, cache: Map<string, Signer>): Signer {
  const k = epoch.toString();
  let s = cache.get(k);
  if (!s) { s = epoch === 0n ? { key: id.key, trees: id.trees, pool } : { key: epochKey(id.key, Number(epoch)), trees: new Map(), pool }; cache.set(k, s); }
  return s;
}

export type SpendStep = 'reading' | 'signing' | 'caching' | 'confirming' | 'executing';
export interface SpendResult { signature: string; bytes: number; idx: number; cached: boolean; cacheSignature?: string; cacheBytes?: number; }

/**
 * Spend from the vault: choose the leaf, publish the subtree root if this is
 * the first leaf of its subtree, sign the digest, send `execute` as a v0
 * transaction through the lookup table. The leaf is recorded before signing.
 */
export async function spend(f: Flow, id: SolanaIdentity, st: AccountState, signer: Signer, table: { address: Pubkey; addresses: Pubkey[] }, req: SpendRequest, onStep: (s: SpendStep) => void): Promise<SpendResult> {
  const accountB58 = toBase58(id.account);
  if (recordMissing(f.cluster, accountB58, st)) throw new Error('this device has no record for the current epoch; rotate keys before spending');
  const idx = nextIndex(f.cluster, accountB58, st);
  const treeIdx = BigInt(idx >> H);
  const payer = f.wallet.publicKey;
  const pub: CchsPublic = { root: st.root, recRoot: st.recRoot, seed: st.pkSeed };

  // Token spends need the recipient's associated token account to exist; the wallet creates it first.
  if (req.kind === 'token') {
    const t = req.token!;
    const destAta = associatedTokenAddress(req.to, t.mint, t.tokenProgram);
    if (!(await f.rpc.accountInfo(destAta))) {
      onStep('confirming');
      await sendLegacy(f, [createAtaIdempotent(payer, req.to, t.mint, t.tokenProgram)]);
    }
  }

  onStep('signing');
  const ck = `0/${treeIdx}`;
  if (!signer.trees.has(ck)) signer.trees.set(ck, await signer.pool.tree(signer.key, 'C', 0, treeIdx, H));
  const bottom = signer.trees.get(ck)!;

  // First leaf of the subtree in this epoch: cache its root (own transaction, legacy size).
  let cacheSignature: string | undefined, cacheBytes: number | undefined;
  const cache = await f.rpc.accountInfo(cachePda(id.account, st.epoch, treeIdx));
  const cached = !!cache && cache.data.length >= 32 && cache.data.slice(8, 32).some((b) => b !== 0);
  if (!cached) {
    const l1 = cchsC.topLayer(signer.key, treeIdx, bottom.root, signer.trees);
    if (!cchsC.verifyTopLayer(pub, treeIdx, bottom.root, l1)) throw new Error('local top-layer proof does not verify against the on-chain root');
    onStep('caching');
    const r = await sendLegacy(f, [setComputeUnitLimit(CU_CACHE), cacheSubtreeIx(payer, id.account, st.epoch, treeIdx, l1, bottom.root)]);
    cacheSignature = r.signature; cacheBytes = r.bytes;
  } else if (!keyEq(cache!.data.slice(8, 32), bottom.root)) {
    throw new Error('the cached subtree root differs from this key tree; wrong mnemonic or epoch');
  }

  const inner = innerInstruction(id.vault, req);
  const m = executeMessage(id.account, st.nonce, idx, inner);
  markSigned(f.cluster, accountB58, st.epoch, idx);
  const sig = cchsC.sign(signer.key, idx, m, true, signer.trees);
  cchsC.verify(pub, idx, m, sig, bottom.root);

  onStep('executing');
  const { blockhash, lastValidBlockHeight } = await f.rpc.latestBlockhash();
  const ixs = [setComputeUnitLimit(CU_EXECUTE), executeIx(id.account, st.epoch, idx, sig.l0, inner)];
  const msg = compileMessage(payer, blockhash, ixs, table);
  const tx = unsignedTransaction(msg);
  const sim = await f.rpc.simulate(tx);
  if (sim.err) throw new Error(`simulation failed: ${describeError(sim.err, sim.logs)}`);
  const signature = await f.wallet.signAndSend(tx, f.cluster);
  await f.rpc.confirm(signature, lastValidBlockHeight);
  return { signature, bytes: tx.length, idx, cached, cacheSignature, cacheBytes };
}

/** Rotate to the next epoch: new roots from the same mnemonic, authorised by recovery leaf `recNonce`. */
export async function recover(f: Flow, id: SolanaIdentity, st: AccountState, pool: CchsPool): Promise<{ signature: string; bytes: number; epoch: bigint }> {
  const accountB58 = toBase58(id.account);
  const recNonce = Number(st.recNonce);
  if (recNonce >= RECOVERIES) throw new Error('recovery leaves exhausted');
  if (recNonce <= highestRecoverySigned(f.cluster, accountB58)) throw new Error('this recovery leaf was already signed on this device; wait for the chain to show it or refresh');
  const cur = epochSigner(id, st.epoch, pool, new Map());
  const nextEpoch = st.epoch + 1n;
  const nextKey = epochKey(id.key, Number(nextEpoch));
  const next = await pool.keygen(nextKey, 'C', new Map(), { firstSubtree: false });
  const m = cchsC.recoveryDigest({ tag: SOLANA_TAG, account: id.account, recNonce: BigInt(recNonce), newRoot: next.root, newRecRoot: next.recRoot, newSeed: next.seed });
  if (!cur.trees.has('ff/0')) cur.trees.set('ff/0', await pool.tree(cur.key, 'C', 0xff, 0n, REC_H));
  markRecoverySigned(f.cluster, accountB58, recNonce);
  const sig = cchsC.signRecovery(cur.key, recNonce, m, cur.trees);
  if (!cchsC.verifyRecovery({ root: st.root, recRoot: st.recRoot, seed: st.pkSeed }, recNonce, m, sig)) throw new Error('local recovery proof does not verify against the on-chain recovery root');
  const r = await sendLegacy(f, [setComputeUnitLimit(CU_RECOVER), recoverIx(id.account, next, sig)]);
  markSigned(f.cluster, accountB58, nextEpoch, -1); // fresh record for the new epoch on this device
  return { ...r, epoch: nextEpoch };
}
