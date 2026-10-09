// Solana primitives without a Solana client library: base58 keys, program
// derived addresses, legacy and v0 message serialisation, a JSON-RPC client,
// the few native instructions the account needs (System, ComputeBudget,
// AddressLookupTable, SPL Token, Associated Token) and a Wallet Standard
// connector for Phantom / Backpack / Solflare. About 400 lines; the whole
// surface the CCHS account uses, nothing else.

import { sha256 } from '@noble/hashes/sha256';
import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';

export type Pubkey = Uint8Array; // 32 bytes

export const toBase58 = (k: Uint8Array): string => base58.encode(k);
export function fromBase58(s: string): Pubkey {
  const k = base58.decode(s.trim());
  if (k.length !== 32) throw new Error(`not a 32-byte key: ${s}`);
  return k;
}
export const keyEq = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);
export const shortKey = (s: string) => (s.length > 16 ? `${s.slice(0, 6)}…${s.slice(-6)}` : s);

export const SYSTEM_PROGRAM = fromBase58('11111111111111111111111111111111');
export const COMPUTE_BUDGET_PROGRAM = fromBase58('ComputeBudget111111111111111111111111111111');
export const LOOKUP_TABLE_PROGRAM = fromBase58('AddressLookupTab1e1111111111111111111111111');
export const TOKEN_PROGRAM = fromBase58('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
export const TOKEN_2022_PROGRAM = fromBase58('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
export const ASSOCIATED_TOKEN_PROGRAM = fromBase58('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
export const LAMPORTS_PER_SOL = 1_000_000_000n;

// ------------------------------------------------------------------ encoding
const enc = new TextEncoder();
export const utf8 = (s: string) => enc.encode(s);
export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
export function u8(n: number) { return Uint8Array.of(n & 0xff); }
export function u32le(n: number) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; }
export function u64le(n: bigint | number) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; }
export function readU64le(b: Uint8Array, o: number): bigint { return new DataView(b.buffer, b.byteOffset + o, 8).getBigUint64(0, true); }
/** Solana's compact-u16 length prefix. */
export function compactU16(n: number): Uint8Array {
  const out: number[] = [];
  let rem = n;
  for (;;) {
    let b = rem & 0x7f; rem >>= 7;
    if (rem === 0) { out.push(b); break; }
    b |= 0x80; out.push(b);
  }
  return Uint8Array.from(out);
}
export function compactArray(items: Uint8Array[]): Uint8Array { return concat(compactU16(items.length), ...items); }
export function toBase64(b: Uint8Array): string { let s = ''; for (const x of b) s += String.fromCharCode(x); return btoa(s); }
export function fromBase64(s: string): Uint8Array { const bin = atob(s); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }

// --------------------------------------------------------------------- PDAs
const PDA_MARKER = utf8('ProgramDerivedAddress');
function onCurve(k: Uint8Array): boolean {
  try { ed25519.ExtendedPoint.fromHex(k); return true; } catch { return false; }
}
/** `Pubkey::find_program_address`: the first bump from 255 down whose hash is off the curve. */
export function findProgramAddress(seeds: Uint8Array[], programId: Pubkey): [Pubkey, number] {
  for (const s of seeds) if (s.length > 32) throw new Error('seed longer than 32 bytes');
  for (let bump = 255; bump >= 0; bump--) {
    const h = sha256(concat(...seeds, u8(bump), programId, PDA_MARKER));
    if (!onCurve(h)) return [h, bump];
  }
  throw new Error('no viable bump');
}
export function associatedTokenAddress(owner: Pubkey, mint: Pubkey, tokenProgram: Pubkey = TOKEN_PROGRAM): Pubkey {
  return findProgramAddress([owner, tokenProgram, mint], ASSOCIATED_TOKEN_PROGRAM)[0];
}

// ------------------------------------------------------------- instructions
export interface AccountMeta { pubkey: Pubkey; isSigner: boolean; isWritable: boolean; }
export interface Instruction { programId: Pubkey; keys: AccountMeta[]; data: Uint8Array; }
const w = (pubkey: Pubkey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: true });
const r = (pubkey: Pubkey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: false });
export const meta = { w, r };

export const systemTransfer = (from: Pubkey, to: Pubkey, lamports: bigint): Instruction =>
  ({ programId: SYSTEM_PROGRAM, keys: [w(from, true), w(to)], data: concat(u32le(2), u64le(lamports)) });
export const setComputeUnitLimit = (units: number): Instruction =>
  ({ programId: COMPUTE_BUDGET_PROGRAM, keys: [], data: concat(u8(2), u32le(units)) });
export const setComputeUnitPrice = (microLamports: bigint): Instruction =>
  ({ programId: COMPUTE_BUDGET_PROGRAM, keys: [], data: concat(u8(3), u64le(microLamports)) });

export function lookupTableAddress(authority: Pubkey, recentSlot: bigint): [Pubkey, number] {
  return findProgramAddress([authority, u64le(recentSlot)], LOOKUP_TABLE_PROGRAM);
}
export function createLookupTable(authority: Pubkey, payer: Pubkey, recentSlot: bigint): { ix: Instruction; table: Pubkey } {
  const [table, bump] = lookupTableAddress(authority, recentSlot);
  return { table, ix: { programId: LOOKUP_TABLE_PROGRAM, keys: [w(table), r(authority, true), w(payer, true), r(SYSTEM_PROGRAM)], data: concat(u32le(0), u64le(recentSlot), u8(bump)) } };
}
export const extendLookupTable = (table: Pubkey, authority: Pubkey, payer: Pubkey, addresses: Pubkey[]): Instruction =>
  ({ programId: LOOKUP_TABLE_PROGRAM, keys: [w(table), r(authority, true), w(payer, true), r(SYSTEM_PROGRAM)], data: concat(u32le(2), u64le(addresses.length), ...addresses) });

/** SPL Token `TransferChecked` (works for Token and Token-2022). `owner` signs; here it is the vault PDA, which the program signs for. */
export const tokenTransferChecked = (tokenProgram: Pubkey, source: Pubkey, mint: Pubkey, dest: Pubkey, owner: Pubkey, amount: bigint, decimals: number, ownerSigns = true): Instruction =>
  ({ programId: tokenProgram, keys: [w(source), r(mint), w(dest), r(owner, ownerSigns)], data: concat(u8(12), u64le(amount), u8(decimals)) });
/** Associated Token `CreateIdempotent`. */
export const createAtaIdempotent = (payer: Pubkey, owner: Pubkey, mint: Pubkey, tokenProgram: Pubkey): Instruction =>
  ({ programId: ASSOCIATED_TOKEN_PROGRAM, keys: [w(payer, true), w(associatedTokenAddress(owner, mint, tokenProgram)), r(owner), r(mint), r(SYSTEM_PROGRAM), r(tokenProgram)], data: u8(1) });

// ----------------------------------------------------------------- messages
export interface CompiledMessage { bytes: Uint8Array; staticKeys: Pubkey[]; lookups: number; }

/**
 * Compile instructions into a legacy message, or a v0 message when a lookup
 * table is given (every non-signer key found in the table is loaded from it).
 */
export function compileMessage(payer: Pubkey, blockhash: Uint8Array, ixs: Instruction[], table?: { address: Pubkey; addresses: Pubkey[] }): CompiledMessage {
  type Info = { key: Pubkey; signer: boolean; writable: boolean };
  const infos = new Map<string, Info>();
  const touch = (key: Pubkey, signer: boolean, writable: boolean) => {
    const id = toBase58(key);
    const cur = infos.get(id);
    if (cur) { cur.signer ||= signer; cur.writable ||= writable; } else infos.set(id, { key, signer, writable });
  };
  touch(payer, true, true);
  for (const ix of ixs) { for (const k of ix.keys) touch(k.pubkey, k.isSigner, k.isWritable); touch(ix.programId, false, false); }

  const inTable = (key: Pubkey) => table?.addresses.findIndex((a) => keyEq(a, key)) ?? -1;
  const all = [...infos.values()];
  const isStatic = (i: Info) => i.signer || keyEq(i.key, payer) || inTable(i.key) < 0;
  const staticInfos = all.filter(isStatic);
  const looked = all.filter((i) => !isStatic(i));
  const order = (a: Info, b: Info) => {
    const rank = (i: Info) => (keyEq(i.key, payer) ? 0 : i.signer && i.writable ? 1 : i.signer ? 2 : i.writable ? 3 : 4);
    return rank(a) - rank(b);
  };
  staticInfos.sort(order);
  const lookedW = looked.filter((i) => i.writable), lookedR = looked.filter((i) => !i.writable);
  const keys = [...staticInfos.map((i) => i.key), ...lookedW.map((i) => i.key), ...lookedR.map((i) => i.key)];
  const indexOf = (key: Pubkey) => { const i = keys.findIndex((k) => keyEq(k, key)); if (i < 0) throw new Error('key not compiled'); return i; };

  const numSigners = staticInfos.filter((i) => i.signer || keyEq(i.key, payer)).length;
  const numReadonlySigned = staticInfos.filter((i) => (i.signer || keyEq(i.key, payer)) && !i.writable).length;
  const numReadonlyUnsigned = staticInfos.filter((i) => !(i.signer || keyEq(i.key, payer)) && !i.writable).length;
  const header = Uint8Array.of(numSigners, numReadonlySigned, numReadonlyUnsigned);
  const compiledIxs = ixs.map((ix) => concat(u8(indexOf(ix.programId)), compactArray(ix.keys.map((k) => u8(indexOf(k.pubkey)))), compactU16(ix.data.length), ix.data));
  const body = concat(header, compactArray(staticInfos.map((i) => i.key)), blockhash, compactArray(compiledIxs));
  if (!table) return { bytes: body, staticKeys: staticInfos.map((i) => i.key), lookups: 0 };
  const lookup = concat(table.address, compactArray(lookedW.map((i) => u8(inTable(i.key)))), compactArray(lookedR.map((i) => u8(inTable(i.key)))));
  const lookups = looked.length ? [lookup] : [];
  return { bytes: concat(u8(0x80), body, compactArray(lookups)), staticKeys: staticInfos.map((i) => i.key), lookups: looked.length };
}
/** Unsigned wire transaction: `numSigners` empty signatures followed by the message (what a wallet is asked to sign and send). */
export function unsignedTransaction(msg: CompiledMessage, numSigners = 1): Uint8Array {
  return concat(compactArray(Array.from({ length: numSigners }, () => new Uint8Array(64))), msg.bytes);
}
export const PACKET_SIZE = 1232;

// ---------------------------------------------------------------------- RPC
export type Cluster = 'devnet' | 'mainnet-beta';
export const DEFAULT_RPC: Record<Cluster, string> = {
  devnet: 'https://api.devnet.solana.com',
  'mainnet-beta': 'https://api.mainnet-beta.solana.com',
};
export const EXPLORER = (cluster: Cluster, kind: 'tx' | 'address', id: string) =>
  `https://explorer.solana.com/${kind}/${id}${cluster === 'devnet' ? '?cluster=devnet' : ''}`;

export interface AccountInfo { data: Uint8Array; owner: Pubkey; lamports: bigint; executable: boolean; }

export class Rpc {
  private id = 0;
  constructor(readonly url: string) {}

  async call<T>(method: string, params: unknown[] = []): Promise<T> {
    const res = await fetch(this.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++this.id, method, params }) });
    if (!res.ok) throw new Error(`RPC ${method}: HTTP ${res.status}`);
    const j = (await res.json()) as { result?: T; error?: { code: number; message: string; data?: unknown } };
    if (j.error) throw new Error(`RPC ${method}: ${j.error.message}`);
    return j.result as T;
  }
  async latestBlockhash(): Promise<{ blockhash: Uint8Array; lastValidBlockHeight: number }> {
    const r = await this.call<{ value: { blockhash: string; lastValidBlockHeight: number } }>('getLatestBlockhash', [{ commitment: 'confirmed' }]);
    return { blockhash: fromBase58(r.value.blockhash), lastValidBlockHeight: r.value.lastValidBlockHeight };
  }
  slot(): Promise<number> { return this.call<number>('getSlot', [{ commitment: 'finalized' }]); }
  async balance(key: Pubkey): Promise<bigint> {
    const r = await this.call<{ value: number }>('getBalance', [toBase58(key), { commitment: 'confirmed' }]);
    return BigInt(r.value);
  }
  async accountInfo(key: Pubkey): Promise<AccountInfo | null> {
    const r = await this.call<{ value: { data: [string, string]; owner: string; lamports: number; executable: boolean } | null }>('getAccountInfo', [toBase58(key), { encoding: 'base64', commitment: 'confirmed' }]);
    if (!r.value) return null;
    return { data: fromBase64(r.value.data[0]), owner: fromBase58(r.value.owner), lamports: BigInt(r.value.lamports), executable: r.value.executable };
  }
  async rentExempt(bytes: number): Promise<bigint> { return BigInt(await this.call<number>('getMinimumBalanceForRentExemption', [bytes])); }
  /** Token accounts of `owner` under one token program (parsed). */
  async tokenAccounts(owner: Pubkey, tokenProgram: Pubkey): Promise<TokenHolding[]> {
    const r = await this.call<{ value: { pubkey: string; account: { data: { parsed: { info: { mint: string; tokenAmount: { amount: string; decimals: number } } } } } }[] }>(
      'getTokenAccountsByOwner', [toBase58(owner), { programId: toBase58(tokenProgram) }, { encoding: 'jsonParsed', commitment: 'confirmed' }]);
    return r.value.map((v) => ({ address: fromBase58(v.pubkey), mint: fromBase58(v.account.data.parsed.info.mint), amount: BigInt(v.account.data.parsed.info.tokenAmount.amount), decimals: v.account.data.parsed.info.tokenAmount.decimals, tokenProgram }));
  }
  async simulate(tx: Uint8Array): Promise<{ err: unknown; logs: string[]; unitsConsumed?: number }> {
    const r = await this.call<{ value: { err: unknown; logs: string[] | null; unitsConsumed?: number } }>('simulateTransaction', [toBase64(tx), { encoding: 'base64', sigVerify: false, replaceRecentBlockhash: true, commitment: 'confirmed' }]);
    return { err: r.value.err, logs: r.value.logs ?? [], unitsConsumed: r.value.unitsConsumed };
  }
  async send(tx: Uint8Array): Promise<string> {
    return this.call<string>('sendTransaction', [toBase64(tx), { encoding: 'base64', preflightCommitment: 'confirmed', maxRetries: 5 }]);
  }
  /** Poll until the signature is confirmed (or errors / the blockhash expires). */
  async confirm(signature: string, lastValidBlockHeight?: number, timeoutMs = 90_000): Promise<void> {
    const t0 = Date.now();
    for (;;) {
      const r = await this.call<{ value: ({ confirmationStatus: string; err: unknown } | null)[] }>('getSignatureStatuses', [[signature], { searchTransactionHistory: true }]);
      const s = r.value[0];
      if (s?.err) throw new Error(`transaction failed: ${JSON.stringify(s.err)}`);
      if (s && (s.confirmationStatus === 'confirmed' || s.confirmationStatus === 'finalized')) return;
      if (lastValidBlockHeight !== undefined) {
        const h = await this.call<number>('getBlockHeight', [{ commitment: 'confirmed' }]);
        if (h > lastValidBlockHeight) throw new Error('transaction expired before confirmation');
      }
      if (Date.now() - t0 > timeoutMs) throw new Error('confirmation timed out');
      await new Promise((res) => setTimeout(res, 1500));
    }
  }
  signaturesFor(key: Pubkey, before?: string, limit = 1000): Promise<{ signature: string; slot: number; err: unknown }[]> {
    return this.call('getSignaturesForAddress', [toBase58(key), { limit, before, commitment: 'confirmed' }]);
  }
  transaction(signature: string): Promise<ParsedTx | null> {
    return this.call('getTransaction', [signature, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }]);
  }
}
export interface TokenHolding { address: Pubkey; mint: Pubkey; amount: bigint; decimals: number; tokenProgram: Pubkey; }
export interface ParsedTx { transaction: { message: { instructions: { programId: string; program?: string; parsed?: { type: string; info: Record<string, unknown> } }[] } }; }

/** Decimals of a mint (offset 44 of both Token and Token-2022 mint layouts). */
export function mintDecimals(info: AccountInfo): number {
  if (info.data.length < 82) throw new Error('not a mint account');
  return info.data[44];
}
export function formatAmount(amount: bigint, decimals: number): string {
  const s = amount.toString().padStart(decimals + 1, '0');
  const int = s.slice(0, s.length - decimals), frac = s.slice(s.length - decimals).replace(/0+$/, '');
  return frac ? `${int}.${frac}` : int;
}
export function parseAmount(text: string, decimals: number): bigint {
  const t = text.trim();
  if (!/^\d*(\.\d*)?$/.test(t) || t === '' || t === '.') throw new Error('bad amount');
  const [int, frac = ''] = t.split('.');
  if (frac.length > decimals) throw new Error(`at most ${decimals} decimals`);
  return BigInt(int || '0') * 10n ** BigInt(decimals) + BigInt((frac + '0'.repeat(decimals)).slice(0, decimals) || '0');
}

// --------------------------------------------------------- Wallet Standard
// https://github.com/wallet-standard/wallet-standard — the injection protocol
// Phantom, Backpack, Solflare and others implement. The app announces itself
// and every wallet registers; nothing is imported.
export interface StandardAccount { address: string; publicKey: Uint8Array; chains: string[]; features: string[]; }
interface StandardWallet {
  name: string; icon: string; chains: string[]; accounts: StandardAccount[];
  features: Record<string, unknown> & {
    'standard:connect'?: { connect(opts?: { silent?: boolean }): Promise<{ accounts: StandardAccount[] }> };
    'solana:signAndSendTransaction'?: { signAndSendTransaction(...inputs: { transaction: Uint8Array; account: StandardAccount; chain: string; options?: { preflightCommitment?: string; skipPreflight?: boolean } }[]): Promise<{ signature: Uint8Array }[]> };
  };
}
const registry: StandardWallet[] = [];
let announced = false;
function discover(): StandardWallet[] {
  if (typeof window === 'undefined') return [];
  if (!announced) {
    announced = true;
    type Api = { register: (...ws: StandardWallet[]) => () => void };
    const api: Api = { register: (...ws) => { for (const w of ws) if (!registry.includes(w)) registry.push(w); return () => {}; } };
    window.addEventListener('wallet-standard:register-wallet', ((e: CustomEvent<(api: Api) => void>) => { try { e.detail(api); } catch { /* ignore a misbehaving wallet */ } }) as EventListener);
    window.dispatchEvent(new CustomEvent('wallet-standard:app-ready', { detail: api }));
  }
  return registry.filter((w) => w.features['solana:signAndSendTransaction'] && w.features['standard:connect']);
}
export function solanaWallets(): { name: string; icon: string }[] { return discover().map((w) => ({ name: w.name, icon: w.icon })); }

export interface ConnectedSolanaWallet {
  name: string;
  address: string;
  publicKey: Pubkey;
  /** Sign with the wallet and let it broadcast; returns the base58 signature. */
  signAndSend(tx: Uint8Array, cluster: Cluster): Promise<string>;
}
export async function connectSolanaWallet(preferred?: string): Promise<ConnectedSolanaWallet> {
  const ws = discover();
  if (!ws.length) throw new Error('No Solana wallet detected. Install Phantom, Backpack or Solflare.');
  const wlt = ws.find((w) => w.name === preferred) ?? ws[0];
  const { accounts } = await wlt.features['standard:connect']!.connect();
  const acct = accounts[0] ?? wlt.accounts[0];
  if (!acct) throw new Error('the wallet authorised no account');
  const chainOf = (c: Cluster) => (c === 'devnet' ? 'solana:devnet' : 'solana:mainnet');
  return {
    name: wlt.name, address: acct.address, publicKey: new Uint8Array(acct.publicKey),
    async signAndSend(tx, cluster) {
      const chain = chainOf(cluster);
      if (!wlt.chains.includes(chain)) throw new Error(`${wlt.name} does not offer ${chain}`);
      const [{ signature }] = await wlt.features['solana:signAndSendTransaction']!.signAndSendTransaction({ transaction: tx, account: acct, chain, options: { preflightCommitment: 'confirmed' } });
      return toBase58(new Uint8Array(signature));
    },
  };
}
