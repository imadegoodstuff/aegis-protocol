// The CCHS-C-20 account on Solana (program AoQ7c3GuxiF7nshFnM872FoxUz7oUDhygdhoRX6jMQKr,
// live on mainnet-beta). Same flows as the wallet's Solana panel:
//
//   const acct = await SolanaAccount.derive({ master, rpc: 'https://…', cluster: 'mainnet-beta' });
//   acct.account, acct.vault                       // base58, fixed before anything exists on chain
//   await acct.create(feePayer)                    // account + lookup table, one transaction
//   await acct.depositSol(feePayer, 10_000_000n)   // from the fee payer into the vault
//   await acct.depositToken(feePayer, holding, amount)
//   await acct.spend(feePayer, { kind: 'token', to, amount, token })   // one WOTS+ leaf per execute
//   await acct.recover(feePayer)
//
// The fee payer signs and sends the transaction (a Wallet Standard wallet in a
// browser, or `keypairFeePayer` in node); it never holds authority over the
// vault. The device that holds the master signs the WOTS+ leaf.

import { ed25519 } from "@noble/curves/ed25519";
import type { CchsKey } from "../../wallet/src/aegis/cchs";
import type { CchsPool } from "../../wallet/src/aegis/cchsPool";
import {
  Rpc, TOKEN_2022_PROGRAM, TOKEN_PROGRAM, compactArray, concat, connectSolanaWallet, fromBase58, solanaWallets, toBase58,
  type Cluster, type ConnectedSolanaWallet, type Pubkey, type TokenHolding,
} from "../../wallet/src/aegis/solana";
import {
  SOLANA_PROGRAM_ID, createAccount, createTable, decodeAccount, decodeTable, depositSol, depositToken, deriveSolanaIdentity, epochSigner, findTable,
  recover, spend, vaultHoldings, type AccountState, type Flow, type Signer, type SolanaIdentity, type SpendRequest, type SpendResult, type SpendStep,
} from "../../wallet/src/aegis/solanaAccount";
import { createPool } from "./pool";

export { Rpc, SOLANA_PROGRAM_ID, connectSolanaWallet, fromBase58, solanaWallets, toBase58 };
export type { AccountState, Cluster, ConnectedSolanaWallet as SolanaFeePayer, Pubkey, SpendRequest, SpendResult, SpendStep, TokenHolding };

/**
 * Fee payer backed by a local ed25519 keypair (the 64-byte `solana-keygen`
 * format, or a 32-byte seed). Signs the transaction and sends it through the
 * given RPC. For servers, bots and tests; browsers use `connectSolanaWallet`.
 */
export function keypairFeePayer(secret: Uint8Array, rpc: Rpc): ConnectedSolanaWallet {
  const seed = secret.slice(0, 32);
  const pub = secret.length >= 64 ? secret.slice(32, 64) : ed25519.getPublicKey(seed);
  return {
    name: "keypair", address: toBase58(pub), publicKey: pub,
    async signAndSend(tx) {
      const nSigs = tx[0];
      const msg = tx.slice(1 + nSigs * 64);
      const header = msg[0] & 0x80 ? 1 : 0;
      const numSigners = msg[header];
      if (numSigners !== 1) throw new Error(`transaction needs ${numSigners} signers; the keypair fee payer provides one`);
      return rpc.send(concat(compactArray([ed25519.sign(msg, seed)]), msg));
    },
  };
}

export class SolanaAccount {
  private signers = new Map<string, Signer>();
  private constructor(readonly identity: SolanaIdentity, readonly rpc: Rpc, readonly cluster: Cluster, readonly pool: CchsPool) {}

  static async derive(o: { master: CchsKey; rpc: Rpc | string; cluster?: Cluster; pool?: CchsPool }): Promise<SolanaAccount> {
    const pool = o.pool ?? createPool();
    const rpc = typeof o.rpc === "string" ? new Rpc(o.rpc) : o.rpc;
    const id = await deriveSolanaIdentity(o.master, pool);
    return new SolanaAccount(id, rpc, o.cluster ?? "mainnet-beta", pool);
  }

  /** Account PDA, base58. */
  get account(): string { return toBase58(this.identity.account); }
  /** Vault PDA (send SOL and tokens here), base58. */
  get vault(): string { return toBase58(this.identity.vault); }
  get programId(): string { return toBase58(SOLANA_PROGRAM_ID); }

  private flow(wallet: ConnectedSolanaWallet): Flow { return { rpc: this.rpc, cluster: this.cluster, wallet }; }

  /** True when the program exists on this RPC's cluster. */
  async programDeployed(): Promise<boolean> { return !!(await this.rpc.accountInfo(SOLANA_PROGRAM_ID))?.executable; }
  /** On-chain state, or null before `create`. */
  async state(): Promise<AccountState | null> {
    const info = await this.rpc.accountInfo(this.identity.account);
    return info ? decodeAccount(info.data) : null;
  }
  /** SOL and token balances of the vault. */
  holdings() { return vaultHoldings(this.rpc, this.identity.vault); }
  /** The fee payer's token accounts (what `depositToken` can move). */
  async feePayerTokens(wallet: ConnectedSolanaWallet): Promise<TokenHolding[]> {
    const [a, b] = await Promise.all([this.rpc.tokenAccounts(wallet.publicKey, TOKEN_PROGRAM), this.rpc.tokenAccounts(wallet.publicKey, TOKEN_2022_PROGRAM)]);
    return [...a, ...b].filter((t) => t.amount > 0n);
  }

  /** Create the account and its address lookup table in one transaction. */
  async create(wallet: ConnectedSolanaWallet) {
    if (!(await this.programDeployed())) throw new Error(`program ${this.programId} is not deployed on this cluster`);
    const r = await createAccount(this.flow(wallet), this.identity);
    return { signature: r.signature, table: toBase58(r.table), bytes: r.bytes };
  }
  /** Lookup table for an account created without one. */
  async createLookupTable(wallet: ConnectedSolanaWallet) {
    const r = await createTable(this.flow(wallet), this.identity);
    return { signature: r.signature, table: toBase58(r.table), bytes: r.bytes };
  }
  depositSol(wallet: ConnectedSolanaWallet, lamports: bigint) { return depositSol(this.flow(wallet), this.identity.vault, lamports); }
  depositToken(wallet: ConnectedSolanaWallet, holding: TokenHolding, amount: bigint) { return depositToken(this.flow(wallet), this.identity.vault, holding, amount); }

  private async table() {
    const addr = await findTable(this.rpc, this.cluster, this.identity.account);
    if (!addr) throw new Error("no lookup table for this account; call createLookupTable first");
    const info = await this.rpc.accountInfo(addr);
    if (!info) throw new Error("lookup table account not found");
    return { address: addr, addresses: decodeTable(info.data) };
  }

  /**
   * Spend from the vault with one WOTS+ leaf. `req.to` is a base58 address or
   * 32-byte key; for tokens pass the vault's holding (from `holdings()`).
   * The first leaf of a subtree sends `cache_subtree` first.
   */
  async spend(wallet: ConnectedSolanaWallet, req: { kind: "sol" | "token"; to: string | Pubkey; amount: bigint; token?: TokenHolding }, onStep: (s: SpendStep) => void = () => {}): Promise<SpendResult> {
    const st = await this.state();
    if (!st) throw new Error("account not created");
    const to = typeof req.to === "string" ? fromBase58(req.to) : req.to;
    const signer = epochSigner(this.identity, st.epoch, this.pool, this.signers);
    const table = await this.table();
    return spend(this.flow(wallet), this.identity, st, signer, table, { ...req, to }, onStep);
  }

  /** Rotate to the next epoch (new roots from the same master). */
  async recover(wallet: ConnectedSolanaWallet) {
    const st = await this.state();
    if (!st) throw new Error("account not created");
    return recover(this.flow(wallet), this.identity, st, this.pool);
  }
}
