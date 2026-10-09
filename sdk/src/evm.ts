// The CCHS-K-20 account on an EVM chain (evm/src/AegisCCHSAccount.sol via the
// factory). The same steps the wallet's Protect panel performs, as a class:
//
//   const acct = await EvmAccount.derive({ master, chain: base, publicClient, pool });
//   acct.address                      // fixed by the mnemonic and the chain, before anything is deployed
//   await acct.status()               // factory / proxy / account present, balances
//   await acct.protect(walletClient, { value: parseEther('0.1'), tokens: [usdc] })
//   await acct.execute(walletClient, { to, value, data })   // one WOTS+ leaf, relayed by walletClient
//   await acct.recover(walletClient)                        // rotate to the next epoch
//
// `walletClient` is any viem WalletClient (browser wallet, private key, …); it
// pays gas and holds no authority over the account.

import {
  encodeFunctionData, erc20Abi, hexToBytes, keccak256, type Address, type Chain, type Hex, type PublicClient, type WalletClient,
} from "viem";
import { cchsK, H, signatureBytes, toAbiLayerSig, toHex, type CchsKey, type Tree } from "../../wallet/src/aegis/cchs";
import {
  ACCOUNT_ABI, DETERMINISTIC_PROXY, FACTORY_ABI, FACTORY_ADDRESS, FACTORY_PUBLISH_DATA, deriveChainIdentity, epochKey, highestRecoverySigned,
  laneFirst, laneOf, LANES, markIndexSigned, markRecoverySigned, nextSigningIndex, predictAccount, recordMissing, type ChainIdentity,
} from "../../wallet/src/aegis/cchsAccount";
import type { CchsPool } from "../../wallet/src/aegis/cchsPool";
import { createPool } from "./pool";

export { ACCOUNT_ABI, DETERMINISTIC_PROXY, FACTORY_ABI, FACTORY_ADDRESS, FACTORY_PUBLISH_DATA, LANES, predictAccount };

export interface EvmStatus {
  factory: "present" | "absent";
  proxy: "present" | "absent";
  account: "deployed" | "none";
  balance: bigint;
  /** Present when the account is deployed. */
  epoch?: number;
  nextIdx?: bigint;
  recNonce?: bigint;
}
export interface ProtectOptions {
  /** Native value to move into the account. */
  value?: bigint;
  /** ERC-20 tokens to move; the wallet's whole balance of each. Approvals are sent first when needed. */
  tokens?: Address[];
  /** Publish the factory on this chain if it is absent (one extra transaction, ~3.7 M gas). Default true. */
  publishFactory?: boolean;
  onStep?: (step: string, tx?: Hex) => void;
}
export interface ExecuteRequest { to: Address; value?: bigint; data?: Hex; }
export interface ExecuteResult { hash: Hex; idx: number; lane: number; layers: 1 | 2; signatureBytes: number; }

type EpochKeys = { key: CchsKey; trees: Map<string, Tree>; root: Hex; recRoot: Hex; seed: Hex };

export class EvmAccount {
  private epochs = new Map<number, EpochKeys>();
  private constructor(
    readonly chain: Chain,
    readonly publicClient: PublicClient,
    readonly identity: ChainIdentity,
    readonly pool: CchsPool,
    /** Lane this signer uses (0..15). Two signers of one account must use different lanes. */
    readonly lane: number,
  ) {}

  /** Derive the chain's key tree (about a second in-process) and the account address. */
  static async derive(o: { master: CchsKey; chain: Chain; publicClient: PublicClient; pool?: CchsPool; lane?: number }): Promise<EvmAccount> {
    const lane = o.lane ?? 0;
    if (!Number.isInteger(lane) || lane < 0 || lane >= LANES) throw new Error(`lane must be in [0, ${LANES})`);
    const pool = o.pool ?? createPool();
    const id = await deriveChainIdentity(o.master, o.chain.id, pool);
    return new EvmAccount(o.chain, o.publicClient, id, pool, lane);
  }

  get address(): Address { return this.identity.address; }
  /** Epoch-0 public key: top root, recovery root, 16-byte seed. */
  get publicKey() { return { root: this.identity.root, recRoot: this.identity.recRoot, seed: this.identity.seed }; }

  async status(): Promise<EvmStatus> {
    const pub = this.publicClient;
    const [fc, px, ac, balance] = await Promise.all([
      pub.getCode({ address: FACTORY_ADDRESS }), pub.getCode({ address: DETERMINISTIC_PROXY }), pub.getCode({ address: this.address }), pub.getBalance({ address: this.address }),
    ]);
    const has = (c?: Hex) => !!c && c !== "0x";
    const st: EvmStatus = { factory: has(fc) ? "present" : "absent", proxy: has(px) ? "present" : "absent", account: has(ac) ? "deployed" : "none", balance };
    if (st.account === "deployed") {
      const [epoch, nextIdx, recNonce] = await Promise.all([
        this.read<bigint>("epoch"), this.read<bigint>("nextIdx", [this.lane]), this.read<bigint>("recNonce"),
      ]);
      st.epoch = Number(epoch); st.nextIdx = nextIdx; st.recNonce = recNonce;
    }
    return st;
  }

  private read<T>(functionName: string, args: unknown[] = []): Promise<T> {
    return this.publicClient.readContract({ address: this.address, abi: ACCOUNT_ABI, functionName, args }) as Promise<T>;
  }
  private async wait(hash: Hex) { await this.publicClient.waitForTransactionReceipt({ hash }); }
  private signerOf(wc: WalletClient): Address {
    if (!wc.account) throw new Error("walletClient has no account");
    return wc.account.address;
  }

  /** Raw transaction that publishes the factory on this chain (anyone may send it; same address everywhere). */
  factoryPublishTx(): { to: Address; data: Hex } { return { to: DETERMINISTIC_PROXY, data: FACTORY_PUBLISH_DATA }; }

  /**
   * Create the account (if needed) and move assets into it. On a fresh chain
   * this is: publish factory → approve each token → `deployAndMove`. On an
   * existing account it is plain transfers. Every transaction is confirmed
   * before the next.
   */
  async protect(wc: WalletClient, o: ProtectOptions = {}): Promise<{ hashes: Hex[] }> {
    const from = this.signerOf(wc);
    const pub = this.publicClient;
    const value = o.value ?? 0n;
    const tokens = o.tokens ?? [];
    const step = o.onStep ?? (() => {});
    const hashes: Hex[] = [];
    const st = await this.status();
    const balances = await Promise.all(tokens.map((t) => pub.readContract({ address: t, abi: erc20Abi, functionName: "balanceOf", args: [from] }) as Promise<bigint>));
    const movable = tokens.map((t, i) => ({ t, bal: balances[i] })).filter((x) => x.bal > 0n);

    if (st.account === "deployed") {
      for (const { t, bal } of movable) {
        step(`transfer ${t}`);
        const h = await wc.writeContract({ address: t, abi: erc20Abi, functionName: "transfer", args: [this.address, bal], chain: this.chain, account: from });
        hashes.push(h); step(`transfer ${t}`, h); await this.wait(h);
      }
      if (value > 0n) {
        step("transfer native");
        const h = await wc.sendTransaction({ to: this.address, value, chain: this.chain, account: from });
        hashes.push(h); step("transfer native", h); await this.wait(h);
      }
      return { hashes };
    }

    if (st.factory === "absent") {
      if (o.publishFactory === false) throw new Error("factory is absent on this chain");
      if (st.proxy !== "present") throw new Error("deterministic-deployment proxy is absent on this chain");
      step("publish factory");
      const h = await wc.sendTransaction({ ...this.factoryPublishTx(), chain: this.chain, account: from });
      hashes.push(h); step("publish factory", h); await this.wait(h);
      const code = await pub.getCode({ address: FACTORY_ADDRESS });
      if (!code || code === "0x") throw new Error("factory did not appear at the expected address");
    }
    for (const { t, bal } of movable) {
      const allowance = (await pub.readContract({ address: t, abi: erc20Abi, functionName: "allowance", args: [from, FACTORY_ADDRESS] })) as bigint;
      if (allowance >= bal) continue;
      step(`approve ${t}`);
      const h = await wc.writeContract({ address: t, abi: erc20Abi, functionName: "approve", args: [FACTORY_ADDRESS, bal], chain: this.chain, account: from });
      hashes.push(h); step(`approve ${t}`, h); await this.wait(h);
    }
    const { root, recRoot, seed } = this.identity;
    step("deploy");
    const h = movable.length
      ? await wc.writeContract({ address: FACTORY_ADDRESS, abi: FACTORY_ABI, functionName: "deployAndMove", args: [root, recRoot, seed, false, movable.map((x) => x.t)], value, chain: this.chain, account: from })
      : await wc.writeContract({ address: FACTORY_ADDRESS, abi: FACTORY_ABI, functionName: "deploy", args: [root, recRoot, seed, false], value, chain: this.chain, account: from });
    hashes.push(h); step("deploy", h); await this.wait(h);
    return { hashes };
  }

  /** Calldata for an ERC-20 transfer out of the account, for `execute`. */
  static erc20Transfer(token: Address, to: Address, amount: bigint): ExecuteRequest {
    return { to: token, value: 0n, data: encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [to, amount] }) };
  }

  private async onchainPublicKey() {
    const [root, recRoot, seed] = await Promise.all([this.read<Hex>("root"), this.read<Hex>("recRoot"), this.read<Hex>("pkSeed")]);
    return { root, recRoot, seed };
  }
  /** Keys of `epoch`, checked against the public key the chain holds. */
  private async epochKeys(epoch: number): Promise<EpochKeys> {
    let e = this.epochs.get(epoch);
    if (!e) {
      const ci = this.identity;
      if (epoch === 0) e = { key: ci.key, trees: ci.trees, root: ci.root, recRoot: ci.recRoot, seed: ci.seed };
      else {
        const key = epochKey(ci.key, epoch);
        const trees = new Map<string, Tree>();
        const pub = await this.pool.keygen(key, "K", trees, { firstSubtree: false });
        e = { key, trees, root: toHex(pub.root), recRoot: toHex(pub.recRoot), seed: toHex(pub.seed) };
      }
      this.epochs.set(epoch, e);
    }
    const onchain = await this.onchainPublicKey();
    const same = (a: Hex, b: Hex) => a.toLowerCase() === b.toLowerCase();
    if (!same(e.root, onchain.root) || !same(e.recRoot, onchain.recRoot) || !same(e.seed, onchain.seed)) {
      throw new Error(`the chain holds a public key for epoch ${epoch} that this master does not derive`);
    }
    return e;
  }

  /**
   * Execute `to.call{value}(data)` from the account with one WOTS+ leaf of
   * this signer's lane. The leaf is recorded as used before it is signed;
   * the digest is checked against the contract's `digestAt` before signing.
   */
  async execute(wc: WalletClient, req: ExecuteRequest): Promise<ExecuteResult> {
    const from = this.signerOf(wc);
    const account = this.address, lane = this.lane, chainId = this.chain.id;
    const value = req.value ?? 0n, data = req.data ?? "0x";
    const [nextIdx, nonce, epochBig] = await Promise.all([this.read<bigint>("nextIdx", [lane]), this.read<bigint>("nonce", [lane]), this.read<bigint>("epoch")]);
    const epoch = Number(epochBig);
    if (recordMissing(chainId, account, epoch, nextIdx, lane)) {
      throw new Error(`lane ${lane} of this account has been used (nextIdx ${nextIdx - BigInt(laneFirst(lane))} in the lane) and this host holds no record of it; recover to a new epoch or use another lane`);
    }
    const { key, trees } = await this.epochKeys(epoch);
    const idx = nextSigningIndex(chainId, account, epoch, nextIdx, lane);
    const [needsTop, onchainDigest] = await Promise.all([
      this.read<boolean>("needsTopLayerAt", [BigInt(idx)]), this.read<Hex>("digestAt", [BigInt(idx), req.to, value, data]),
    ]);
    const m = cchsK.executeDigest({ chainId: BigInt(chainId), account: hexToBytes(account), nonce, idx: BigInt(idx), target: hexToBytes(req.to), value, dataHash: hexToBytes(keccak256(data)) });
    if (toHex(m).toLowerCase() !== onchainDigest.toLowerCase()) throw new Error("local digest does not match the contract; refusing to sign");

    const treeIdx = BigInt(idx >> H), ck = `0/${treeIdx}`;
    if (!trees.has(ck)) trees.set(ck, await this.pool.tree(key, "K", 0, treeIdx, H));
    markIndexSigned(chainId, account, epoch, idx, lane);
    const sig = cchsK.sign(key, idx, m, !needsTop, trees);
    const onchain = await this.onchainPublicKey();
    cchsK.verify({ root: hexToBytes(onchain.root), recRoot: hexToBytes(onchain.recRoot), seed: hexToBytes(onchain.seed) }, idx, m, sig, needsTop ? undefined : trees.get(ck)!.root);

    const hash = sig.l1
      ? await wc.writeContract({ address: account, abi: ACCOUNT_ABI, functionName: "executeFirst", args: [req.to, value, data, BigInt(idx), toAbiLayerSig(sig.l0), toAbiLayerSig(sig.l1)], chain: this.chain, account: from })
      : await wc.writeContract({ address: account, abi: ACCOUNT_ABI, functionName: "execute", args: [req.to, value, data, BigInt(idx), toAbiLayerSig(sig.l0)], chain: this.chain, account: from });
    await this.wait(hash);
    return { hash, idx, lane: laneOf(idx), layers: sig.l1 ? 2 : 1, signatureBytes: signatureBytes(sig) };
  }

  /** Rotate to epoch + 1 (keys derived from the same master), authorised by the recovery tree. */
  async recover(wc: WalletClient): Promise<{ hash: Hex; epoch: number }> {
    const from = this.signerOf(wc);
    const account = this.address, chainId = this.chain.id;
    const [epochBig, recNonce] = await Promise.all([this.read<bigint>("epoch"), this.read<bigint>("recNonce")]);
    const epoch = Number(epochBig);
    if (Number(recNonce) <= highestRecoverySigned(chainId, account)) throw new Error("a rotation for this recovery leaf was already signed by this host; wait for it to land");
    const cur = await this.epochKeys(epoch);
    const nextKey = epochKey(this.identity.key, epoch + 1);
    const nextTrees = new Map<string, Tree>();
    const next = await this.pool.keygen(nextKey, "K", nextTrees, { firstSubtree: false });
    this.epochs.set(epoch + 1, { key: nextKey, trees: nextTrees, root: toHex(next.root), recRoot: toHex(next.recRoot), seed: toHex(next.seed) });
    const m = cchsK.recoveryDigest({ chainId: BigInt(chainId), account: hexToBytes(account), recNonce, newRoot: next.root, newRecRoot: next.recRoot, newSeed: next.seed });
    markRecoverySigned(chainId, account, Number(recNonce));
    const sig = cchsK.signRecovery(cur.key, Number(recNonce), m, cur.trees);
    const hash = await wc.writeContract({
      address: account, abi: ACCOUNT_ABI, functionName: "recover",
      args: [toHex(next.root), toHex(next.recRoot), toHex(next.seed), sig.wots.map(toHex), sig.auth.map(toHex)],
      chain: this.chain, account: from,
    });
    await this.wait(hash);
    markIndexSigned(chainId, account, epoch + 1, -1, this.lane);
    return { hash, epoch: epoch + 1 };
  }
}
