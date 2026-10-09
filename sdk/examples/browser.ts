// In a browser the user's own wallet is the fee payer, exactly as on the site.
// Bundle this with Vite / esbuild / webpack; index records go to localStorage.

import { parseEther } from "viem";
import { base } from "viem/chains";
import {
  EvmAccount, SolanaAccount, connectSolanaWallet, createPool, makePublicClient, makeWalletClient,
  masterFromMnemonic, requestAccounts, switchChain, type WorkerLike,
} from "@aegis-protocol/sdk";

// Key generation on real workers (one tree of 1 024 leaves per worker job).
// cchs.worker.ts:  import { handleLeaves } from '@aegis-protocol/sdk';
//                  self.onmessage = async (e) => self.postMessage(await handleLeaves(e.data));
const pool = createPool({
  size: navigator.hardwareConcurrency ?? 4,
  spawn: () => new Worker(new URL("./cchs.worker.ts", import.meta.url), { type: "module" }) as unknown as WorkerLike,
});

export async function protectOnBase(mnemonic: string) {
  const master = masterFromMnemonic(mnemonic);
  const from = await requestAccounts();                 // MetaMask, Rabby, …
  await switchChain(base.id);
  const acct = await EvmAccount.derive({ master, chain: base, publicClient: makePublicClient(base), pool });
  return acct.protect(makeWalletClient(base, from), { value: parseEther("0.01") });
}

export async function protectOnSolana(mnemonic: string) {
  const master = masterFromMnemonic(mnemonic);
  const wallet = await connectSolanaWallet();           // Phantom, Solflare, Backpack, … (Wallet Standard)
  const acct = await SolanaAccount.derive({ master, rpc: "https://api.mainnet-beta.solana.com", pool });
  if (!(await acct.state())) await acct.create(wallet);
  return acct.depositSol(wallet, 5_000_000n);
}
