// Thin wallet connector built on viem + window.ethereum.
// No wagmi / no walletconnect / no appkit — ~15 KB total.

import {
  createPublicClient,
  createWalletClient,
  custom,
  http,
  type Address,
  type PublicClient,
  type WalletClient,
  type Chain,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia, baseSepolia, mainnet, base, arbitrum, optimism, polygon, bsc, avalanche, linea, scroll, mantle, blast, mode } from "viem/chains";

export const SUPPORTED_CHAINS: Record<number, Chain> = {
  [sepolia.id]:     sepolia,
  [baseSepolia.id]: baseSepolia,
  [mainnet.id]:     mainnet,
  [base.id]:        base,
  [arbitrum.id]:    arbitrum,
  [optimism.id]:    optimism,
  [polygon.id]:     polygon,
  [bsc.id]:         bsc,
  [avalanche.id]:   avalanche,
  [linea.id]:       linea,
  [scroll.id]:      scroll,
  [mantle.id]:      mantle,
  [blast.id]:       blast,
  [mode.id]:        mode,
};

/** Order in which the Protect panel lists EVM chains. */
export const PROTECT_CHAINS: Chain[] = [mainnet, bsc, polygon, arbitrum, optimism, base, avalanche, linea, scroll, mantle, blast, mode, sepolia, baseSepolia];

export const DEFAULT_CHAIN = sepolia;

type Eip1193 = { request: (args: { method: string; params?: unknown[] }) => Promise<unknown>; on?: (event: string, cb: (...args: unknown[]) => void) => void; removeListener?: (event: string, cb: (...args: unknown[]) => void) => void; };

// ---------- Local relayer ----------
// The browser extension has no injected wallet to relay through, so it pays
// gas from a key of its own: the mnemonic's secp256k1 key (`evmGasKey`),
// funded with gas money only. It is presented to the panels as an EIP-1193
// provider so that nothing above this file changes: `eth_sendTransaction`
// is signed locally and sent over the chain's public RPC; chain switching
// is a variable; everything else is forwarded to the public client.

let localRelayer: { key: Hex; chainId: number } | null = null;

export function setLocalRelayer(privateKey: Hex | null, chainId: number = DEFAULT_CHAIN.id): void {
  localRelayer = privateKey ? { key: privateKey, chainId } : null;
}

export function localRelayerAddress(): Address | null {
  return localRelayer ? privateKeyToAccount(localRelayer.key).address : null;
}

function localProvider(): Eip1193 {
  return {
    async request({ method, params }) {
      const r = localRelayer!;
      const chain = SUPPORTED_CHAINS[r.chainId];
      switch (method) {
        case "eth_requestAccounts":
        case "eth_accounts":
          return [privateKeyToAccount(r.key).address];
        case "eth_chainId":
          return "0x" + r.chainId.toString(16);
        case "wallet_switchEthereumChain": {
          const id = parseInt((params as [{ chainId: string }])[0].chainId, 16);
          if (!SUPPORTED_CHAINS[id]) throw Object.assign(new Error("unsupported chain"), { code: 4902 });
          r.chainId = id;
          return null;
        }
        case "wallet_addEthereumChain":
          return null;
        case "eth_sendTransaction": {
          const [tx] = params as [{ to?: Address; data?: Hex; value?: Hex; gas?: Hex }];
          const wc = createWalletClient({ chain, account: privateKeyToAccount(r.key), transport: http(RPC_OVERRIDES[chain.id], { timeout: 20_000 }) });
          return wc.sendTransaction({
            to: tx.to, data: tx.data,
            value: tx.value ? BigInt(tx.value) : undefined,
            gas: tx.gas ? BigInt(tx.gas) : undefined,
          });
        }
        default:
          return makePublicClient(chain).request({ method, params } as never);
      }
    },
  };
}

export function detectInjected(): Eip1193 | null {
  if (localRelayer) return localProvider();
  if (typeof window === "undefined") return null;
  const e = (window as unknown as { ethereum?: Eip1193 }).ethereum;
  return e ?? null;
}

export async function requestAccounts(): Promise<Address> {
  const eth = detectInjected();
  if (!eth) throw new Error("No injected wallet detected. Install MetaMask / Rabby / Trust.");
  const accounts = (await eth.request({ method: "eth_requestAccounts" })) as Address[];
  if (!accounts || !accounts.length) throw new Error("No account authorized");
  return accounts[0];
}

export async function getChainId(): Promise<number> {
  const eth = detectInjected();
  if (!eth) throw new Error("no wallet");
  const hex = (await eth.request({ method: "eth_chainId" })) as string;
  return parseInt(hex, 16);
}

export async function switchChain(chainId: number): Promise<void> {
  const eth = detectInjected();
  if (!eth) throw new Error("no wallet");
  const hex = "0x" + chainId.toString(16);
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: hex }] });
  } catch (err: unknown) {
    // 4902 = chain not added. Add it.
    const code = (err as { code?: number }).code;
    const chain = SUPPORTED_CHAINS[chainId];
    if (code === 4902 && chain) {
      await eth.request({
        method: "wallet_addEthereumChain",
        params: [{
          chainId: hex,
          chainName: chain.name,
          nativeCurrency: chain.nativeCurrency,
          rpcUrls: [chain.rpcUrls.default.http[0]],
          blockExplorerUrls: chain.blockExplorers ? [chain.blockExplorers.default.url] : [],
        }],
      });
    } else { throw err; }
  }
}

// Public endpoints used when a chain's viem default is unreliable from browsers.
const RPC_OVERRIDES: Record<number, string> = { [polygon.id]: "https://1rpc.io/matic" };

export function makePublicClient(chain: Chain): PublicClient {
  // A public endpoint that does not answer should surface as an error in the
  // panel within seconds, not leave a row on "reading…" for a minute.
  return createPublicClient({ chain, transport: http(RPC_OVERRIDES[chain.id], { timeout: 8_000, retryCount: 1 }) });
}

export function makeWalletClient(chain: Chain, account: Address): WalletClient {
  const eth = detectInjected();
  if (!eth) throw new Error("no wallet");
  return createWalletClient({ chain, transport: custom(eth as never), account });
}

export function shortAddr(a?: Address | string | null): string {
  if (!a) return "—";
  return a.length > 14 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a;
}

// ---------- Deployment registry ----------
// Loaded from src/aegis/deployment.<chainkey>.json when present.

export type Deployment = { chainId: number; verifier: Hex; factory: Hex; upgradeHelper: Hex };

export async function loadDeployment(chainId: number): Promise<Deployment | null> {
  const key =
    chainId === sepolia.id     ? "sepolia" :
    chainId === baseSepolia.id ? "base-sepolia" :
    chainId === base.id        ? "base" :
    chainId === arbitrum.id    ? "arbitrum" :
    chainId === optimism.id    ? "optimism" :
    chainId === polygon.id     ? "polygon" :
    chainId === mainnet.id     ? "mainnet" : null;
  if (!key) return null;
  try {
    const mod = await import(/* @vite-ignore */ `./deployment.${key}.json`);
    return mod.default as Deployment;
  } catch { return null; }
}
