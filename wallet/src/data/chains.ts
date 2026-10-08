export type ChainStatus = "mainnet" | "preview" | "research";

export type Chain = {
  name: string;
  family: "EVM" | "Starknet" | "SVM" | "Cosmos" | "Move" | "Other" | "Bitcoin";
  status: ChainStatus;
  sameAddr?: boolean;    // true for EVM chains that share one CREATE2 address
  wallet?: string;       // native wallet to import this derived address into
};

/** Status legend:
 *  mainnet  = address derivation uses the chain's STANDARD scheme; importable to
 *             the native wallet listed in `wallet`; usable on mainnet TODAY.
 *             The PQ smart-account layer is a separate roadmap item per chain.
 *  preview  = address shown but non-standard (needs chain-specific SDK for proper
 *             derivation — e.g. TON StateInit, Starknet account factory).
 *  research = blocked on external dependency (BIP-360 for Bitcoin).
 */
export const CHAINS: Chain[] = [
  { name: "Ethereum",    family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask / Rabby" },
  { name: "BSC",         family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask / Rabby" },
  { name: "Polygon",     family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask / Rabby" },
  { name: "Arbitrum",    family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask / Rabby" },
  { name: "Optimism",    family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask / Rabby" },
  { name: "Base",        family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask / Coinbase" },
  { name: "Avalanche",   family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask / Core" },
  { name: "Linea",       family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask" },
  { name: "Scroll",      family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask / Rabby" },
  { name: "Mantle",      family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask" },
  { name: "Blast",       family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask / Rabby" },
  { name: "Mode",        family: "EVM",      status: "mainnet", sameAddr: true, wallet: "MetaMask / Rabby" },

  { name: "Solana",      family: "SVM",      status: "mainnet", wallet: "Phantom / Backpack / Solflare" },
  { name: "TRON",        family: "EVM",      status: "mainnet", wallet: "TronLink / Trust" },

  { name: "Osmosis",     family: "Cosmos",   status: "mainnet", wallet: "Keplr / Leap" },
  { name: "Injective",   family: "Cosmos",   status: "mainnet", wallet: "Keplr (Ethermint path)" },
  { name: "Neutron",     family: "Cosmos",   status: "mainnet", wallet: "Keplr / Leap" },
  { name: "Juno",        family: "Cosmos",   status: "mainnet", wallet: "Keplr / Leap" },
  { name: "Stargaze",    family: "Cosmos",   status: "mainnet", wallet: "Keplr / Leap" },

  { name: "NEAR",        family: "Other",    status: "mainnet", wallet: "near-cli / NEAR Wallet (implicit)" },
  { name: "Aptos",       family: "Move",     status: "mainnet", wallet: "Petra / Pontem / Martian" },
  { name: "Sui",         family: "Move",     status: "mainnet", wallet: "Sui Wallet / Suiet / Nightly" },
  { name: "Bitcoin",     family: "Bitcoin",  status: "mainnet", wallet: "Sparrow / Electrum (BIP-84 WIF)" },

  { name: "TON",         family: "Other",    status: "preview", wallet: "Tonkeeper (import via ed25519 secret)" },
  { name: "Starknet",    family: "Starknet", status: "preview", wallet: "Argent X / Braavos (needs factory)" },
];
