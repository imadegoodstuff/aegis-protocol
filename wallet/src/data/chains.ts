export type ChainStatus = "live" | "soon" | "research";

export type Chain = {
  name: string;
  family: "EVM" | "Starknet" | "SVM" | "Cosmos" | "Move" | "Other" | "Bitcoin";
  status: ChainStatus;
  sameAddr?: boolean;
};

/** 排序：先 live 的 EVM (同地址)，再 Starknet，再 soon */
export const CHAINS: Chain[] = [
  { name: "Ethereum",    family: "EVM",      status: "live", sameAddr: true },
  { name: "BSC",         family: "EVM",      status: "live", sameAddr: true },
  { name: "Polygon",     family: "EVM",      status: "live", sameAddr: true },
  { name: "Arbitrum",    family: "EVM",      status: "live", sameAddr: true },
  { name: "Optimism",    family: "EVM",      status: "live", sameAddr: true },
  { name: "Base",        family: "EVM",      status: "live", sameAddr: true },
  { name: "Avalanche",   family: "EVM",      status: "live", sameAddr: true },
  { name: "Linea",       family: "EVM",      status: "live", sameAddr: true },
  { name: "Scroll",      family: "EVM",      status: "live", sameAddr: true },
  { name: "Mantle",      family: "EVM",      status: "live", sameAddr: true },
  { name: "Blast",       family: "EVM",      status: "live", sameAddr: true },
  { name: "Mode",        family: "EVM",      status: "live", sameAddr: true },
  { name: "Starknet",    family: "Starknet", status: "live" },

  { name: "Solana",      family: "SVM",      status: "soon" },
  { name: "Osmosis",     family: "Cosmos",   status: "soon" },
  { name: "Injective",   family: "Cosmos",   status: "soon" },
  { name: "TRON",        family: "EVM",      status: "soon" },
  { name: "NEAR",        family: "Other",    status: "soon" },
  { name: "Aptos",       family: "Move",     status: "soon" },
  { name: "Sui",         family: "Move",     status: "soon" },
  { name: "TON",         family: "Other",    status: "soon" },

  { name: "Bitcoin",     family: "Bitcoin",  status: "research" },
];
