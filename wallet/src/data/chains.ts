export type ChainStatus = "live" | "testnet" | "research";

export type Chain = {
  name: string;
  family: "EVM" | "Starknet" | "SVM" | "Cosmos" | "Move" | "Other" | "Bitcoin";
  status: ChainStatus;
  sameAddr?: boolean;
};

/** Status legend:
 *  live     = contract + verifier scaffold deployable; wallet shows derived address
 *  testnet  = full address derivation live in wallet + adapter skeleton + deploy script
 *             (needs funded deployer EOA/account to go on-chain)
 *  research = blocked on external dependency (e.g. BIP-360 activation for Bitcoin)
 */
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

  { name: "Solana",      family: "SVM",      status: "testnet" },
  { name: "TRON",        family: "EVM",      status: "testnet" },
  { name: "Osmosis",     family: "Cosmos",   status: "testnet" },
  { name: "Injective",   family: "Cosmos",   status: "testnet" },
  { name: "Neutron",     family: "Cosmos",   status: "testnet" },
  { name: "Juno",        family: "Cosmos",   status: "testnet" },
  { name: "Stargaze",    family: "Cosmos",   status: "testnet" },
  { name: "NEAR",        family: "Other",    status: "testnet" },
  { name: "Aptos",       family: "Move",     status: "testnet" },
  { name: "Sui",         family: "Move",     status: "testnet" },
  { name: "TON",         family: "Other",    status: "testnet" },

  { name: "Bitcoin",     family: "Bitcoin",  status: "research" },
];
