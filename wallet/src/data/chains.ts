export type ChainStatus = "mainnet" | "preview" | "research";

/** State of the CCHS verifier for that chain. Keep this truthful. */
export type PqStatus =
  | "contract"   // verifier complete and tested; factory not yet published on this chain
  | "source"     // verifier source exists against shared test vectors; not deployed
  | "blocked"    // blocked on an external dependency (opcode, protocol feature)
  | "none";

export type Chain = {
  name: string;
  family: "EVM" | "Starknet" | "SVM" | "Cosmos" | "Move" | "Other" | "Bitcoin";
  status: ChainStatus;   // standard address derivation
  pq: PqStatus;          // CCHS verifier
  set: "K-20" | "S-20" | "C-20" | "—";
  sameAddr?: boolean;    // the factory is at one CREATE2 address on these chains (accounts differ per chain: one key tree each)
  wallet?: string;       // native wallet that can import the derived address
};

const EVM = (name: string, wallet = "MetaMask / Rabby"): Chain =>
  ({ name, family: "EVM", status: "mainnet", pq: "contract", set: "K-20", sameAddr: true, wallet });

export const CHAINS: Chain[] = [
  EVM("Ethereum"), EVM("Base", "MetaMask / Coinbase"), EVM("Arbitrum"), EVM("Optimism"), EVM("Polygon"),
  EVM("BSC"), EVM("Avalanche", "MetaMask / Core"), EVM("Linea", "MetaMask"), EVM("Scroll"),
  EVM("Mantle", "MetaMask"), EVM("Blast"), EVM("Mode"),

  { name: "TRON",      family: "EVM",      status: "mainnet", pq: "contract", set: "K-20", wallet: "TronLink / Trust" },
  { name: "Solana",    family: "SVM",      status: "mainnet", pq: "source",   set: "C-20", wallet: "Phantom / Backpack / Solflare" },
  { name: "Osmosis",   family: "Cosmos",   status: "mainnet", pq: "source",   set: "S-20", wallet: "Keplr / Leap" },
  { name: "Injective", family: "Cosmos",   status: "mainnet", pq: "source",   set: "S-20", wallet: "Keplr" },
  { name: "Neutron",   family: "Cosmos",   status: "mainnet", pq: "source",   set: "S-20", wallet: "Keplr / Leap" },
  { name: "Juno",      family: "Cosmos",   status: "mainnet", pq: "source",   set: "S-20", wallet: "Keplr / Leap" },
  { name: "Stargaze",  family: "Cosmos",   status: "mainnet", pq: "source",   set: "S-20", wallet: "Keplr / Leap" },
  { name: "NEAR",      family: "Other",    status: "mainnet", pq: "source",   set: "S-20", wallet: "near-cli / NEAR Wallet" },
  { name: "Aptos",     family: "Move",     status: "mainnet", pq: "source",   set: "S-20", wallet: "Petra / Pontem" },
  { name: "Sui",       family: "Move",     status: "mainnet", pq: "source",   set: "S-20", wallet: "Sui Wallet / Suiet" },
  { name: "Starknet",  family: "Starknet", status: "preview", pq: "source",   set: "S-20", wallet: "Argent X / Braavos" },
  { name: "TON",       family: "Other",    status: "preview", pq: "source",   set: "S-20", wallet: "Tonkeeper" },
  { name: "Bitcoin",   family: "Bitcoin",  status: "mainnet", pq: "blocked",  set: "—",    wallet: "Sparrow / Electrum" },
];
