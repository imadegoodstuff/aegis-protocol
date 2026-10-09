// Tokenised real-world assets the Protect panel knows about.
//
// An Aegis account is an ordinary contract address, so any ERC-20 or SPL
// token can be held and spent through it; this file only saves the user the
// address lookup and records what each issuer's contract will do when the
// recipient is an address it has never seen. Most tokenised funds gate
// transfers: a `transfer` to an address outside the issuer's allowlist
// reverts. The panel simulates the transfer before asking for a signature,
// so a leaf is never spent on a transfer the token would refuse.
//
// Addresses are the issuers' own publications (BlackRock's token-address
// page, docs.ondo.finance/addresses, docs.superstate.com, Franklin
// Templeton's Benji DevHub, Paxos and Tether contract pages), checked
// 2026-10-09. A wrong address here cannot move funds: the panel reads
// `symbol()` and `decimals()` first and drops anything that is not a token.

import type { Address } from "viem";

export type RwaKind = "treasury fund" | "yield dollar" | "gold";

/** How the token contract treats a recipient it does not know. */
export type RwaGate =
  | "allowlist"        // issuer (or its transfer agent) must register the address; transfers to others revert
  | "self-allowlist"   // the holder registers the address themselves (Ondo USDY); blocklist and sanctions list apply
  | "open";            // no allowlist; the issuer keeps freeze / seize powers

export type RwaToken = {
  symbol: string;
  name: string;
  issuer: string;
  kind: RwaKind;
  gate: RwaGate;
  /** EVM chain id → token contract (proxy) address. */
  evm: Record<number, Address>;
  /** SPL mint on Solana mainnet-beta, when the issuer has one. */
  solana?: string;
  /** Where the holder registers an address, when that is possible. */
  register?: string;
};

const ETHEREUM = 1, OPTIMISM = 10, BSC = 56, POLYGON = 137, MANTLE = 5000, BASE = 8453, ARBITRUM = 42161, AVALANCHE = 43114, SEPOLIA = 11155111;

export const RWA_TOKENS: RwaToken[] = [
  {
    symbol: "BUIDL", name: "BlackRock USD Institutional Digital Liquidity Fund", issuer: "BlackRock / Securitize",
    kind: "treasury fund", gate: "allowlist",
    evm: {
      [ETHEREUM]:  "0x7712c34205737192402172409a8F7ccef8aA2AEc",
      [POLYGON]:   "0x2893Ef551B6dD69F661Ac00F11D93E5Dc5Dc0e99",
      [AVALANCHE]: "0x53FC82f14F009009b440a706e31c9021E1196A2F",
      [OPTIMISM]:  "0xa1CDAb15bBA75a80dF4089CaFbA013e376957cF5",
      [ARBITRUM]:  "0xA6525Ae43eDCd03dC08E775774dCAbd3bb925872",
      [BSC]:       "0x2D5BdC96D9C8AabBDB38c9A27398513e7E5ef84F",
    },
    solana: "GyWgeqpy5GueU2YbkE8xqUeVEokCMMCEeUrfbtMw6phr",
    register: "https://securitize.io",
  },
  {
    symbol: "USDY", name: "Ondo US Dollar Yield", issuer: "Ondo Finance",
    kind: "yield dollar", gate: "self-allowlist",
    evm: {
      [ETHEREUM]: "0x96F6eF951840721AdBF46Ac996b59E0235CB985C",
      [MANTLE]:   "0x5bE26527e817998A7206475496fDE1E68957c5A6",
      [ARBITRUM]: "0x35e050d3C0eC2d29D269a8EcEa763a183bDF9A9D",
    },
    solana: "A1KLoBrKBde8Ty9qtNQUtq3C2ortoC3u7twggz7sEto6",
    register: "https://app.ondo.finance/account/wallets",
  },
  {
    symbol: "OUSG", name: "Ondo Short-Term US Government Treasuries", issuer: "Ondo Finance",
    kind: "treasury fund", gate: "allowlist",
    evm: { [ETHEREUM]: "0x1B19C19393e2d034D8Ff31ff34c81252FcBbee92" },
    solana: "i7u4r16TcsJTgq1kAG8opmVZyVnAKBwLKu6ZPMwzxNc",
    register: "https://ondo.finance/ousg",
  },
  {
    symbol: "USTB", name: "Superstate Short Duration US Government Securities Fund", issuer: "Superstate",
    kind: "treasury fund", gate: "allowlist",
    evm: {
      [ETHEREUM]: "0x43415eB6ff9DB7E26A15b704e7A3eDCe97d31C4e",
      [SEPOLIA]:  "0x39727692cF58137Bd8c401eFE87Cc8A190D62ead",
    },
    register: "https://superstate.com",
  },
  {
    symbol: "BENJI", name: "Franklin OnChain U.S. Government Money Fund", issuer: "Franklin Templeton",
    kind: "treasury fund", gate: "allowlist",
    evm: {
      [ETHEREUM]:  "0x3ddc84940ab509c11b20b76b466933f40b750dc9",
      [POLYGON]:   "0x408A634B8a8f0dE729B48574a3a7Ec3fE820B00A",
      [ARBITRUM]:  "0xB9e4765BCE2609bC1949592059B17Ea72fEe6C6A",
      [BASE]:      "0x60CfC2b186a4CF647486e42c42B11cC6D571d1E4",
      [AVALANCHE]: "0xe08b4c1005603427420e64252a8b120cace4d122",
    },
    solana: "5Tu84fKBpe9vfXeotjvfvWdWbAjy3hqsExvuHgFqFxA1",
    register: "https://digitalassets.franklintempleton.com/benji/",
  },
  {
    symbol: "PAXG", name: "Pax Gold", issuer: "Paxos",
    kind: "gold", gate: "open",
    evm: { [ETHEREUM]: "0x45804880De22913dAFE09f4980848ECE6EcbAf78" },
  },
  {
    symbol: "XAUt", name: "Tether Gold", issuer: "Tether",
    kind: "gold", gate: "open",
    evm: { [ETHEREUM]: "0x68749665FF8D2d112Fa859AA293F07A622782F38" },
  },
];

/** Known RWA tokens on one EVM chain. */
export function rwaOnChain(chainId: number): { token: RwaToken; address: Address }[] {
  return RWA_TOKENS.flatMap((token) => (token.evm[chainId] ? [{ token, address: token.evm[chainId] }] : []));
}

export function rwaByAddress(chainId: number, address: Address): RwaToken | undefined {
  const a = address.toLowerCase();
  return RWA_TOKENS.find((t) => t.evm[chainId]?.toLowerCase() === a);
}

export function rwaBySolanaMint(mint: string): RwaToken | undefined {
  return RWA_TOKENS.find((t) => t.solana === mint);
}

export function gateText(gate: RwaGate): string {
  switch (gate) {
    case "allowlist": return "issuer allowlist: the Aegis address must be registered by the issuer before it can receive";
    case "self-allowlist": return "holder registers the Aegis address with the issuer; blocklist and sanctions list still apply";
    case "open": return "no allowlist; issuer retains freeze powers";
  }
}
