// Chain lists and the browser connectors the site uses. Everything here is
// safe to import in node; the connector functions throw when no browser
// wallet is present.
//
// EVM: `PROTECT_CHAINS` is the list the Protect panel offers, `makePublicClient`
// its read client (public RPC, short timeout). In a browser, `requestAccounts`
// + `makeWalletClient` give the viem WalletClient that `EvmAccount` methods
// take as the fee payer.
//
// Solana: `connectSolanaWallet` finds a Wallet Standard wallet (Phantom,
// Solflare, Backpack, …) and returns a `ConnectedSolanaWallet` whose
// `signAndSend` is the fee payer `SolanaAccount` methods take.

export {
  SUPPORTED_CHAINS, PROTECT_CHAINS, DEFAULT_CHAIN,
  detectInjected, requestAccounts, getChainId, switchChain, makePublicClient, makeWalletClient, shortAddr,
} from "../../wallet/src/aegis/wallet";

// (`connectSolanaWallet`, `solanaWallets`, `Rpc` are exported from ./solana.)
export {
  DEFAULT_RPC as SOLANA_DEFAULT_RPC, EXPLORER as SOLANA_EXPLORER, formatAmount, parseAmount,
  type ConnectedSolanaWallet,
} from "../../wallet/src/aegis/solana";
