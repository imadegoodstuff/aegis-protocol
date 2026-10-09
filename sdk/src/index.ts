// @aegis-protocol/sdk — everything the site at aegisprotocol.si can do, as a
// library: hash-only post-quantum accounts (CCHS) on EVM chains, Solana and
// Bitcoin signet, plus the per-chain address derivation of the Derive panel.
// Spec: CCHS.spec.md in the repository. The code is the wallet's own client
// (wallet/src/aegis) behind a small API, so the SDK and the site agree byte
// for byte.

export * from "./keys";
export * from "./pool";
export * from "./store";
export * from "./chains";
export * from "./identity";
export * from "./evm";
export * from "./solana";
export * from "./bitcoin";

// Signature primitives, for hosts that verify or build their own flows.
export { cchsS, cchsK, forVariant, makeCchs, toHex, type Cchs, type CchsPublic, type CchsSignature, type LayerSig, type Tree, type Variant } from "../../wallet/src/aegis/cchs";
export { cchsC, makeCompact, type Compact } from "../../wallet/src/aegis/cchsCompact";
export { handleLeaves } from "../../wallet/src/aegis/cchsWorkerCore";
export { compileMessage, unsignedTransaction, findProgramAddress, associatedTokenAddress, PACKET_SIZE } from "../../wallet/src/aegis/solana";
export * as solanaIx from "../../wallet/src/aegis/solanaAccount";
export * as btcScript from "../../wallet/src/aegis/btcCchs";
export * as btcTx from "../../wallet/src/aegis/btcTx";
