// One mnemonic, one independent key tree per chain (cchsAccount.ts header).

import { generateMnemonic, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { cchsMaster, chainKey, epochKey, evmChainTag, labelChainTag } from "../../wallet/src/aegis/cchsAccount";
import type { CchsKey } from "../../wallet/src/aegis/cchs";

export type { CchsKey };
export { cchsMaster, chainKey, epochKey, evmChainTag, labelChainTag };

/** A fresh 24-word mnemonic (256 bits). CCHS accounts need at least 128 bits; 24 words is the recommendation. */
export function newMnemonic(words: 12 | 24 = 24): string {
  return generateMnemonic(wordlist, words === 24 ? 256 : 128);
}
export function isValidMnemonic(m: string): boolean {
  return validateMnemonic(m.trim(), wordlist);
}
/** 32-byte master from a mnemonic (BIP-39 seed, HKDF "aegis/cchs/master/v1"). The only secret. */
export function masterFromMnemonic(mnemonic: string, passphrase = ""): CchsKey {
  if (!isValidMnemonic(mnemonic)) throw new Error("invalid BIP-39 mnemonic");
  return cchsMaster(mnemonic, passphrase);
}
/** Chain key of an EVM chain (tag 0x00 ‖ chainId BE). */
export const evmChainKey = (master: CchsKey, chainId: number): CchsKey => chainKey(master, evmChainTag(chainId));
/** Chain key of a labelled chain ("solana", "ton", …; tag 0x01 ‖ label). */
export const labelledChainKey = (master: CchsKey, label: string): CchsKey => chainKey(master, labelChainTag(label));
