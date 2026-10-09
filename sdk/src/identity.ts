// What the site's Derive panel shows for a mnemonic: the standard per-chain
// addresses (importable into each chain's native wallet) and the SLH-DSA
// (FIPS 205, SHAKE-192s) key pair behind the hybrid account line. These are
// separate from the CCHS accounts of evm.ts / solana.ts / bitcoin.ts, whose
// addresses come from the hash-only key trees.
//
// `derive` returns addresses only; `identity` also returns secret keys and
// should stay on the device that holds the mnemonic.

export {
  derive, identity, mnemonicEntropyBits, CCHS_MIN_SEED_BITS,
  pqSign, pqVerify, predictEvmAccountAddress,
  type Derived, type Identity,
} from "../../wallet/src/aegis/derive";

// TRON: same 20 bytes as the EVM address, base58check with prefix 0x41.
export {
  TRON_ADDRESS_PREFIX, TRON_CHAIN_IDS, TRON_FULL_HOSTS,
  toTronBase58, fromTronBase58, parseTronAddress, formatTronAddress, tronCreate2, predictTronAccount, predictTronFactory,
  type TronAddress,
} from "../../wallet/src/aegis/tronAccount";
