// The CCHS-UTXO account on Bitcoin signet (BITCOIN.md §5), as the site's
// Bitcoin panel runs it: lineage read from a public esplora API, one
// transaction per spend that pays the recipient and re-creates the account at
// its successor state, broadcast through a relay in front of a Bitcoin
// Inquisition node (ordinary nodes do not relay OP_CAT spends).
//
//   const btc = BitcoinAccount.derive({ master });
//   btc.address0                               // first address of the lineage
//   const lin = await btc.sync();              // state, address, UTXOs, history
//   const p = btc.prepare(lin, { to, sat: 5_000n, feerate: await recommendedFeerate() });
//   await btc.broadcast(p, relayUrl);          // or carry p.hex to an Inquisition node by hand
//
// Signet only. Mainnet has neither OP_CAT nor OP_CHECKSIGFROMSTACK, and a
// P2TR output keeps a key path (BITCOIN.md §4).

import { labelChainTag, chainKey } from "../../wallet/src/aegis/cchsAccount";
import {
  BtcAccount, DEFAULT_RELAY, DUST, MIN_FEERATE, MIN_SUCCESSOR, SIGNET_API, SIGNET_EXPLORER,
  broadcastViaRelay, recommendedFeerate, relayInfo, stateLabel, txStatus,
  type BtcUtxo, type Lineage, type LineageStep, type PendingSpend, type PreparedSpend,
} from "../../wallet/src/aegis/btcAccount";
import { DEFAULT_HT, HB, NO_SUBTREE, type BtcState, type LeafName } from "../../wallet/src/aegis/btcCchs";
import type { CchsKey } from "../../wallet/src/aegis/cchs";

export {
  BtcAccount, DEFAULT_HT, DEFAULT_RELAY, DUST, HB, MIN_FEERATE, MIN_SUCCESSOR, NO_SUBTREE, SIGNET_API, SIGNET_EXPLORER,
  broadcastViaRelay, recommendedFeerate, relayInfo, stateLabel, txStatus,
};
export type { BtcState, BtcUtxo, LeafName, Lineage, LineageStep, PendingSpend, PreparedSpend };

/** Label under which the Bitcoin chain key hangs off the master (same as the site). */
export const BITCOIN_LABEL = "bitcoin";

export class BitcoinAccount extends BtcAccount {
  /**
   * Derive the Bitcoin account of `master`. Only the epoch's top and recovery
   * trees are built here (well under a second); bottom subtrees are built when
   * a leaf of them is signed. `HT` is the top-tree height (default 4: 16
   * subtrees of 2^HB leaves per epoch).
   */
  static derive(o: { master: CchsKey; HT?: number }): BitcoinAccount {
    return new BitcoinAccount(chainKey(o.master, labelChainTag(BITCOIN_LABEL)), o.HT ?? DEFAULT_HT);
  }

  /** Broadcast a prepared spend through a relay and record it so `sync` keeps showing it until it is mined. */
  async broadcast(p: PreparedSpend, relayUrl: string = this.relayUrl): Promise<string> {
    if (!relayUrl) throw new Error("no relay URL: set one, or submit p.hex to a Bitcoin Inquisition node yourself");
    const id = await broadcastViaRelay(relayUrl, p.hex);
    if (id.toLowerCase() !== p.txid) throw new Error(`relay returned a different txid: ${id}`);
    this.recordBroadcast(p, p.from);
    return id;
  }
}
