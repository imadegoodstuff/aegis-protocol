# Aegis — Bitcoin adapter

**Status**: implemented and executed on Bitcoin Inquisition signet, where
`OP_CAT` (BIP-347) and `OP_CHECKSIGFROMSTACK` (BIP-348) are active, and on an
Inquisition regtest node in CI. Not usable on mainnet: the opcodes are not
active there, and the output is P2TR (key path present). See `BITCOIN.md`.

There is no contract VM, so the account is the UTXO. Each UTXO of a lineage
commits to the CCHS state after the previous spend,

```
state = (root, recRoot, pkSeed, epoch, t, R_t, nextIdx)
```

and offers three Tapscript leaves generated from one template:

| leaf | what it verifies | successor |
|---|---|---|
| `exec` | WOTS+ leaf `idx ≥ nextIdx` of cached subtree `t`, 10-level path to `R_t` | `nextIdx = idx + 1` |
| `execFirst` | top-layer WOTS+ of leaf `t' > t` on `R_{t'}` with its path to `root`, then the bottom layer | `(t', R_{t'}, idx + 1)` |
| `recover` | WOTS+ leaf `epoch` of the recovery tree under `recRoot` | next epoch's public key, nothing cached |

The message every leaf signs is the transaction's BIP-341 sighash; the script
proves the witness-supplied message *is* that sighash with `OP_CHECKSIGVERIFY`
and `OP_CHECKSIGFROMSTACK` on one Schnorr signature under the public key of
`d = 1` (no secret involved), reassembles the WOTS+ digits into bytes with
`OP_CAT` and compares. Hashing is SHA-256 with the per-tree public seed in
every call (`BITCOIN.md` §5.2).

## Code

| | |
|---|---|
| `wallet/src/aegis/btcCchs.ts` | hashing, key trees, the three leaf scripts, witnesses, state machine, reference verifier |
| `wallet/src/aegis/btcTx.ts` | transaction serialization, BIP-341 script-path sighash, bech32m, binding signature |
| `wallet/scripts/check-btc.mts` | executes the leaves in a Tapscript interpreter (BIP-342 + `OP_CAT` + `OP_CHECKSIGFROMSTACK`), pins sizes — `npm run btc` |
| `wallet/scripts/btc-flow.mts` | runs a lineage `execFirst → exec → exec → recover → execFirst` against a node — `npm run btc-flow` |
| `wallet/src/aegis/btcTapscript.ts` | the earlier flat variant (one hard-coded key per leaf, no binding), kept for the size it is quoted at |

## Running a lineage

Against Bitcoin Inquisition (regtest or signet; `getdeploymentinfo` must show
`op_cat` and `checksigfromstack` active):

```
cd wallet
BTC_NETWORK=regtest BTC_RPC_URL=http://127.0.0.1:18443 BTC_RPC_USER=u BTC_RPC_PASS=p \
BTC_MASTER_HEX=<32-byte test master, hex> BTC_TOP_HEIGHT=2 npm run btc-flow
```

On regtest the script funds the account from the node wallet and mines; on
signet it prints the first address and waits for a confirmed payment to it.
Every transaction is checked by the reference verifier and `testmempoolaccept`
before broadcast. A leaf is never signed twice: the fee is fixed from an upper
bound of the witness before signing.

## What mainnet still needs

1. `OP_CAT` or `OP_CHECKSIGFROMSTACK` active (the binding and the hashing need
   concatenation; the implementation uses both).
2. A key-less output type (BIP-360 P2MR) for two reasons: the P2TR key path is
   open to a discrete-log adversary, and a P2TR commitment is an elliptic-curve
   tweak no script can check, so the successor output is built by the signer
   rather than forced by a covenant. The P2MR form (universal code tree,
   32-byte state leaf, `sha_outputs` covenant) is specified in `BITCOIN.md`
   §5.1 and differs from the running code only in concatenate-and-compare
   steps over data already in the sighash.

Until then the wallet receives at BIP-84 P2WPKH and labels the address as not
post-quantum (`BITCOIN.md` §6).
