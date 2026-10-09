# Testnet multi-chain determinism demo (hybrid `AegisAccountV2` line)

## Goal

Prove that `AegisAccountFactory` and `SphincsC13Verifier` of the hybrid V2
account land at the **same** address on every EVM chain, given only a shared
deployer EOA at nonce 0. This concerns the V2 contracts only; hash-only
`AegisCCHS` accounts have a per-chain address by design (`CCHS.spec.md` §3,
§5.4), and their factory is published through the deterministic-deployment
proxy without a deployer key (`README.md`).

The claim here is "same infrastructure address on every chain", independently
verifiable from a block explorer in 60 seconds.

## Chains used for the demo

- Sepolia (Ethereum testnet, chain id 11155111)
- BSC Testnet (chain id 97)
- Mumbai (Polygon testnet, chain id 80001)

## Prerequisites

1. **A fresh deployer EOA**. Generate offline:
   ```bash
   cast wallet new                      # produces a brand-new keypair
   ```
   Make sure its nonce is 0 on each target chain (easiest guarantee: use it
   nowhere else, ever).

2. **Minimum gas** on each testnet. Approximate:
   - Sepolia:     0.05 ETH (verifier is heavier at ~1.5M gas)
   - BSC Testnet: 0.1 BNB
   - Mumbai:      1 MATIC

   Faucets:
   - https://sepoliafaucet.com
   - https://testnet.bnbchain.org/faucet-smart
   - https://faucet.polygon.technology

3. **A fee collector address**. For testnet demos: any address you control
   (does not need funds). For mainnet: an immutable address — e.g., a 72h
   timelock or `0x000000000000000000000000000000000000dEaD`.

4. **RPC URLs**. Any public endpoint works; Alchemy / Infura / Ankr are fine.

## Step 1 — Offline prediction

Before spending a single wei, compute what the addresses WILL be:

```bash
cd evm
export AEGIS_DEPLOYER_KEY=0x...        # the fresh EOA
export AEGIS_FEE_COLLECTOR=0x...       # immutable
export AEGIS_VERIFIER=prod             # or "stub"
forge script script/PredictAddresses.s.sol
```

Output:
```
Deployer EOA    : 0x...
Verifier kind   : prod
Verifier (nonce 0) -> 0xAEG....
Factory  (nonce 1) -> 0xAEG....
```

Record these two addresses. They are what you expect on every chain.

## Step 2 — Deploy

```bash
export RPC_SEPOLIA=https://...
export RPC_BSC_TESTNET=https://...
export RPC_MUMBAI=https://...
bash script/testnet_deploy.sh
```

This runs the deployment on each chain in sequence (deployer must have gas on
each one), and writes per-chain JSON into `deployments/testnet/`.

## Step 3 — Verify the invariant

The script runs an automatic consistency check at the end. Expected output:

```json
[
  { "verifier": "0xAEG....", "factory": "0xAEG...." },
  { "verifier": "0xAEG....", "factory": "0xAEG...." },
  { "verifier": "0xAEG....", "factory": "0xAEG...." }
]
```

**All three must be identical.** If one differs, something broke the
determinism (likely cause: solc version drift, or bytecode metadata snuck in —
check `foundry.toml` has `bytecode_hash = "none"`).

## Step 4 — Manual verification on explorers

Open the three explorers in parallel and search for the Factory address:

- https://sepolia.etherscan.io/address/0xAEG....
- https://testnet.bscscan.com/address/0xAEG....
- https://mumbai.polygonscan.com/address/0xAEG....

All three MUST show:
- Same bytecode length
- Same `keccak256(bytecode)` (click "Bytecode" tab, hash it yourself)
- Same immutable `VERIFIER()` and `FEE_COLLECTOR()` return values when calling
  Read Contract

That's the proof.

## Step 5 (optional) — Deploy a user AegisAccount

Once the Factory is on each chain, user deployment is identical:

```bash
cast send 0xAEG...FACTORY \
    "deploy(bytes,address,address)" \
    "0x$(cat pk.hex)" \
    0xGUARDIAN... \
    0xECDSA_OWNER... \
    --rpc-url "$RPC_SEPOLIA" --private-key $USER_KEY
```

Any user with the same `(pq_pk, guardian, ecdsa_owner)` on any chain gets the
same AegisAccount address. That is the final proof.

## Troubleshooting

- "deployer EOA must have nonce 0": you already sent a tx from this address on
  this chain. Use a fresh EOA.
- Addresses differ between chains: check `bytecode_hash = "none"` and
  `cbor_metadata = false` in `evm/foundry.toml`. Any solc metadata bytes being
  embedded in bytecode will cause drift.
- "Insufficient funds": wrong chain / wrong EOA / faucet pending.
