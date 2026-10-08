# Aegis — TRON adapter

**Status**: shares the EVM Solidity contracts (same bytecode); only the address
encoder differs.

## How TRON reuses the EVM artifact

TRON's TVM is a close EVM superset. The exact same `AegisAccount` and
`AegisAccountFactory` Solidity sources compile to the same bytecode, deploy via
the same `CREATE2` semantics, and store the same immutable state. The only
Aegis-specific difference is address encoding.

## Address encoding

TRON wraps the 20-byte EVM-style address like this:

```
raw = 0x41 || keccak256(uncompressed_pubkey)[12:]   // 21 bytes
tron_addr = base58check(raw)                        // "T..." (34 chars)
```

So an account that lives at EVM `0xAEG5…b2E1` on, say, BSC lives at the same
underlying 20 bytes on TRON — just encoded as `T<base58check>`.

See `scripts/tron_address.ts` (added later) for conversion helpers.

## Deploy

```bash
# Compile the shared EVM artifact
cd ../evm && forge build

# Push to TRON via tronweb or tronbox using the SAME .json artifact:
# (example sketch; wire up tronbox properly)
cd ../tron
npm i tronweb
node scripts/deploy.js \
    --rpc https://api.trongrid.io \
    --artifact ../evm/out/AegisAccountFactory.sol/AegisAccountFactory.json \
    --salt 0x... \
    --private-key $AEGIS_DEPLOYER_KEY
```

## Address consistency with EVM chains

Because TRON uses the same 20-byte derivation but a different textual encoding,
your Aegis EVM address `0xAEG5…b2E1` corresponds to a specific TRON address
`T...`. Both control the same account identity. The CREATE2 math is identical
across every EVM/TVM chain that honors EIP-1014.

## v0.1 TODO

- `scripts/deploy.js` and `scripts/tron_address.ts` (the only TRON-specific code
  the whole adapter needs). ~1 week of work.
