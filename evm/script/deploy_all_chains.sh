#!/usr/bin/env bash
# Deploy Aegis to every EVM chain from the SAME deployer EOA at nonce 0 and 1
# => identical Verifier and Factory addresses across all chains.
#
# Requirements:
#   - AEGIS_DEPLOYER_KEY   : freshly created EOA private key, nonce==0 on every target
#   - AEGIS_FEE_COLLECTOR  : immutable fee recipient address
#   - RPC_* env vars set per chain (see foundry.toml)
#
# After this script completes on all chains, run burn_deployer.sh to destroy
# the deployer EOA private key publicly.

set -euo pipefail

CHAINS=(
  "ethereum"
  "bsc"
  "polygon"
  "arbitrum"
  "optimism"
  "base"
  "avalanche"
  "linea"
  "scroll"
  "mantle"
  "blast"
  "mode"
)

RESULTS_DIR="./deployments"
mkdir -p "$RESULTS_DIR"

for chain in "${CHAINS[@]}"; do
  echo "========== Deploying to $chain =========="
  forge script script/DeployMultichain.s.sol \
      --rpc-url "$chain" \
      --broadcast \
      --slow \
      --private-key "$AEGIS_DEPLOYER_KEY" \
      --json \
    | tee "$RESULTS_DIR/$chain.json"
  echo
done

echo "========== Address consistency check =========="
jq -s '[.[] | {chain: .chain, verifier: .returns.verifier.value, factory: .returns.factory.value}]' \
    "$RESULTS_DIR"/*.json

echo
echo "If the above list shows IDENTICAL verifier and factory addresses across"
echo "all chains, the deploy is correct. Now destroy the deployer key:"
echo "    bash script/burn_deployer.sh"
