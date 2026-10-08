#!/usr/bin/env bash
# Testnet multi-chain deploy demonstration.
#
# Requires a FRESHLY generated deployer EOA whose nonce is 0 on every target
# testnet. Fund it with the minimum gas on each chain, then run this script.
#
# Expected result: identical Verifier and Factory addresses across all 3
# testnets. This is the "same address, every chain" claim, PROVEN on-chain.
#
# Required env:
#   AEGIS_DEPLOYER_KEY    - 0x-prefixed private key, nonce 0 on each testnet
#   AEGIS_FEE_COLLECTOR   - immutable fee recipient
#   AEGIS_VERIFIER        - "prod" (default) or "stub"
#   RPC_SEPOLIA           - Sepolia RPC URL
#   RPC_BSC_TESTNET       - BSC Testnet RPC URL
#   RPC_MUMBAI            - Mumbai (Polygon testnet) RPC URL
#
# OFFLINE pre-check first:
#   forge script script/PredictAddresses.s.sol

set -euo pipefail
cd "$(dirname "$0")/.."

: "${AEGIS_DEPLOYER_KEY:?set AEGIS_DEPLOYER_KEY}"
: "${AEGIS_FEE_COLLECTOR:?set AEGIS_FEE_COLLECTOR}"
: "${AEGIS_VERIFIER:=prod}"

mkdir -p deployments/testnet

TESTNETS=(
  "sepolia:$RPC_SEPOLIA"
  "bsc_testnet:$RPC_BSC_TESTNET"
  "mumbai:$RPC_MUMBAI"
)

echo "=== OFFLINE prediction ==="
forge script script/PredictAddresses.s.sol | tee deployments/testnet/prediction.log

for pair in "${TESTNETS[@]}"; do
  name="${pair%%:*}"
  rpc="${pair#*:}"
  echo
  echo "=== Deploying to $name ==="
  AEGIS_DEPLOYER_KEY=$AEGIS_DEPLOYER_KEY \
  AEGIS_FEE_COLLECTOR=$AEGIS_FEE_COLLECTOR \
  AEGIS_VERIFIER=$AEGIS_VERIFIER \
  forge script script/DeployMultichain.s.sol \
      --rpc-url "$rpc" \
      --broadcast \
      --slow \
      --private-key "$AEGIS_DEPLOYER_KEY" \
      --json \
    | tee "deployments/testnet/$name.json"
done

echo
echo "=== Address consistency check ==="
if command -v jq >/dev/null; then
  jq -s '[.[] | {verifier: .returns.verifier.value, factory: .returns.factory.value}]' \
      deployments/testnet/sepolia.json \
      deployments/testnet/bsc_testnet.json \
      deployments/testnet/mumbai.json
else
  echo "jq not installed; eyeball the three JSON files in deployments/testnet/"
fi

echo
echo "If verifier and factory addresses are IDENTICAL across all three testnets,"
echo "then CREATE address determinism is proven across EVM chains with the same"
echo "deployer EOA + nonce + bytecode."
