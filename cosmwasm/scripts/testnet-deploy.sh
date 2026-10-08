#!/usr/bin/env bash
# Aegis — CosmWasm testnet deployment (defaults to Osmosis testnet).
#
# Prerequisites:
#   rustup target add wasm32-unknown-unknown
#   osmosisd                 # or neutrond / injectived / junod
#   MNEMONIC="..." for a wallet with testnet gas (osmo faucet)
#
# Env:
#   AEGIS_CHAIN           = osmosis-testnet | neutron-testnet | injective-testnet
#   AEGIS_RPC             = tendermint RPC URL
#   AEGIS_WALLET          = key name imported into osmosisd keyring

set -euo pipefail
cd "$(dirname "$0")/.."

: "${AEGIS_CHAIN:=osmosis-testnet}"
: "${AEGIS_WALLET:?set AEGIS_WALLET (keyring key name)}"
: "${AEGIS_RPC:?set AEGIS_RPC}"

echo "=== 1. Build (wasm32-unknown-unknown, release) ==="
RUSTFLAGS='-C link-arg=-s' cargo build --release --lib --target wasm32-unknown-unknown
WASM=target/wasm32-unknown-unknown/release/aegis_cosmwasm.wasm
ls -lh "$WASM"

echo "=== 2. Pick CLI binary ==="
case "$AEGIS_CHAIN" in
  osmosis-*)  CLI=osmosisd ;;
  neutron-*)  CLI=neutrond ;;
  injective-*) CLI=injectived ;;
  juno-*)     CLI=junod ;;
  *) echo "unknown AEGIS_CHAIN=$AEGIS_CHAIN"; exit 1 ;;
esac
command -v "$CLI" >/dev/null || { echo "install $CLI first"; exit 1; }

echo "=== 3. Store code ==="
STORE_TX=$($CLI tx wasm store "$WASM" \
    --from "$AEGIS_WALLET" --node "$AEGIS_RPC" \
    --gas auto --gas-adjustment 1.4 --gas-prices 0.025uosmo \
    -y -o json | jq -r '.txhash')
echo "store tx = $STORE_TX"
sleep 6

CODE_ID=$($CLI query tx "$STORE_TX" --node "$AEGIS_RPC" -o json \
  | jq -r '.events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')
echo "code_id = $CODE_ID"

echo
echo "=== 4. Instantiate (per-user — pass real pq_pk_hash / guardian / fallback / fee) ==="
INIT_MSG=$(cat <<EOF
{
  "pq_pk_hash": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
  "guardian":      "osmo1...",
  "fallback_addr": "osmo1...",
  "fee_collector": "osmo1..."
}
EOF
)
echo "Instantiate with: $CLI tx wasm instantiate $CODE_ID '$INIT_MSG' --label aegis-v1 --no-admin ..."
echo "Fill in real osmo1... addresses first, then run manually."
