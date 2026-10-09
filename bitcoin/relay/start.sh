#!/bin/sh
# Start the Inquisition signet node, then the relay. The RPC password is generated
# per container unless BITCOIN_RPC_PASS is set; it never leaves the container.
set -e
: "${BITCOIN_RPC_PASS:=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
export BITCOIN_RPC_PASS

bitcoind -signet -datadir=/data -server=1 -prune=2000 -dbcache=512 \
  -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -rpcport=38332 \
  -rpcuser="$BITCOIN_RPC_USER" -rpcpassword="$BITCOIN_RPC_PASS" \
  -addnode=inquisition.bitcoin-signet.net -daemon=0 &
BITCOIND=$!

until bitcoin-cli -signet -datadir=/data -rpcuser="$BITCOIN_RPC_USER" -rpcpassword="$BITCOIN_RPC_PASS" -rpcport=38332 getblockchaininfo >/dev/null 2>&1; do
  sleep 2
done
echo "bitcoind up"

node server.mjs &
RELAY=$!

trap 'kill $RELAY $BITCOIND 2>/dev/null; wait' INT TERM
wait $BITCOIND
