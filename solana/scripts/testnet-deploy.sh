#!/usr/bin/env bash
# Aegis — Solana devnet deployment.
# Deploys the aegis_account Anchor program to devnet.
#
# Prerequisites:
#   solana --version   >= 1.18.17
#   anchor --version   >= 0.30.1
#   SOL_KEYPAIR=~/.config/solana/id.json  (devnet-funded, 2+ SOL)
#   solana config set --url https://api.devnet.solana.com
#
# After deploy, the printed program ID should be pinned in Anchor.toml
# (declare_id! in src/lib.rs).

set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== 1. Verify environment ==="
solana --version
anchor --version
solana config get
solana balance

echo "=== 2. Build ==="
anchor build

echo "=== 3. Deploy to devnet ==="
anchor deploy --provider.cluster devnet

echo
echo "=== 4. Program info ==="
PROG=$(solana address -k target/deploy/aegis_account-keypair.json)
echo "program id : $PROG"
solana program show "$PROG"

echo
echo "Done. Update Anchor.toml + declare_id! with $PROG and rebuild if first-time."
