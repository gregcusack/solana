#!/bin/bash
set -e

echo "about to show args: "
mkdir logs
touch logs/tmp.log
args=("$@")
for arg in "${args[@]}"; do
  echo "Bootstrap Argument: $arg" >> logs/tmp.log
done

/home/solana/k8s-cluster/src/scripts/decode-accounts.sh -t "bootstrap"

# see multinode-demo/boostrap-validator.sh for these default commands
nohup solana-validator \
  --no-os-network-limits-test \
  --no-wait-for-vote-to-start-leader \
  --full-snapshot-interval-slots 200 \
  --identity identity.json \
  --vote-account vote.json \
  --ledger ledger \
  --log - \
  --gossip-host $MY_POD_IP \
  --gossip-port 8001 \
  --rpc-port 8899 \
  --rpc-faucet-address $MY_POD_IP:9900 \
  --no-poh-speed-test \
  --no-incremental-snapshots \
  --full-rpc-api \
  --allow-private-addr \
  "$@" &

nohup solana-faucet --keypair faucet.json >logs/faucet.log 2>&1 &

# # Sleep for an hour (3600 seconds)
sleep 3600