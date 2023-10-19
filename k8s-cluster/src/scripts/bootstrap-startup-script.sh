#!/bin/bash
set -e

/home/solana/k8s-cluster-scripts/decode-accounts.sh -t "bootstrap"

# start faucet
nohup solana-faucet --keypair faucet.json >logs/faucet.log 2>&1 &

genesis_args=()
bootstrap_args=()

while [[ "$#" -gt 0 ]]; do
    case $1 in
        genesis_script)
            shift 1
            while [[ "$#" -gt 0 && ! "$1" == "genesis_script" && ! "$1" == "bootstrap_script" ]]; do
                genesis_args+=("$1")
                shift 1
            done
            ;;

        bootstrap_script)
            shift 1
            while [[ "$#" -gt 0 && ! "$1" == "genesis_script" && ! "$1" == "bootstrap_script" ]]; do
                bootstrap_args+=("$1")
                shift 1
            done
            ;;

        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Genesis Args: ${genesis_args[@]}"
echo "Bootstrap Args: ${bootstrap_args[@]}"

echo "fetching spl"
/home/solana/fetch-spl.sh
echo "got spl"

echo "creating genesis"
solana-genesis "${genesis_args[@]}"
echo "done creating genesis"

# Start the bootstrap validator node
# shellcheck disable=SC1091
source /home/solana/k8s-cluster-scripts/common.sh

if [[ "$SOLANA_GPU_MISSING" -eq 1 ]]; then
  echo "Testnet requires GPUs, but none were found!  Aborting..."
  exit 1
fi

if [[ -n $SOLANA_CUDA ]]; then
  program="solana-validator --cuda"
else
  program="solana-validator"
fi

no_restart=0
maybeRequireTower=true

echo "PROGRAM: $program"

args=()
while [[ -n $1 ]]; do
  if [[ ${1:0:1} = - ]]; then
    if [[ $1 = --init-complete-file ]]; then # Done
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --gossip-host ]]; then # set with env variables
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --gossip-port ]]; then # set with env variables
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --dev-halt-at-slot ]]; then # not enabled in net.sh
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --dynamic-port-range ]]; then # not enabled in net.sh
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --limit-ledger-size ]]; then # Done
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --no-rocksdb-compaction ]]; then # not enabled in net.sh
      args+=("$1")
      shift
    elif [[ $1 = --enable-rpc-transaction-history ]]; then # enabled through full-rpc
      args+=("$1")
      shift
    elif [[ $1 = --rpc-pubsub-enable-block-subscription ]]; then # not enabled in net.sh
      args+=("$1")
      shift
    elif [[ $1 = --enable-cpi-and-log-storage ]]; then # not enabled in net.sh
      args+=("$1")
      shift
    elif [[ $1 = --enable-extended-tx-metadata-storage ]]; then # enabled through full-rpc
      args+=("$1")
      shift
    elif [[ $1 = --enable-rpc-bigtable-ledger-storage ]]; then # not enabled in net.sh
      args+=("$1")
      shift
    elif [[ $1 = --tpu-disable-quic ]]; then # Done
      args+=("$1")
      shift
    elif [[ $1 = --tpu-enable-udp ]]; then # Done
      args+=("$1")
      shift
    elif [[ $1 = --rpc-send-batch-ms ]]; then # not enabled in net.sh
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --rpc-send-batch-size ]]; then # not enabled in net.sh
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --skip-poh-verify ]]; then # Done
      args+=("$1")
      shift
    elif [[ $1 = --no-restart ]]; then # not enabled in net.sh
      no_restart=1
      shift
    elif [[ $1 == --wait-for-supermajority ]]; then # Done
      args+=("$1" "$2")
      shift 2
    elif [[ $1 == --expected-bank-hash ]]; then # Done
      args+=("$1" "$2")
      shift 2
    elif [[ $1 == --accounts ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 == --maximum-snapshots-to-retain ]]; then  # not enabled in net.sh
      args+=("$1" "$2")
      shift 2
    elif [[ $1 == --no-snapshot-fetch ]]; then # Done
      args+=("$1")
      shift
    elif [[ $1 == --accounts-db-skip-shrink ]]; then
      args+=("$1")
      shift
    elif [[ $1 == --skip-require-tower ]]; then # Done
      maybeRequireTower=false
      shift
    elif [[ $1 = --log-messages-bytes-limit ]]; then # not enabled in net.sh
      args+=("$1" "$2")
      shift 2
    else
      echo "Unknown argument: $1"
      $program --help
      exit 1
    fi
  else
    echo "Unknown argument: $1"
    $program --help
    exit 1
  fi
done

# These keypairs are created by ./setup.sh and included in the genesis config
identity=identity.json
vote_account=vote.json

ledger_dir=/home/solana/ledger
[[ -d "$ledger_dir" ]] || {
  echo "$ledger_dir does not exist"
  exit 1
}

if [[ $maybeRequireTower = true ]]; then
  args+=(--require-tower)
fi

args+=(
  --no-os-network-limits-test \
  --no-wait-for-vote-to-start-leader \
  --snapshot-interval-slots 200 \
  --identity "$identity" \
  --vote-account "$vote_account" \
  --ledger ledger \
  --log logs/solana-validator.log \
  --gossip-host "$MY_POD_IP" \
  --gossip-port 8001 \
  --rpc-port 8899 \
  --rpc-faucet-address "$MY_POD_IP":9900 \
  --no-poh-speed-test \
  --no-incremental-snapshots \
  --full-rpc-api \
  --allow-private-addr
)

echo "Bootstrap Args"
for arg in "${args[@]}"; do
  echo "$arg"
done

pid=
kill_node() {
  # Note: do not echo anything from this function to ensure $pid is actually
  # killed when stdout/stderr are redirected
  set +ex
  if [[ -n $pid ]]; then
    declare _pid=$pid
    pid=
    kill "$_pid" || true
    wait "$_pid" || true
  fi
}

kill_node_and_exit() {
  kill_node
  exit
}

trap 'kill_node_and_exit' INT TERM ERR

while true; do
  echo "$program ${args[*]}"
  $program "${args[@]}" &
  pid=$!
  echo "pid: $pid"

  if ((no_restart)); then
    wait "$pid"
    exit $?
  fi

  while true; do
    if [[ -z $pid ]] || ! kill -0 "$pid"; then
      echo "############## validator exited, restarting ##############"
      break
    fi
    sleep 1
  done

  kill_node
done