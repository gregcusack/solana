#!/bin/bash

echo "about to show args: "

/home/solana/k8s-cluster/src/scripts/decode-accounts.sh -t "validator"


#!/usr/bin/env bash
#
# Start a validator
#
here=$(dirname "$0")
# shellcheck source=multinode-demo/common.sh
# source "$here"/common.sh
source /home/solana/k8s-cluster/src/scripts/common.sh

args=(
  --max-genesis-archive-unpacked-size 1073741824
  --no-poh-speed-test
  --no-os-network-limits-test
)
airdrops_enabled=1
node_sol=500 # 500 SOL: number of SOL to airdrop the node for transaction fees and vote account rent exemption (ignored if airdrops_enabled=0)
label=
identity=identity.json
vote_account=vote.json
no_restart=0
gossip_entrypoint=$BOOTSTRAP_GOSSIP_PORT
ledger_dir=/home/solana/ledger
faucet_address=$BOOTSTRAP_FAUCET_PORT

usage() {
  if [[ -n $1 ]]; then
    echo "$*"
    echo
  fi
  cat <<EOF

usage: $0 [OPTIONS] [cluster entry point hostname]

Start a validator with no stake

OPTIONS:
  --ledger PATH             - store ledger under this PATH
  --init-complete-file FILE - create this file, if it doesn't already exist, once node initialization is complete
  --label LABEL             - Append the given label to the configuration files, useful when running
                              multiple validators in the same workspace
  --node-sol SOL            - Number of SOL this node has been funded from the genesis config (default: $node_sol)
  --no-voting               - start node without vote signer
  --rpc-port port           - custom RPC port for this node
  --no-restart              - do not restart the node if it exits
  --no-airdrop              - The genesis config has an account for the node. Airdrops are not required.

EOF
  exit 1
}

maybeRequireTower=true

positional_args=()
while [[ -n $1 ]]; do
  if [[ ${1:0:1} = - ]]; then
    # validator.sh-only options
    if [[ $1 = --label ]]; then
      label="-$2"
      shift 2
    elif [[ $1 = --no-restart ]]; then
      no_restart=1
      shift
    elif [[ $1 = --node-sol ]]; then
      node_sol="$2"
      shift 2
    elif [[ $1 = --no-airdrop ]]; then
      airdrops_enabled=0
      shift
    # solana-validator options
    elif [[ $1 = --expected-genesis-hash ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --expected-shred-version ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --identity ]]; then
      identity=$2
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --authorized-voter ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --authorized-withdrawer ]]; then
      authorized_withdrawer=$2
      shift 2
    elif [[ $1 = --vote-account ]]; then
      vote_account=$2
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --init-complete-file ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --ledger ]]; then
      ledger_dir=$2
      shift 2
    elif [[ $1 = --entrypoint ]]; then
      gossip_entrypoint=$2
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --no-snapshot-fetch ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --no-voting ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --dev-no-sigverify ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --dev-halt-at-slot ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --rpc-port ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --rpc-faucet-address ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --accounts ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --gossip-port ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --dynamic-port-range ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --snapshot-interval-slots ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --maximum-snapshots-to-retain ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --limit-ledger-size ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --no-rocksdb-compaction ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --enable-rpc-transaction-history ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --enable-cpi-and-log-storage ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --enable-extended-tx-metadata-storage ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --skip-poh-verify ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --tpu-disable-quic ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --tpu-enable-udp ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --rpc-send-batch-ms ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --rpc-send-batch-size ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --log ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --known-validator ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 = --halt-on-known-validators-accounts-hash-mismatch ]]; then
      args+=("$1")
      shift
    elif [[ $1 = --max-genesis-archive-unpacked-size ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 == --wait-for-supermajority ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 == --expected-bank-hash ]]; then
      args+=("$1" "$2")
      shift 2
    elif [[ $1 == --accounts-db-skip-shrink ]]; then
      args+=("$1")
      shift
    elif [[ $1 == --skip-require-tower ]]; then
      maybeRequireTower=false
      shift
    elif [[ $1 = -h ]]; then
      usage "$@"
    else
      echo "Unknown argument: $1"
      exit 1
    fi
  else
    positional_args+=("$1")
    shift
  fi
done

if [[ "$SOLANA_GPU_MISSING" -eq 1 ]]; then
  echo "Testnet requires GPUs, but none were found!  Aborting..."
  exit 1
fi

if [[ ${#positional_args[@]} -gt 1 ]]; then
  usage "$@"
fi

# if [[ -n $REQUIRE_LEDGER_DIR ]]; then
#   if [[ -z $ledger_dir ]]; then
#     usage "Error: --ledger not specified"
#   fi
#   SOLANA_CONFIG_DIR="$ledger_dir"
# fi

if [[ -n $REQUIRE_KEYPAIRS ]]; then
  if [[ -z $identity ]]; then
    usage "Error: --identity not specified"
  fi
  if [[ -z $vote_account ]]; then
    usage "Error: --vote-account not specified"
  fi
  if [[ -z $authorized_withdrawer ]]; then
    usage "Error: --authorized_withdrawer not specified"
  fi
fi

# if [[ -z "$ledger_dir" ]]; then
#   ledger_dir="$SOLANA_CONFIG_DIR/validator$label"
# fi
# mkdir -p "$ledger_dir"

if [[ -n $gossip_entrypoint ]]; then
  # Prefer the --entrypoint argument if supplied...
  if [[ ${#positional_args[@]} -gt 0 ]]; then
    usage "$@"
  fi
else
  # ...but also support providing the entrypoint's hostname as the first
  #    positional argument
  entrypoint_hostname=${positional_args[0]}
  if [[ -z $entrypoint_hostname ]]; then
    gossip_entrypoint=127.0.0.1:8001
  else
    gossip_entrypoint="$entrypoint_hostname":8001
  fi
fi

# faucet_address="${gossip_entrypoint%:*}":9900

: "${identity:=$ledger_dir/identity.json}"
: "${vote_account:=$ledger_dir/vote-account.json}"
: "${authorized_withdrawer:=$ledger_dir/authorized-withdrawer.json}"

default_arg --entrypoint "$gossip_entrypoint"
if ((airdrops_enabled)); then
  default_arg --rpc-faucet-address "$faucet_address"
fi

default_arg --identity "$identity"
default_arg --vote-account "$vote_account"
default_arg --ledger "$ledger_dir"
default_arg --log logs/solana-validator
default_arg --full-rpc-api
default_arg --no-incremental-snapshots
default_arg --allow-private-addr

if [[ $maybeRequireTower = true ]]; then
  default_arg --require-tower
fi

if [[ -n $SOLANA_CUDA ]]; then
  program=$solana_validator_cuda
else
  program=$solana_validator
fi

set -e
PS4="$(basename "$0"): "

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

# wallet() {
#   (
#     set -x
#     $solana_cli --keypair "$identity" --url "$rpc_url" "$@"
#   )
# }

# setup_validator_accounts() {
#   declare node_sol=$1

#   if [[ -n "$SKIP_ACCOUNTS_CREATION" ]]; then
#     return 0
#   fi

#   if ! wallet vote-account "$vote_account"; then
#     if ((airdrops_enabled)); then
#       echo "Adding $node_sol to validator identity account:"
#       (
#         set -x
#         $solana_cli \
#           --keypair "$SOLANA_CONFIG_DIR/faucet.json" --url "$rpc_url" \
#           transfer --allow-unfunded-recipient "$identity" "$node_sol"
#       ) || return $?
#     fi

#     echo "Creating validator vote account"
#     wallet create-vote-account "$vote_account" "$identity" "$authorized_withdrawer" || return $?
#   fi
#   echo "Validator vote account configured"

#   echo "Validator identity account balance:"
#   wallet balance || return $?

#   return 0
# }

# shellcheck disable=SC2086
# rpc_url=$($solana_gossip --allow-private-addr rpc-url --timeout 180 --entrypoint "$gossip_entrypoint")

# [[ -r "$identity" ]] || $solana_keygen new --no-passphrase -so "$identity"
# [[ -r "$vote_account" ]] || $solana_keygen new --no-passphrase -so "$vote_account"
# [[ -r "$authorized_withdrawer" ]] || $solana_keygen new --no-passphrase -so "$authorized_withdrawer"

# setup_validator_accounts "$node_sol"

MAX_RETRIES=5

# Delay between retries (in seconds)
RETRY_DELAY=1

# Solana RPC URL
SOLANA_RPC_URL="http://$BOOTSTRAP_RPC_PORT"

# Identity file
IDENTITY_FILE=$identity

# Function to run a Solana command with retries. need reties because sometimes dns resolver fails
# if pod dies and starts up again it may try to create a vote account or something that already exists
run_solana_command() {
    local command="$1"
    local description="$2"

    for ((retry_count=1; retry_count<=$MAX_RETRIES; retry_count++)); do
        echo "Attempt $retry_count for: $description"
        $command

        if [ $? -eq 0 ]; then
            echo "Command succeeded: $description"
            return 0
        else
            echo "Command failed for: $description (Exit status $?)"
            if [ $retry_count -lt $MAX_RETRIES ]; then
                echo "Retrying in $RETRY_DELAY seconds..."
                sleep $RETRY_DELAY
            fi
        fi
    done

    echo "Max retry limit reached. Command still failed for: $description"
    return 1
}

# Run Solana commands with retries
run_solana_command "solana -u $SOLANA_RPC_URL airdrop "$node_sol" $IDENTITY_FILE" "Airdrop"
run_solana_command "solana -u $SOLANA_RPC_URL create-vote-account --allow-unsafe-authorized-withdrawer vote.json $IDENTITY_FILE $IDENTITY_FILE -k $IDENTITY_FILE" "Create Vote Account"
run_solana_command "solana -u $SOLANA_RPC_URL create-stake-account stake.json "$stake_sol" -k $IDENTITY_FILE" "Create Stake Account"
run_solana_command "solana -u $SOLANA_RPC_URL delegate-stake stake.json vote.json --force -k $IDENTITY_FILE" "Delegate Stake"

# Check if any of the commands failed
if [ $? -ne 0 ]; then
    echo "One or more commands failed."
    exit 1
fi

echo "All commands succeeded. Running solana-validator next..."

while true; do
  echo "$PS4$program ${args[*]}"

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



# args=()
# stake_sol=
# node_sol=

# # Iterate through the command-line arguments
# while [ $# -gt 0 ]; do
#   if [[ ${1:0:2} = -- ]]; then
#     echo "first arg: $1"
#     if [[ $1 = --internal-node-stake-sol ]]; then
#       stake_sol=$2
#       shift 2
#     elif [[ $1 == --internal-node-sol ]]; then
#       node_sol=$2
#       shift 2
#     elif [[ $1 == --tpu-enable-udp ]]; then
#       args+=($1)
#       shift 1
#     elif [[ $1 == --tpu-disable-quic ]]; then
#       args+=($1)
#       shift 1
#     else
#       echo "Unknown argument: $1"
#       exit 1
#     fi
#   fi
# done

# for arg in "${args[@]}"; do
#   echo "Argument: $arg"
# done



# # Check if the --internal-node-stake-sol flag was provided
# if [ -z "$stake_sol" ]; then
#   echo "Usage: $0 --internal-node-stake-sol <sol>"
#   exit 1
# fi
# if [ -z "$node_sol" ]; then
#   echo "Usage: $0 --internal-node-sol <sol>"
#   exit 1
# fi

# echo "Sol stake: $stake_sol"

# /home/solana/k8s-cluster/src/scripts/decode-accounts.sh -t "validator"

# Maximum number of retries
# MAX_RETRIES=5

# # Delay between retries (in seconds)
# RETRY_DELAY=1

# # Solana RPC URL
# SOLANA_RPC_URL="http://$BOOTSTRAP_RPC_PORT"

# # Identity file
# IDENTITY_FILE=$identity

# # Function to run a Solana command with retries. need reties because sometimes dns resolver fails
# # if pod dies and starts up again it may try to create a vote account or something that already exists
# run_solana_command() {
#     local command="$1"
#     local description="$2"

#     for ((retry_count=1; retry_count<=$MAX_RETRIES; retry_count++)); do
#         echo "Attempt $retry_count for: $description"
#         $command

#         if [ $? -eq 0 ]; then
#             echo "Command succeeded: $description"
#             return 0
#         else
#             echo "Command failed for: $description (Exit status $?)"
#             if [ $retry_count -lt $MAX_RETRIES ]; then
#                 echo "Retrying in $RETRY_DELAY seconds..."
#                 sleep $RETRY_DELAY
#             fi
#         fi
#     done

#     echo "Max retry limit reached. Command still failed for: $description"
#     return 1
# }

# # Run Solana commands with retries
# run_solana_command "solana -u $SOLANA_RPC_URL airdrop "$node_sol" $IDENTITY_FILE" "Airdrop"
# run_solana_command "solana -u $SOLANA_RPC_URL create-vote-account --allow-unsafe-authorized-withdrawer vote.json $IDENTITY_FILE $IDENTITY_FILE -k $IDENTITY_FILE" "Create Vote Account"
# run_solana_command "solana -u $SOLANA_RPC_URL create-stake-account stake.json "$stake_sol" -k $IDENTITY_FILE" "Create Stake Account"
# run_solana_command "solana -u $SOLANA_RPC_URL delegate-stake stake.json vote.json --force -k $IDENTITY_FILE" "Delegate Stake"

# # Check if any of the commands failed
# if [ $? -ne 0 ]; then
#     echo "One or more commands failed."
#     exit 1
# fi

# echo "All commands succeeded. Running solana-validator next..."

# nohup solana-validator \
#   --no-os-network-limits-test \
#   --identity identity.json \
#   --vote-account vote.json \
#   --entrypoint $BOOTSTRAP_GOSSIP_PORT \
#   --rpc-faucet-address $BOOTSTRAP_FAUCET_PORT \
#   --gossip-port 8001 \
#   --rpc-port 8899 \
#   --ledger ledger \
#   --log logs/solana-validator.log \
#   --full-rpc-api \
#   --allow-private-addr \
#   "${args[@]}" \
#   >logs/init-validator.log 2>&1 &


# # Sleep for an hour (3600 seconds)
sleep 3600