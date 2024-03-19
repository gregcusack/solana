#!/bin/bash
# set -e

SECRET_FILE="/home/solana/client-accounts/faucet.base64"
DECODED_FILE="/home/solana/faucet.json"

# Check if the secret file exists
if [ -f "$SECRET_FILE" ]; then
    echo "Secret file found at $SECRET_FILE"

    # Read and decode the base64-encoded secret
    SECRET_CONTENT=$(base64 -d < "$SECRET_FILE")

    # Save the decoded secret content to a file
    echo "$SECRET_CONTENT" > "$DECODED_FILE"
    echo "Decoded secret content saved to $DECODED_FILE"
else
    echo "Secret file not found at $SECRET_FILE"
fi

mkdir -p /home/solana/logs

clientToRun="$1"
benchTpsExtraArgs="$2"
clientType="${3:-thin-client}"

shift 3

runtime_args=()
while [[ -n $1 ]]; do
  if [[ ${1:0:1} = - ]]; then
    if [[ $1 = --target-node ]]; then
      echo "--target-node not supported yet...not including" >> logs/client.log 2>&1
      # runtime_args+=("$1" "$2")
      shift 2
    elif [[ $1 = --duration ]]; then
      runtime_args+=("$1" "$2")
      shift 2
    elif [[ $1 = --num-nodes ]]; then
      runtime_args+=("$1" "$2")
      shift 2
    else
      echo "Unknown argument: $1"
      solana-bench-tps --help
      exit 1
    fi
  else
    echo "Unknown argument: $1"
    solana-bench-tps --help
    exit 1
  fi
done

missing() {
  echo "Error: $1 not specified"
  exit 1
}

# [[ -n $deployMethod ]] || missing deployMethod
# [[ -n $entrypointIp ]] || missing entrypointIp

threadCount=$(nproc)
if [[ $threadCount -gt 4 ]]; then
  threadCount=4
fi

TPU_CLIENT=false
RPC_CLIENT=false
case "$clientType" in
  thin-client)
    TPU_CLIENT=false
    RPC_CLIENT=false
    ;;
  tpu-client)
    TPU_CLIENT=true
    RPC_CLIENT=false
    ;;
  rpc-client)
    TPU_CLIENT=false
    RPC_CLIENT=true
    ;;
  *)
    echo "Unexpected clientType: \"$clientType\""
    exit 1
    ;;
esac

case $clientToRun in
bench-tps)
  args=()

  if ${TPU_CLIENT}; then
    args+=(--use-tpu-client)
    args+=(--url "$BOOTSTRAP_RPC_ADDRESS")
  elif ${RPC_CLIENT}; then
    args+=(--use-rpc-client)
    args+=(--url "$BOOTSTRAP_RPC_ADDRESS")
  else
    args+=(--entrypoint "$BOOTSTRAP_GOSSIP_ADDRESS")
  fi

  clientCommand="\
    solana-bench-tps \
      --sustained \
      --threads $threadCount \
      $benchTpsExtraArgs \
      --read-client-keys ./client-accounts.yml \
      ${args[*]} \
      ${runtime_args[*]} \
  "
  ;;
idle)
  # In net/remote/remote-client.sh, we add faucet keypair here
  # but in this case we already do that in the docker container
  # by default
  while true; do sleep 3600; done
  ;;
*)
  echo "Unknown client name: $clientToRun"
  exit 1
esac

echo "client command to run: $clientCommand" >> logs/client.log 2>&1

$clientCommand >> logs/client.log 2>&1
