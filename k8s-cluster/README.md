# How to run
From your local build host, login to Docker for pushing/pulling repos. we assume auth for registryies are already setup.
```
docker login
```

```
kubectl create ns <namespace>
```

Clone the repo
```
git clone -b solana-k8s-cluster git@github.com:gregcusack/solana.git
cd solana
```

1) Build local solana version (aka based on the current commit)
```
cargo run --bin solana-k8s --
    -n <namespace e.g. greg-test>
    --num-validators 3
    --bootstrap-image <registry>/bootstrap-<image-name>:<tag>
    --validator-image <registry>/validator-<image-name>:<tag>
    --prebuild-genesis
    --deploy-method local
    --do-build
    --docker-build
    --registry <your-docker-registry-name>
    --image-name <name-of-your-image-to-build>
    --base-image <base-image-of-docker-image: default ubuntu:20.04>
    --tag <imagetag. default: latest>
```

2) Pull specific release (e.g. v1.16.5)
```
cargo run --bin solana-k8s --
    -n <namespace e.g. greg-test>
    --num-validators 3
    --bootstrap-image <registry>/bootstrap-<image-name>:<tag>
    --validator-image <registry>/validator-<image-name>:<tag>
    --prebuild-genesis
    --deploy-method tar
    --release-channel <release-channel. e.g. v1.16.5 (must prepend with 'v')>
    --do-build
    --docker-build
    --registry <docker-registry>
    --image-name <name-of-your-image-to-build>
    --base-image <base-image-of-docker-image: default ubuntu:20.04>
    --tag <imagetag. default: latest>
```

Example
```
cargo run --bin solana-k8s --
    -n greg-test
    --num-validators 3
    --bootstrap-image gregcusack/bootstrap-k8s-cluster-image:v2
    --validator-image gregcusack/validator-k8s-cluster-image:v2
    --prebuild-genesis
    --deploy-method local
    --do-build
    --docker-build
    --registry gregcusack
    --image-name k8s-cluster-image
    --base-image ubuntu:20.04
    --tag v2
```

## Metrics are now supported as of 11/14/23!! ~woo~
1) Setup metrics database:
```
cd k8s-cluster/src/scripts
./init-metrics -c <database-name> <metrics-username>
# enter password when promted
```
2) add the following to your `solana-k8s` command from above
```
--metrics-host https://internal-metrics.solana.com # need the `https://` here
--metrics-port 8086
--metrics-db <database-name>            # from (1)
--metrics-username <metrics-username>   # from (1)
--metrics-password <metrics-password>   # from (1)
```

Verify validators have deployed:
```
kubectl get pods -n <namespace>
```
^ `STATUS` should be `Running` and `READY` should be `1/1` for all

Verify validators are connected properly:
```
BOOTSTRAP_POD=$(kubectl get pods -n greg-test | grep bootstrap | awk '{print $1}')
kubectl exec -it -n <namespace> $BOOTSTRAP_POD -- /bin/bash

solana -ul gossip # should see `--num-validators`+1 nodes (including bootstrap)
solana -ul validators # should see `--num-validators`+1 current validators (including bootstrap)
```
^ if you ran the tar deployment, you should see the Stake by Version as well read `<release-channel>` in the `solana -ul validators` output.

TODO:
- we currently write binary to file for genesis, then read it back to verify it. and then read it again to convert into a base64 string and then converted into binrary and then converted into a GenesisConfig lol. So need to fix

### Notes
- Have tested deployments of up to 500 validators
- Additional validator commandline flags are coming....stay tuned
- Once again, we assume you are logged into docker and you are pulling from a public repo (Monogon hosts need to access)