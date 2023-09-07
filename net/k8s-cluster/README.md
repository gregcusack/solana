# How to run
From your local build host, login to Docker for pushing/pulling repos. we assume auth for registryies are already setup.
```
docker login
```

```
kubectl create ns <namespace>
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

Important Notes: this isn't designed the best way currently. 
- bootstrap and validator docker images are build exactly the same although the pods they run in are not build the same
- `--bootstrap-image` and `--validator-image` must match the format outlined above. The pods in the replicasets pull the exact `--bootstrap-image` and `--validator-image` images from dockerhub.
    - The docker container that is build is named based off of `--registry`, `--image-name`, `--base-image`, and `--tag`
    - Whenever image name you give will be prepended with either `bootstrap-` or `validator-`. not the best design currently but that's currently how it's build. 
    So make sure when you set `--boostrap-image` you make sure to prepend the `image-name` with `boostrap-` and same thing for `--validator-image` w/ `validator-`


Other Notes:
- Def some hardcoded stuff in here still 
- genesis creation is hardcoded for the most part in terms of stakes, lamports, etc. But does include all validator accounts that are created on deployment.

TODO:
- we currently write binary to file for genesis, then read it back to verify it. and then read it again to convert into a base64 string and then converted into binrary and then converted into a GenesisConfig lol. So need to fix
- Figure out env variables for private keys. idk how this is going to work


# Legacy info
### Kubernetes Deployment 
1) Create your namespace!
```
kubectl create ns <your-namespace>
```
2) Launch Bootstrap validator
```
kubectl apply -f bootstrap.yaml --namespace=<your-namespace>
```

3) Launch all other validators
- wait for bootstrap to come online
- edit the `validator.yaml` file if you want to increase the number of validators you want to deploy. default: 1
```
kubectl apply -f validator.yaml --namespace=<your-namespace>
```

4) Check for successful connections
- get name of bootstrap pod
```
kubectl get pods -n <your-namespace>
```
- exec into bootstrap pod
```
kubectl exec -it <pod-name-from-above> -n <your-namespace> -- /bin/bash
```
- run following commands to ensure validator connections successful. should see all pods running:
```
solana -ul validators
solana -ul gossip
```



### TODO
- [x] Make number of validators to deploy configurable
- [ ] Configure to be able to set any type of flags needed (see net.sh scripts for gce)
- [x] Configurable namespace -> define your own namespace and deploy into it

#### docker containers for solana validators
Builds off of: https://github.com/yihau/solana-local-cluster


build containers here with:
bootstrap:
```
sudo docker build -t solana-bootstrap-validator:latest -f bootstrap-validator/Dockerfile .
```

validator:
```
sudo docker build -t solana-validator:latest -f validator/Dockerfile .
```

Run bootstrap:
```
docker run -it -d --name bootstrap --network=solana-cluster --ip=192.168.0.101 solana-bootstrap-validator:latest
```

Run validator:
```
docker run -it -d --name validator --network=solana-cluster --ip=192.168.0.102 solana-validator:latest
```