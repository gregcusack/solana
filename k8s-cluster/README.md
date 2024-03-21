# Deploy Validator Clusters for Testing

## Disclaimer:
This library is a work in progress. It will be built over a series of PRs. Plan and progress for PRs is can be found [here](https://github.com/gregcusack/monogon-pr-plan/blob/main/README.md)

## How to run

### Setup
From your local build host, login to Docker for pushing/pulling repos. we assume auth for registryies are already setup.
```
docker login
```

```
kubectl create ns <namespace>
```

### Run
```
cargo run --bin solana-k8s --
    -n <namespace e.g. monogon-test>
```
