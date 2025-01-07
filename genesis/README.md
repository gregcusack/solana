# Genesis

## There are a few ways to bake validator accounts and staked into genesis:
### 1) Through bootstrap validator cli args:
```
--bootstrap-validator <IDENTITY_PUBKEY> <VOTE_PUBKEY> <STAKE_PUBKEY>
--bootstrap-validator-lamports <LAMPORTS>
--bootstrap-validator-stake-lamports <LAMPORTS>
```
Note: you can pass in `--bootstrap-validator ...` multiple times but the lamports associated with `--bootstrap-validator-lamports` and `--bootstrap-validator-stake-lamports` will apply to all `--bootstrap-validator` arguments.
For example:
```
cargo run --bin solana-genesis --
    --bootstrap-validator <IDENTITY_PUBKEY_0> <VOTE_PUBKEY_0> <STAKE_PUBKEY_0>
    --bootstrap-validator <IDENTITY_PUBKEY_1> <VOTE_PUBKEY_1> <STAKE_PUBKEY_1>
    ...
    --bootstrap-validator <IDENTITY_PUBKEY_N> <VOTE_PUBKEY_N> <STAKE_PUBKEY_N>
    --bootstrap-validator-stake-lamports 10000000000
    --bootstrap-validator 100000000000
```
All validator accounts will receive the same number of stake and account lamports

### 2) Through the primordial accounts file flag:
```
--primordial-accounts-file <PATH_TO_PRIMORDIAL_ACCOUNTS_YAML>
```
The primordial accounts file has the following format:
```
---
<IDENTITY_PUBKEY_0>:
  balance: <LAMPORTS_0>
  owner: <OWNER_PUBKEY_0>
  data: <BAS64_ENCODED_DATA_0>
  executable: false
<IDENTITY_PUBKEY_1>:
  balance: <LAMPORTS_1>
  owner: <OWNER_PUBKEY_1>
  data: <BAS64_ENCODED_DATA_1>
  executable: true
...
<IDENTITY_PUBKEY_N>:
  balance: <LAMPORTS_N>
  owner: <OWNER_PUBKEY_N>
  data: <BAS64_ENCODED_DATA_N>
  executable: true
```
The `data` portion of the yaml file holds BASE64 encoded data about the account. `data` can include both vote and stake account information.

### 3) Through the validator accounts file flag:
The validator accounts file is an alternative to the primordial accounts file. The main goal with the validator accounts file is to:
- Bake validator stakes into genesis with different stake and acount distributions
- Remove the overhead of forcing the user to serialize and deserialize validator stake and vote account state if they want varying stake distributions - as required by (2)
```
--validator-accounts-file <PATH_TO_VALIDATOR_ACCOUNTS_YAML>
```
The validator accounts file has the following format:
```
validator_accounts:
- balance_lamports: <balance-lamports-0>
  stake_lamports: <stake-lamports-0>
  identity_account: <identity-pubkey-0>
  vote_account: <vote-pubkey-0>
  stake_account: <stake-pubkey-0>
- balance_lamports: <balance-lamports-1>
  stake_lamports: <stake-lamports-1>
  identity_account: <identity-pubkey-1>
  vote_account: <vote-pubkey-1>
  stake_account: <stake-pubkey-1>
...
- balance_lamports: <balance-lamports-N>
  stake_lamports: <stake-lamports-N>
  identity_account: <identity-pubkey-N>
  vote_account: <vote-pubkey-N>
  stake_account: <stake-pubkey-N>
```