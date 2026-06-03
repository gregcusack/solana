# Votor QUIC Datagram Change Stack

## Why This Stack Is Shaped This Way

The goal is to switch votor from QUIC stream mode to QUIC datagram mode. The stack is intentionally organized so the protocol pieces and the production behavior flip are not reviewed all at once.

The key idea is:

```text
First:  keep the current stream setup working
Then:   add the datagram setup beside it
Then:   wire both through an explicit transport enum
Finally: flip the default from stream to datagram
```

That is why the core wiring commit introduces `VotorTransportProtocol::{ QuicStream, QuicDatagram }` and `AlpenglowTransport::{ QuicStream, QuicDatagram }` instead of directly deleting the old path. The enum makes the old behavior and new behavior explicit. The first integration commit keeps `QuicStream` as the default, so review can focus on whether the datagram path is wired correctly without also reviewing a rollout. The final commit changes only the default to `QuicDatagram`, making the actual behavior switch small and obvious.

Why this approach is useful:

- It preserves the current votor stream path while the datagram implementation is introduced.
- It makes rollback simple: use `QuicStream` again instead of reverting the whole transport implementation.
- It keeps the production behavior switch isolated to one small commit.
- It separates protocol-sensitive changes from implementation plumbing where possible.
- It reduces risk to unrelated validator paths: Tower, ReplayStage, TPU transaction networking, TPU vote networking, and non-votor vote paths are not supposed to change.

Top-level commit flow:

1. `c21e1fc76d` - Preserve peer identity in votor fanout targets.
   Votor still sends through `ConnectionCache` streams, but fanout now carries `(Pubkey, SocketAddr)` so the later datagram path can target authenticated peers.

2. `fbd2d8e721` - Normalize BLS sigverify input bytes.
   BLS sigverify still receives old streamer `PacketBatch` input, but internally converts it into authenticated byte items. This prepares sigverify for datagram input without changing the transport yet.

3. `edbf3b9730` - Add the unused `solana-quic-datagram` endpoint crate.
   This introduces the generic datagram endpoint, allowlist, banlist, connection handling, transport tuning, and endpoint tests without wiring it into validator startup.

4. `c5ab519d4f` - Test connection semantics.
   This validates the important datagram transport rules such as one connection per peer, dialing placeholders, tiebreaking, and peer movement before votor depends on them.

5. `b65c44561f` - Add the votor datagram wrapper and benchmark.
   This creates the votor-specific wrapper around the generic endpoint, including ALPN and allowlist construction, but still does not switch production votor.

6. `c1517add2c` - Add an additive datagram send path to `VotingService`.
   `VotingService::new()` still uses `ConnectionCache -> QUIC stream`. A new `VotingService::new_datagram()` path sends to the datagram egress channel, but nobody uses it by default yet.

7. `c3730df0a1` - Test datagram identity rotation through the votor wrapper.
   This verifies that the key updater exposed by the votor wrapper works before validator startup registers it.

8. `e77dcd9691` - Wire votor datagram transport behind config.
   Validator and TVU can now select either stream mode or datagram mode through `VotorTransportProtocol` and `AlpenglowTransport`. The default remains `QuicStream`, so this is integration without rollout.

9. `05b3d50d24` - Default votor to QUIC datagrams.
   This is the rollout commit. It changes the default from `QuicStream` to `QuicDatagram` and updates the admin RPC test expectation for the datagram key updater.

Bottom line: the stack first makes the new datagram path possible, then wires it through the current validator setup as a selectable mode, and only at the end changes the default. That is the cleanest review shape for a transport change because the final behavior switch is easy to see and easy to revert.

## Differences From `pr-12572`

This stack is no longer trying to be final-code-identical to `pr-12572`. The core goal is still the same: make votor use QUIC datagrams instead of QUIC streams. The important difference is how the change is introduced.

`pr-12572` is closer to "replace stream mode with datagram mode now." This stack is closer to "add datagram mode, keep stream mode as a selectable fallback, default to datagram, and remove stream mode later only after the new path is validated."

The intentional differences are:

1. Validator and TVU keep two explicit transport modes. `QuicStream` preserves the old BLS `ConnectionCache` plus simple-qos streamer path, while `QuicDatagram` builds the new datagram endpoint and routes datagram ingress into BLS sigverify. This is different from `pr-12572`, which more directly wires startup into datagrams.

2. The old BLS streamer path remains selectable. That is not protocol-required for datagrams, but it gives a fallback and lets the default flip be reviewed separately from the implementation.

3. BLS sigverify accepts both stream packet batches and authenticated datagrams. This is needed because the stack preserves both transports; the verifier should only care about authenticated bytes and the remote pubkey, not which transport produced them.

4. `VotingService` gains datagram sending additively. `VotingService::new()` keeps using `ConnectionCache -> QUIC stream`, while `VotingService::new_datagram()` sends to the datagram egress channel. `pr-12572` is more direct because it replaces the main voting-service path sooner.

5. `StakedValidatorsCache` keeps compatibility constructors while adding allowlist support for datagram admission. That avoids forcing stream-mode callers to understand the datagram allowlist before the transport switch.

6. Local-cluster and tests differ because this stack has both modes for a while. Tests cover the old fallback and the new default path until stream mode is intentionally removed in a later cleanup.

7. Lockfile differences should be reviewed carefully. Some dependency movement follows from the staged implementation, but any incidental lockfile churn should be squashed away or regenerated cleanly before publishing.


## `c21e1fc76d` - `votor: preserve peer identity in fanout targets`

What it does:

This commit threads peer identity through votor fanout by changing cached targets and test override listeners from bare socket addresses to `(Pubkey, SocketAddr)` style data. It keeps the existing `ConnectionCache` QUIC stream send path in place; the new pubkey is carried only so a later datagram sender can target authenticated peers.

Why it exists:

QUIC datagram sending needs a peer identity, not just an address, because the datagram endpoint/connection table targets authenticated peers by `Pubkey`. This commit threads that identity through votor fanout before changing transport.

What it does not do:

No datagram crate, no BLS sigverify changes, no validator wiring, no banlist/allowlist changes, no production transport switch.

## `fbd2d8e721` - `core: normalize BLS sigverify input bytes`

What it does:

This commit refactors BLS sigverify so the verifier first works with normalized authenticated byte items rather than directly parsing streamer packets everywhere. The actual input is still the old `PacketBatch` receiver, and the consensus message bytes are deserialized with `wincode::deserialize_exact(...)` to match votor serialization and reject trailing data.

Why it exists:

Datagram ingress will naturally produce authenticated `(remote_pubkey, bytes)` items instead of streamer `PacketBatch` values. This commit isolates the verifier from packet-specific parsing first, so the later datagram switch can replace the producer without rewriting vote/certificate verification logic at the same time.

What it does not do:

No datagram receiver, no banlist type change, no validator/TVU wiring, no voting-service changes, and no production transport switch.

## `edbf3b9730` - `quic-datagram: add unused endpoint crate`

What it does:

This commit adds the new generic `solana-quic-datagram` crate and its endpoint API, including authenticated datagram egress/ingress, allowlist and banlist support, one-connection-per-peer handling, datagram-only QUIC transport configuration, identity rotation, basic hardening, metrics, and endpoint tests. Nothing in validator, TVU, BLS sigverify, or votor production wiring uses the crate yet.

Why it exists:

The previous two commits prepared votor egress to carry peer identity and prepared BLS sigverify to consume authenticated bytes. This commit supplies the transport object that can produce and consume that shape: authenticated peer-keyed QUIC datagrams with explicit admission, banning, connection ownership, and datagram-only QUIC settings.

Review note:

As a stack step, this isolates production risk well. As an individual commit, it is still large: it combines the base endpoint, connection table, hardening/tuning, metrics, and identity-rotation policy. If we wanted an even more reviewable stack, this commit could be split into smaller transport-only commits. For this staged branch, this is the foundation commit that later votor and validator commits build on, even though the final shape now intentionally differs from `pr-12572` by keeping a selectable stream fallback.

## `c5ab519d4f` - `quic-datagram: test connection semantics`

What it does:

This commit adds focused integration tests for the datagram endpoint connection semantics: lexicographic peer tiebreaking, failed `Dialing` cleanup, peer address movement, and nextest config for this networking-heavy crate.

Why it exists:

The previous commit added a lot of new transport machinery. The highest-risk parts are not raw `send_datagram` calls; they are the state-machine rules around who owns a connection, when a connection may be reused, when a dial may be retried, and how address changes are handled. These tests lock down those rules before any votor or validator code starts depending on them.

What it does not do:

No endpoint implementation changes, no votor changes, no validator/TVU wiring, no BLS sigverify changes, no banlist or allowlist behavior changes, and no production transport switch.

NOTE: this could probably be PRed with the commit above.

## `b65c44561f` - `votor: add datagram endpoint wrapper and benchmark`

What it does:

This commit adds the votor-specific wrapper around the generic datagram endpoint: alpenglow ALPN, endpoint spawn helper, staked-node allowlist construction, and a fanout/fanin benchmark example.

Why it exists:

The transport crate is intentionally generic. Votor still needs a small integration layer to pin down alpenglow-specific protocol choices and to translate the validator bank/stake view into the transport allowlist. This commit creates that layer before touching `VotingService`, TVU, or validator startup.

Why this is the best next step:

After the generic transport and its tests, this is the narrowest useful votor-facing step: define the wire ALPN and allowlist construction once, in `agave-votor`, while production still uses the old streamer/`ConnectionCache` path. Later commits can consume this wrapper instead of duplicating protocol constants and stake-admission logic inside `core` or `validator`.

Review note:

The wrapper is directly relevant to the datagram switch because ALPN and staked admission are protocol/compatibility boundaries. The benchmark is not required for the minimal production diff; it is additive validation/performance tooling. If we were minimizing review surface aggressively, the benchmark could be split from the wrapper or moved to a separate perf PR.

What it does not do:

No `VotingService` send-path change, no validator startup wiring, no TVU/BLS sigverify channel changes, no production endpoint construction, no banlist behavior change, no `ConnectionCache` removal, and no production transport switch.

## `c1517add2c` - `votor: add additive datagram send path`

VotingService had one way to send votes:

```text
VotingService -> ConnectionCache -> QUIC stream
```

The send logic was baked directly into the service.

This commit changes that to:

```text
VotingService -> "some sender"
```

Then it defines two possible senders:

```text
ConnectionCacheMessageSender -> QUIC stream
DatagramMessageSender        -> QUIC datagram channel
```

But the default constructor still picks the old one:

```text
VotingService::new()
  -> ConnectionCacheMessageSender
  -> QUIC stream
```

So after this commit, production is still:

```text
VotingService -> ConnectionCache -> QUIC stream
```

The only new thing is that we now have another constructor:

```text
VotingService::new_datagram()
  -> DatagramMessageSender
  -> QUIC datagram channel
```

But nobody calls that yet.

What it does:

This is the code change behind the diagram above: the final send operation becomes pluggable, while production still uses the old stream sender.

Why it exists:

At this point the stack has a datagram transport and a votor wrapper, but `VotingService` still only knows how to send through `ConnectionCache` streams. This commit introduces the smallest useful production-adjacent abstraction: keep the old broadcast pipeline, serialization, target selection, and service thread, but make the final send operation pluggable.

Why this is the best next step:

This is the correct point to touch `VotingService` because peer identity has already been preserved in fanout targets, and the votor datagram wrapper already exists. Making the datagram path additive lets reviewers inspect the send-path change without also reviewing validator startup, TVU ingress, BLS sigverify channel changes, or a default behavior flip.

Review note:

This commit is close to the minimal votor egress diff. It avoids removing `ConnectionCache` and avoids changing existing callers of `VotingService::new(...)`. The main non-egress addition is allowlist refresh plumbing in `StakedValidatorsCache`; that is needed for datagram endpoint admission, but it is an implementation coupling to review carefully because endpoint allowlist updates are now driven by the same cache refresh path used for fanout target discovery.

What it does not do:

No validator constructs the datagram endpoint yet. No validator calls `VotingService::new_datagram(...)` yet. No inbound datagram receiver is wired into BLS sigverify. No TVU fields change in this commit. No old stream path is removed, no `ConnectionCache` behavior changes for existing callers, and no production transport switch happens here.

## `c3730df0a1` - `votor: test datagram identity rotation`

What it does:

This commit adds a test that sends through the votor datagram wrapper, rotates the client identity through the wrapper key updater, and verifies later traffic arrives under the new identity.

Why it exists:

The generic `solana-quic-datagram` crate already tests the lower-level `KeyUpdater` mechanics. This commit verifies that the votor wrapper actually exposes that key updater correctly. That matters because validator wiring will later register the returned key updater in the validator key-update registry.

Why this is the best next step:

The previous commit made datagram sending available to `VotingService`, but validator startup still has not constructed the endpoint or registered identity-rotation support. Before adding that startup wiring, this test checks the votor-facing endpoint wrapper contract: spawn returns an endpoint whose `key_updater` can rotate the QUIC/TLS identity and send subsequent datagrams under the new pubkey.

What it does not do:

No production code changes, no `VotingService` change, no validator/TVU wiring, no BLS sigverify change, no default behavior change, no new protocol constant, and no production transport switch.

## `e77dcd9691` - `core: wire votor datagram transport behind config`

Simple dataflow after this commit:

```text
Default / old path:
VotingService -> ConnectionCache -> QUIC stream
Inbound QUIC simple_qos streamer -> PacketBatch -> BLS sigverify
```

```text
Configured datagram path:
VotingService::new_datagram() -> datagram egress channel -> QuicDatagramEndpoint
QuicDatagramEndpoint ingress channel -> Datagram -> BLS sigverify
```

What it does:

This commit wires the stream and datagram votor transports through explicit config enums in validator and TVU. `QuicStream` still builds the old BLS `ConnectionCache` plus simple-qos streamer path, `QuicDatagram` builds the new datagram endpoint and routes datagram ingress into BLS sigverify, and the default remains `QuicStream` in this commit.

Why it exists:

The earlier commits made datagram sending and the datagram endpoint available, but nothing in the validator could actually choose it. This commit connects the pieces end to end under a config enum: validator startup can construct the datagram endpoint, TVU can route datagram ingress into BLS sigverify, and the BLS voting service can use the datagram egress channel.

Why this is the best next step:

This is the right place for the first full integration because the previous commits isolated the risky pieces: peer identity in fanout, normalized BLS input bytes, the generic endpoint, votor wrapper, and additive `VotingService::new_datagram(...)`. With those pieces already reviewed, this commit can focus on wiring and preserving the old path behind `VotorTransportProtocol::QuicStream`.

Review note:

This is a real integration commit and should get careful review. It touches validator startup, TVU initialization, BLS sigverify, banlist abstraction, key-updater registration, and local-cluster config cloning. The important safety property is that the default remains `QuicStream`, so the normal path should still be the old stream-mode behavior until the final default-flip commit. The main review questions are whether the datagram endpoint task lifetime is acceptable, whether the stub-channel behavior outside Testnet/Development is intentional, and whether the new generic banlist trait preserves old ban semantics for stream mode.

What it does not do:

It does not make datagrams the default. It does not remove the old simple-qos streamer path. It does not remove the old BLS `ConnectionCache` path. It does not add a public CLI flag for selecting the transport. It does not change TPU transaction networking, TPU vote transaction networking, Tower consensus logic, ReplayStage consensus logic, or non-votor vote paths beyond passing the selected alpenglow transport into TVU.


## `05b3d50d24` - `validator: default votor to quic datagrams`

What it does:

This commit flips `VotorTransportProtocol::default()` from `QuicStream` to `QuicDatagram` and updates the admin RPC identity-update test expectation for the datagram key updater.

Why it exists:

The previous commit wired both transports behind `VotorTransportProtocol`, but intentionally kept `QuicStream` as the default. This commit performs the actual behavior switch: votor now uses the QUIC datagram path by default.

Why this is the best next step:

The default flip belongs after the dual-path wiring commit. At that point the old stream path still exists for fallback, the datagram endpoint is wired end to end, BLS sigverify can consume datagram ingress, and `VotingService` can send through datagram egress. Keeping this as a separate commit makes the production behavior change obvious and easy to revert without removing the datagram implementation.

Review note:

This is a tiny diff but a high-impact commit. The code changed here is only the default enum variant and an admin RPC test expectation, but the behavior it selects is the full datagram transport path added in the earlier commits. Review should treat this as the rollout point, not as a harmless cleanup.

What it does not do:

It does not remove `QuicStream`. It does not remove the old simple-qos BLS streamer path. It does not remove the old BLS `ConnectionCache` path. It does not add a CLI flag for selecting transport. It does not change Tower consensus, ReplayStage consensus, TPU transaction networking, TPU vote transaction networking, or non-votor vote paths.
