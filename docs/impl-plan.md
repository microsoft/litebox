# Broker Architecture Implementation Plan

## Goal

Implement the broker architecture as incremental vertical slices while keeping the existing LiteBox behavior working.

The target architecture has two trust domains:

```text
User mode:
  Shim + local core + optional BrokerService clients

Authority domain:
  broker entry/server + litebox_broker_host + BrokerCore + optional BrokerServices + PolicyEngine + BrokerPlatform
  broker-kernel user-mode support, in kernel-backed deployments
```

The local core reaches local mechanics and broker channels through deployment support: the host OS user-mode ABI plus a broker transport endpoint in hosted userland, or calls into broker-kernel user-mode support plus broker-channel delivery in a broker-kernel deployment.

The baseline is the stricter durable-unicorn model: no host fd/HANDLE delegation to untrusted code, ABI-neutral broker objects, broker-owned control/event/data channels, authenticated per-process broker associations, and fail-closed behavior.

## Implementation principles

- Build vertical slices, not a big-bang refactor.
- Keep local core untrusted and broker authority explicit.
- Keep BrokerCore shim-neutral.
- Keep BrokerCore protocol-neutral and channel-neutral. BrokerCore exposes in-domain authority methods and domain types; broker entry/server code adapts protocol requests and channel credentials before calling it.
- Keep the broker protocol modular: the outer request/response envelope is for connection-level broker messages and coarse authority routing, while object/domain operations live in nested request/response families such as `CoreRequest::Event` and `EventResponse`.
- Keep the control channel strictly paired request/response; broker-initiated readiness, interrupt, fault, revocation, and session-failure messages should use a separate notification channel/message family.
- Put domain-specific authority in BrokerServices.
- Put final allow/deny/audit decisions in PolicyEngine.
- Keep BrokerPlatform as authorized backend execution, not a policy owner.
- Keep broker-kernel user-mode support separate from broker request decode/authorization; `litebox_broker_host` owns the reusable protocol-to-core adapter for both userland and kernel brokers.
- Start in userland; move to kernel-broker deployment after broker semantics are proven.

## Phase 0: Boundary freeze

Define and document the core vocabulary in code and docs:

- `local core`
- `litebox_broker_local` adapter
- optional BrokerService client
- `BrokerCore`
- `BrokerService`
- `PolicyEngine`
- `BrokerPlatform`
- `litebox_broker_host`
- broker-kernel user-mode support

Exit criteria:

- Design doc and code comments use one vocabulary.
- No new code treats local core as trusted.
- No broker API is modeled as host syscall proxying.

## Phase 1: Shared protocol/types crate

Create a shared crate for broker protocol types.

Initial contents:

- protocol version type;
- broker event reference handles with reference generations;
- small broker request/response envelope with minimal nested event request/response families;
- readiness and wait outcome payloads;
- ABI-neutral error categories;

Richer request/response envelopes, control/event/data channel frame headers, policy profile IDs, host syscall profile IDs, and feature negotiation structures are added when later milestones need them.

Prefer `no_std` for shared types, adding `alloc` only in crates that need owned buffers, so they can be reused by userland and kernel-broker deployments.

Exit criteria:

- Shared types compile independently.
- Wire-visible fields are explicit and versioned.
- Caller identity is not caller-chosen inside request payloads.

## Phase 2: Userland broker skeleton

Implement a userland broker process first.

Initial scope:

- one broker process per sandbox session;
- at least one authenticated process association within the broker session;
- control channel only;
- major-version/minor-compatible protocol negotiation;
- neutral blocking `no_std` control-channel traits with channel-specific error types and explicit clean-close receive semantics;
- channel-produced peer credentials returned through the server control-channel trait and mapped by the broker server into BrokerCore caller credentials;
- reusable `no_std + alloc` request/response wire codec for byte-stream channel implementations;
- Unix-domain-socket framing as the first concrete userland channel implementation;
- a Unix-socket executable that wires the generic channel-neutral server to the concrete Unix control-channel implementation;
- server-owned protocol negotiation, request sequencing, unknown-tag handling, protocol/core type adaptation, and connection-close reasons;
- BrokerCore-owned caller associations, object/reference authority, policy hooks, event behavior, and association cleanup;
- default-deny PolicyEngine;
- fail-closed channel/session behavior.

Exit criteria:

- A user-side client can connect and negotiate. In the current hosted userland path, `litebox_runner_linux_userland` consumes an externally owned Unix-socket endpoint via `--broker-socket`, uses `litebox_broker_local` to negotiate, constructs the `LiteBox` local core with broker control already present, and the Linux shim reaches migrated event objects through the local-core event domain rather than through broker-specific APIs.
- Broker binds caller identity to the authenticated channel endpoint. The first hosted executable passes the explicit unauthenticated placeholder through the same server API that later deployment-specific authentication will use.
- Userland channel code only receives/sends decoded frames and supplies peer credentials; the generic server owns broker protocol dispatch and reports successful termination as peer-close or broker-close with a reason.
- The Unix-socket channel adapter and hosted broker executable live in separate crates, so clients can depend on the channel without pulling in broker core/server deployment code.
- BrokerCore depends only on shared broker value DTOs from `litebox_broker_protocol`; it does not depend on protocol envelopes, channel traits, wire codecs, or concrete IPC crates.
- Client code does not need to depend on the userland broker server crate to use the first Unix socket channel.
- The generic broker server library does not depend on concrete Unix socket channel code and remains `no_std`.
- Malformed or unauthorized requests fail closed or return policy-denied according to explicit policy.
- Unsupported future protocol operations return `UnsupportedOperation` without closing the connection so clients can probe optional features explicitly; newer core error categories or wait outcomes that the server adapter cannot represent return `Internal`.
- Version-mismatch negotiation responses advertise the broker-supported version and keep the connection in negotiation state so clients can downgrade without reconnecting or guessing.
- BrokerCore/object operations are grouped below the broker envelope instead of added as unrelated top-level `BrokerRequest` and `BrokerResponse` variants.
- Control-channel contracts live in `litebox_broker_protocol::channel`, separate from semantic message DTO modules but in the same shared protocol crate. Future broker-initiated readiness, interrupt, fault, revocation, or session-failure traffic must use a separate notification channel/message family rather than unsolicited control-channel responses.

## Phase 3: Local core facade

Introduce the local core without moving every subsystem.

Initial scope:

- wrap existing LiteBox ergonomics in the local core;
- add the `litebox_broker_local` adapter;
- keep existing local implementations available behind a profile/feature;
- add a broker-backed handle-table view for experimental objects.

Exit criteria:

- Current tests can still use the local profile.
- A broker-backed profile can issue a simple broker request.
- local-core handle entries can store opaque broker reference handles plus local cached rights hints.

## Phase 4: First broker-owned object

Start with a small event or pipe-like object, not filesystem or networking.

Broker owns:

- broker-internal object ID and lifetime;
- initial reference ID, reference generation, and rights;
- readiness state;
- wait/wakeup state.

The local core owns:

- guest-visible handle number;
- typed facade;
- buffer marshalling;
- non-authoritative readiness cache.

Exit criteria:

- Create, wait, and signal work through BrokerCore and the separate broker process.
- BrokerCore and the server already release association-owned references on channel disconnect, and BrokerCore has an explicit in-domain `close_object_reference` operation. Protocol-level close, duplicate, explicit readiness queries, and broader stale-handle coverage remain future work after the first end-to-end path is proven.

## Phase 5: Broker-backed fd semantics

Move fd authority to BrokerCore while keeping guest fd numbers in local core.

BrokerCore owns:

- object refs;
- rights;
- reference generations;
- refcounts;
- dup/pass/close;
- inherited object tables;
- process-exit cleanup.

The local core owns:

- guest fd number allocation;
- raw-int fd conversion;
- typed fd wrappers;
- local ABI metadata and cached hints.

Exit criteria:

- Double close, stale fd, dup, inherited refs, and process-exit cleanup are tested.
- The local core cannot create a live broker object by editing local fd state.

## Phase 6: Control/notification/data channels

Add the durable-unicorn-style control/notification/data channel separation.

Channels:

- control: object operations and responses;
- event: broker-to-process async events;
- data: bulk payload bytes.

Linux hosted prototype:

- broker creates inherited private `memfd`;
- ring header has magic/version/layout;
- broker binds ring set to authenticated runner identity;
- broker validates all ring metadata, cursors, frame bounds, and producer roles.

Exit criteria:

- Control channel supports concurrent request IDs.
- Event channel reports readiness/lifecycle/fail-closed events.
- Data channel can carry payloads for the first broker-owned object.
- Invalid cursor movement or malformed frames fail closed.

## Phase 7: Host syscall profiles

Define host syscall profiles for hosted userland.

Profiles:

- bootstrap profile;
- fast local profile;
- strict profile.

Linux targets:

- fast-futex mode: small syscall allowlist, including futex for ring/private waits;
- strict-seccomp-like mode: all mappings, fds, signal handlers, and trampoline state installed before lockdown.

Exit criteria:

- Direct guest `mmap`, `mprotect`, `munmap`, `mremap`, `memfd_create`, `open/openat`, `ioctl`, and `fcntl` cannot bypass broker policy after lockdown.
- Guest-visible mapping operations enter the shim/local-core path and are emulated or broker-mediated.

## Phase 8: Filesystem BrokerService

Add a minimal filesystem BrokerService.

Start with a restricted virtual or host-backed filesystem.

Broker side owns:

- namespace roots;
- directory objects;
- open file descriptions;
- file object IDs;
- path lookup;
- permissions;
- read/write policy.

The local core owns:

- path string conversion;
- buffer marshalling;
- guest fd view;
- data-channel wrappers.

Exit criteria:

- Filesystem operations are directory-relative.
- No host fd/HANDLE is exposed to local core.
- File data uses mediated control/data channel or broker-owned ring.
- PolicyEngine can deny open/read/write independently.

## Phase 9: Memory and mapping authority

Move security-sensitive mapping authority broker-side.

Broker side owns:

- mapping object identity;
- memory grants;
- shared mappings;
- executable mapping policy;
- page-fault decisions where applicable.

The local core owns:

- loader helpers;
- guest pointer handling;
- cached VMA view;
- local anonymous/private scratch allocation allowed by host profile.

Exit criteria:

- Broker-visible mappings require BrokerCore validation and PolicyEngine authorization.
- Executable memory cannot be created without rewrite/validation policy.
- Shared memory grants cannot be forged by local core.

## Phase 10: Multiprocess

Implement one guest process as one sandboxed host process.

Broker owns:

- session identity;
- guest process identity;
- per-process channel set;
- process lifecycle;
- process-exit cleanup;
- inherited broker object table.

Shim/local core owns:

- ABI-specific fork semantics;
- ABI-specific exec semantics;
- guest memory replacement;
- guest fd-number presentation.

Exit criteria:

- Broker-mediated process creation works.
- Child process cannot impersonate parent.
- Inherited objects are explicit.
- Process exit releases broker-owned refs.

## Phase 11: Network BrokerService

Add broker-owned networking after filesystem and process identity are stable.

Broker side owns:

- socket object identity;
- port allocation;
- bind/listen/connect state;
- flow metadata;
- firewall policy context;
- TX/RX rings where enabled.

The local core owns:

- socket syscall facade;
- send/recv marshalling;
- local readiness cache.

Exit criteria:

- L3/L4 firewall policy is enforced by PolicyEngine.
- The local core cannot send or receive guest-visible network traffic directly through host network devices.
- Data path uses broker-mediated operations or broker-owned rings.

## Phase 12: Kernel-broker deployment

Only after userland semantics are stable, implement broker-kernel deployment.

Separate trusted deployment code into:

- broker-kernel user-mode support: trusted-domain support for user-mode execution and channel delivery;
- `litebox_broker_host`: broker protocol/core adaptation reused from the userland broker;
- BrokerPlatform: privileged backend execution;
- BrokerCore/BrokerServices/PolicyEngine: shared authority logic.

Exit criteria:

- Broker-kernel user-mode support does not decode or authorize BrokerRequest.
- `litebox_broker_host` protocol semantics and BrokerCore object semantics are reused through the same protocol-to-core adapter boundary.
- Kernel-broker deployment passes the same broker-object conformance tests as userland broker.

## Phase 13: OP-TEE BrokerService

Add OP-TEE-specific authority only where generic BrokerCore cannot express it.

BrokerService owns:

- TA/session authority;
- persistent object semantics;
- PTA access-control context;
- OP-TEE-specific lifecycle semantics.

PolicyEngine owns:

- final OP-TEE policy decisions and audit.

Exit criteria:

- OP-TEE shim remains user-mode ABI code.
- Trusted deployment does not need the full OP-TEE shim.
- OP-TEE authority cannot be created in local core.

## Suggested first milestone

The smallest useful milestone is:

```text
single process
userland broker
typed control client
control channel only
minimal PolicyEngine
broker-owned event object
local-core fd table maps guest fd -> broker reference handle
```

This proves the trust boundary before taking on filesystem, networking, mapping, or multiprocess complexity.

## Validation strategy

Add conformance tests at each layer:

- protocol parsing rejects malformed frames;
- policy default-denies unknown operations;
- caller identity is channel-bound;
- stale reference IDs fail;
- wrong reference generation fails;
- process disconnect cleans up refs;
- local-core handle edits cannot create authority;
- shared-memory cursor/frame corruption fails closed;
- broker failure forces session failure.

Prefer tests that run against both userland broker and later kernel-broker implementations.
