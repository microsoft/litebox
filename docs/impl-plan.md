# Broker Split Implementation Plan

## Goal

Implement the broker split as incremental vertical slices while keeping the existing LiteBox behavior working.

The target architecture is:

```text
User mode:
  Shim + UserLiteBox + optional shim-specific user clients

Authority domain:
  BrokerCore + optional BrokerServices + PolicyEngine + BrokerPlatform

Kernel-broker deployments:
  BrokerHost supports user-mode UserLiteBox execution and broker transport
```

The baseline is the stricter durable-unicorn model: no host fd/HANDLE delegation to untrusted code, ABI-neutral broker objects, broker-owned control/event/data channels, authenticated per-process broker associations, and fail-closed behavior.

## Implementation principles

- Build vertical slices, not a big-bang refactor.
- Keep UserLiteBox untrusted and broker authority explicit.
- Keep BrokerCore shim-neutral.
- Put domain-specific authority in BrokerServices.
- Put final allow/deny/audit decisions in PolicyEngine.
- Keep BrokerPlatform as authorized backend execution, not a policy owner.
- Keep BrokerHost separate from broker request decode/authorization.
- Start in userland; move to kernel-broker deployment after broker semantics are proven.

## Phase 0: Boundary freeze

Define and document the core vocabulary in code and docs:

- `UserLiteBox`
- `BrokerClient` adapter
- `BrokerCore`
- `BrokerService`
- `PolicyEngine`
- `BrokerPlatform`
- `BrokerHost`

Exit criteria:

- Design doc and code comments use one vocabulary.
- No new code treats UserLiteBox as trusted.
- No broker API is modeled as host syscall proxying.

## Phase 1: Shared protocol/types crate

Create a shared crate for broker protocol types.

Initial contents:

- protocol version;
- session/process/workload IDs;
- broker object IDs with type tags and generations;
- request/response envelopes;
- ABI-neutral error categories;
- control/event/data channel frame headers;
- policy profile IDs;
- host syscall profile IDs;
- feature negotiation structures.

Prefer `no_std + alloc` for shared types so they can be reused by userland and kernel-broker deployments.

Exit criteria:

- Shared types compile independently.
- Wire-visible fields are explicit and versioned.
- Caller identity is not caller-chosen inside request payloads.

## Phase 2: Userland broker skeleton

Implement a userland broker process first.

Initial scope:

- one broker process per sandbox session;
- one authenticated process association;
- control channel only;
- exact protocol version negotiation;
- default-deny PolicyEngine;
- fail-closed channel/session behavior.

Exit criteria:

- UserLiteBox can connect and negotiate.
- Broker binds caller identity to the authenticated transport.
- Malformed or unauthorized requests fail closed or return policy-denied according to explicit policy.

## Phase 3: UserLiteBox facade

Introduce UserLiteBox without moving every subsystem.

Initial scope:

- wrap existing LiteBox ergonomics behind UserLiteBox;
- add BrokerClient adapter;
- keep existing local implementations available behind a profile/feature;
- add a broker-backed handle-table view for experimental objects.

Exit criteria:

- Current tests can still use the local profile.
- A broker-backed profile can issue a simple broker request.
- UserLiteBox handle entries can store broker object ID + generation + cached rights.

## Phase 4: First broker-owned object

Start with a small event or pipe-like object, not filesystem or networking.

Broker owns:

- object ID and generation;
- endpoint/reference lifetime;
- close semantics;
- readiness state;
- wait/wakeup state.

UserLiteBox owns:

- guest-visible handle number;
- typed facade;
- buffer marshalling;
- non-authoritative readiness cache.

Exit criteria:

- Create, duplicate, close, wait, and readiness work through BrokerCore.
- Stale handles and wrong-generation handles are rejected.
- Process disconnect cleans up broker-owned references.

## Phase 5: Broker-backed fd semantics

Move fd authority to BrokerCore while keeping guest fd numbers in UserLiteBox.

BrokerCore owns:

- object refs;
- rights;
- generations;
- refcounts;
- dup/pass/close;
- inherited object tables;
- process-exit cleanup.

UserLiteBox owns:

- guest fd number allocation;
- raw-int fd conversion;
- typed fd wrappers;
- local ABI metadata and cached hints.

Exit criteria:

- Double close, stale fd, dup, inherited refs, and process-exit cleanup are tested.
- UserLiteBox cannot create a live broker object by editing local fd state.

## Phase 6: Control/event/data transport

Add the durable-unicorn-style channel split.

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
- Guest-visible mapping operations enter shim/UserLiteBox and are emulated or broker-mediated.

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

UserLiteBox owns:

- path string conversion;
- buffer marshalling;
- guest fd view;
- data-channel wrappers.

Exit criteria:

- Filesystem operations are directory-relative.
- No host fd/HANDLE is exposed to UserLiteBox.
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

UserLiteBox owns:

- loader helpers;
- guest pointer handling;
- cached VMA view;
- local anonymous/private scratch allocation allowed by host profile.

Exit criteria:

- Broker-visible mappings require BrokerCore validation and PolicyEngine authorization.
- Executable memory cannot be created without rewrite/validation policy.
- Shared memory grants cannot be forged by UserLiteBox.

## Phase 10: Multiprocess

Implement one guest process as one sandboxed host process.

Broker owns:

- session identity;
- guest process identity;
- per-process channel set;
- process lifecycle;
- process-exit cleanup;
- inherited broker object table.

Shim/UserLiteBox owns:

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

UserLiteBox owns:

- socket syscall facade;
- send/recv marshalling;
- local readiness cache.

Exit criteria:

- L3/L4 firewall policy is enforced by PolicyEngine.
- UserLiteBox cannot send or receive guest-visible network traffic directly through host network devices.
- Data path uses broker-mediated operations or broker-owned rings.

## Phase 12: Kernel-broker deployment

Only after userland semantics are stable, implement broker-kernel deployment.

Split trusted deployment code into:

- BrokerHost: user-mode execution support and transport delivery;
- BrokerPlatform: privileged backend execution;
- BrokerCore/BrokerServices/PolicyEngine: shared authority logic.

Exit criteria:

- BrokerHost does not decode or authorize BrokerRequest.
- BrokerCore protocol and object semantics are reused.
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
- OP-TEE authority cannot be created in UserLiteBox.

## Suggested first milestone

The smallest useful milestone is:

```text
single process
userland broker
control channel only
default-deny PolicyEngine
broker-owned event/pipe object
UserLiteBox fd table maps guest fd -> broker object id
```

This proves the trust boundary before taking on filesystem, networking, mapping, or multiprocess complexity.

## Validation strategy

Add conformance tests at each layer:

- protocol parsing rejects malformed frames;
- policy default-denies unknown operations;
- caller identity is transport-bound;
- stale object IDs fail;
- wrong generation fails;
- process disconnect cleans up refs;
- UserLiteBox local handle edits cannot create authority;
- shared-memory cursor/frame corruption fails closed;
- broker failure forces session failure.

Prefer tests that run against both userland broker and later kernel-broker implementations.
