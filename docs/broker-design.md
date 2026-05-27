# LiteBox Broker Split Design

## Goal

Enable true multi-process and multi-session LiteBox support while preserving portability across userland and kernel platforms.

This design is shim-agnostic. A shim can expose a POSIX-like ABI, an OP-TEE-compatible ABI, or another guest/runtime ABI. The broker split should not assume any one shim's syscall set, process model, or resource vocabulary.

The design separates LiteBox into:

```text
Always user mode:
  Shim + LocalCore + ShimPlatform
  optional shim-specific local clients

Authority domain:
  BrokerCore + optional BrokerServices + BrokerPlatform
```

The authority domain differs by deployment:

| Deployment | Broker location |
|---|---|
| **Userland platform** | privileged broker process |
| **Kernel platform** | kernel or equivalent trusted domain |

## Component model

```text
guest workload
  |
  v
Shim
  |
  v
LocalCore + optional shim-specific local clients
  |
  v
BrokerClient
  |
  v
BrokerCore + optional BrokerServices
  |
  v
BrokerPlatform
```

### Shim

Runs in user mode. Owns guest ABI mechanics for a particular shim: entry/trap handling, argument decoding, return-value conventions, exception delivery, frame construction, and guest-visible ABI details.

### LocalCore

Runs in user mode. Provides ergonomic support to the shim, local caching, fast-path helpers, guest memory marshalling, and per-workload views of state.

LocalCore is **not trusted** for security.

### ShimPlatform

Runs in user mode. Provides only local execution mechanics: guest pointer representation, local TLS, local trampoline/entry support, local synchronization, and other process-local helpers.

### BrokerClient

Boundary adapter from local user-mode components to the broker authority domain.

In userland, this is IPC. In kernel mode, this is a syscall/upcall-style ABI into the trusted domain.

### BrokerCore

Required, shim-neutral trusted substrate. BrokerCore owns global and shared state: workload identity, process/session/thread identity, handle/resource capabilities, shared object lifetime, wait queues, namespace state, signal/event routing, shared synchronization, readiness, and generic policy decisions.

BrokerCore should not bake in every shim's ABI semantics. It provides the authority primitives that shims and broker services build on.

### BrokerServices

Optional trusted extensions hosted inside the broker authority domain.

A BrokerService is useful when a shim or domain has security-relevant semantics that are too specific to belong in BrokerCore. Examples include OP-TEE TA/session authority, secure-storage semantics, PTA access control, or another guest ABI's domain-specific resource model.

BrokerServices should not reinvent authority. They should use BrokerCore capabilities, identities, memory grants, wait queues, lifecycle state, and accounting wherever possible.

### BrokerPlatform

Trusted backend for privileged operations: address-space control, host I/O, filesystem/device/network access, randomness/secrets, timers, scheduling hooks, firewall enforcement, and platform-specific primitives.

## Two interfaces

There are two conceptual interfaces and one physical crossing.

| Interface | Userland deployment | Kernel deployment | Purpose |
|---|---|---|---|
| **Shim <-> LocalCore** | same address space | same address space | ergonomic user-mode ABI implementation |
| **LocalCore / shim-specific local client <-> broker** | IPC | user/kernel boundary | trusted authority and shared state |

The broker crossing should use one shared envelope and dispatch to either BrokerCore or an optional BrokerService:

```text
BrokerRequest {
  caller_identity,
  target: BrokerCore | BrokerService(service_id),
  operation,
  handles,
  memory_grants,
  payload,
}
```

The crossing must be explicit, stable, handle-based, versioned, and switch-friendly. The user-mode interface can remain ergonomic because it always stays in user mode.

Logical API split:

| API | Shape |
|---|---|
| `Shim -> LocalCore` | ergonomic in-process API |
| `Shim -> shim-specific local client` | ergonomic typed client for optional BrokerService |
| `LocalCore -> BrokerCore` | generic capability/resource protocol |
| `shim-specific local client -> BrokerService` | shim/domain-specific protocol |
| `BrokerService -> BrokerCore` | trusted in-domain API |

The "shim-specific local client" is not a new authority layer. It is the local, typed client-side half of an optional BrokerService.

## Deployment contract and negotiation

The local runner and global broker should match through a shared deployment contract, not ad hoc discovery.

Shared spec crates should define:

- the broker envelope and handle/memory-grant formats;
- BrokerCore protocol versions;
- BrokerService IDs, protocol versions, request/response types, and feature requirements;
- BrokerPlatform feature names and capability profiles;
- deployment profiles that bind a shim, local platform, required services, and required broker features.

Startup should fail closed:

1. The runner selects a deployment profile, such as `optee-on-lvbs` or `optee-on-userland`.
2. The local side connects to the broker and sends required BrokerCore, BrokerService, and BrokerPlatform feature versions.
3. The broker replies with supported services and capabilities.
4. The local side starts only if the required versions and features match.

ShimPlatform should not depend on kernel internals. It should depend on a negotiated BrokerPlatform capability profile: memory-grant format, trap/upcall mechanism, shared-page support, direct fast-path permissions, broker-mediated network/storage requirements, timer behavior, and similar features. The broker owns enforcement; local code only adapts to supported capabilities.

## Security invariant

The core security rule is:

> User-mode Shim, LocalCore, and ShimPlatform may request operations and cache derived state, but they must never create authority.

Therefore BrokerCore, BrokerServices, and BrokerPlatform must be authoritative for:

- workload, process, session, thread, and namespace identity;
- handle/resource capabilities;
- handle passing, duplication, revocation, and cleanup;
- shared memory and mapping permissions;
- filesystem, network, device, and host I/O policy;
- signal, event, wait, readiness, and lifecycle state;
- randomness, secrets, and trusted time;
- quotas and revocation;
- network and application-level firewall policy;
- shim/domain-specific trusted semantics when a BrokerService is present.

A compromised user-mode shim/core should not be able to escape the broker-granted authority.

## State ownership

| State | Owner |
|---|---|
| guest ABI decoding state | Shim |
| per-workload cache/view | LocalCore |
| shim-specific local typed client state | optional local client |
| guest memory marshalling | LocalCore + broker revalidation |
| private synchronization fast paths | LocalCore |
| shared synchronization | BrokerCore |
| guest-visible handle numbers | LocalCore view, BrokerCore authority |
| open/shared resource descriptions | BrokerCore |
| shim/domain-specific authoritative state | optional BrokerService backed by BrokerCore |
| IPC/event/queue/socket-like resources | BrokerCore-owned resources |
| address-space mappings | BrokerCore/BrokerPlatform authority |
| host-visible I/O | BrokerPlatform |
| process/session/workload lifecycle | BrokerCore |

## Network and firewall enforcement

The design can support a network or application-level firewall, but only if the broker is the authoritative network path.

In that configuration, LocalCore and ShimPlatform must not send or receive traffic directly through a platform network device. They may only operate on broker-granted network resources. BrokerCore owns the virtual socket/NIC/resource state, applies policy, and then invokes BrokerPlatform to interact with the real network backend.

Possible datapath shapes:

| Shape | Security property | Performance tradeoff |
|---|---|---|
| broker-mediated control and data | simplest to reason about; every byte is broker-visible | highest IPC/switch overhead |
| broker-approved shared rings | broker still owns policy and drains/fills rings | lower overhead, more queue/accounting complexity |
| broker protocol proxy | enables application-level policy when broker sees plaintext/protocol metadata | protocol-specific and more complex |

Layer-specific implications:

- Packet and connection policy can be enforced by the broker from packet headers, connection metadata, endpoint capabilities, and resource labels.
- Application-level policy requires the broker to see application-level metadata or plaintext. If the guest workload performs end-to-end encryption entirely inside its own address space, the broker can still enforce connection-level policy, but it cannot inspect encrypted payloads unless the design explicitly uses a broker proxy, broker-managed protocol endpoint, or broker-controlled keys.
- Centralizing traffic in the broker creates a throughput and latency bottleneck. The design should plan for batching, shared-memory rings, flow control, per-resource quotas, and efficient policy caching.

## Performance model

The design should avoid "every operation is remote" while preserving security.

Use:

- local guest ABI decoding;
- local cache for non-authoritative handle/process/session views;
- direct user-mode fast paths for private state;
- batched broker calls where possible;
- shared-memory rings for bulk IPC and network data;
- broker-mediated setup with local data-plane access where security allows;
- explicit invalidation/revocation for stale LocalCore caches.

The broker path is required for authority changes, cross-workload operations, shared resources, host-visible effects, and firewall-enforced traffic.

## Why this is better than moving all core into broker

Moving the whole core into broker would make the trusted boundary too large and too chatty. It would also force guest pointer handling, guest ABI compatibility policy, and shim-specific logic into the trusted domain.

This split keeps the trusted computing base smaller:

```text
User mode:
  compatibility, marshalling, caching, fast paths

Authority domain:
  validation, capabilities, shared state, optional domain authority, host effects
```

## Main risks

| Risk | Mitigation |
|---|---|
| LocalCore cache diverges from BrokerCore | generation-tagged handles, invalidation, broker authority checks |
| user shim bypasses policy | broker validates every security-relevant request |
| ABI becomes too chatty | batching, shared memory data planes, local private fast paths |
| duplicated logic | keep policy/authority in BrokerCore; keep ABI translation in LocalCore |
| handle/resource lifetime bugs | broker-owned object IDs, refcounts, cleanup on lifecycle transitions |
| address-space lifecycle complexity | broker-authoritative mappings, shared object IDs, careful copy-on-write/shared-memory design |
| firewall datapath bottleneck | shared rings, batching, quotas, policy caching, and broker-side flow control |
| encrypted traffic hides application data | enforce metadata/connection policy unless using broker proxying or broker-managed keys/endpoints |
| BrokerServices become a second monolithic core | make them optional, small, versioned, and backed by BrokerCore primitives |
| local platform depends on trusted-domain internals | expose negotiated BrokerPlatform capability profiles instead of implementation details |

## Prior-art positioning

LiteBox's proposed design combines ideas from several systems:

- **Drawbridge / Graphene / Gramine**: user-mode library OS compatibility.
- **gVisor**: guest ABI mediation outside the host kernel fast path.
- **Exokernel / seL4-like systems**: small trusted authority boundary and explicit capabilities.
- **Userland broker systems**: privileged service owns shared state and host effects.

The distinctive LiteBox claim is one architecture that supports both:

```text
userland broker process
kernel broker
```

while keeping:

```text
Shim + LocalCore + ShimPlatform
```

always in user mode.

## Mapping current components

The current code does not match the final boundaries exactly. In particular, some current shims and platforms are linked together in the trusted domain for existing deployments. The mapping below describes the intended migration target.

### `litebox_shim_optee`

Today, this crate combines OP-TEE ABI handling, TA loading, per-TA state, page-manager use, syscall dispatch, and some session/object/crypto bookkeeping.

Future mapping:

| Current responsibility | Target component |
|---|---|
| OP-TEE entry/request decoding, return conventions, TA ABI details | Shim |
| TA-local syscall helpers, guest buffer marshalling, local loader helpers | LocalCore |
| non-authoritative TA/session/object caches | LocalCore |
| authoritative TA/session registry, cross-TA/session state, OP-TEE persistent object semantics, PTA access control | OP-TEE BrokerService backed by BrokerCore |
| generic identities, capabilities, memory grants, lifecycle, wait/notify, accounting | BrokerCore |
| trusted secrets, secure storage backend, normal-world shared-memory validation, address-space operations | BrokerPlatform |

This likely means `litebox_shim_optee` should eventually become thinner: the OP-TEE ABI layer remains shim-specific and user-mode, while reusable local-core and broker-facing pieces move behind generic interfaces. The kernel/trusted deployment does not need the full OP-TEE shim; it needs only the OP-TEE-aware enforcement that creates authority.

### `litebox`

Today, `litebox` is an in-process core library. Its current `LiteBox` object and subsystems assume Rust references, generic platform traits, in-process locks, and in-process descriptor/resource identity.

Future mapping:

| Current responsibility | Target component |
|---|---|
| ergonomic in-process helpers used by shims | LocalCore |
| guest-visible handle table view | LocalCore backed by BrokerCore |
| shared resource identity/lifetime | BrokerCore |
| synchronization/wait/readiness authority for shared objects | BrokerCore |
| platform trait surface | split into ShimPlatform and BrokerPlatform traits |
| shim/domain-specific authority | optional BrokerServices, not generic BrokerCore |

The important change is that the current core API should not become the cross-boundary ABI. LocalCore can keep ergonomic Rust APIs, but BrokerCore needs an explicit handle/capability protocol.

### `litebox_platform_lvbs`

Today, this crate is effectively a trusted-domain platform: it owns page tables, user-memory validation, VTL switching, syscall/exception entry, host calls, randomness/secrets hooks, and network backend hooks.

Future mapping:

| Current responsibility | Target component |
|---|---|
| page-table and address-space management | BrokerPlatform |
| VTL/trusted-domain entry and dispatch glue | BrokerPlatform / broker entry layer |
| normal-world memory mapping and validation | BrokerPlatform |
| host I/O, network backend hooks, root key/secrets | BrokerPlatform |
| user-mode shim local helpers | new/extracted ShimPlatform surface, not the current crate wholesale |

In the new model, LVBS is mostly the kernel/trusted-domain BrokerPlatform. The user-mode ShimPlatform for an OP-TEE workload should be a smaller local execution layer that learns available trusted-domain behavior through a negotiated capability profile, not by depending on LVBS internals.

### `litebox_runner_lvbs`

Today, this crate boots the trusted-domain runtime, initializes the LVBS platform, dispatches VTL calls, handles OP-TEE messages, creates task page tables, manages sessions, and directly invokes the OP-TEE shim.

Future mapping:

| Current responsibility | Target component |
|---|---|
| early boot and trusted-domain initialization | broker bootstrap |
| VTL call dispatch | broker external entry layer |
| session/page-table orchestration | BrokerCore + OP-TEE BrokerService + BrokerPlatform |
| direct long-lived ownership of shim objects | should move out of trusted domain or become broker-managed process/session objects |
| local/broker compatibility checks | deployment profile negotiation |

The runner becomes less of an application runner and more of a broker bootstrap/entrypoint for the trusted deployment.

### OP-TEE-on-userland runner

The current OP-TEE userland runner sets a platform, builds `OpteeShim`, loads binaries, optionally rewrites syscall instructions, and runs the workload in one process.

Future mapping:

| Current responsibility | Target component |
|---|---|
| command-line harness and binary loading for tests | runner/test harness |
| `OpteeShim` construction | Shim + LocalCore process setup |
| platform selection for local execution | ShimPlatform setup |
| broker/service compatibility | deployment profile negotiation |
| shared/security-authoritative state | separate privileged broker process |

This runner is a good prototype for the userland deployment shape, but it currently lacks a separate broker authority.

### `litebox_platform_multiplex`

Today, this crate chooses one monolithic platform type at compile time.

Future mapping:

| Current responsibility | Target component |
|---|---|
| selecting a single `Platform` | split into ShimPlatform selection and BrokerPlatform selection |
| global platform accessor for shim-side code | ShimPlatform accessor |
| trusted backend selection | BrokerPlatform accessor inside the broker |

This split is needed because the current platform traits mix local execution mechanics with trusted authority.

## Initial implementation direction

The first milestone should not attempt full multi-process support for every shim. Start with the smallest authority substrate:

1. Define the component split: `Shim`, `LocalCore`, `ShimPlatform`, `BrokerClient`, `BrokerCore`, optional `BrokerServices`, and `BrokerPlatform`.
2. Define the shared broker envelope, handle format, memory-grant format, service IDs, protocol versions, and deployment profile format.
3. Define broker-owned identity for workloads, processes, sessions, and threads.
4. Define broker-owned capability/resource IDs with generation checks.
5. Make LocalCore handle tables broker-backed views.
6. Add startup negotiation between runner and broker, including required BrokerCore, BrokerService, and BrokerPlatform features.
7. Add one simple broker-owned shared resource, such as an event object or pipe-like queue.
8. Add a broker wait/wakeup channel.
9. Prototype broker-owned network resources with firewall enforcement.
10. Add a small OP-TEE BrokerService only for authority that cannot be represented by generic BrokerCore primitives.
11. Expand to shared memory, lifecycle transitions, IPC, filesystem policy, network policy, and shim-specific resource models.

That gives a controlled path from current single-process/single-session assumptions toward true shared-state support without rewriting every shim and platform at once.
