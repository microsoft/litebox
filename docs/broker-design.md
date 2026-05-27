# LiteBox Broker Split Design

## Goal

Enable true multi-process and multi-session LiteBox support while preserving portability across userland and kernel platforms.

This design is shim-agnostic. A shim can expose a POSIX-like ABI, an OP-TEE-compatible ABI, or another guest ABI. The broker split should not assume any one shim's syscall set, process model, or resource vocabulary.

The design separates LiteBox into:

```text
Always user mode:
  Shim + UserCore + UserPlatform
  optional shim-specific user clients

UserPlatform support:
  hosted userland: existing host OS/user ABI
  broker kernel: BrokerHost

Authority domain:
  BrokerCore + optional BrokerServices + PolicyEngine + BrokerPlatform
```

The authority domain differs by deployment:

| Deployment | Broker location | UserPlatform support |
|---|---|---|
| **Userland platform** | privileged broker process | existing host OS/user ABI |
| **Kernel platform** | kernel or equivalent trusted domain | `BrokerHost`, which can carry broker entry transport without decoding broker requests |

## Component model

```text
User mode:
  guest workload
    |
    v
  Shim
    |
    v
  UserCore + optional shim-specific user clients
    -- via BrokerClient adapter over UserPlatform transport -->
  broker authority interface

  UserPlatform implements the traits required by UserCore and provides the transport used by the BrokerClient adapter.

Hosted userland:
  UserPlatform <-> host OS/user ABI

Broker-kernel deployment:
  UserPlatform <-> BrokerHost

Authority domain:
  broker authority interface -> BrokerCore + optional BrokerServices
                                      |              |
                                      | consult      | execute after authorization
                                      v              v
                                PolicyEngine   BrokerPlatform
```

### Shim

Runs in user mode. Owns guest ABI mechanics for a particular shim: entry/trap handling, argument decoding, return-value conventions, exception delivery, frame construction, and guest-visible ABI details.

### UserCore

Runs in user mode. Provides ergonomic support to the shim, local caching, fast-path helpers, guest memory marshalling, and per-workload views of state.

UserCore is **not trusted** for security.

### UserPlatform

Runs in user mode. Implements the platform traits required by UserCore. Provides deployment-specific local execution mechanics: guest pointer representation, local TLS, local trampoline/entry support, local synchronization, local memory allocation support, logging/debug plumbing, and the low-level transport used by `BrokerClient`.

UserPlatform is **not trusted** for security; it executes in the same user-mode context as the guest and UserCore.

UserPlatform is not intended to be universal. A hosted userland UserPlatform may use native host syscalls for private, non-authoritative mechanics. A broker-kernel deployment either must provide the user ABI that this UserPlatform expects or must select a different UserPlatform.

UserPlatform knows the local execution ABI and the broker transport/profile. It talks only to the host support layer, which is the host OS/user ABI in hosted userland or BrokerHost in broker-kernel deployments. It does **not** call BrokerCore, BrokerServices, or BrokerPlatform directly, and it does not interpret broker-authority payloads.

### BrokerClient adapter

Thin in-process adapter used by UserCore and shim-specific user clients to call the broker authority interface.

BrokerClient is not a separate trust boundary or authority component. It is bundled with the user-mode side and serializes typed calls into the explicit broker protocol over the transport supplied by UserPlatform.

### BrokerHost

Kernel-side host support for UserPlatform in broker-kernel deployments.

BrokerHost provides the user-mode execution substrate that UserPlatform expects: trap/syscall/upcall entry, private synchronization primitives, anonymous local memory mechanics, thread/process setup mechanics, broker transport endpoints, and possibly a compatibility ABI subset.

BrokerHost is separate from BrokerCore, PolicyEngine, and BrokerPlatform. It is not the platform implementation used by BrokerCore; it is the host-side component that lets user-mode LiteBox processes run and reach the broker. It may be trusted kernel code, but it should not create LiteBox authority by itself. Security-relevant operations must still route through BrokerCore, optional BrokerServices, PolicyEngine, and BrokerPlatform.

BrokerHost may carry broker authority traffic as transport, but decoding, validation, and dispatch of `BrokerRequest` belong to the broker entry layer in BrokerCore, not BrokerHost.

In broker-kernel deployments, BrokerHost shares the trusted-domain TCB with BrokerCore, BrokerServices, PolicyEngine, and BrokerPlatform. The "no LiteBox authority" rule is a code-organization invariant enforced by review, not a sandboxing boundary; BrokerHost code is in the TCB and must be audited accordingly.

### BrokerCore

Required, shim-neutral trusted substrate. BrokerCore owns global and shared state: workload identity, process/session/thread identity, handle/resource capabilities, shared object lifetime, wait queues, namespace state, signal/event routing, shared synchronization, and readiness.

BrokerCore should not bake in every shim's ABI semantics. It provides the authority primitives that shims, broker services, and PolicyEngine build on. BrokerCore enforces structural invariants, such as capability validity and object lifetime, and supplies state/context to PolicyEngine for authorization.

### BrokerServices

Optional trusted extensions hosted inside the broker authority domain.

A BrokerService is useful when a shim or domain has security-relevant semantics that are too specific to belong in BrokerCore. Examples include OP-TEE TA/session authority, secure-storage semantics, PTA access control, or another guest ABI's domain-specific resource model.

BrokerServices should not reinvent authority. They should use BrokerCore capabilities, identities, memory grants, wait queues, lifecycle state, and accounting wherever possible. A BrokerService must not grant or exercise authority over a resource without going through BrokerCore's capability/lifecycle primitives and PolicyEngine authorization, even when its own protocol is shim-specific.

### PolicyEngine

Trusted policy decision and audit component inside the broker authority domain.

PolicyEngine is the broker's reference-monitor component. BrokerCore and BrokerServices gather context, validate structural invariants, and ask PolicyEngine to authorize authority-changing or host-effecting operations before BrokerCore mutates authoritative state, a BrokerService grants domain authority, or BrokerPlatform performs backend execution.

PolicyEngine should not own all broker state. It consumes facts from BrokerCore and BrokerServices, returns allow/deny decisions plus constraints, and emits audit records. Keeping policy decisions here prevents firewall, filesystem, device, storage, and domain-specific access checks from being hidden in BrokerPlatform or duplicated across BrokerServices.

### BrokerPlatform

Trusted backend for privileged operations: address-space control, host I/O, filesystem/device/network access, randomness/secrets, timers, scheduling hooks, host-side execution of PolicyEngine-authorized operations, and platform-specific primitives.

## Three interfaces

There are three logical interfaces. In a broker-kernel deployment, the UserPlatform/host interface and the broker authority interface may use the same trap instruction or kernel entry path, but they must remain separate contracts with separate authority rules. When they share a path, BrokerHost should only classify and deliver traffic; BrokerRequest decoding, validation, dispatch, and authorization remain broker-authority responsibilities.

| Interface | Userland deployment | Kernel deployment | Purpose |
|---|---|---|---|
| **Shim <-> UserCore** | same address space | same address space | ergonomic user-mode ABI implementation |
| **UserPlatform <-> host support layer** | host OS/user ABI | BrokerHost ABI | local non-authoritative mechanics |
| **UserCore / shim-specific user client <-> broker** | IPC | user/kernel boundary | trusted authority and shared state |

The interfaces have different stability and trust requirements:

| Interface | Shape | Authority |
|---|---|---|
| `Shim <-> UserCore` | ergonomic in-process API | no authority; user-mode compatibility layer |
| `UserPlatform <-> host support layer` | deployment-specific host ABI | local mechanics only; must not create LiteBox authority |
| `UserCore / shim-specific user client <-> broker` | explicit broker protocol | authority boundary; broker validates every security-relevant operation |

The broker authority interface should use one shared envelope and dispatch to either BrokerCore or an optional BrokerService:

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

PolicyEngine is not a user-callable broker target. BrokerCore and BrokerServices call it inside the authority domain before granting authority, mutating protected state, or invoking BrokerPlatform for host-visible effects.

The negotiated policy profile is bound to the authenticated broker session or deployment profile, not chosen by each request. It only needs an explicit request field if a future design supports multiple simultaneous policy profiles on one authenticated transport.

The broker authority interface must be explicit, stable, handle-based, versioned, and switch-friendly. The UserPlatform/host-support interface is also versioned, but it is selected per deployment and only supports local mechanics. The Shim/UserCore interface can remain ergonomic because it always stays in user mode.

External broker authority APIs:

| API | Shape |
|---|---|
| `UserCore -> BrokerCore` | generic capability/resource protocol |
| `shim-specific user client -> BrokerService` | shim/domain-specific protocol |

Internal broker-authority APIs:

| API | Shape |
|---|---|
| `BrokerCore / BrokerService -> PolicyEngine` | in-domain authorization and audit |
| `BrokerService -> BrokerCore` | trusted in-domain API |
| `BrokerCore / BrokerService -> BrokerPlatform` | backend execution after PolicyEngine authorization |

The "shim-specific user client" is not a new authority layer. It is the user-mode, typed client-side half of an optional BrokerService.

## UserPlatform and host calls

UserPlatform may use local host/kernel calls, but only for local mechanics that do not create LiteBox authority.

| UserPlatform operation | Allowed? | Requirement |
|---|---|---|
| private memory allocation, TLS, logging, local scratch mappings | yes | must not grant guest-visible authority |
| private locks/futex-like synchronization | yes | must not represent broker-owned shared state |
| broker transport notification | yes | broker validates every request |
| direct host file, network, or device access for guest-visible resources | no, unless broker-granted | must be mediated by PolicyEngine-authorized broker policy |
| guest-visible mappings or executable/shared memory | only with broker grant | BrokerCore validates the object, PolicyEngine authorizes, and BrokerPlatform applies |
| trusted randomness, secrets, or security-sensitive time | no | must come from broker authority |

If a UserPlatform uses a Linux-like syscall ABI, it only works in deployments that provide that ABI. In a broker-kernel deployment, the kernel must either expose the required ABI through BrokerHost or the runner must select a different UserPlatform. The stable portability target is the shim/UserCore/broker contract, not a single universal UserPlatform binary.

## Deployment contract and negotiation

The user-side runner and global broker should match through a shared deployment contract, not ad hoc discovery.

Shared spec crates should define:

- the broker envelope and handle/memory-grant formats;
- broker transport authentication and peer identity binding;
- BrokerCore protocol versions;
- BrokerService IDs, protocol versions, request/response types, and feature requirements;
- PolicyEngine policy versions, policy profile IDs, and audit requirements;
- broker capability names and profiles;
- UserPlatform/BrokerHost ABI names and versions;
- deployment profiles that bind a shim, UserPlatform, broker transport, required services, and required broker features.

Startup should fail closed:

1. The runner selects a deployment profile, such as `optee-on-lvbs` or `optee-on-userland`.
2. The runner selects a UserPlatform that matches the deployment's host ABI.
3. The user side establishes an authenticated broker transport. In userland, this can use OS IPC peer credentials; in broker-kernel deployments, this comes from the trusted entry path.
4. The broker binds the caller identity used in `BrokerRequest` to the authenticated peer. User mode does not choose its own authority identity.
5. The user side sends required BrokerCore, BrokerService, PolicyEngine policy profile, broker capability, UserPlatform, and BrokerHost versions.
6. The broker replies with supported services and capabilities.
7. The user side starts only if the required versions and features match.

UserPlatform should not depend on BrokerPlatform internals. It should depend on the host ABI selected by the deployment profile and the negotiated broker contract: memory-grant format, trap/upcall mechanism, shared-page support, direct fast-path permissions, broker-mediated network/storage requirements, timer behavior, and similar features. Enforcement happens broker-side through PolicyEngine; user-mode code only adapts to supported capabilities.

## Security invariant

The core security rule is:

> User-mode Shim, UserCore, and UserPlatform may request operations and cache derived state, but they must never create authority.

Therefore BrokerCore, BrokerServices, PolicyEngine, and BrokerPlatform must be authoritative for:

- workload, process, session, thread, and namespace identity;
- handle/resource capabilities;
- handle passing, duplication, revocation, and cleanup;
- shared memory and mapping permissions;
- filesystem, network, device, and host I/O policy;
- signal, event, wait, readiness, and lifecycle state;
- randomness, secrets, and trusted time;
- timers and scheduling-visible state;
- quotas and revocation;
- network and application-level firewall policy;
- shim/domain-specific trusted semantics when a BrokerService is present.

A compromised user-mode shim/core should not be able to escape the broker-granted authority.

All authority-changing or host-effecting operations must be authorized by PolicyEngine before BrokerCore state mutation, BrokerService authority grants, or BrokerPlatform backend execution. BrokerCore remains responsible for structural capability/lifecycle validity; BrokerServices provide domain-specific context; PolicyEngine makes the policy decision.

Any broker-side validation of data sourced from user-controlled memory, including shared rings, memory grants, and scatter/gather descriptors, must operate on a private snapshot or otherwise revalidate before use. UserCore and UserPlatform must be assumed hostile for the duration of an in-flight request.

## State ownership

| State | Owner |
|---|---|
| guest ABI decoding state | Shim |
| per-workload cache/view | UserCore |
| shim-specific user client state | optional shim-specific user client |
| guest memory marshalling | UserCore + broker revalidation |
| private user-platform mechanics | UserPlatform via host support layer |
| private synchronization fast paths | UserCore |
| shared synchronization | BrokerCore |
| guest-visible handle numbers | UserCore view, BrokerCore authority |
| open/shared resource descriptions | BrokerCore |
| shim/domain-specific authoritative state | optional BrokerService backed by BrokerCore |
| policy decisions, constraints, and audit records | PolicyEngine |
| IPC/event/queue/socket-like resources | BrokerCore-owned resources |
| guest-visible/security-sensitive address-space mappings | BrokerCore + PolicyEngine + BrokerPlatform |
| user-platform-only scratch mappings | UserPlatform via host support layer |
| host-visible I/O | BrokerPlatform executes PolicyEngine-authorized policy |
| process/session/workload lifecycle | BrokerCore |

UserCore-owned entries in this table are non-authoritative views, caches, or private fast paths. Broker-visible data and security-relevant state must still be revalidated by BrokerCore, BrokerServices, and PolicyEngine at the authority boundary.

## Network and firewall enforcement

The design can support a network or application-level firewall, but only if the broker is the authoritative network path.

In that configuration, UserCore and UserPlatform must not send or receive guest-visible traffic directly through a platform network device. They may only operate on broker-granted network resources. BrokerCore owns the virtual socket/NIC/resource state, BrokerServices provide domain-specific context when needed, PolicyEngine authorizes policy, and BrokerPlatform executes approved backend operations.

Possible datapath shapes:

| Shape | Security property | Performance tradeoff |
|---|---|---|
| broker-mediated control and data | simplest to reason about; every byte is broker-visible | highest IPC/switch overhead |
| broker-approved shared rings | broker still owns state and PolicyEngine authorizes policy | lower overhead, more queue/accounting complexity |
| broker protocol proxy | enables application-level policy when broker sees plaintext/protocol metadata | protocol-specific and more complex |

Layer-specific implications:

- Packet and connection policy can be authorized by PolicyEngine from packet headers, connection metadata, endpoint capabilities, and resource labels supplied by BrokerCore/BrokerServices.
- Application-level policy requires PolicyEngine or a broker-side policy helper to see application-level metadata or plaintext. If the guest workload performs end-to-end encryption entirely inside its own address space, the broker can still enforce connection-level policy, but it cannot inspect encrypted payloads unless the design explicitly uses a broker proxy, broker-managed protocol endpoint, or broker-controlled keys.
- Centralizing traffic in the broker creates a throughput and latency bottleneck. The design should plan for batching, shared-memory rings, flow control, per-resource quotas, and efficient policy caching.
- Broker-side policy decisions must be made on stable data. If packet descriptors or payload metadata arrive through shared memory, the broker must snapshot or revalidate them before enforcement.

## Performance model

The design should avoid "every operation is remote" while preserving security.

Use:

- local guest ABI decoding;
- local cache for non-authoritative handle/process/session views;
- direct UserPlatform fast paths for private state;
- batched broker calls where possible;
- shared-memory rings for bulk IPC and network data;
- broker-mediated setup with local data-plane access where security allows;
- cached PolicyEngine decisions when the cache key includes all security-relevant context and supports revocation;
- explicit invalidation/revocation for stale UserCore caches.

The broker path is required for authority changes, cross-workload operations, shared resources, host-visible effects, and firewall-enforced traffic.

## Why this is better than moving all core into broker

Moving the whole core into broker would make the trusted boundary too large and too chatty. It would also force guest pointer handling, guest ABI compatibility policy, and shim-specific logic into the trusted domain.

This split keeps the trusted computing base smaller:

```text
User mode:
  compatibility, marshalling, caching, fast paths

Authority domain:
  validation, capabilities, shared state, policy enforcement, optional domain authority, host effects
```

## Main risks

| Risk | Mitigation |
|---|---|
| UserCore cache diverges from BrokerCore | generation-tagged handles, invalidation, broker authority checks |
| user shim bypasses policy | broker validates every security-relevant request and routes policy decisions through PolicyEngine |
| ABI becomes too chatty | batching, shared memory data planes, local private fast paths |
| duplicated logic | keep policy in PolicyEngine, authority state in BrokerCore/BrokerServices, and ABI translation in UserCore |
| handle/resource lifetime bugs | broker-owned object IDs, refcounts, cleanup on lifecycle transitions |
| address-space lifecycle complexity | broker-authoritative mappings, shared object IDs, careful copy-on-write/shared-memory design |
| firewall datapath bottleneck | shared rings, batching, quotas, policy caching, and broker-side flow control |
| encrypted traffic hides application data | enforce metadata/connection policy unless using broker proxying or broker-managed keys/endpoints |
| BrokerServices become a second monolithic core | make them optional, small, versioned, and backed by BrokerCore primitives |
| UserPlatform depends on unavailable host ABI | select UserPlatform by deployment profile, or provide the needed ABI through BrokerHost |
| UserPlatform depends on trusted-domain internals | expose negotiated broker/host capability profiles instead of implementation details |
| shared-memory TOCTOU or double-fetch bugs | validate broker requests against private snapshots or revalidate every use of user-controlled fields |
| unauthenticated broker transport | authenticate peers before negotiation and bind `caller_identity` to the authenticated transport endpoint |
| PolicyEngine becomes a second core | keep it decision/audit focused; authoritative object state remains in BrokerCore/BrokerServices |

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
Shim + UserCore + UserPlatform
```

always in user mode.

## Mapping current components

The current code does not match the final boundaries exactly. In particular, some current shims and platforms are linked together in the trusted domain for existing deployments. The mapping below describes the intended migration target.

Where a current crate spans both user-mode and authority responsibilities, the mapping below describes the destination split, not a one-to-one rename.

### `litebox_shim_optee`

Today, this crate combines OP-TEE ABI handling, TA loading, per-TA state, page-manager use, syscall dispatch, and some session/object/crypto bookkeeping.

Future mapping:

| Current responsibility | Target component |
|---|---|
| OP-TEE entry/request decoding, return conventions, TA ABI details | Shim |
| TA-local syscall helpers, guest buffer marshalling, local loader helpers | UserCore, with broker revalidation for broker-visible data |
| non-authoritative TA/session/object caches | UserCore |
| authoritative TA/session registry, cross-TA/session state, OP-TEE persistent object semantics, PTA access-control context | OP-TEE BrokerService backed by BrokerCore |
| OP-TEE policy decisions and audit, including PTA and secure-storage authorization | PolicyEngine |
| generic identities, capabilities, memory grants, lifecycle, wait/notify, accounting | BrokerCore |
| trusted secrets, secure storage backend, normal-world shared-memory validation, address-space operations | BrokerPlatform after PolicyEngine authorization |

This likely means `litebox_shim_optee` should eventually become thinner: the OP-TEE ABI layer remains shim-specific and user-mode, while reusable UserCore and broker-facing pieces move behind generic interfaces. The kernel/trusted deployment does not need the full OP-TEE shim; it needs only the OP-TEE-aware enforcement that creates authority.

### `litebox`

Today, `litebox` is an in-process core library. Its current `LiteBox` object and subsystems assume Rust references, generic platform traits, in-process locks, and in-process descriptor/resource identity.

Future mapping:

| Current responsibility | Target component |
|---|---|
| ergonomic in-process helpers used by shims | UserCore |
| guest-visible handle table view | UserCore backed by BrokerCore |
| shared resource identity/lifetime | BrokerCore |
| synchronization/wait/readiness authority for shared objects | BrokerCore |
| platform trait surface | split into UserPlatform, BrokerHost, and BrokerPlatform surfaces |
| shim/domain-specific authority | optional BrokerServices plus PolicyEngine decisions, not generic BrokerCore |

The important change is that the current core API should not become the cross-boundary ABI. UserCore can keep ergonomic Rust APIs, but BrokerCore needs an explicit handle/capability protocol.

### `litebox_platform_lvbs`

Today, this crate is effectively a trusted-domain platform: it owns page tables, user-memory validation, VTL switching, syscall/exception entry, host calls, randomness/secrets hooks, and network backend hooks.

Future mapping:

| Current responsibility | Target component |
|---|---|
| page-table and address-space management | BrokerPlatform |
| VTL/trusted-domain trap and transport mechanism | BrokerHost |
| broker request decode, validation, and dispatch | broker entry layer in BrokerCore |
| normal-world memory mapping and validation | BrokerPlatform |
| host I/O, network backend hooks, root key/secrets | BrokerPlatform executing PolicyEngine-authorized operations |
| user-mode shim platform helpers | new/extracted UserPlatform surface, not the current crate wholesale |

In the new model, LVBS contributes both BrokerPlatform and BrokerHost pieces. BrokerPlatform owns privileged backend authority. BrokerHost exposes the host ABI that lets a user-mode UserPlatform execute and reach the broker. The LVBS-targeted UserPlatform selected by a deployment profile, such as `optee-on-lvbs`, should be a smaller platform layer than the current LVBS crate.

### `litebox_runner_lvbs`

Today, this crate boots the trusted-domain environment, initializes the LVBS platform, dispatches VTL calls, handles OP-TEE messages, creates task page tables, manages sessions, and directly invokes the OP-TEE shim.

Future mapping:

| Current responsibility | Target component |
|---|---|
| early boot and trusted-domain initialization | broker bootstrap |
| VTL trap/transport dispatch | BrokerHost |
| broker request decode, validation, and dispatch | broker entry layer in BrokerCore |
| session/page-table orchestration | BrokerCore + OP-TEE BrokerService + PolicyEngine + BrokerPlatform |
| shim ABI state and non-authoritative per-task helpers | user-mode OP-TEE Shim + UserCore |
| authoritative TA/session/object identity currently held by the runner | BrokerCore + OP-TEE BrokerService + PolicyEngine |
| local/broker compatibility checks | deployment profile negotiation |
| local user ABI support | BrokerHost |

The runner becomes less of an application runner and more of a broker bootstrap/entrypoint for the trusted deployment.

### OP-TEE-on-userland runner

The current OP-TEE userland runner sets a platform, builds `OpteeShim`, loads binaries, optionally rewrites syscall instructions, and runs the workload in one process.

Future mapping:

| Current responsibility | Target component |
|---|---|
| command-line harness and binary loading for tests | runner/test harness |
| `OpteeShim` construction | Shim + UserCore process setup |
| platform selection for local execution | UserPlatform setup |
| broker/service compatibility | deployment profile negotiation |
| shared/security-authoritative state | separate privileged broker process |

This runner is a good prototype for the userland deployment shape, but it currently lacks a separate broker authority.

### `litebox_platform_multiplex`

Today, this crate chooses one monolithic platform type at compile time.

Future mapping:

| Current responsibility | Target component |
|---|---|
| selecting a single `Platform` | split into UserPlatform selection always, BrokerPlatform selection in the broker, and BrokerHost selection only for broker-kernel deployments |
| global platform accessor for shim-side code | UserPlatform accessor |
| trusted backend selection | BrokerPlatform accessor inside the broker |
| policy module/profile selection | PolicyEngine configuration inside the broker |

This split is needed because the current platform traits mix local execution mechanics with trusted authority.

### Other shims, platforms, and runners

The OP-TEE/LVBS sections above are worked examples, not an exhaustive crate-by-crate migration plan. Other existing crates follow the same destination split:

| Current component | Target shape |
|---|---|
| `litebox_shim_linux`, `litebox_shim_windows` | Shim plus UserCore-facing ABI translation; any shared or policy-relevant process, descriptor, filesystem, network, or device authority moves to BrokerCore, optional BrokerServices, and PolicyEngine. |
| `litebox_platform_linux_userland`, `litebox_platform_windows_userland` | hosted UserPlatform implementations; native host calls are limited to local non-authoritative mechanics and broker transport. |
| `litebox_platform_linux_kernel` | broker-kernel pieces split like LVBS: privileged backend operations become BrokerPlatform, while any user-mode support/trap transport becomes BrokerHost. |
| `litebox_runner_linux_userland`, `litebox_runner_windows_userland`, `litebox_runner_linux_on_windows_userland` | user-side runners that select UserPlatform, create Shim/UserCore, authenticate to the broker, and negotiate deployment profile compatibility. |
| `litebox_runner_snp` | trusted-deployment bootstrap analogous to LVBS; split external entry/transport support into BrokerHost, authority state into BrokerCore/BrokerServices/PolicyEngine, and backend privileged operations into BrokerPlatform. |

## Initial implementation direction

The first milestone should not attempt full multi-process support for every shim. Start with the smallest authority substrate:

1. Define the component split: `Shim`, `UserCore`, `UserPlatform`, optional shim-specific user clients, `BrokerCore`, optional `BrokerServices`, `PolicyEngine`, `BrokerPlatform`, and, in broker-kernel deployments, `BrokerHost`.
2. Define the BrokerClient adapter, shared broker envelope, handle format, memory-grant format, service IDs, protocol versions, transport authentication, policy profile/version format, UserPlatform/BrokerHost ABI versions, and deployment profile format.
3. Define broker-owned identity for workloads, processes, sessions, and threads.
4. Define broker-owned capability/resource IDs with generation checks.
5. Make UserCore handle tables broker-backed views.
6. Add startup negotiation between runner and broker, including required BrokerCore, BrokerService, PolicyEngine, broker capability, UserPlatform, and BrokerHost features.
7. Add a minimal PolicyEngine that can authorize/deny one simple broker-owned shared resource, such as an event object or pipe-like queue.
8. Add a broker wait/wakeup channel.
9. Prototype broker-owned network resources with PolicyEngine firewall policy and BrokerPlatform backend execution.
10. Add a small OP-TEE BrokerService only for authority that cannot be represented by generic BrokerCore primitives.
11. Expand to shared memory, lifecycle transitions, IPC, filesystem policy, network policy, and shim-specific resource models.

That gives a controlled path from current single-process/single-session assumptions toward true shared-state support without rewriting every shim and platform at once.
