# LiteBox Broker Split Design

## Goal

Enable true multi-process and multi-session LiteBox support while preserving portability across userland and kernel-backed deployments.

This design is shim-agnostic. A shim can expose a POSIX-like ABI, an OP-TEE-compatible ABI, a Windows-like ABI, or another guest ABI. The broker split should not assume any one shim's syscall set, process model, or resource vocabulary.

The design separates LiteBox into:

```text
Always user mode:
  Shim + UserLiteBox
  optional shim-specific user clients

Host support for UserLiteBox:
  hosted userland: existing host OS/user ABI
  broker kernel: BrokerHost

Authority domain:
  BrokerCore + optional BrokerServices + PolicyEngine + BrokerPlatform
```

The authority domain differs by deployment:

| Deployment | Broker location | UserLiteBox host support |
|---|---|---|
| **Userland broker** | privileged broker process | existing host OS/user ABI |
| **Kernel broker** | kernel or equivalent trusted domain | `BrokerHost`, which can carry broker entry transport without decoding broker requests |

## Component model

```text
User mode:
  guest workload
    |
    v
  Shim
    |
    v
  UserLiteBox + optional shim-specific user clients
    -- via BrokerClient adapter over UserLiteBox transport -->
  broker authority interface

Hosted userland:
  UserLiteBox <-> host OS/user ABI

Broker-kernel deployment:
  UserLiteBox <-> BrokerHost

Authority domain:
  broker authority interface -> BrokerCore + optional BrokerServices
                                      |              |
                                      | consult      | execute after authorization
                                      v              v
                                PolicyEngine   BrokerPlatform
```

### Shim

Runs in user mode. Owns guest ABI mechanics for a particular shim: entry/trap handling, argument decoding, return-value conventions, exception delivery, frame construction, and guest-visible ABI details.

### UserLiteBox

Runs in user mode. It is the combined user-mode LiteBox component that replaces the earlier top-level split between user-core logic and user-platform mechanics.

UserLiteBox contains:

- user-facing core APIs used by shims;
- guest pointer and guest memory marshalling helpers;
- local caches and non-authoritative views of broker state;
- private synchronization and wait helpers;
- broker-owned control/event/data channel wrappers;
- a thin BrokerClient adapter;
- an internal user-platform layer that talks to host support.

UserLiteBox is **not trusted** for security. It executes in the same user-mode context as the guest and shim. It may request operations and cache derived state, but it must never create authority.

The old distinction between user core and user platform can remain as an internal implementation structure if it is useful for code organization. It is not a security boundary and does not need to be reflected as a top-level architectural component.

Because UserLiteBox always runs in user mode, it can use Rust `std` heavily in deployments that provide a normal user-mode runtime: allocation, collections, threads, TLS, synchronization, IPC clients, async runtimes, richer errors, and broker-channel abstractions.

### BrokerClient adapter

Thin in-process adapter used by UserLiteBox and shim-specific user clients to call the broker authority interface.

BrokerClient is not a separate trust boundary or authority component. It is bundled with the user-mode side and serializes typed calls into the explicit broker protocol over the transport supplied by UserLiteBox's host-support layer.

### BrokerHost

Kernel-side host support for UserLiteBox in broker-kernel deployments.

BrokerHost provides the user-mode execution substrate that UserLiteBox expects: trap/syscall/upcall entry, private synchronization primitives, anonymous local memory mechanics, thread/process setup mechanics, broker transport endpoints, and possibly a compatibility ABI subset.

BrokerHost is separate from BrokerCore, PolicyEngine, and BrokerPlatform. It is not the platform implementation used by BrokerCore; it is the host-side component that lets user-mode LiteBox processes run and reach the broker. It may be trusted kernel code, but it should not create LiteBox authority by itself. Security-relevant operations must still route through BrokerCore, optional BrokerServices, PolicyEngine, and BrokerPlatform.

BrokerHost may carry broker authority traffic as transport, but decoding, validation, and dispatch of `BrokerRequest` belong to the broker entry layer in BrokerCore, not BrokerHost.

In broker-kernel deployments, BrokerHost shares the trusted-domain TCB with BrokerCore, BrokerServices, PolicyEngine, and BrokerPlatform. The "no LiteBox authority" rule is a code-organization invariant enforced by review, not a sandboxing boundary; BrokerHost code is in the TCB and must be audited accordingly.

### BrokerCore

Required, shim-neutral trusted substrate. BrokerCore owns global and shared state: workload identity, process/session/thread identity, handle/resource capabilities, shared object lifetime, wait queues, namespace state, signal/event routing, shared synchronization, and readiness.

BrokerCore should not bake in every shim's ABI semantics. It provides the authority primitives that shims, broker services, and PolicyEngine build on. BrokerCore enforces structural invariants, such as capability validity and object lifetime, and supplies state/context to PolicyEngine for authorization.

### BrokerServices

Optional trusted extensions hosted inside the broker authority domain.

A BrokerService is useful when a shim or domain has security-relevant semantics that are too specific to belong in BrokerCore. Examples include OP-TEE TA/session authority, secure-storage semantics, POSIX process/signal semantics, filesystem semantics, socket semantics, or another guest ABI's domain-specific resource model.

BrokerServices should not reinvent authority. They should use BrokerCore capabilities, identities, memory grants, wait queues, lifecycle state, and accounting wherever possible. A BrokerService must not grant or exercise authority over a resource without going through BrokerCore's capability/lifecycle primitives and PolicyEngine authorization, even when its own protocol is shim-specific.

### PolicyEngine

Trusted policy decision and audit component inside the broker authority domain.

PolicyEngine is the broker's reference-monitor component. BrokerCore and BrokerServices gather context, validate structural invariants, and ask PolicyEngine to authorize authority-changing or host-effecting operations before BrokerCore mutates authoritative state, a BrokerService grants domain authority, or BrokerPlatform performs backend execution.

PolicyEngine should not own all broker state. It consumes facts from BrokerCore and BrokerServices, returns allow/deny decisions plus constraints, and emits audit records. Keeping policy decisions here prevents firewall, filesystem, device, storage, and domain-specific access checks from being hidden in BrokerPlatform or duplicated across BrokerServices.

### BrokerPlatform

Trusted backend for privileged operations: address-space control, host I/O, filesystem/device/network access, randomness/secrets, timers, scheduling hooks, host-side execution of PolicyEngine-authorized operations, and platform-specific primitives.

## Three interfaces

There are three logical interfaces. In a broker-kernel deployment, the UserLiteBox/host interface and the broker authority interface may use the same trap instruction or kernel entry path, but they must remain separate contracts with separate authority rules. When they share a path, BrokerHost should only classify and deliver traffic; BrokerRequest decoding, validation, dispatch, and authorization remain broker-authority responsibilities.

| Interface | Userland deployment | Kernel deployment | Purpose |
|---|---|---|---|
| **Shim <-> UserLiteBox** | same address space | same address space | ergonomic user-mode guest ABI implementation |
| **UserLiteBox <-> host support layer** | host OS/user ABI | BrokerHost ABI | local non-authoritative mechanics |
| **UserLiteBox / shim-specific user client <-> broker** | IPC | user/kernel boundary | trusted authority and shared state |

The interfaces have different stability and trust requirements:

| Interface | Shape | Authority |
|---|---|---|
| `Shim <-> UserLiteBox` | ergonomic in-process API | no authority; user-mode compatibility layer |
| `UserLiteBox <-> host support layer` | deployment-specific host ABI | local mechanics only; must not create LiteBox authority |
| `UserLiteBox / shim-specific user client <-> broker` | explicit broker protocol | authority boundary; broker validates every security-relevant operation |

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

External broker authority APIs:

| API | Shape |
|---|---|
| `UserLiteBox -> BrokerCore` | generic capability/resource protocol |
| `shim-specific user client -> BrokerService` | shim/domain-specific protocol |

Internal broker-authority APIs:

| API | Shape |
|---|---|
| `BrokerCore / BrokerService -> PolicyEngine` | in-domain authorization and audit |
| `BrokerService -> BrokerCore` | trusted in-domain API |
| `BrokerCore / BrokerService -> BrokerPlatform` | backend execution after PolicyEngine authorization |

The "shim-specific user client" is not a new authority layer. It is the user-mode, typed client-side half of an optional BrokerService.

## Broker protocol and channels

The broker protocol follows the stricter durable-unicorn shape: a custom, versioned, ABI-neutral object-operation protocol, not a host syscall proxy.

Each sandboxed process has exactly one authenticated broker association. That association may contain multiple logical traffic classes:

| Channel | Direction | Purpose |
|---|---|---|
| control | bidirectional | handshake, object operations, operation responses |
| event | broker to process | lifecycle, readiness, interrupt-like events, broker/session failure |
| data | bidirectional | bulk payload bytes associated with authorized object operations |

The broker creates or authorizes all channels and binds them to the host-authenticated peer identity of the guest process. UserLiteBox does not prove identity by filling in request fields.

The protocol exposes broker-owned objects through opaque, typed object identifiers. Shims may map those identifiers to guest-visible integers, but the broker remains authoritative for object type, lifetime, generation, rights, and policy. Object rights are broker-internal; UserLiteBox cannot amplify authority by editing request fields.

The protocol never passes host file descriptors, handles, sockets, directory handles, or other host-native resources to untrusted code in the baseline design. UserLiteBox receives only broker object identifiers, response data, event data, and broker-created channel endpoints whose authority is already bound by the broker.

Bulk I/O uses broker-owned data channels or broker-owned shared memory rings. The control channel authorizes an operation and binds it to an object and request identifier; the data channel carries bytes for that authorized operation. Shared memory is an optimization, not an authority transfer, and all shared-memory contents remain untrusted.

## Rust `std` and runtime strategy

The new split should not force one Rust runtime model everywhere.

| Component | Recommended baseline |
|---|---|
| `UserLiteBox` | `std`, because it always runs in user mode |
| userland broker | `std` |
| broker-kernel deployment | start with `no_std + alloc + BrokerHost/BrokerPlatform traits`; consider a custom `std` target only if the host grows rich enough |
| shared protocol/types | `no_std + alloc` where feasible, so they can cross user/kernel and userland/kernel-broker deployments |

Using `std` in UserLiteBox is a simplification, not a security decision. UserLiteBox is still untrusted. `std` merely makes the user-mode implementation easier: normal collections, `std::sync`, broker object wrappers, IPC clients, threads, and async/data-channel libraries can be used when the deployment supports them.

Strict host-syscall profiles constrain how much of `std` can be used after lockdown. Any `std` functionality that may issue disallowed host syscalls must either run only during bootstrap, be avoided in strict mode, or be implemented on top of the approved broker/host-support ABI.

For a broker kernel or trusted host, a custom Rust `std` target may eventually be useful if BrokerHost can provide enough primitives: allocator, blocking/scheduling, synchronization, time, I/O, panic policy, and TLS. It should not be the first requirement. A staged design is safer:

1. Define a small BrokerHost/BrokerPlatform trait surface.
2. Implement it for a `std` userland broker.
3. Implement it for LVBS/SNP/kernel-backed brokers with `no_std + alloc`.
4. Only introduce a custom `std` target if the trait surface naturally becomes "basically std."

## UserLiteBox and host calls

UserLiteBox may use local host/kernel calls, but only for local mechanics that do not create LiteBox authority.

| UserLiteBox operation | Allowed? | Requirement |
|---|---|---|
| private memory allocation, TLS, logging, local scratch mappings | yes | must not grant guest-visible authority |
| private locks/futex-like synchronization | yes | must not represent broker-owned shared state |
| broker transport notification | yes | broker validates every request |
| broker-owned shared-ring data movement | yes | ring ownership, cursor movement, and frames are validated by the broker |
| direct host file, network, or device access for guest-visible resources | no | must be mediated by broker-owned objects and PolicyEngine-authorized broker policy |
| guest-visible mappings or executable/shared memory | only through broker/UserLiteBox mediation | BrokerCore validates the object, PolicyEngine authorizes, and BrokerPlatform/BrokerHost applies |
| trusted randomness, secrets, or security-sensitive time | no | must come from broker authority |

If UserLiteBox uses a Linux-like syscall ABI, it only works in deployments that provide that ABI. In a broker-kernel deployment, the kernel must either expose the required ABI through BrokerHost or the runner must select a different UserLiteBox build/profile. The stable portability target is the shim/UserLiteBox/broker contract, not a single universal UserLiteBox binary.

### Host syscall profiles

The strict design still needs a small host-kernel interface for local mechanics, but the interface must be explicitly profiled and locked down.

| Phase/profile | Allowed host-kernel access |
|---|---|
| bootstrap | setup-only calls such as mapping broker-created shared memory, installing signal handlers, setting TLS, creating local scratch mappings, and preparing syscall-capture/trampoline state |
| fast local mode | a small allowlist for performance, such as futex waits/wakes on private locks or broker-ring cursors |
| strict mode | post-lockdown calls only; on Linux this can target `SECCOMP_MODE_STRICT`-like behavior where only `read`, `write`, `_exit`, and `sigreturn` remain available |

Direct guest `mmap`, `mprotect`, `munmap`, `mremap`, `memfd_create`, `open/openat`, `ioctl`, `fcntl`, and similar authority-bearing or mapping-changing calls must not reach the host unrestricted after lockdown. Guest-visible mapping operations must enter the shim/UserLiteBox path and then either be emulated from pre-reserved local memory or mediated by the broker.

If unrestricted `mmap`/`mprotect` remain available to the sandbox, broker mapping policy is bypassable. The design must either block those syscalls after bootstrap, constrain them to anonymous private local mechanics with a host-enforced profile, or route them through UserLiteBox/BrokerHost mediation.

### Linux userland bootstrap profile

The durable-unicorn Linux experiment provides a concrete hosted-userland profile:

- the broker creates one anonymous `memfd` per spawned runner;
- the `memfd` is inherited by the runner and identified by an environment/argument convention;
- the `memfd` contains shared metadata and broker-created rings;
- the broker binds the mapped ring set to the host-authenticated spawned runner identity;
- the runner maps the `memfd`, initializes UserLiteBox/shim state, installs sandbox restrictions, then enters guest code.

The initial Linux ring set can use five unidirectional rings:

| Ring | Direction | Purpose |
|---|---|---|
| control | broker to runner | broker responses, setup, control messages |
| control | runner to broker | broker requests and responses |
| event | broker to runner | asynchronous events and fail-closed notifications |
| data | broker to runner | bulk response/event payload bytes |
| data | runner to broker | bulk request payload bytes |

Broker-to-runner rings can be SPSC because there is one broker-side producer and one runner-side consumer. Runner-to-broker rings may need MPSC in fast local mode, where multiple host threads can produce directly. Strict mode may route all production through a UserLiteBox scheduler, but keeping the MPSC layout preserves one transport format.

Shared-memory rings are not trusted. The broker validates header magic/version, ring offsets/capacities, producer/consumer roles, cursor movement, frame bounds, and frame contents before acting. Impossible cursor movement, malformed frames, or writes inconsistent with ring ownership are protocol failures.

Linux can expose two protection modes:

| Mode | Shape |
|---|---|
| fast-futex mode | allows a small syscall allowlist, including futex wait/wake on ring cursors or private locks |
| strict-seccomp mode | installs mappings, fds, signal handlers, and trampoline state before lockdown; after lockdown, only a strict syscall set remains available |

In strict-seccomp mode, guest host-thread parallelism may need to become a shim/UserLiteBox scheduling illusion rather than real host threads. This is a compatibility/performance tradeoff, not a broker policy bypass.

## Deployment contract and negotiation

The user-side runner and global broker should match through a shared deployment contract, not ad hoc discovery.

Shared spec crates should define:

- the broker envelope and handle/memory-grant formats;
- broker transport authentication and peer identity binding;
- BrokerCore protocol versions;
- BrokerService IDs, protocol versions, request/response types, and feature requirements;
- PolicyEngine policy versions, policy profile IDs, and audit requirements;
- broker capability names and profiles;
- UserLiteBox/BrokerHost ABI names and versions;
- control/event/data channel formats;
- shared-memory/ring layout versions and validation rules;
- host syscall profiles for bootstrap, fast local mode, and strict mode;
- deployment profiles that bind a shim, UserLiteBox profile, broker transport, required services, and required broker features.

Startup should fail closed:

1. The runner selects a deployment profile, such as `optee-on-lvbs` or `optee-on-userland`.
2. The runner selects a UserLiteBox profile that matches the deployment's host ABI.
3. The user side establishes an authenticated broker transport. In userland, this can use OS IPC peer credentials; in broker-kernel deployments, this comes from the trusted entry path.
4. The broker binds the caller identity used in `BrokerRequest` to the authenticated peer. User mode does not choose its own authority identity.
5. The user side sends required BrokerCore, BrokerService, PolicyEngine policy profile, broker capability, UserLiteBox, BrokerHost, channel/ring, and host-syscall-profile versions.
6. The broker replies with supported services and capabilities.
7. The user side starts only if the required versions and features match.

UserLiteBox should not depend on BrokerPlatform internals. It should depend on the host ABI selected by the deployment profile and the negotiated broker contract: memory-grant format, trap/upcall mechanism, shared-page support, direct fast-path permissions, broker-mediated network/storage requirements, timer behavior, and similar features. Enforcement happens broker-side through PolicyEngine; user-mode code only adapts to supported capabilities.

## Security invariant

The core security rule is:

> User-mode Shim and UserLiteBox may request operations and cache derived state, but they must never create authority.

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

A compromised user-mode shim/UserLiteBox should not be able to escape the broker-granted authority.

All authority-changing or host-effecting operations must be authorized by PolicyEngine before BrokerCore state mutation, BrokerService authority grants, or BrokerPlatform backend execution. BrokerCore remains responsible for structural capability/lifecycle validity; BrokerServices provide domain-specific context; PolicyEngine makes the policy decision.

Any broker-side validation of data sourced from user-controlled memory, including shared rings, memory grants, and scatter/gather descriptors, must operate on a private snapshot or otherwise revalidate before use. UserLiteBox must be assumed hostile for the duration of an in-flight request.

## State ownership

| State | Owner |
|---|---|
| guest ABI decoding state | Shim |
| per-workload cache/view | UserLiteBox |
| shim-specific user client state | optional shim-specific user client |
| guest memory marshalling | UserLiteBox + broker revalidation |
| private user-mode mechanics | UserLiteBox via host support layer |
| private synchronization fast paths | UserLiteBox |
| shared synchronization | BrokerCore |
| guest-visible handle numbers | UserLiteBox view, BrokerCore authority |
| open/shared resource descriptions | BrokerCore |
| shim/domain-specific authoritative state | optional BrokerService backed by BrokerCore |
| policy decisions, constraints, and audit records | PolicyEngine |
| IPC/event/queue/socket-like resources | BrokerCore-owned resources |
| guest-visible/security-sensitive address-space mappings | BrokerCore + PolicyEngine + BrokerPlatform |
| user-only scratch mappings | UserLiteBox via host support layer |
| host-visible I/O | BrokerPlatform executes PolicyEngine-authorized policy |
| process/session/workload lifecycle | BrokerCore |

UserLiteBox-owned entries in this table are non-authoritative views, caches, or private fast paths. Broker-visible data and security-relevant state must still be revalidated by BrokerCore, BrokerServices, and PolicyEngine at the authority boundary.

## Process and session model

The stricter baseline uses one broker per sandbox session and one sandboxed host process per guest process.

| Concept | Owner |
|---|---|
| sandbox session | broker |
| guest process identity | BrokerCore |
| authenticated host process association | broker transport / BrokerHost or host OS |
| guest-visible process semantics | shim + UserLiteBox, backed by BrokerCore identity |
| process creation | broker-mediated |
| `exec`-like ABI behavior | shim/UserLiteBox within an existing broker association unless policy requires otherwise |

All guest processes in one sandbox session share one broker. The broker assigns guest process identity, creates or authorizes the private channel set for each process, and binds the channel set to the host-authenticated peer identity. A guest process cannot claim another process's identity by choosing request fields.

POSIX-like `fork` is broker-mediated at the identity/channel/resource level, while ABI-specific memory and descriptor inheritance semantics remain shim/UserLiteBox work. POSIX-like `exec` is preferably a shim/UserLiteBox replacement of guest memory and ABI state inside the existing sandboxed host process, so BrokerCore does not become ABI-specific.

## UserLiteBox vs BrokerCore in current `litebox`

The current `litebox` crate should not be split by whole module. Most modules mix ergonomic user-facing logic with authority-bearing state. The useful split is by responsibility.

| Current area | Keep in UserLiteBox | Move to BrokerCore / broker side |
|---|---|---|
| `LiteBox` object | user-mode facade, std-backed helpers, broker connection/session object | broker session/workload identity |
| `fd::Descriptors` | guest fd number table/cache, typed wrappers, syscall ergonomics | authoritative object IDs, generations, rights, dup/pass/close/refcounts |
| `fd::RawDescriptorStorage` | raw-int fd conversion for shim ABI | validation that a handle is live and authorized |
| fd metadata | local ABI metadata and cached hints | shared open-description metadata and metadata inherited/duplicated/passed across processes |
| `path.rs` | string/CStr conversion, cheap normalization helpers | authoritative path lookup, namespace traversal, permission checks |
| `fs::*` | user-facing file API stubs, buffer marshalling, broker data-channel wrappers | filesystem namespace, inode/node identity, cwd/root, permissions, open file descriptions |
| `pipes.rs` | typed pipe fd facade and read/write marshalling | pipe object, ring state, endpoint lifetime, readiness/wakeup |
| `event::wait` | per-thread wait context, blocking current thread, local timeout conversion | shared wait queues, readiness state, cross-process wake routing |
| `event::polling` | readiness cache and ergonomic polling facade | authoritative readiness generations for shared objects |
| `sync::futex` | private futex fast path | shared futex table keyed by shared memory object/address |
| `net::*` | socket API facade and send/recv buffer marshalling | socket objects, local ports, listen backlog, connection state, firewall-visible flow state |
| `mm::PageManager` | loader helpers, guest pointer handling, cached VMA view | authoritative mappings, permissions, memory grants, shared mappings, page-fault decisions |
| `tls.rs` | shim/user-local TLS | none |
| `utils::id_pool` and similar utilities | reusable helper where local-only | broker-owned ID allocation when IDs carry authority |
| current `platform` traits | internal UserLiteBox host-support layer where local-only | BrokerHost/BrokerPlatform traits where trusted-domain or backend effects are required |

Concrete examples:

- `fd::Descriptors` currently stores in-process descriptor entries with `Arc<RwLock<DescriptorEntry>>`. UserLiteBox can keep the ergonomic raw-fd and typed-fd presentation, but BrokerCore should own the live object, rights, generation, refcount, passing, duplication, close, and revoke semantics.
- `fs::in_mem`, `fs::layered`, and `fs::nine_p` currently store namespace-like state in-process. In a multiprocess design, namespace state and open file descriptions must be broker-side. UserLiteBox should only marshal paths/buffers and use broker-owned data channels or rings for payloads.
- `net::Network` currently owns smoltcp socket state, local port allocation, close queues, and platform packet I/O. If the broker enforces network/firewall policy, socket and port authority must be broker-side. UserLiteBox should keep the socket facade and use broker-owned rings for data movement.
- `mm::PageManager` currently owns VMA state and calls platform page-management operations. UserLiteBox can keep loader-side helpers and cached VMA views, but authoritative mapping permissions, shared mappings, and page-fault decisions belong broker-side.

## Control path and data path separation

The broker should be on the control path for authority, but it does not need to be on every byte of every data path.

```text
Control path:
  UserLiteBox -> BrokerCore/BrokerService -> PolicyEngine -> BrokerPlatform

Data path:
  UserLiteBox moves bytes through broker-owned data channels or rings
```

The broker still owns setup, rights, revocation model, object identity, and audit boundaries. Once it creates a constrained data channel or shared ring, UserLiteBox can move bytes without a control RPC per byte, but the broker still owns the object and validates frames/cursors before acting.

Good candidates:

| Surface | Local data path candidate | Broker-controlled setup |
|---|---|---|
| regular file read/write | broker data channel or broker-owned shared file cache | open/path resolution/permissions/flags |
| read-only file/executable pages | broker-approved mapping/static backing | file open + mapping permission |
| pipe/queue bulk bytes | shared memory ring per pipe endpoint | create pipe, endpoint rights, readiness/wakeup |
| local IPC/domain sockets | shared rings between endpoints | connect/bind/permission/routing |
| network sockets | broker-owned shared TX/RX rings when policy allows | socket/create/connect/bind/listen/firewall |
| 9P filesystem | shared-memory request/data rings | attach/walk/open/auth/policy |
| private futexes | entirely local for private memory | broker only for shared futexes |
| event/poll readiness | local cache for readiness bits | authoritative wait queue/wakeup generation |
| guest memory copy | local copy-in/copy-out | broker validates grants for broker-visible ops |

Rule:

> Data path may be local only through broker-owned channels or rings whose use cannot exceed the approved broker object rights.

If immediate revocation, full audit, or byte-level policy is required, the data path stays broker-mediated.

## No host-handle delegation in the baseline

The durable-unicorn experiment chose the stricter rule that the broker never passes host file descriptors, HANDLEs, sockets, directory handles, or similar host-native objects to untrusted code. This design adopts that rule as the baseline.

Host resources stay broker-owned:

```text
UserLiteBox asks broker: open(path, flags)
BrokerCore resolves object/capability
PolicyEngine authorizes path/flags/caller
BrokerPlatform opens host object and stores host handle privately
Broker returns broker object id, not host fd/HANDLE
UserLiteBox uses control/data channels for operations
```

This avoids moving enforcement into UserLiteBox or the runner, avoids cross-OS handle-rights mismatches, and makes revocation/audit simpler. The cost is higher broker involvement on data operations. Performance should first be recovered through broker-owned data rings, batching, and object-specific data channels rather than raw host-handle delegation.

Reintroducing host-handle delegation would require a separate future design note with object-specific proof obligations. It is not assumed by this architecture.

## Network and firewall enforcement

The design can support a network or application-level firewall, but only if the broker is the authoritative network path.

In that configuration, UserLiteBox must not send or receive guest-visible traffic directly through a platform network device. It may only operate on broker-granted network resources. BrokerCore owns the virtual socket/NIC/resource state, BrokerServices provide domain-specific context when needed, PolicyEngine authorizes policy, and BrokerPlatform executes approved backend operations.

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
- direct UserLiteBox fast paths for private state;
- batched broker calls where possible;
- shared-memory rings for bulk IPC, pipe, queue, and network data;
- broker-mediated setup with local data-plane access where security allows;
- cached PolicyEngine decisions when the cache key includes all security-relevant context and supports revocation;
- explicit invalidation/revocation for stale UserLiteBox caches.

The broker path is required for authority changes, cross-workload operations, shared resources, host-visible effects, and firewall-enforced traffic.

## Why this is better than moving all core into broker

Moving the whole core into broker would make the trusted boundary too large and too chatty. It would also force guest pointer handling, guest ABI compatibility policy, and shim-specific logic into the trusted domain.

This split keeps the trusted computing base smaller:

```text
User mode:
  compatibility, marshalling, caching, broker-owned local data channels

Authority domain:
  validation, capabilities, shared state, policy enforcement, optional domain authority, host effects
```

## Main risks

| Risk | Mitigation |
|---|---|
| UserLiteBox cache diverges from BrokerCore | generation-tagged handles, invalidation, broker authority checks |
| user shim bypasses policy | broker validates every security-relevant request and routes policy decisions through PolicyEngine |
| ABI becomes too chatty | batching, shared memory data planes, control/event/data channel split, local private fast paths |
| duplicated logic | keep policy in PolicyEngine, authority state in BrokerCore/BrokerServices, and ABI translation in UserLiteBox |
| handle/resource lifetime bugs | broker-owned object IDs, refcounts, cleanup on lifecycle transitions |
| broker bottleneck from no host-handle delegation | use broker-owned rings, batching, object-specific data channels, and policy caching |
| address-space lifecycle complexity | broker-authoritative mappings, shared object IDs, careful copy-on-write/shared-memory design |
| firewall datapath bottleneck | shared rings, batching, quotas, policy caching, and broker-side flow control |
| encrypted traffic hides application data | enforce metadata/connection policy unless using broker proxying or broker-managed keys/endpoints |
| BrokerServices become a second monolithic core | make them optional, small, versioned, and backed by BrokerCore primitives |
| UserLiteBox depends on unavailable host ABI | select UserLiteBox profile by deployment, or provide the needed ABI through BrokerHost |
| UserLiteBox depends on trusted-domain internals | expose negotiated broker/host capability profiles instead of implementation details |
| shared-memory TOCTOU or double-fetch bugs | validate broker requests against private snapshots or revalidate every use of user-controlled fields |
| unauthenticated broker transport | authenticate peers before negotiation and bind `caller_identity` to the authenticated transport endpoint |
| PolicyEngine becomes a second core | keep it decision/audit focused; authoritative object state remains in BrokerCore/BrokerServices |
| custom kernel `std` target becomes a distraction | start with `no_std + alloc + traits`; introduce custom `std` only if the host support surface justifies it |

## Prior-art positioning

LiteBox's proposed design combines ideas from several systems rather than copying any one of them.

| System | Relevant idea | LiteBox lesson |
|---|---|---|
| **Drawbridge** | application + LibOS in a picoprocess over a narrow Host ABI | keep UserLiteBox user-mode and keep the broker ABI narrow |
| **Haven** | Drawbridge-style LibOS inside shielded execution | a narrow host interface composes with stronger isolation domains, but LiteBox's broker is trusted TCB rather than untrusted host |
| **Graphene / Gramine** | LibOS plus PAL/host ABI, including SGX deployments | separate compatibility logic from host adaptation; avoid baking one host ABI into core |
| **gVisor** | userspace kernel plus brokered filesystem/gofer model | rich domains like filesystems and sockets need real broker services, not just generic RPC |
| **Chromium sandbox** | sandboxed target, broker/browser process, Mojo IPC, delegated handles | useful contrast: delegated handles can work, but LiteBox's stricter baseline keeps host handles broker-owned |
| **Capsicum** | capability mode, broker opens resources and passes restricted fds | useful contrast: capability fd passing is powerful, but requires OS support for precise rights |
| **Lind / Native Client** | POSIX LibOS inside a restricted sandbox with brokered host operations | UserLiteBox should not be a generic syscall escape hatch |
| **Arrakis / Exokernel** | OS as control plane, application gets direct data path after safe allocation | broker can be the control plane while UserLiteBox uses broker-owned rings/data channels for safe data paths |
| **seL4 / capability microkernels** | explicit unforgeable capabilities define authority | BrokerCore handles should carry object identity, rights, and generation checks |
| **Qubes OS** | compartmentalized workloads use service VMs for devices/network | isolate rich authority into broker services and policy, especially device/network access |
| **Nabla / Kata / unikernels** | reduce host syscall surface or use VM-backed isolation | narrow the authority interface; choose stronger isolation per deployment when needed |

The distinctive LiteBox claim is one architecture that supports both:

```text
userland broker process
kernel broker
```

while keeping:

```text
Shim + UserLiteBox
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
| TA-local syscall helpers, guest buffer marshalling, local loader helpers | UserLiteBox, with broker revalidation for broker-visible data |
| non-authoritative TA/session/object caches | UserLiteBox |
| authoritative TA/session registry, cross-TA/session state, OP-TEE persistent object semantics, PTA access-control context | OP-TEE BrokerService backed by BrokerCore |
| OP-TEE policy decisions and audit, including PTA and secure-storage authorization | PolicyEngine |
| generic identities, capabilities, memory grants, lifecycle, wait/notify, accounting | BrokerCore |
| trusted secrets, secure storage backend, normal-world shared-memory validation, address-space operations | BrokerPlatform after PolicyEngine authorization |

This likely means `litebox_shim_optee` should eventually become thinner: the OP-TEE ABI layer remains shim-specific and user-mode, while reusable UserLiteBox and broker-facing pieces move behind generic interfaces. The kernel/trusted deployment does not need the full OP-TEE shim; it needs only the OP-TEE-aware enforcement that creates authority.

### `litebox`

Today, `litebox` is an in-process no_std core library. Its current `LiteBox` object and subsystems assume Rust references, generic platform traits, in-process locks, and in-process descriptor/resource identity.

Future mapping:

| Current responsibility | Target component |
|---|---|
| ergonomic in-process helpers used by shims | UserLiteBox |
| guest-visible handle table view | UserLiteBox backed by BrokerCore |
| private sync, TLS, path conversion, guest marshalling | UserLiteBox |
| broker-owned data-channel wrappers | UserLiteBox |
| shared resource identity/lifetime | BrokerCore |
| synchronization/wait/readiness authority for shared objects | BrokerCore |
| final policy decision/audit | PolicyEngine |
| platform trait surface | internal UserLiteBox host-support layer, BrokerHost, and BrokerPlatform surfaces |
| shim/domain-specific authority | optional BrokerServices plus PolicyEngine decisions, not generic BrokerCore |

The important change is that the current core API should not become the cross-boundary ABI. UserLiteBox can keep ergonomic Rust APIs, but BrokerCore needs an explicit handle/capability protocol.

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
| user-mode shim/platform helpers | UserLiteBox internals, not the current crate wholesale |

In the new model, LVBS contributes both BrokerPlatform and BrokerHost pieces. BrokerPlatform owns privileged backend authority. BrokerHost exposes the host ABI that lets a user-mode UserLiteBox execute and reach the broker. The LVBS-targeted UserLiteBox selected by a deployment profile, such as `optee-on-lvbs`, should be smaller than the current LVBS crate.

### `litebox_runner_lvbs`

Today, this crate boots the trusted-domain environment, initializes the LVBS platform, dispatches VTL calls, handles OP-TEE messages, creates task page tables, manages sessions, and directly invokes the OP-TEE shim.

Future mapping:

| Current responsibility | Target component |
|---|---|
| early boot and trusted-domain initialization | broker bootstrap |
| VTL trap/transport dispatch | BrokerHost |
| broker request decode, validation, and dispatch | broker entry layer in BrokerCore |
| session/page-table orchestration | BrokerCore + OP-TEE BrokerService + PolicyEngine + BrokerPlatform |
| shim ABI state and non-authoritative per-task helpers | user-mode OP-TEE Shim + UserLiteBox |
| authoritative TA/session/object identity currently held by the runner | BrokerCore + OP-TEE BrokerService + PolicyEngine |
| user/broker compatibility checks | deployment profile negotiation |
| local user ABI support | BrokerHost |

The runner becomes less of an application runner and more of a broker bootstrap/entrypoint for the trusted deployment.

### OP-TEE-on-userland runner

The current OP-TEE userland runner sets a platform, builds `OpteeShim`, loads binaries, optionally rewrites syscall instructions, and runs the workload in one process.

Future mapping:

| Current responsibility | Target component |
|---|---|
| command-line harness and binary loading for tests | runner/test harness |
| `OpteeShim` construction | Shim + UserLiteBox process setup |
| user-mode local execution | UserLiteBox setup |
| broker/service compatibility | deployment profile negotiation |
| shared/security-authoritative state | separate privileged broker process |

This runner is a good prototype for the userland deployment shape, but it currently lacks a separate broker authority.

### `litebox_platform_multiplex`

Today, this crate chooses one monolithic platform type at compile time.

Future mapping:

| Current responsibility | Target component |
|---|---|
| selecting a single `Platform` | split into UserLiteBox profile selection, BrokerPlatform selection in the broker, and BrokerHost selection only for broker-kernel deployments |
| global platform accessor for shim-side code | UserLiteBox internal host-support accessor |
| trusted backend selection | BrokerPlatform accessor inside the broker |
| policy module/profile selection | PolicyEngine configuration inside the broker |

This split is needed because the current platform traits mix local execution mechanics with trusted authority.

### Other shims, platforms, and runners

The OP-TEE/LVBS sections above are worked examples, not an exhaustive crate-by-crate migration plan. Other existing crates follow the same destination split:

| Current component | Target shape |
|---|---|
| `litebox_shim_linux`, `litebox_shim_windows` | Shim plus UserLiteBox-facing ABI translation; any shared or policy-relevant process, descriptor, filesystem, network, or device authority moves to BrokerCore, optional BrokerServices, and PolicyEngine. |
| `litebox_platform_linux_userland`, `litebox_platform_windows_userland` | hosted UserLiteBox host-support implementations; native host calls are limited to local non-authoritative mechanics and broker transport/rings. |
| `litebox_platform_linux_kernel` | broker-kernel pieces split like LVBS: privileged backend operations become BrokerPlatform, while any user-mode support/trap transport becomes BrokerHost. |
| `litebox_runner_linux_userland`, `litebox_runner_windows_userland`, `litebox_runner_linux_on_windows_userland` | user-side runners that select UserLiteBox profile, create Shim/UserLiteBox, authenticate to the broker, and negotiate deployment profile compatibility. |
| `litebox_runner_snp` | trusted-deployment bootstrap analogous to LVBS; split external entry/transport support into BrokerHost, authority state into BrokerCore/BrokerServices/PolicyEngine, and backend privileged operations into BrokerPlatform. |

## Initial implementation direction

The first milestone should not attempt full multi-process support for every shim. Start with the smallest authority substrate:

1. Define the component split: `Shim`, `UserLiteBox`, optional shim-specific user clients, `BrokerCore`, optional `BrokerServices`, `PolicyEngine`, `BrokerPlatform`, and, in broker-kernel deployments, `BrokerHost`.
2. Define the BrokerClient adapter, shared broker envelope, handle format, memory-grant format, service IDs, protocol versions, transport authentication, policy profile/version format, control/event/data channel schema, shared-memory ring layout, UserLiteBox/BrokerHost ABI versions, and deployment profile format.
3. Decide the Rust runtime strategy: `std` for UserLiteBox and userland broker; `no_std + alloc + traits` for kernel broker first; custom kernel `std` target only if later justified.
4. Define host syscall profiles for bootstrap, fast local mode, and strict mode.
5. Define broker-owned identity for workloads, processes, sessions, and threads.
6. Define broker-owned capability/resource IDs with generation checks.
7. Make UserLiteBox handle tables broker-backed views.
8. Add startup negotiation between runner and broker, including required BrokerCore, BrokerService, PolicyEngine, broker capability, channel/ring, host syscall profile, UserLiteBox, and BrokerHost features.
9. Add a minimal PolicyEngine that can authorize/deny one simple broker-owned shared resource, such as an event object or pipe-like queue.
10. Add a broker wait/wakeup channel.
11. Prototype a broker-owned pipe or queue with shared-ring data path.
12. Prototype a broker-owned file object with mediated control/data-channel I/O, not host-handle delegation.
13. Prototype broker-owned network resources with PolicyEngine firewall policy and BrokerPlatform backend execution.
14. Add a small OP-TEE BrokerService only for authority that cannot be represented by generic BrokerCore primitives.
15. Expand to shared memory, lifecycle transitions, IPC, filesystem policy, network policy, and shim-specific resource models.

That gives a controlled path from current single-process/single-session assumptions toward true shared-state support without rewriting every shim and platform at once.
