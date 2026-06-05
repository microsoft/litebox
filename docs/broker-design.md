# LiteBox Broker Architecture Design

## Goal

Enable true multi-process and multi-session LiteBox support while preserving portability across userland and kernel-backed deployments.

This design is shim-agnostic. A shim can expose a POSIX-like ABI, an OP-TEE-compatible ABI, a Windows-like ABI, or another guest ABI. The broker architecture should not assume any one shim's syscall set, process model, or resource vocabulary.

The design has two trust domains:

```text
User mode:
  Shim + local core
  optional BrokerService clients

Authority domain:
  broker entry/host + litebox_broker_host + BrokerCore + optional BrokerServices + PolicyEngine + BrokerPlatform
  broker-kernel user-mode support, in kernel-backed deployments
```

The local core reaches local mechanics and broker channels through deployment support selected by the deployment profile:

| Deployment | Broker location | Deployment support used by local core |
|---|---|---|
| **Userland broker** | privileged broker process | host OS user-mode ABI plus a broker transport endpoint |
| **Kernel broker** | kernel or equivalent trusted domain | broker-kernel user-mode support plus broker-channel delivery without decoding broker requests |

## Component model

```text
User mode:
  guest workload
    |
    v
  Shim
    |
    v
  local core + optional BrokerService clients
    -- via litebox_broker_local over the selected broker channel -->
  broker authority interface

Authority domain:
  broker-kernel user-mode support (kernel-backed deployments)
    -- carries/classifies channel traffic -->
  broker authority interface -> litebox_broker_host
                                 |
                                  v
                                BrokerCore + optional BrokerServices
                                      |              |
                                      | consult      | execute after authorization
                                      v              v
                                PolicyEngine   BrokerPlatform
```

Deployment support supplies two things to user mode: local mechanics that do not create LiteBox authority, and a broker channel. In hosted userland, those are the host OS user-mode ABI plus a broker transport endpoint. In a broker-kernel deployment, they are calls into broker-kernel user-mode support plus broker-channel delivery.

### Shim

Runs in user mode. Owns guest ABI mechanics for a particular shim: entry/trap handling, argument decoding, return-value conventions, exception delivery, frame construction, and guest-visible ABI details.

### Local core

Runs in user mode. It is the LiteBox runtime below the shim: the component that presents local APIs to shims, manages non-authoritative local state, and turns broker-backed resources into local objects.

The local core contains:

- user-facing core APIs used by shims;
- guest pointer and guest memory marshalling helpers;
- local caches and non-authoritative views of broker state;
- private synchronization and wait helpers;
- broker-owned control/notification/data channel wrappers;
- the `litebox_broker_local` adapter;
- internal deployment-support calls for local mechanics.

The local core is **not trusted** for security. It executes in the same user-mode context as the guest and shim. It may request operations and cache derived state, but it must never create authority.

The old distinction between user core and user platform can remain as an internal implementation structure if it is useful for code organization. It is not a security boundary and does not need to be reflected as a top-level architectural component.

The local core should keep its contracts portable instead of assuming `std` everywhere. Hosted adapters may use `std` for threads, synchronization, IPC clients, async runtimes, richer errors, and broker-channel plumbing when the selected deployment permits those facilities.

### Broker-local adapter

Thin in-process adapter used by local-core code to call the broker authority interface.

This adapter is not a separate trust boundary or authority component. It is bundled with the user-mode side and serializes typed calls into the explicit broker protocol over the selected broker channel.

### Broker-kernel user-mode support

Future kernel-side support for running the user-mode local core in broker-kernel deployments.

This code runs in the kernel or equivalent trusted domain. It is part of the broker-kernel deployment, not part of the local core. It provides the execution support that the user-mode local core expects: trap/syscall/upcall entry, private synchronization primitives, anonymous local memory mechanics, thread/process setup mechanics, broker channel endpoints, and any compatibility ABI that the selected local-core profile requires.

Broker-kernel user-mode support is separate from BrokerCore, PolicyEngine, and BrokerPlatform. It is not the platform implementation used by BrokerCore; it is trusted-domain support that lets user-mode LiteBox processes run and reach the broker. It should not create LiteBox authority by itself. Security-relevant operations must still route through BrokerCore, optional BrokerServices, PolicyEngine, and BrokerPlatform.

Broker-kernel user-mode support may carry broker authority traffic, but decoding, validation, and dispatch of `BrokerRequest` belong to `litebox_broker_host`, not this support code or BrokerCore.

In broker-kernel deployments, this support code shares the trusted-domain TCB with BrokerCore, BrokerServices, PolicyEngine, and BrokerPlatform. The "no LiteBox authority" rule is a code-organization invariant enforced by review, not a sandboxing boundary; this code is in the TCB and must be audited accordingly.

### BrokerCore

Required, shim-neutral trusted core. BrokerCore owns global and shared state: workload identity, process/session/thread identity, handle/resource capabilities, shared object lifetime, wait queues, namespace state, signal/event routing, shared synchronization, and readiness.

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

## Crate layout and naming

The broker architecture should use crate names that make the authority boundary visible. Start with standalone crates rather than moving the existing `litebox` crate wholesale into the broker.

| Crate | Initial role |
|---|---|
| `litebox_broker_protocol` | Shared `no_std + alloc` protocol crate for broker-visible DTOs, transport-neutral control-channel contracts, and the current reusable byte codec under `litebox_broker_protocol::wire`: protocol version type and initial version constant, opaque event reference handles, event request/response messages, readiness/wait outcomes, ABI-neutral errors, known/unknown receive wrappers, peer credentials, local/host control-channel traits, and request/response message-body encoding. |
| `litebox_broker_core` | Protocol- and channel-independent authority logic: the single broker core constructed for the broker process/kernel lifetime, broker-owned caller associations, object/reference registry, object type and rights authority, reference generations, policy hooks, wait/readiness state, association cleanup, and the first broker-owned event object. It exposes direct domain methods and domain types; it does not decode broker protocol requests or know concrete IPC. |
| `litebox_broker_host` | Shared `no_std` broker-side protocol/core adapter for hosted and kernel broker deployments: free receive/send loop over a caller-owned `BrokerCore` and generic host control channel. It owns protocol negotiation, request sequencing, unknown-tag handling, protocol/core type conversion, peer-credential-to-caller-credential mapping, and typed broker-close reasons. |
| `litebox_broker_transport` | Hosted concrete broker transport implementations. The current implementation is a Unix-domain-socket control channel under `unix_socket`. The crate owns stream framing and channel trait adaptation; it does not assemble a broker deployment or depend on broker core/host crates. |
| `litebox_broker_userland` | Hosted `std` broker executable. This deployment crate wires `BrokerCore`, the current policy, the generic broker host loop, and the Unix-socket transport together. |
| `litebox_broker_local` | `no_std` channel-neutral local-side adapter linked into local-core deployments and runners: negotiate broker protocol, track local negotiation state, sequence request/response pairs, map broker errors, and expose typed broker calls. |
| `litebox` | Local core crate: guest fd table view, syscall/resource routing, local-private mechanics, broker-backed object wrappers, and compatibility-profile glue. |

`litebox_broker_local` should stay narrow. It is not the syscall classifier and does not implement non-delegable syscall handling. Shim dispatch and the local core decide whether an operation is local-private, broker-delegated, or host-arbitrated; the local adapter only carries broker-delegated operations over the selected control channel.

Channel delivery must remain replaceable. `litebox_broker_protocol` and `litebox_broker_core` must not depend on Unix-domain sockets, shared-memory rings, traps, hypercalls, or any specific IPC implementation. BrokerCore may reuse shared value DTOs from `litebox_broker_protocol`, but it must not depend on protocol envelopes, channel traits, wire codecs, or concrete IPC. The broker host adapts protocol and channel concepts into direct BrokerCore domain calls. Shared control-channel traits live in `litebox_broker_protocol::channel`; concrete IPC implementations, such as `litebox_broker_transport` or a later shared-memory ring crate, live outside the broker deployment crate without changing broker object semantics.

The current control-channel contract is deliberately serial: one broker authority request is in flight on a connection, and the next request waits for the matching response. A future shared-memory ring or multiplexed transport can either keep that semantic contract behind a blocking adapter, or introduce protocol correlation IDs in a later extension if concurrent in-flight control operations become necessary.

Shared broker DTOs and the current wire codec live in `litebox_broker_protocol` to avoid repeating request/response, handle/readiness, and message-body encoding shapes across protocol, core, local, transport, and host code. BrokerCore still keeps authority-domain internals private: object IDs, reference storage, rights, policy decisions, and associations remain core-only, while `litebox_broker_host` is the sanctioned mapping boundary for protocol envelopes and channel outcomes.

Control-channel traits model only the paired broker authority request/response lane. Broker-initiated notifications such as readiness changes, interrupts, faults, revocations, or session failure should use a separately named notification channel/message family rather than arriving as unsolicited `BrokerResponse` values on the control channel. The notification lane should mirror the layered protocol style, for example `BrokerNotification::Core(CoreNotification::Object(...))` or a session-level notification family, but it should not reuse response enums because notifications are not replies to local requests.

Forward-compatible protocol probing is explicit: unknown requests decoded from the wire stay in channel-level receive wrappers rather than entering the known protocol enums, so the generic host can return `UnsupportedOperation` without closing the connection or exposing wire tag width through the channel interface. Structurally malformed frames remain channel/wire errors. BrokerCore only sees supported, already-adapted domain operations. Core errors or wait outcomes that are newer than the host adapter can represent map to the neutral protocol `Internal` error rather than being reported as unsupported operations.

Negotiation separates the broker's max-supported protocol version from the effective version spoken on a connection. The broker response advertises the max-supported version after accepting a compatible request, while local and host connection state retain the requested effective version; all future feature gating should use the effective negotiated version. Version mismatches report the broker-supported version without closing the connection, so local peers can retry with a compatible version on expensive or credentialed channels instead of reconnecting and guessing.

The known broker protocol keeps the outer envelope intentionally small. Connection-level messages such as negotiation and common errors stay at the broker layer; BrokerCore/object operations are grouped below that layer by authority domain and object family, for example `BrokerRequest::Core(CoreRequest::Event(EventRequest::Wait { .. }))`. New object families should add a nested request/response family instead of growing a flat top-level `BrokerRequest`/`BrokerResponse` operation list. The wire codec may encode those nested families as layered tags, but tag widths and unknown-tag handling remain private to the codec.

Kernel/trusted deployments will likely link broker-kernel user-mode support and broker-authority pieces into one binary or image, but the code should still preserve their logical separation:

| Future crate/layer | Role |
|---|---|
| broker-kernel user-mode support | Trusted-domain support for user-mode execution, trap/upcall/channel delivery, process/thread setup, broker-channel endpoints, and the kernel support ABI used by local core. It supplies or adapts a host control channel, but `litebox_broker_host` still owns broker-side protocol/channel adaptation into BrokerCore. |
| `litebox_broker_kernel` | Kernel/trusted-domain deployment wiring for `litebox_broker_core`, `litebox_broker_host`, BrokerServices, PolicyEngine, BrokerPlatform, and broker-kernel user-mode support. |

These names do not require separate runtime processes. In a kernel-broker deployment, broker-kernel user-mode support, `litebox_broker_host`, BrokerCore, BrokerServices, PolicyEngine, and BrokerPlatform can be compiled into one trusted binary. The code boundary still matters: broker-kernel user-mode support carries or classifies traffic, `litebox_broker_host` decodes and sequences broker protocol requests, and BrokerCore validates domain invariants and authorizes domain operations with PolicyEngine.

## Runtime interfaces

There are three logical interfaces. In a broker-kernel deployment, the local-core deployment-support interface and the broker authority interface may use the same trap instruction or kernel entry path, but they must remain separate contracts with separate authority rules. When they share a path, broker-kernel user-mode support should only classify and deliver traffic to the host control channel; `litebox_broker_host` decodes and sequences `BrokerRequest` values, while BrokerCore/BrokerServices/PolicyEngine remain responsible for domain authority.

| Interface | Userland deployment | Kernel deployment | Purpose |
|---|---|---|---|
| **Shim <-> local core** | same address space | same address space | ergonomic user-mode guest ABI implementation |
| **local core <-> deployment support** | host OS user-mode ABI | broker-kernel support ABI | local non-authoritative mechanics |
| **local core / BrokerService client <-> broker** | IPC | user/kernel boundary | trusted authority and shared state |

The interfaces have different stability and trust requirements:

| Interface | Shape | Authority |
|---|---|---|
| `Shim <-> local core` | ergonomic in-process API | no authority; user-mode compatibility layer |
| `local core <-> deployment support` | deployment-specific host ABI | local mechanics only; must not create LiteBox authority |
| `local core / BrokerService client <-> broker` | explicit broker protocol | authority boundary; broker validates every security-relevant operation |

The broker authority interface should use one shared envelope and dispatch to either BrokerCore or an optional BrokerService. Caller identity is bound to the authenticated channel by broker entry code; it is not supplied as a user-controlled request field.

```text
BrokerRequest {
  target: BrokerCore | BrokerService(service_id),
  operation,
  handles,
  memory_grants,
  payload,
}
```

PolicyEngine is not a user-callable broker target. BrokerCore and BrokerServices call it inside the authority domain before granting authority, mutating protected state, or invoking BrokerPlatform for host-visible effects.

The negotiated policy profile is bound to the authenticated broker session or deployment profile, not chosen by each request. It only needs an explicit request field if a future design supports multiple simultaneous policy profiles on one authenticated channel.

External broker authority APIs:

| API | Shape |
|---|---|
| `local core -> broker host/entry -> BrokerCore` | generic capability/resource protocol adapted into direct BrokerCore domain calls |
| `BrokerService client -> BrokerService` | service-specific protocol for an optional BrokerService |

Internal broker-authority APIs:

| API | Shape |
|---|---|
| `BrokerCore / BrokerService -> PolicyEngine` | in-domain authorization and audit |
| `BrokerService -> BrokerCore` | trusted in-domain API |
| `BrokerCore / BrokerService -> BrokerPlatform` | backend execution after PolicyEngine authorization |

A BrokerService client is not a new authority layer. It is optional user-mode typed client code for a matching BrokerService, used only when a service-specific protocol is clearer than routing through generic local-core APIs.

## Broker protocol and channels

The broker protocol follows the stricter durable-unicorn shape: a custom, versioned, ABI-neutral object-operation protocol, not a host syscall proxy.

Each sandboxed process has exactly one authenticated broker association. That association may contain multiple logical traffic classes:

| Channel | Direction | Purpose |
|---|---|---|
| control | bidirectional | handshake, object operations, operation responses |
| notification | broker to process | lifecycle, readiness, interrupt-like notifications, broker/session failure |
| data | bidirectional | bulk payload bytes associated with authorized object operations |

The broker creates or authorizes all channels and binds them to the host-authenticated peer identity of the guest process. The local core does not prove identity by filling in request fields.

Use "notification channel" for broker-initiated asynchronous traffic. Avoid "event channel" because event already names a broker-owned object family and guest-visible eventfd-like behavior.

The protocol exposes broker-owned objects through opaque per-association reference handles: a reference identifier plus a reference generation. Object identifiers stay broker-internal. Shims may map those handles to guest-visible integers, but the broker remains authoritative for object type, object lifetime, reference lifetime, reference generations, rights, and policy. Object types and rights are broker-internal for authorization; the local core cannot amplify authority by editing request fields.

The protocol never passes host file descriptors, handles, sockets, directory handles, or other host-native resources to untrusted code in the baseline design. The local core receives only broker reference handles, response data, notification payloads, and broker-created channel endpoints whose authority is already bound by the broker.

Bulk I/O uses broker-owned data channels or broker-owned shared memory rings. The control channel authorizes an operation and binds it to an object and request identifier; the data channel carries bytes for that authorized operation. Shared memory is an optimization, not an authority transfer, and all shared-memory contents remain untrusted.

## Rust `std` and runtime strategy

The new architecture should not force one Rust runtime model everywhere.

| Component | Recommended baseline |
|---|---|
| local core | portable core APIs; `std` adapters only where the selected deployment permits them |
| userland broker | `std` |
| broker-kernel deployment | start with `no_std + alloc + broker-kernel support/BrokerPlatform traits`; consider a custom `std` target only if broker-kernel support grows rich enough |
| shared protocol/types | `no_std + alloc` where feasible, so they can cross user/kernel and userland/kernel-broker deployments |

Using `std` in hosted local-core adapters is a deployment convenience, not a security decision. The local core is still untrusted. `std` can be used for normal collections, `std::sync`, broker object wrappers, IPC clients, threads, and async/data-channel libraries when the deployment supports those APIs, but cross-deployment contracts should not require a normal host OS runtime.

Strict host-syscall profiles constrain how much hosted `std` functionality can be used after lockdown. Any `std` functionality that may issue disallowed host syscalls must either run only during bootstrap, be avoided in strict mode, or be implemented on top of the approved deployment-support ABI.

For a broker kernel or trusted host, a custom Rust `std` target may eventually be useful if broker-kernel user-mode support can provide enough primitives: allocator, blocking/scheduling, synchronization, time, I/O, panic policy, and TLS. It should not be the first requirement. A staged design is safer:

1. Define a small broker-kernel support/BrokerPlatform trait surface.
2. Implement it for a `std` userland broker.
3. Implement it for LVBS/SNP/kernel-backed brokers with `no_std + alloc`.
4. Only introduce a custom `std` target if the trait surface naturally becomes "basically std."

## Local core and deployment-support calls

The local core may use deployment-provided host/kernel calls, but only for local mechanics that do not create LiteBox authority.

| local-core operation | Allowed? | Requirement |
|---|---|---|
| private memory allocation, TLS, logging, local scratch mappings | yes | must not grant guest-visible authority |
| private locks/futex-like synchronization | yes | must not represent broker-owned shared state |
| broker notification channel | yes | broker validates every request |
| broker-owned shared-ring data movement | yes | ring ownership, cursor movement, and frames are validated by the broker |
| direct host file, network, or device access for guest-visible resources | no | must be mediated by broker-owned objects and PolicyEngine-authorized broker policy |
| guest-visible mappings or executable/shared memory | only through broker/local-core mediation | BrokerCore validates the object, PolicyEngine authorizes, and BrokerPlatform or broker-kernel user-mode support applies |
| trusted randomness, secrets, or security-sensitive time | no | must come from broker authority |

If the local core uses a Linux-like syscall ABI, it only works in deployments that provide that ABI. In a broker-kernel deployment, the kernel must either expose the required ABI through broker-kernel user-mode support or the runner must select a different local-core build/profile. The stable portability target is the shim/local-core/broker contract, not a single universal local-core binary.

### Host syscall profiles

The strict design still needs a small host-kernel interface for local mechanics, but the interface must be explicitly profiled and locked down.

| Phase/profile | Allowed host-kernel access |
|---|---|
| bootstrap | setup-only calls such as mapping broker-created shared memory, installing signal handlers, setting TLS, creating local scratch mappings, and preparing syscall-capture/trampoline state |
| fast local mode | a small allowlist for performance, such as futex waits/wakes on private locks or broker-ring cursors |
| strict mode | post-lockdown calls only; on Linux this can target `SECCOMP_MODE_STRICT`-like behavior where only `read`, `write`, `_exit`, and `sigreturn` remain available |
| arbitrated mode | selected non-delegable syscalls are trapped/validated before execution in the user process context |

Direct guest `mmap`, `mprotect`, `munmap`, `mremap`, `memfd_create`, `open/openat`, `ioctl`, `fcntl`, and similar authority-bearing or mapping-changing calls must not reach the host unrestricted after lockdown. Guest-visible mapping operations must enter the shim/local-core path and then either be emulated from pre-reserved local memory or mediated by the broker.

If unrestricted `mmap`/`mprotect` remain available to the sandbox, broker mapping policy is bypassable. The design must either block those syscalls after bootstrap, constrain them to anonymous private local mechanics with a host-enforced profile, or route them through local-core/broker-kernel support mediation.

LITESHIELD's useful distinction is between delegable and non-delegable syscalls:

| Class | Meaning for LiteBox |
|---|---|
| delegable | translate into BrokerCore/BrokerService operations |
| local-private | allow directly under the host syscall profile because no LiteBox authority is created |
| non-delegable/arbitrated | must execute in the process context, but only after trap/validation by the local-core/broker-kernel support arbitration path |
| blocked | never allowed after lockdown |

Memory-management and process-management calls are the hard cases. If they cannot be safely delegated to the broker, deployment support needs an arbitration mechanism that can validate address ranges, mapping types, permissions, and target objects before allowing the host syscall to complete.

### Linux userland bootstrap profile

The durable-unicorn Linux experiment provides a future hosted-userland profile where the broker owns runner launch and ring setup:

- the broker creates one anonymous `memfd` per spawned runner;
- the `memfd` is inherited by the runner and identified by an environment/argument convention;
- the `memfd` contains shared metadata and broker-created rings;
- the broker binds the mapped ring set to the host-authenticated spawned runner identity;
- the runner maps the `memfd`, initializes shim/local-core state, installs sandbox restrictions, then enters guest code.

This is intentionally different from the current Unix-socket path. Today, `litebox_runner_linux_userland` does not spawn or supervise the broker. It consumes an already-running broker endpoint via unstable `--broker-socket`, negotiates the broker protocol through `litebox_broker_local`, and then starts the guest. A startup smoke test exercises only that connection/negotiation path, while broker-backed nonblocking Linux `eventfd` exercises the implemented guest-visible broker object path through the local-core event counter. Broker lifecycle ownership stays outside the runner until a later deployment profile explicitly defines broker-owned launch.

The initial Linux ring set can use five unidirectional rings:

| Ring | Direction | Purpose |
|---|---|---|
| control | broker to runner | broker responses, setup, control messages |
| control | runner to broker | broker requests and responses |
| notification | broker to runner | asynchronous notifications and fail-closed notices |
| data | broker to runner | bulk response/notification payload bytes |
| data | runner to broker | bulk request payload bytes |

Broker-to-runner rings can be SPSC because there is one broker-side producer and one runner-side consumer. Runner-to-broker rings may need MPSC in fast local mode, where multiple host threads can produce directly. Strict mode may route all production through a local core scheduler, but keeping the MPSC layout preserves one ring format.

Shared-memory rings are not trusted. The broker validates header magic/version, ring offsets/capacities, producer/consumer roles, cursor movement, frame bounds, and frame contents before acting. Impossible cursor movement, malformed frames, or writes inconsistent with ring ownership are protocol failures.

Linux can expose two protection modes:

| Mode | Shape |
|---|---|
| fast-futex mode | allows a small syscall allowlist, including futex wait/wake on ring cursors or private locks |
| strict-seccomp mode | installs mappings, fds, signal handlers, and trampoline state before lockdown; after lockdown, only a strict syscall set remains available |

In strict-seccomp mode, guest host-thread parallelism may need to become a shim/local-core scheduling illusion rather than real host threads. This is a compatibility/performance tradeoff, not a broker policy bypass.

## Deployment contract and negotiation

The user-side runner and global broker should match through a shared deployment contract, not ad hoc discovery.

Shared spec crates should define:

- the broker envelope and handle/memory-grant formats;
- broker channel authentication and peer identity binding;
- broker authority protocol versions;
- BrokerService IDs, protocol versions, request/response types, and feature requirements;
- PolicyEngine policy versions, policy profile IDs, and audit requirements;
- broker capability names and profiles;
- deployment-support ABI names and versions;
- control/notification/data channel formats;
- shared-memory/ring layout versions and validation rules;
- host syscall profiles for bootstrap, fast local mode, and strict mode;
- deployment profiles that bind a shim, local-core profile, broker channel, required services, and required broker features.

The eventual deployment contract should fail closed:

1. The runner selects a deployment profile, such as `optee-on-lvbs` or `optee-on-userland`.
2. The runner selects a local-core profile that matches the deployment's host ABI.
3. The user side establishes an authenticated broker channel. In userland, this can use OS IPC peer credentials; in broker-kernel deployments, this comes from the trusted entry path. The current Unix-socket channel returns an explicit unauthenticated placeholder credential through the same `HostControlChannel` API that later authenticated channels will implement.
4. The broker binds the caller identity used for dispatch to the authenticated peer credential. User mode does not choose its own authority identity.
5. The user side sends required BrokerCore, BrokerService, PolicyEngine policy profile, broker capability, local-core profile, deployment-support, channel/ring, and host-syscall-profile versions.
6. The broker replies with supported services and capabilities.
7. The user side starts only if the required versions and features match.

The current hosted userland path implements the first control-channel subset of that contract: an externally supplied Unix socket, protocol negotiation, unauthenticated placeholder peer credentials, and a broker setup deadline that bounds connection and negotiation. It also routes the migrated nonblocking `eventfd` object family through broker-backed local-core event counters. Full deployment-profile negotiation, host syscall profile matching, channel/ring negotiation, authenticated identity binding, and broader guest-visible broker object routing remain future work.

The local core should not depend on BrokerPlatform internals. It should depend on the host ABI selected by the deployment profile and the negotiated broker contract: memory-grant format, trap/upcall mechanism, shared-page support, direct fast-path permissions, broker-mediated network/storage requirements, timer behavior, and similar features. Enforcement happens broker-side through PolicyEngine; user-mode code only adapts to supported capabilities.

## Security invariant

The core security rule is:

> User-mode Shim and local core may request operations and cache derived state, but they must never create authority.

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

A compromised user-mode shim/local-core path should not be able to escape the broker-granted authority.

All authority-changing or host-effecting operations must be authorized by PolicyEngine before BrokerCore state mutation, BrokerService authority grants, or BrokerPlatform backend execution. BrokerCore remains responsible for structural capability/lifecycle validity; BrokerServices provide domain-specific context; PolicyEngine makes the policy decision.

Any broker-side validation of data sourced from user-controlled memory, including shared rings, memory grants, and scatter/gather descriptors, must operate on a private snapshot or otherwise revalidate before use. The local core must be assumed hostile for the duration of an in-flight request.

## State ownership

| State | Owner |
|---|---|
| guest ABI decoding state | Shim |
| per-workload cache/view | local core |
| BrokerService client state | optional BrokerService client |
| guest memory marshalling | local core + broker revalidation |
| private user-mode mechanics | local core via deployment support |
| private synchronization fast paths | local core |
| shared synchronization | BrokerCore |
| guest-visible handle numbers | local core view, BrokerCore authority |
| open/shared resource descriptions | BrokerCore |
| shim/domain-specific authoritative state | optional BrokerService backed by BrokerCore |
| policy decisions, constraints, and audit records | PolicyEngine |
| IPC/event/queue/socket-like resources | BrokerCore-owned resources |
| guest-visible/security-sensitive address-space mappings | BrokerCore + PolicyEngine + BrokerPlatform |
| user-only scratch mappings | local core via deployment support |
| host-visible I/O | BrokerPlatform executes PolicyEngine-authorized policy |
| process/session/workload lifecycle | BrokerCore |

local-core-owned entries in this table are non-authoritative views, caches, or private fast paths. Broker-visible data and security-relevant state must still be revalidated by BrokerCore, BrokerServices, and PolicyEngine at the authority boundary.

## Process and session model

The stricter baseline uses one broker per sandbox session and one sandboxed host process per guest process.

| Concept | Owner |
|---|---|
| sandbox session | broker |
| guest process identity | BrokerCore |
| authenticated host process association | broker channel plus host OS or broker-kernel user-mode support identity |
| guest-visible process semantics | shim + local core, backed by BrokerCore identity |
| process creation | broker-mediated |
| `exec`-like ABI behavior | shim/local-core within an existing broker association unless policy requires otherwise |

All guest processes in one sandbox session share one broker. The broker assigns guest process identity, creates or authorizes the private channel set for each process, and binds the channel set to the host-authenticated peer identity. A guest process cannot claim another process's identity by choosing request fields.

POSIX-like `fork` is broker-mediated at the identity/channel/resource level, while ABI-specific memory and descriptor inheritance semantics remain shim/local-core work. POSIX-like `exec` is preferably a shim/local-core replacement of guest memory and ABI state inside the existing sandboxed host process, so BrokerCore does not become ABI-specific.

## Local core vs BrokerCore in current `litebox`

The current `litebox` crate should not be migrated by whole module. Most modules mix ergonomic user-facing logic with authority-bearing state. The useful boundary is by responsibility.

| Current area | Keep in local core | Move to BrokerCore / broker side |
|---|---|---|
| `LiteBox` object | user-mode facade, std-backed helpers, broker connection/session object | broker session/workload identity |
| `fd::Descriptors` | guest fd number table/cache, typed wrappers, syscall ergonomics | authoritative object IDs, reference IDs, reference generations, rights, dup/pass/close/refcounts |
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
| current `platform` traits | internal local-core deployment-support adapter where local-only | broker-kernel support/BrokerPlatform traits where trusted-domain or backend effects are required |

Concrete examples:

- `fd::Descriptors` currently stores in-process descriptor entries with `Arc<RwLock<DescriptorEntry>>`. The local core can keep the ergonomic raw-fd and typed-fd presentation, but BrokerCore should own the live object, closeable reference, rights, reference generations, refcount, passing, duplication, close, and revoke semantics.
- `fs::in_mem`, `fs::layered`, and `fs::nine_p` currently store namespace-like state in-process. In a multiprocess design, namespace state and open file descriptions must be broker-side. The local core should only marshal paths/buffers and use broker-owned data channels or rings for payloads.
- `net::Network` currently owns smoltcp socket state, local port allocation, close queues, and platform packet I/O. If the broker enforces network/firewall policy, socket and port authority must be broker-side. The local core should keep the socket facade and use broker-owned rings for data movement.
- `mm::PageManager` currently owns VMA state and calls platform page-management operations. The local core can keep loader-side helpers and cached VMA views, but authoritative mapping permissions, shared mappings, and page-fault decisions belong broker-side.

## Control path and data path separation

The broker should be on the control path for authority, but it does not need to be on every byte of every data path.

```text
Control path:
  local core -> BrokerCore/BrokerService -> PolicyEngine -> BrokerPlatform

Data path:
  local core moves bytes through broker-owned data channels or rings
```

The broker still owns setup, rights, revocation model, object identity, and audit boundaries. Once it creates a constrained data channel or shared ring, the local core can move bytes without a control RPC per byte, but the broker still owns the object and validates frames/cursors before acting.

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
local core asks broker: open(path, flags)
BrokerCore resolves object/capability
PolicyEngine authorizes path/flags/caller
BrokerPlatform opens host object and stores host handle privately
Broker returns broker reference handle, not host fd/HANDLE
local core uses control/data channels for operations
```

This avoids moving enforcement into local core or the runner, avoids cross-OS handle-rights mismatches, and makes revocation/audit simpler. The cost is higher broker involvement on data operations. Performance should first be recovered through broker-owned data rings, batching, and object-specific data channels rather than raw host-handle delegation.

Reintroducing host-handle delegation would require a separate future design note with object-specific proof obligations. It is not assumed by this architecture.

## Trusted data-plane services

The stricter baseline keeps host resources broker-owned and avoids raw host-handle delegation to local core. SKernel suggests a future performance direction that preserves this rule: introduce trusted data-plane services inside the broker authority domain.

In that model:

```text
local core:
  untrusted ABI compatibility, marshalling, local caches

BrokerCore / PolicyEngine:
  object identity, rights, lifecycle, policy

Broker data-plane service:
  trusted high-performance implementation of an object family

BrokerPlatform:
  authorized host/device/backend effects
```

A trusted data-plane service is not local core. It is part of the TCB, like a BrokerService or BrokerPlatform-adjacent component, and can hold backend authority that local core must not receive.

Potential examples:

| Service | Inspired by | LiteBox interpretation |
|---|---|---|
| filesystem data-plane service | SKernel-D FD/image-based filesystem, EROFS/TMPFS | broker-owned filesystem cache/ring service that reduces per-operation broker IPC without exposing host fds |
| network data-plane service | SKernel-D high-performance network stack with device passthrough | trusted broker-side network service; local core talks via rings while PolicyEngine keeps firewall authority |
| memory/resource coordination service | SKernel-R/SKernel-V resource calls | broker-kernel support/BrokerPlatform resource-call path for memory, CPU, and device-resource elasticity |

This is an optimization path, not the first milestone. The initial implementation should still start with simple broker-owned objects and mediated control/data channels. If performance demands it, move hot object-family data paths into trusted broker-side services rather than expanding untrusted local-core authority.

## Network and firewall enforcement

The design can support a network or application-level firewall, but only if the broker is the authoritative network path.

In that configuration, local core must not send or receive guest-visible traffic directly through a platform network device. It may only operate on broker-granted network resources. BrokerCore owns the virtual socket/NIC/resource state, BrokerServices provide domain-specific context when needed, PolicyEngine authorizes policy, and BrokerPlatform executes approved backend operations.

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
- direct local-core fast paths for private state;
- batched broker calls where possible;
- shared-memory rings for bulk IPC, pipe, queue, and network data;
- broker-mediated setup with local data-plane access where security allows;
- cached PolicyEngine decisions when the cache key includes all security-relevant context and supports revocation;
- explicit invalidation/revocation for stale local-core caches.

The broker path is required for authority changes, cross-workload operations, shared resources, host-visible effects, and firewall-enforced traffic.

## Why this is better than moving all core into broker

Moving the whole core into broker would make the trusted boundary too large and too chatty. It would also force guest pointer handling, guest ABI compatibility policy, and shim-specific logic into the trusted domain.

This separation keeps the trusted computing base smaller:

```text
User mode:
  compatibility, marshalling, caching, broker-owned local data channels

Authority domain:
  validation, capabilities, shared state, policy enforcement, optional domain authority, host effects
```

## Main risks

| Risk | Mitigation |
|---|---|
| local-core cache diverges from BrokerCore | generation-tagged handles, invalidation, broker authority checks |
| user shim bypasses policy | broker validates every security-relevant request and routes policy decisions through PolicyEngine |
| ABI becomes too chatty | batching, shared memory data planes, control/notification/data channel separation, local private fast paths |
| duplicated logic | keep policy in PolicyEngine, authority state in BrokerCore/BrokerServices, and ABI translation in local core |
| handle/resource lifetime bugs | broker-owned object IDs, refcounts, cleanup on lifecycle transitions |
| broker bottleneck from no host-handle delegation | use broker-owned rings, batching, object-specific data channels, and policy caching |
| address-space lifecycle complexity | broker-authoritative mappings, shared object IDs, careful copy-on-write/shared-memory design |
| firewall datapath bottleneck | shared rings, batching, quotas, policy caching, and broker-side flow control |
| encrypted traffic hides application data | enforce metadata/connection policy unless using broker proxying or broker-managed keys/endpoints |
| BrokerServices become a second monolithic core | make them optional, small, versioned, and backed by BrokerCore primitives |
| local core depends on unavailable host ABI | select local-core profile by deployment, or provide the needed ABI through deployment support |
| local core depends on trusted-domain internals | expose negotiated broker/host capability profiles instead of implementation details |
| shared-memory TOCTOU or double-fetch bugs | validate broker requests against private snapshots or revalidate every use of user-controlled fields |
| unauthenticated broker channel | authenticate peers before negotiation and bind broker-assigned caller identity to the authenticated channel endpoint |
| PolicyEngine becomes a second core | keep it decision/audit focused; authoritative object state remains in BrokerCore/BrokerServices |
| custom kernel `std` target becomes a distraction | start with `no_std + alloc + traits`; introduce custom `std` only if the broker-kernel support surface justifies it |
| non-delegable syscalls bypass broker mapping/resource policy | block, constrain, or trap/arbitrate them before host execution |
| trusted data-plane services grow too powerful | keep them broker-side, object-family-specific, and PolicyEngine-authorized |

## Prior-art positioning

LiteBox's proposed design combines ideas from several systems rather than copying any one of them.

| System | Relevant idea | LiteBox lesson |
|---|---|---|
| **Drawbridge** | application + LibOS in a picoprocess over a narrow Host ABI | keep the local core user-mode and keep the broker ABI narrow |
| **Haven** | Drawbridge-style LibOS inside shielded execution | a narrow host interface composes with stronger isolation domains, but LiteBox's broker is trusted TCB rather than untrusted host |
| **Graphene / Gramine** | LibOS plus PAL/host ABI, including SGX deployments | separate compatibility logic from host adaptation; avoid baking one host ABI into core |
| **gVisor** | userspace kernel plus brokered filesystem/gofer model | rich domains like filesystems and sockets need real broker services, not just generic RPC |
| **Chromium sandbox** | sandboxed target, broker/browser process, Mojo IPC, delegated handles | useful contrast: delegated handles can work, but LiteBox's stricter baseline keeps host handles broker-owned |
| **Capsicum** | capability mode, broker opens resources and passes restricted fds | useful contrast: capability fd passing is powerful, but requires OS support for precise rights |
| **Lind / Native Client** | POSIX LibOS inside a restricted sandbox with brokered host operations | local core should not be a generic syscall escape hatch |
| **Arrakis / Exokernel** | OS as control plane, application gets direct data path after safe allocation | broker can be the control plane while local core uses broker-owned rings/data channels for safe data paths |
| **LITESHIELD** | userspace microkernel services, shared-memory IPC, delegable vs non-delegable syscall handling | borrow syscall classification and arbitration; keep LiteBox's explicit broker objects and PolicyEngine |
| **SKernel** | separates guest kernel into resource kernel and data kernel; trusted I/O data plane for performance | consider future trusted broker data-plane services, not untrusted local-core authority expansion |
| **seL4 / capability microkernels** | explicit unforgeable capabilities define authority | BrokerCore should keep object identity internal and expose reference capabilities with generation checks while storing authoritative rights |
| **Qubes OS** | compartmentalized workloads use service VMs for devices/network | isolate rich authority into broker services and policy, especially device/network access |
| **Nabla / Kata / unikernels** | reduce host syscall surface or use VM-backed isolation | narrow the authority interface; choose stronger isolation per deployment when needed |

The distinctive LiteBox claim is one architecture that supports both:

```text
userland broker process
kernel broker
```

while keeping:

```text
Shim + local core
```

always in user mode.

## Mapping current components

The current code does not match the final boundaries exactly. In particular, some current shims and platforms are linked together in the trusted domain for existing deployments. The mapping below describes the intended migration target.

Where a current crate spans both user-mode and authority responsibilities, the mapping below describes the destination responsibility boundary, not a one-to-one rename.

### `litebox_shim_optee`

Today, this crate combines OP-TEE ABI handling, TA loading, per-TA state, page-manager use, syscall dispatch, and some session/object/crypto bookkeeping.

Future mapping:

| Current responsibility | Target component |
|---|---|
| OP-TEE entry/request decoding, return conventions, TA ABI details | Shim |
| TA-local syscall helpers, guest buffer marshalling, local loader helpers | local core, with broker revalidation for broker-visible data |
| non-authoritative TA/session/object caches | local core |
| authoritative TA/session registry, cross-TA/session state, OP-TEE persistent object semantics, PTA access-control context | OP-TEE BrokerService backed by BrokerCore |
| OP-TEE policy decisions and audit, including PTA and secure-storage authorization | PolicyEngine |
| generic identities, capabilities, memory grants, lifecycle, wait/notify, accounting | BrokerCore |
| trusted secrets, secure storage backend, normal-world shared-memory validation, address-space operations | BrokerPlatform after PolicyEngine authorization |

This likely means `litebox_shim_optee` should eventually become thinner: the OP-TEE ABI layer remains shim-specific and user-mode, while reusable local core and broker-facing pieces move behind generic interfaces. The kernel/trusted deployment does not need the full OP-TEE shim; it needs only the OP-TEE-aware enforcement that creates authority.

### `litebox`

Today, `litebox` is an in-process no_std core library. Its current `LiteBox` object and subsystems assume Rust references, generic platform traits, in-process locks, and in-process descriptor/resource identity.

Future mapping:

| Current responsibility | Target component |
|---|---|
| ergonomic in-process helpers used by shims | local core |
| guest-visible handle table view | local core backed by BrokerCore |
| private sync, TLS, path conversion, guest marshalling | local core |
| broker-owned data-channel wrappers | local core |
| shared resource identity/lifetime | BrokerCore |
| synchronization/wait/readiness authority for shared objects | BrokerCore |
| final policy decision/audit | PolicyEngine |
| platform trait surface | internal local-core deployment-support adapter, broker-kernel user-mode support, and BrokerPlatform surfaces |
| service-specific authority | optional BrokerServices plus PolicyEngine decisions, not generic BrokerCore |

The important change is that the current core API should not become the cross-boundary ABI. The local core can keep ergonomic Rust APIs, the broker boundary needs an explicit handle/capability protocol, and broker host/entry code adapts that protocol into BrokerCore domain calls.

### `litebox_platform_lvbs`

Today, this crate is effectively a trusted-domain platform: it owns page tables, user-memory validation, VTL switching, syscall/exception entry, host calls, randomness/secrets hooks, and network backend hooks.

Future mapping:

| Current responsibility | Target component |
|---|---|
| page-table and address-space management | BrokerPlatform |
| VTL/trusted-domain trap and channel mechanism | broker-kernel user-mode support |
| broker request decode and dispatch | `litebox_broker_host` |
| domain validation and authorization | BrokerCore + PolicyEngine |
| normal-world memory mapping and validation | BrokerPlatform |
| host I/O, network backend hooks, root key/secrets | BrokerPlatform executing PolicyEngine-authorized operations |
| user-mode shim/platform helpers | local-core internals, not the current crate wholesale |

In the new model, LVBS contributes both BrokerPlatform and broker-kernel user-mode support pieces. BrokerPlatform owns privileged backend authority. Broker-kernel user-mode support exposes the host ABI that lets a user-mode local core execute and reach the broker. The LVBS-targeted local-core profile selected by a deployment profile, such as `optee-on-lvbs`, should be smaller than the current LVBS crate.

### `litebox_runner_lvbs`

Today, this crate boots the trusted-domain environment, initializes the LVBS platform, dispatches VTL calls, handles OP-TEE messages, creates task page tables, manages sessions, and directly invokes the OP-TEE shim.

Future mapping:

| Current responsibility | Target component |
|---|---|
| early boot and trusted-domain initialization | broker bootstrap |
| VTL trap/channel dispatch | broker-kernel user-mode support |
| broker request decode and dispatch | `litebox_broker_host` |
| domain validation and authorization | BrokerCore + PolicyEngine |
| session/page-table orchestration | BrokerCore + OP-TEE BrokerService + PolicyEngine + BrokerPlatform |
| shim ABI state and non-authoritative per-task helpers | user-mode OP-TEE Shim + local core |
| authoritative TA/session/object identity currently held by the runner | BrokerCore + OP-TEE BrokerService + PolicyEngine |
| user/broker compatibility checks | deployment profile negotiation |
| local user ABI support | broker-kernel user-mode support |

The runner becomes less of an application runner and more of a broker bootstrap/entrypoint for the trusted deployment.

### OP-TEE-on-userland runner

The current OP-TEE userland runner sets a platform, builds `OpteeShim`, loads binaries, optionally rewrites syscall instructions, and runs the workload in one process.

Future mapping:

| Current responsibility | Target component |
|---|---|
| command-line harness and binary loading for tests | runner/test harness |
| `OpteeShim` construction | Shim + local-core process setup |
| user-mode local execution | local-core setup |
| broker/service compatibility | deployment profile negotiation |
| shared/security-authoritative state | separate privileged broker process |

This runner is a good prototype for the userland deployment shape, but it currently lacks a separate broker authority.

### `litebox_platform_multiplex`

Today, this crate chooses one monolithic platform type at compile time.

Future mapping:

| Current responsibility | Target component |
|---|---|
| selecting a single `Platform` | separate into local-core profile selection, BrokerPlatform selection in the broker, and broker-kernel user-mode support selection only for broker-kernel deployments |
| global platform accessor for shim-side code | local-core deployment-support accessor |
| trusted backend selection | BrokerPlatform accessor inside the broker |
| policy module/profile selection | PolicyEngine configuration inside the broker |

This separation is needed because the current platform traits mix local execution mechanics with trusted authority.

### Other shims, platforms, and runners

The OP-TEE/LVBS sections above are worked examples, not an exhaustive crate-by-crate migration plan. Other existing crates follow the same destination responsibility boundary:

| Current component | Target shape |
|---|---|
| `litebox_shim_linux`, `litebox_shim_windows` | Shim plus local-core-facing ABI translation; any shared or policy-relevant process, descriptor, filesystem, network, or device authority moves to BrokerCore, optional BrokerServices, and PolicyEngine. |
| `litebox_platform_linux_userland`, `litebox_platform_windows_userland` | hosted local-core deployment-support implementations; native host calls are limited to local non-authoritative mechanics and broker channels/rings. |
| `litebox_platform_linux_kernel` | broker-kernel pieces follow the LVBS boundary: privileged backend operations become BrokerPlatform, while any user-mode support/trap channel becomes broker-kernel user-mode support. |
| `litebox_runner_linux_userland`, `litebox_runner_windows_userland`, `litebox_runner_linux_on_windows_userland` | user-side runners that select local-core profile, create shim/local-core state, authenticate to the broker, and negotiate deployment profile compatibility. |
| `litebox_runner_snp` | trusted-deployment bootstrap analogous to LVBS; move external entry/channel support into broker-kernel user-mode support, authority state into BrokerCore/BrokerServices/PolicyEngine, and backend privileged operations into BrokerPlatform. |

## Initial implementation direction

The first milestone should not attempt full multi-process support for every shim. Start with the smallest authority slice:

The initial slice uses:

```text
litebox_broker_protocol
litebox_broker_core
litebox_broker_transport
litebox_broker_host
litebox_broker_userland
litebox_broker_local
separate userland broker process
Unix-domain-socket channel implementing neutral control-channel traits
control channel only
minimal PolicyEngine
broker-owned event object
```

Early end-to-end shim tests should use a hybrid migration profile: only the migrated object family routes through broker-backed local-core wrappers, while unrelated operations continue through the existing local compatibility path. Shims should keep calling local-core object interfaces; local-core entries can contain either local compatibility state or broker-backed wrappers with cached rights. This is explicitly a migration profile, not the final security posture for arbitrary workloads.

Then proceed incrementally:

1. Define the component boundary: `Shim`, local core, optional BrokerService clients, `BrokerCore`, optional `BrokerServices`, `PolicyEngine`, `BrokerPlatform`, `litebox_broker_host`, and, in broker-kernel deployments, broker-kernel user-mode support.
2. Create `litebox_broker_protocol` with the shared protocol version type, opaque event reference handle format, minimal event request/response messages, readiness/wait outcomes, ABI-neutral errors, known/unknown receive wrappers, peer credentials, and neutral control-channel traits needed for the first event-object path.
3. Create `litebox_broker_core` with broker-owned process association IDs, authority-only object type and rights metadata, caller credentials supplied by broker entry code, an event object registry plus per-association reference IDs with generation checks, a minimal object/reference registry, association cleanup, and policy hooks. BrokerCore must stay protocol-neutral and channel-neutral.
4. Add `litebox_broker_protocol::wire` with reusable message-body encoding, create `litebox_broker_transport` with the concrete Unix-domain-socket implementation, create `litebox_broker_host` with protocol negotiation, request sequencing, unknown-tag handling, and adaptation from channel/protocol requests to direct BrokerCore domain calls, and create `litebox_broker_userland` as the hosted executable that assembles those pieces.
5. Add startup negotiation between the local side and broker. The current path starts with protocol negotiation over `--broker-socket`; later deployment profiles add required BrokerCore, BrokerService, PolicyEngine, broker capability, channel/ring, host syscall profile, local-core profile, and deployment-support feature negotiation.
6. Add a broker-owned event object with the smallest end-to-end surface first: create, wait, add, and consume. BrokerCore/host cleanup releases association-owned references on disconnect; protocol-level duplicate, close, explicit readiness queries, and broader stale-handle tests follow after the initial broker path is proven.
7. Use `litebox_broker_local` for typed end-to-end broker tests, keeping the local adapter independent of Unix sockets so future channel implementations can implement the same neutral channel traits.
8. Continue shaping `litebox` as the untrusted local core for syscall/resource routing, local-private operations, broker-backed object wrappers, and compatibility-profile glue.
9. Define host syscall profiles for bootstrap, fast local mode, and strict mode.
10. Make local-core handle tables broker-backed views for migrated object families.
11. Add a broker wait/wakeup channel.
12. Prototype a broker-owned pipe or queue with shared-ring data path.
13. Prototype a broker-owned file object with mediated control/data-channel I/O, not host-handle delegation.
14. Prototype broker-owned network resources with PolicyEngine firewall policy and BrokerPlatform backend execution.
15. Add a small OP-TEE BrokerService only for authority that cannot be represented by generic BrokerCore primitives.
16. Expand to shared memory, lifecycle transitions, IPC, filesystem policy, network policy, and shim-specific resource models.

That gives a controlled path from current single-process/single-session assumptions toward true shared-state support without rewriting every shim and platform at once.
