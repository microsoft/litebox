# uLiteBox: sandbox confinement specification

## 1. Status, scope, and top-down design

This document specifies verification targets, not completed proofs. Its primary
implementation target is `litebox_broker_core`; end-to-end claims additionally
require the host endpoint, transports, providers, runner bootstrap, and host
kernel. The deployment described here is separate-process Linux userland.
See [the tutorial](tutorial.md) for direct and Docker-managed application launch.

For review, start with the policy/authority/result distinction in Section 5.4,
the security obligations in Section 8, and the concrete code mapping in Section 9.
Section 9.1 orders component verification from simpler to harder; it is not a
claim that those proofs are complete. Current assignments, blockers, and
integration approvals belong in [the agent task board](agent-tasks.md).

The design proceeds from one security goal to the system model, precise predicates,
transition obligations, and implementation-level proofs:

```text
Sandbox confinement under the immutable launch policy
    every application/runner effect stays within derived authority
                                  ^
                                  | requires all three
    broker enforcement + native-operation confinement + correct deployment
             ^
             | supported by broker integrity invariants
    identity + references + policy + lifecycle + quotas + memory/transport safety
```

Broker integrity is a supporting invariant, not a second independent security
goal. Together with correct authorization and faithful enforcement, it
establishes confinement for broker-mediated effects. Whole-sandbox confinement
additionally requires native-operation confinement and correct bootstrap and
descriptor/mapping delegation. If those conditions are proved or explicit
deployment assumptions, the broker proof composes into the sandbox theorem.
Process separation alone does not establish those conditions.

Linux syscall semantics and errno translation belong to the Linux ABI shim.
The broker model uses guest-neutral identities, resources, operations, and rights.

## 2. Security goal and supporting obligations

### Security goal: sandbox confinement

**Every security-relevant effect attributable to a sandbox process must be
within that process's authority derived from the immutable launch policy.**

This covers broker-mediated operations and direct host operations, including
access through delivered descriptors or mappings. A sandbox process must not
obtain an unassigned file, network destination, object reference, or other
process's authority merely by supplying a pathname, integer, or claimed identity.

"Assigned" includes permitted creation/open operations, explicit transfer or
inheritance, and the fixed runtime operations needed under seccomp. It is not
limited to resources listed before startup, nor does it imply no IPC or sharing.

Runners in the same sandbox intentionally share its launch-time policy and may
share files and other resources. Sharing data does not grant authority to change
that policy. After launch, the sandbox policy is immutable; there is no dynamic
policy-update operation, including through maintenance. Policy-authorized
`chmod` and `chown` may change filesystem permissions or ownership and thereby
affect other runners' syscall results, but not their broker-policy permissions.
Section 5.4 distinguishes stable authorization decisions from execution results.

### Supporting obligation: broker integrity and faithful enforcement

**Starting from valid broker state, arbitrary runner behavior must preserve
broker memory/control-flow safety and authority invariants. Every effect the
broker performs must follow a permitted authorization or maintenance rule.**

The broker must preserve the sealed policy and faithfully enforce it for every
broker-mediated effect. Computing a correct policy decision is not sufficient:
the authenticated caller, checked target, operation, and actual effect must
agree. Memory safety, identity binding, reference provenance, and check/use
consistency are proof obligations supporting this enforcement claim.

The adversary may replace the entire runner runtime, not merely invoke valid
Linux syscalls. Broker correctness cannot depend on an honest local client,
well-formed requests, stable shared bytes, or cooperative disconnection.

"Still works normally" means preserving security and executing only specified
transitions. It does not promise uninterrupted service: recoverable errors and
specified fail-closed termination are allowed. Availability, fairness, and total
denial-of-service resistance would need separate requirements.

### Supporting obligations: native confinement and correct deployment

Runner operations that do not pass through the broker must still remain within
policy-derived authority. Bootstrap, syscall restrictions, inherited/delivered
host descriptors, mappings, and their lifetimes must establish and preserve this
condition. For example, an unintended inherited host file descriptor can permit
access without a broker request or broker corruption. A broker-only proof does
not rule out that deployment error.

## 3. System boundary and adversary

### 3.1 Asymmetric broker-runner trust

```text
untrusted Linux process                    separate broker process
  application                              host endpoint
  Linux ABI shim           hostile IPC ->  authority core
  local LiteBox                            policy and object state
  local broker client                      providers/backends
          |                                        |
          | seccomp-constrained host calls         | authorized operations
          v                                        v
                           host kernel
```

This is analogous to a browser broker and sandboxed renderer. The broker is the
resource authority; the runner is its untrusted client. Authentication identifies
the client but does not make its requests trustworthy.

All components inside a runner share its address space. A malicious application
may corrupt the Linux shim or local client, generate raw syscalls, guess handles,
forge requests, mutate shared buffers during processing, race operations, close
descriptors, disconnect, and crash. Its private memory and shared-buffer contents
are arbitrary inputs to this specification.

The broker may supervise multiple runners. Normally each guest process has its
own runner, with guest threads inside it. Broker and runner may have the same
non-root host UID but different effective authority because of seccomp and
descriptor restrictions. "Trusted broker" does not mean "root broker".

There is no reverse guarantee against an intentionally malicious broker:
applications rely on it for services and process supervision. However, a
**runner-induced broker compromise violates the broker-integrity obligation**, not an excluded
case hidden behind the phrase "trusted broker".

### 3.2 External assumptions and proof boundaries

The operator supplies the intended initial broker code, policy, and limits.
Trusted launch seals the sandbox policy before any untrusted runner executes.
Later runner creation uses that same policy, not a runner-supplied replacement.
The host kernel and execution/compiler model must uphold the process, memory,
descriptor, and syscall semantics used by the proofs. An operator deliberately
replacing broker code or a compromised host kernel is outside this model.

Broker-core correctness is a proof obligation, not an assumption. Endpoint and
provider contracts are separately proved or explicitly assumed at the core
boundary; any end-to-end theorem must discharge those assumptions.

Bootstrap must install the runner filters before untrusted execution, cover all
relevant threads/children, and remove ambient host descriptors. Release runners
have null host standard streams; guest I/O is broker-mediated. Rewriting alone
is not confinement. Deliberately shared data is not broker-private memory.

The host-side containerd shim is trusted orchestration, unlike the Linux ABI shim
inside a runner. Its native runtime implements only a subset of OCI isolation
settings. Ordinary Docker around LiteBox can add an outer boundary, but that
boundary is not assumed for every LiteBox deployment.

The in-process runner mode does not provide broker-runner address-space isolation
and is excluded from this separate-process security contract.

## 4. Abstract domains and state

The following names are specification concepts, not existing Verus declarations.

| Symbol | Definition |
| --- | --- |
| `p` | Stable broker process key, not a caller-supplied guest PID or host PID. |
| `s` | Sandbox identity; multiple runners may belong to the same sandbox and share its policy and resources. |
| `h` | Broker reference handle. It is not a host file descriptor. |
| `r` | Canonical resource identity or scope: object identity, filesystem entry within a backend, normalized network endpoint, process, or bounded memory region. |
| `op` | Operation kind plus all security-relevant arguments: route, supplied handle/descriptor, access mode, target, length/range, destination, and requested rights as applicable. |
| `a` | One actor action: runner input, shared-memory mutation, raw syscall, scheduling/provider completion, or specified trusted startup/maintenance. |
| `e` | One security-relevant effect, with origin, target resource, operation, and actual result/extent. |
| `E` | Finite sequence of effects emitted by one transition; it may be empty. |

An effect records actual resource access or disclosure, mutation, authority
creation/transfer/release, or security-relevant lifecycle/accounting changes.
It is not merely a successful response or host syscall. Responses disclosing
protected data count even without a write. Denied attempts need not produce a
resource-access effect; bookkeeping and denial responses still follow their
specified rules. Timing and other side channels are not modeled here.

The system state is `S = (B, K, X)`:

| Component | Contents |
| --- | --- |
| `B.Cfg` | Trusted launch-time policy, backend authority boundaries, and resource ceilings, sealed for the entire post-launch trace. |
| `B.P` | Process keys, immutable sandbox/principal bindings for each process lifetime, association credentials, namespace IDs, jobs, parent/child relations, lifecycle, and cancellation state. |
| `B.H` | Handle table: owner process key, object identity, rights, and per-reference metadata, including ghost issuance/provenance records. |
| `B.O` | Typed objects, provider-resource identities, and mutable semantic state, including filesystem permission bits and ownership. These filesystem attributes are not the sealed broker policy. |
| `B.A` | Associations: bound process, protocol status, buffer-slot usage, and in-flight request records. |
| `B.U` | Committed charges and partially acquired/pending reservations for each resource kind and accounting scope. |
| `B.L` | Operation leases and pending grant records: caller, exact operation/target, checked authority, lifetime, and applicable budget. |
| `B.N` | Fresh handle/process-key allocation and namespace-ID lifetime accounting. |
| `B.M` | Broker-private memory and execution status, including a distinguished `BadBroker` state for memory/control-flow violations. |
| `K` | Kernel state relevant to separation, per-thread syscall filters, descriptor access modes, mappings, retained in-flight operation references, and supervised process lifetime. |
| `X` | Untrusted runner memory and shared bytes, including transport data. |

`B.L` and parts of `B.U` may be ghost state describing Rust leases and reservation
lifetimes rather than new runtime tables. Shared file contents belong to `X`
when runner-writable; pointers to them do not confer authority over `B.H` or
other private metadata.

A valid initial state includes trusted startup grants and accounts for every
pre-existing descriptor/mapping. Effects before the runner's sandbox is installed
belong to trusted bootstrap, not to the untrusted guest-execution trace.
Filesystem metadata is operational state: authorized creation, `chmod`, or
`chown` may initialize or change it according to filesystem semantics. Such
changes do not update `B.Cfg`, authenticated principal bindings, or broker
reference rights. Broker authority metadata remains protected even when the
filesystem state it governs is mutable.

### 4.1 Kernel boundary condition

`KernelBoundary(S)` states the deployment conditions needed by the broker proof:
runner execution is in separate address spaces, cannot directly read/write
broker-private memory or alter its code/control state through host facilities,
and remains subject to the intended installed syscall filters. Descriptors and
mappings that can affect the broker are limited to the intended IPC/shared-data
interfaces, not private authority metadata.

This is not the assertion that every raw syscall effect satisfies `Grant`.
Filter installation, inheritance, descriptor delivery, and preservation of this
boundary require separate proofs. In particular, kernel correctness alone does
not establish this condition for an incorrectly configured runner.

## 5. Effects and authority: `GuestEffect`, `Grant`, `AuthorizedEffect`

### 5.1 `GuestEffect(e, p)`

`GuestEffect(e, p)` is true exactly when the effect exercises or changes authority
for a request or direct action of runner `p`. This includes:

- a broker operation whose caller is the process bound to its association;
- a raw host syscall or mapping access by `p`;
- publishing, transferring, or releasing authority through `p`'s operation.

The origin is derived from kernel identity or broker-private request records,
not from a runner field claiming who performed the operation. The definition
is independent of whether the effect was authorized.

Trusted maintenance has a separate origin. A runner-triggered disconnect can
cause maintenance, but this does not permit arbitrary effects to be relabeled
as cleanup: only the specific owner-death/retirement rules below qualify.

`BrokerEffect(e)` separately identifies effects performed by the broker or a
provider on its behalf, including changes to its private authority/accounting
state. An effect can satisfy both predicates: a broker read serving `p` is
both a `BrokerEffect` and a `GuestEffect`. A later direct use of a delivered
descriptor is a `GuestEffect` but not a `BrokerEffect`.

### 5.2 `Grant(S, p, r, op)`

`Grant(S, p, r, op)` means that **before performing the effect**, process `p`
has authority for that exact operation on resource `r`. It is established by
one of the following mechanisms; an unmatched operation has no grant. This is
an effect-authority predicate, not the broker-policy grant/reject decision for
a request. That separate decision is `BrokerPolicyAllows` in Section 5.4.

| Mechanism | Required facts |
| --- | --- |
| Existing broker reference | The exact handle supplied in `op` is live in `B.H`, belongs to `p`, names `r`, and contains the required rights. The object's kind, file access mode, and operation-specific restrictions permit `op`. |
| Creation/open/path operation | `B.Cfg` permits the association principal to perform that operation within the configured backend/namespace/destination scope; applicable permission, lifecycle, size, and reservation checks hold. No existing handle is required. |
| Transfer/inheritance | The source is owned and authorized, the object kind is transferable, and new rights are nonempty subsets of source rights and target-policy rights. The target relationship and quota checks hold. |
| Acquired operation lease | A live `B.L` record was created by checked authorization for this caller and exact operation. The effect remains within its target, access, lifetime, and budget. A runner cannot select a lease belonging to another request by guessing its identifier. |
| Delegated host descriptor/mapping | `K` resolves the actual descriptor/mapping or retained in-flight kernel reference of `p` to the granted resource with the intended access modes; its provenance and scope match a trusted delegation, and syscall restrictions permit this use. |
| Fixed runtime authority | The actual host operation is permitted by the configured seccomp rules and arguments, and any resource it names is already available with compatible authority. An allowed syscall number alone does not grant an arbitrary file descriptor. |

Resource and destination identity is resolved/normalized before authorization.
The grant includes security-relevant parameters; permission to read one file
does not authorize writing it, and permission for one endpoint does not authorize
another. A response's success flag is not evidence of a grant.

Filesystem permission checks are distinct from the broker-policy decision.
They may prevent an otherwise policy-permitted operation from producing a
resource-access effect, returning an error instead. `Grant` includes the
effect-specific checks above; its truth is not the stable policy decision
defined in Section 5.4. Policy permission does not bypass filesystem semantics.

Creation grants derive from the pre-existing policy/scope, not from the reference
created afterward. This prevents retroactively justifying an unauthorized grant
using its resulting handle table.

An operation may acquire a checked lease before a concurrent close. That lease
can authorize its completion after the original handle disappears. New lookups
of the closed handle fail; other live references and delivered mappings have
their own lifetimes. Close is not universal instantaneous revocation.
Likewise, kernel operations may retain an authorized resource after descriptor
close; their completion uses that retained authority, not a fresh descriptor
lookup.

### 5.3 `AuthorizedEffect(S, a, e)`

`AuthorizedEffect(S, a, e)` means that effect `e` is permitted for the actor
action `a` under the **pre-transition** authority in `S`:

- For a guest effect, the caller is derived from the actual action/association,
  `Grant(S, p, r, op)` holds, and the actual effect is within that operation's
  authorized target and extent. It cannot use a different supplied handle,
  disclose additional resources, or exceed a lease budget.
- Trusted startup may grant only the configured initial authority and must
  account for the objects/descriptors it supplies.
- Maintenance may cancel/retire the specified association or process, remove
  its references, release the corresponding charges/resources, and perform
  the explicitly defined supervision/adoption/notification actions. It may not
  broaden policy, close arbitrary foreign references, or act outside their
  permitted lifecycle relationships.
- Pure protocol bookkeeping/error reporting may change only the associated
  request/buffer/failure state and produce the specified bounded response.
  It does not authorize a protected resource access.

There is no "anything done by the broker is authorized" fallback. Security-
relevant private-state changes must also fit these rules. Partial authorized
I/O and a lost response are possible; authorization does not imply rollback,
exactly-once retries, or successful delivery.

### 5.4 Immutable policy and cross-runner authorization stability

**Broker-policy permission** means: the launch-time sandbox policy permits the
authenticated runner to request the specified operation within the specified
resource scope. It does not mean that the operation will succeed or that
filesystem permission checks have passed. "Allowed" without a qualifier is
ambiguous here; use the following distinct terms:

| Term | Meaning | Can X's authorized `chmod` change it for Y? |
| --- | --- | --- |
| Broker-policy permission: `BrokerPolicyAllows(S, y, r, op)` | Whether the sealed broker policy permits Y's fixed operation on the fixed resource/scope. | No. |
| Effect authority: `Grant(S, y, r, op)` | Whether the actual resource effect has the required policy provenance, references/leases, and effect-specific checks from Section 5.2. | Possibly, where the effect depends on filesystem permission checks. |
| Operation result | The returned value/error, and any authorized partial effects, under current filesystem/object state. | Yes; a policy-permitted operation can return a filesystem permission error. |

#### Definition of `BrokerPolicyAllows`

Let `Sandbox(S, y)` and `Principal(S, y)` be derived from broker-authenticated
bindings, never request-supplied credentials. Let `Cfg_launch.Rules[s]` be the
trusted allow rules sealed for sandbox `s` at launch. Define:

```text
BrokerPolicyAllows(S, y, r, op) ==
    exists rule in Cfg_launch.Rules[Sandbox(S, y)]:
        Matches(rule, Principal(S, y), r, op)
```

`Matches` interprets a configured rule's principal, resource/scope, operation,
and argument restrictions. It is a pure predicate on those fixed inputs; it
does not consult mutable filesystem state. No matching rule means policy deny.
Resource/scope restrictions still apply: permitting `open` in one filesystem
scope does not permit opening arbitrary host files.

`Rules` and `Matches` are logical notation, not existing `PolicyEngine` fields
or a claim that LiteBox has a universal per-syscall allowlist. Each component
must interpret them using its actual policy checks and launch-time resource
configuration, with a proved refinement relation as described in Section 9.

Filesystem permission bits, file ownership, mutable file contents, free quota,
request scheduling, and response success are not inputs to this predicate.
Ownership here means filesystem UID/GID metadata, not broker handle ownership
in `B.H`. The latter remains a separate effect-authority check.

Policy permission allows processing subject to the remaining checks; it does
not require a provider call or successful I/O. Invalid handles, filesystem
permission errors, missing files, or exhausted resources can still prevent an
effect. Conversely, permissive filesystem mode bits cannot override a broker
policy denial. This distinction is logical, not a requirement for separate
wire-level response fields or different errno values.

#### Cross-runner property

For distinct runners `x` and `y` in the same sandbox, arbitrary actions by `x`
must preserve this decision for a fixed `y`, `r`, and `op`. In particular:

- No runner may update the shared broker policy or forge the authenticated
  sandbox/principal binding used by the decision.
- Shared file contents, permission bits, ownership, and ordinary object state
  may change through policy-authorized operations; those changes cannot become
  changes to protected broker-policy metadata.
- `x` cannot forge `y`'s identity or mutate `y`'s existing private references,
  rights, or leases outside a separately specified transfer/lifecycle rule.

`BrokerPolicyAllows` is not the whole `Grant` predicate. `Grant` additionally checks
the concrete reference, lease, lifecycle, and other operation prerequisites in
Section 5.2. A policy denial cannot be overridden by creating a handle; leases
and delegated authority must originate in policy-permitted operations. Explicit
transfer/inheritance may create new references within the unchanged policy;
it is not a policy update.

The stability claim fixes resource identity, not merely a pathname or reused
numeric descriptor. Rename, unlink, replacement, or symlink changes can make the
same pathname name a different resource or no resource. Resolution must still
enforce the sealed policy for the actual target; this is not a claim that path
resolution is stable. Similarly, filesystem permissions/ownership, shared
contents, file offsets, resource exhaustion, and lifecycle changes may change
syscall results without changing the policy decision. Even a filesystem
permission error is an execution result, not a broker-policy rejection, when
`BrokerPolicyAllows` remains true. Identical errno values need not identify the same
decision stage. Full `Grant` equality additionally requires preservation of its
reference/lease/lifecycle and other non-policy authorization inputs.

## 6. Broker validity: `Inv(B)`

`Inv(B)` is the conjunction of the following invariants:

| Invariant | Exact obligation |
| --- | --- |
| Private execution safety | `B.M` is not `BadBroker`. Broker accesses respect allocation bounds, access permissions, ownership, and lifetimes; no use-after-free/double-free, attacker-controlled return/call target, or shared writable alias of trusted authority metadata is accepted. |
| Configuration integrity | Every post-launch step preserves the sealed `B.Cfg`; no runner or maintenance path may update policy or reclassify untrusted data as an authenticated credential. |
| Policy/result separation | Authorized filesystem metadata changes cannot alter the sealed broker policy, authenticated principal bindings, or broker reference rights. Filesystem permission checks may change execution results without changing `BrokerPolicyAllows`. |
| Identity/association integrity | Process keys are unique and association bindings refer to the correct retained process lifetime. Caller identity comes from setup; lifecycle/namespace registries and parent/child relations remain consistent. |
| Reference integrity | Every live handle has one owner and one correctly typed object; process reference indexes agree with the global table. Objects/resources remain alive while references or valid leases retain them. |
| Authority provenance | Every reference, lease, and pending grant comes from trusted initialization or a permitted creation/transfer/authorization transition. Rights cannot be widened from runner assertions. |
| Freshness/lifetime integrity | Handle/process-key allocation cannot wrap into an old identity. Namespace IDs are not recycled while their lifetime accounting still retains them. |
| Quota integrity | For each scope/kind, recorded usage equals live charges plus the already-acquired charges of pending reservations, and does not exceed its ceiling. Counts/byte totals cannot overflow or underflow. |
| Protocol integrity | Buffer layouts/indices/ranges are bounded; active slots cannot overlap requests; reuse obeys sequence rules. Failed associations admit no fresh operations; already-authorized leases follow their specified lifetime. |
| Lease integrity | An in-flight lease is bound to the authorized caller, operation, resource, and budget; cancellation/completion releases its state according to the defined lifetime. |

Accounting is per scope: reserving a broker slot and then a process slot need
not be one atomic action. Ghost pending charges account for the intermediate
state, and failure must roll back only charges actually acquired.

`Inv` does not assert that runner-controlled bytes are honest or immutable.
Nor is it a definition of all functional file/socket semantics. It states the
conditions needed to preserve security. Stronger functional correctness or
availability specifications can be added separately.

Private execution safety requires concrete memory-safety/refinement obligations.
Merely assigning an abstract `BadBroker` flag or proving map invariants does
not prove that actual unsafe/FFI code cannot corrupt memory.

## 7. Execution: `Step(S, a, S', E)`

`Step(S, a, S', E)` means that the implementation and modeled kernel/providers
can move from state `S` to state `S'` while processing action `a`, emitting the
actual effects `E`. A trace is an initial state followed by such transitions.

It is an **implementation execution relation**, not a definition that filters
out unauthorized behavior. A bad implementation can have a step into
`BadBroker`, an invalid table state, or an unauthorized effect. Those steps
must fail the proof rather than disappear from the model.

Transitions include:

| Phase/action | State that may evolve and what must be proved |
| --- | --- |
| Runner mutation/raw syscall | `X` may change arbitrarily within runner/shared memory. `K` applies the actual syscall/descriptor rules. No direct change to broker-private authority is permitted. |
| Association setup/admission | Authenticate the expected process lifetime, negotiate bounded layouts, and bind broker-private association state. Authentication does not validate client behavior. |
| Receive/decode | Read arbitrary messages/bytes; validate framing, discriminants, lengths, indices, and actual copied values. Malformed input follows the specified error/termination path. |
| Authorize/reserve | Resolve the bound caller and exact target, establish a grant, and acquire only the required leases/charges. Failure publishes no unauthorized authority. |
| Apply/provider completion | Change typed object state, including filesystem permissions/ownership when authorized, or perform external effects within the checked operation, preserving sealed broker policy and authority invariants. Leases capture authority across lock release and concurrent close; provider results must satisfy their contracts. |
| Response/delegation | Emit bounded correlated responses and notifications; delivered host objects preserve the granted scope/access. Free request resources at their specified lifetime. |
| Close/cancel/retire | Remove only authorized references or specified maintenance-owned state. Preserve outstanding leases and identity/resource lifetime accounting until release is valid. |

A single high-level request can take many steps. Concurrent requests, close,
shared-memory writes, and provider completions may interleave between them.
The model must not silently make a whole request atomic.

Snapshot rules are operation-specific: validate the bytes actually consumed.
If a field is checked then re-read from writable shared memory, a proof must
handle that change explicitly. Validating the buffer's bounds does not make its
contents stable. A notification or later provider effect still needs a recorded
authorization/maintenance origin.

## 8. Formal obligations and composition

In the formulas below, `B` and `B'` are the broker components of `S` and `S'`;
`forall` means every choice, `in` means sequence membership, `and` is conjunction,
and `=>` is implication. Primed state means the state after one transition.
`resource(e)` and `operation(e)` extract the target and complete operation from
the effect record. Quantification includes every permitted scheduling choice.

**Single security goal: sandbox confinement under immutable policy**

```text
For every reachable S and Step(S, a, S', E):
    B.Cfg = Cfg_launch and B'.Cfg = Cfg_launch
    forall process p:
        forall e in E:
            GuestEffect(e, p)
            => Grant(S, p, resource(e), operation(e))
```

Reachable states start from valid trusted configuration and established runner
confinement. Grants may use live leases carrying earlier checked authority.
This formula concerns actual effects, not only admitted API calls.

**Obligation A: broker integrity and faithful enforcement**

```text
Initialization: Inv(B_initial)

Preservation:
    forall S, a, S', E:
        Inv(B) and KernelBoundary(S) and Step(S, a, S', E)
        => Inv(B') and
           (forall e in E:
                BrokerEffect(e) => AuthorizedEffect(S, a, e))
```

The preservation obligation is conditional on `KernelBoundary` and the external
kernel/execution and provider contracts in Section 3, not on an honest runner.
With valid initialization and the separate boundary-preservation obligations,
induction establishes `Inv` and permitted broker effects for every finite trace
prefix. Memory corruption or an unauthorized broker effect is a counterexample,
even if it happens before any response is returned.

Obligation A establishes confinement for broker-mediated guest effects through
the grant case of `AuthorizedEffect`. It does not cover effects performed
directly by a runner merely because the broker remains intact.

**Obligation B: native-operation confinement and boundary preservation**

```text
For every S, a, S', E:
    Inv(B) and KernelBoundary(S) and Step(S, a, S', E)
    => KernelBoundary(S') and
       (forall p, e in E:
            GuestEffect(e, p) and not BrokerEffect(e)
            => Grant(S, p, resource(e), operation(e)))
```

This includes raw host operations and direct uses of delivered descriptors,
mappings, or retained kernel references. It must follow from the concrete
filters, descriptors, mappings, and platform contracts, not from defining
`KernelBoundary` to mean every effect is authorized.

**Obligation C: correct deployment and composition**

Trusted bootstrap establishes `Inv(B_initial)`, `KernelBoundary(S_initial)`,
the intended sealed configuration, and provenance for every initial descriptor,
mapping, and reference before untrusted execution. Delegation and subsequent
process creation preserve those conditions. This is a deployment proof
obligation, not an implication of broker memory safety.

With policy immutability below, initialization and preservation give the
invariants for every finite trace prefix. Every guest effect is either a
broker effect covered by A or a direct effect covered by B, establishing the
single sandbox-confinement goal. C supplies the valid starting boundary.
Under a deployment contract that already guarantees B and C, the broker
enforcement proof is sufficient for the composed claim; the contract must be
stated explicitly rather than presented as another independent security goal.

**Immutable policy and cross-runner decision preservation**

Let `Cfg_launch` be the sealed configuration. `XStep(S, x, a, S', E)` is an
implementation `Step` attributable to `x`, including broker/provider processing
of its requests and specified cleanup triggered by its actions; origin must be
derived from trusted records, not asserted by `x`.

```text
For every reachable post-launch Step(S, a, S', E):
    B.Cfg = Cfg_launch and B'.Cfg = Cfg_launch
    ExistingPrincipalBindingsPreserved(S, S')

For every reachable XStep(S, x, a, S', E):
    forall y, r, op:
        x != y and SameSandbox(S, x, y)
        and FixedAuthorizationQuery(S, S', y, r, op)
        => BrokerPolicyAllows(S, y, r, op) = BrokerPolicyAllows(S', y, r, op)
```

`ExistingPrincipalBindingsPreserved` preserves authenticated sandbox/principal
bindings for retained process lifetimes; new runners receive trusted bindings
under the sealed policy. `FixedAuthorizationQuery` compares the same retained
runner identity, canonical resource/scope, and complete operation in both states,
not fresh resolution of mutable request bytes. It does not assume the conclusion
or equality of the whole authorization state: preservation of the policy and
principal binding must be proved separately. Filesystem metadata need not be
equal. Resource deletion/replacement does not permit identity reuse.

Induction over X-attributable steps gives the same policy decision after any
finite sequence of X's actions. In an interleaved trace, steps of other origins
have their own obligations; equality of the full `Grant` requires its additional
inputs to remain unchanged. The theorem permits data sharing, does not promise
unchanged syscall outcomes, and is not full information-flow noninterference.

## 9. Top-down proof decomposition for LiteBox

| Proof area | Derived obligation | Implementation/proof boundary |
| --- | --- | --- |
| Broker-mediated enforcement | Bound caller + exact reference/scope + operation grant precedes every effect. | [`broker host endpoint`](../litebox_broker_host/src/lib.rs), [`core process authorization`](../litebox_broker_core/src/process.rs), typed object methods. |
| Native confinement and bootstrap | All relevant runner execution paths face the intended syscall rules; ambient descriptors cannot bypass grants. | [`runner bootstrap`](../litebox_runner_linux_userland/src/lib.rs), [`seccomp`](../litebox_platform_linux_userland/src/lib.rs), [`descriptor setup`](../litebox_broker_userland/src/runner.rs). |
| Delegation confinement | Delivered descriptors/mappings preserve the granted resource/access and lifetime. | [`shared-object delivery`](../litebox_broker_userland/src/shared_objects.rs), kernel/provider contracts. |
| Broker integrity: identity and authority | Association bindings, handle ownership/type, grant provenance, and rights attenuation remain valid. | [`peer authentication`](../litebox_broker_transport_linux_userland/src/unix_socket/host.rs), [`object references`](../litebox_broker_core/src/object.rs), [`process operations`](../litebox_broker_core/src/process.rs). |
| Immutable shared policy | Launch seals policy; all subsequent steps preserve it and authenticated principal bindings. X's actions preserve Y's fixed policy decision even when authorized operations change shared filesystem permissions or ownership. | [`policy engine`](../litebox_broker_core/src/policy.rs), process/association bindings, [`filesystem service`](../litebox_broker_core/src/fs/service.rs), provider contracts and direct-host access restrictions. |
| Broker integrity: state/accounting | Every lifecycle, allocation, failure, and teardown step preserves registries and charges under interleavings. | [`core limits/allocation`](../litebox_broker_core/src/lib.rs), [`quota reservations`](../litebox_broker_core/src/quota.rs), process/object lifetimes. |
| Broker integrity: hostile-input safety | Arbitrary bytes and races cannot reach invalid memory/control flow or forge trusted metadata. | Host endpoint, [`transport`](../litebox_broker_transport/src/lib.rs), concrete shared-memory/FFI/provider contracts. |

The table identifies proof obligations, not the implementation order. Verify
one access-control component at a time, in the estimated simple-to-hard order
below. Introduce shared ghost state and verified helpers such as
`authorized_object` only as needed by the current component; do not
require a proof of the entire authority core before the first component result.

For each method, specify its permitted mutations/effects before proving its
implementation. Do not define `Step` as "whatever satisfies the invariant" or
define `Grant` as "whatever the implementation allowed"; that would make the
security theorem circular.

Finally show that concrete executions refine the model, including unsafe/FFI
accesses and provider callbacks. A core proof over typed requests does not prove
wire parsing, shared-memory race handling, syscall-filter completeness, or host
backend confinement.

### Code-facing predicates and refinement map

Every predicate used in a component proof must name its concrete state view,
the implementation function it constrains, and the point where it is checked.
Use the following starting map rather than inventing a second broker API:

| Specification concept | Current LiteBox representation | Required connection |
| --- | --- | --- |
| Sealed policy in `B.Cfg` | `BrokerCore::policy: PolicyEngine`, supplied to `BrokerCore::new`; component resource configuration may also reside in providers/file services. | Define a ghost launch snapshot and prove post-launch operations preserve its concrete interpretation. `PolicyEngine` alone does not encode every backend boundary. |
| Runner identity `p` | `BrokerProcess::key: ProcessKey`; `BrokerHostAssociation::process` retains the associated process. | Dispatch must use that retained identity, not a request-supplied PID or credential. |
| Policy principal | `BrokerProcess::caller_credential: CallerCredential`. | Model the existing credential classes separately from unique `ProcessKey` ownership. Do not equate guest `FileUser` UID/GID with this credential. |
| Sandbox identity `s` | A deployment-level grouping to relate to the selected core, job, file service, and launch context. | Establish this mapping at trusted launch; do not assume `Job`, PID namespace, or a shared core is already the abstract sandbox identifier. |
| References in `B.H` | `BrokerCore::references` maps `ObjectHandle` to `ObjectReference { owner, rights, object, ... }`. | Define a map view preserving exact handle, owner, rights bits, and stable underlying object identity. |
| Reference authorization | `BrokerProcess::authorized_object` and `authorized_object_with_any_rights`. | Prove lookup and owner equality, then all-required-rights containment or any-rights intersection respectively. The two helpers have different contracts. |
| Resource identity and leases | `ObjectEntry` variants, retained `Arc<RwLock<ObjectEntry>>`, and operation/provider-specific retained resources. | Relate the returned object and eventual effect target to the checked identity; ghost identities must not be reused across lifetimes. An `Arc` alone is not the whole operation-authorization proof. |
| Mutable filesystem state | `BrokerProcess::fs: Arc<dyn FileService>`, `File::state: Arc<dyn OpenFile>`, resolver/backend state. | Specify provider effects separately from broker-policy permissions; mode/ownership changes do not rewrite principal rights. |

For example, the reference-table part of authorization has this Verus-style
shape. `ReferenceView` is a proposed proof-source type containing `owner: int`,
`rights: u32`, and a stable ghost object identity; mathematical handle/key
values represent the corresponding concrete newtypes, not caller assertions.

```rust
spec fn reference_allows(
    refs: Map<int, ReferenceView>,
    caller: int,
    handle: int,
    required: u32,
) -> bool {
    refs.dom().contains(handle)
        && refs[handle].owner == caller
        && (refs[handle].rights & required) == required
}
```

The concrete refinement target is
[`authorized_object`](../litebox_broker_core/src/process.rs): at its
reference-table read-lock snapshot, normal return is successful exactly when
this predicate holds, and success returns the same retained underlying object.
Object-kind checks occur in the typed operation helpers, not in this predicate.
Do not require the table entry to remain live after lock release: an authorized
retained operation may outlive concurrent close.

Express the policy/result distinction at actual call sites:

```text
fs::chmod(process, path, user, mode):
    process.require_object_rights(WRITE)  // broker-policy gate
    validate_path(path)
    process.fs.chmod(path, user, mode)   // filesystem operation/result
```

`require_object_rights` calls
`PolicyEngine::principal_object_rights(process.caller_credential)`. Its policy
predicate is a nonempty configured principal-rights result containing `WRITE`;
filesystem mode and `FileUser` are not inputs to that check. Thus X's authorized
`chmod` can change filesystem state used while serving Y without changing Y's
fixed policy predicate. File read/write through existing handles instead use
the reference-rights path (`WAIT`/`WRITE`) and typed file checks; do not pretend
every file operation invokes the same policy function.

For network destinations, map the specification to
`PolicyEngine::authorize_socket_connect` and `socket::transport_connect`.
The policy view must include protocol enablement, permitted internal guest
destinations, and configured per-credential CIDR/port rules. It is not simply
"match a configured external rule": enabled protocols also permit internal
guest addresses. Prove the normalized destination checked by the policy is the
one used for the provider effect. X's socket-state changes may alter Y's result,
but cannot alter this fixed-input policy predicate.

For each covered operation, write its concrete precondition, permitted state
mutations, retained authority, and effect postcondition in the separate proof
sources. Prove both policy-decision agreement and decision-to-effect binding;
neither an error code nor a successful response establishes those properties.
Frame conditions must allow specified transfer/lifecycle effects, rather than
incorrectly freezing all reference state.

**Unresolved implementation linkage must remain visible.** This mapping and
the code sketch are not executable proofs. Use existing read-only interfaces
where sufficient; crate-private state or unannotated implementation bodies may
prevent a separate proof target from establishing the needed refinement.
An external specification, assumed function contract, or verified copy does
not by itself verify the original implementation. Record that linkage as
unproved and ask before any implementation annotation, visibility change, or
refactor needed to discharge it.

### Verification source layout and implementation changes

All verification agents use a self-contained, repository-root `vlitebox` Cargo
crate. Unproved dependency contracts live in a separate, reusable
`vlitebox-thirdparty` crate. Specs/proofs needing private implementation access
may instead live in clearly named `xxx_spec.rs` files inside the executable
crate, wired through verification-only modules. The required target layout is:

```text
vlitebox/
  Cargo.toml
  lib.rs
  trusted/
    <component>_spec.rs
  properties/
    <component>_proof.rs
  <component>_spec.rs
  <component>_proof.rs
vlitebox-thirdparty/
  Cargo.toml
  src/
    lib.rs
    <dependency>_spec.rs
litebox_broker_core/src/
  <component>_spec.rs
```

Add files only when needed. The developer-must-read boundary consists of
`vlitebox/src/trusted/`, the top-level theorem statements in `vlitebox/src/properties/`,
and the dependency contracts in `vlitebox-thirdparty`, not all proof machinery:

- `trusted/<component>_spec.rs` states the intended guarantees and the semantic
  types, views, and definitions needed to understand their strength. These are
  proof targets, not assumed truths.
- `vlitebox-thirdparty/src/<dependency>_spec.rs` contains unproved dependency or
  external contracts, when necessary. These are actual assumptions and must be
  identified separately from proved guarantees. Do not invent assumptions or
  empty dependency-spec files merely to fill the layout.
- `<component>_spec.rs` contains intermediate models and derived definitions.
  `<component>_proof.rs` contains supporting lemmas and refinement proofs.
  Neither may hide additional assumptions or weaken the intended guarantee.
- `properties/<component>_proof.rs` contains the proved top-level properties
  and their proof entry points. Review the theorem statements, including all
  preconditions and conclusions, together with the trusted semantic definitions.
  Proof bodies may use intermediate specs and lemmas. State explicitly whether
  each property concerns a model or the original implementation; placement here
  does not turn a model theorem into an implementation proof.

For implementation-linked results, verify the original executable crate and
the consuming `vlitebox` property target. A successful property-target run alone
checks composition against imported contracts, not the executable bodies that
must establish those contracts.

The `vlitebox-thirdparty` crate shares dependency contracts across component
proofs; it must not contain assumed LiteBox authorization or confinement
guarantees. Proof results must identify the contracts they rely on. Create the
crate when the first dependency contract is needed, rather than adding an empty
crate. Its Rust import name is `vlitebox_thirdparty`.

The `vlitebox` crate consumes executable-crate verification interfaces; executable
crates must not depend back on `vlitebox`. Keep private-state specifications
local rather than widening runtime visibility or source-including implementation
files into the external proof crate. Semantically relevant crate-local specs
also belong to the developer-must-read boundary.

The review boundary includes every definition transitively determining the
meaning of a stated guarantee; a short top-level predicate is insufficient if
its meaning is hidden in intermediate files. Trusted specifications must not
depend semantically on intermediate specs or proofs. Any custom `assume`,
axiom, `external_body`, or assumed function contract must be visible in the
reviewed trust boundary. Each result must identify the must-read files, all
custom assumptions, and whether it proves a model or the original implementation.

Annotate original implementation types with `#[verus_verify]` and executable
functions with `#[verus_spec]`, rather than wrapping executable code in a large
`verus!` block. Work incrementally: types outside the current proof slice may
temporarily remain opaque/external, with a clear "in progress / unverified"
comment. Do not treat those declarations as completed verification or assume
the current authorization target. Prefer references
to the reviewed contract over duplicated security definitions. Separate
specification and proof files may freely use `verus!`. Source organization alone
does not establish the connection to the original implementation.

For this verification effort, the user approves annotations and necessary
build/module wiring in executable crates. Clearly distinguish erased annotations
and proof instrumentation from executable logic. Preserve runtime statements,
algorithms, signatures, and visibility. Refactors, helper extraction, behavior
changes, or bug fixes still require separate approval; do not change correct
implementation code merely to simplify a proof.

### 9.1 Component-by-component Verus verification plan

The milestones are horizontal: each takes one service component from its policy
definition through concrete enforcement. They are not "model everything, then
prove everything, then connect everything." Start with a small shared vocabulary
for sandbox/principal identity, sealed configuration, and fixed policy queries;
extend it only when the next component needs more state.

Difficulty below estimates access-control enforcement and cross-runner policy
stability, not full filesystem, TCP, scheduler, or Linux ABI correctness. It is
relative, based on the current code structure, and may change when concrete
refinement gaps are discovered. A policy-model proof alone is not completion
of a component.

| Recommended order | Component | Estimated difficulty | Main reason |
| --- | --- | --- | --- |
| 1 | Basic IPC object access control | Low-medium for event-counter checks; medium for the component | Small typed objects and common handle checks; readiness, close, and blocking introduce concurrency. |
| 2 | Network access control | Low-medium for policy checks; medium-high for complete enforcement | Explicit socket/destination checks in `policy.rs`; actual endpoint selection and all I/O paths still need coverage. |
| 3 | File access control | High | Path resolution, aliases, mutable namespace/permissions, open modes, and multiple providers. |
| 4 | Process access control | Very high | Creation/inheritance, process identity, groups, signals, and asynchronous retirement affect many components. |
| 5 | Shared mappings and synchronization | Very high; strongest external dependencies | Memory aliasing, unmapping, direct-host authority, and synchronization cross broker/runner/kernel boundaries. |

Split IPC into basic objects and shared-memory/synchronization so the first IPC
result does not depend on proving memory mapping and futex behavior.

The syscall lists below map **guest Linux entry points** to proof scope, using
[`SyscallRequest::try_from_raw`](../litebox_common_linux/src/lib.rs) and the
[`Linux shim dispatch`](../litebox_shim_linux/src/lib.rs) as the current inventory.
Legacy names vary between x86-64 and AArch64. Being listed does not mean every
flag/subcommand is supported, every call reaches the broker, or the call has
already been verified. The broker proof remains guest-neutral.

1. **Basic IPC object access control.** Begin with event counters, then pipes,
   timers, and readiness queues. Verify object creation, owner/type/rights
   checks, permitted sharing, close, and retained operation lifetimes. Add
   blocking/cancellation and readiness registration without assuming an entire
   request is atomic. Shared data and readiness may change, but cannot rewrite
   broker policy or forge foreign references. Complete Unix-domain socket
   integration in the following network milestone.

   **Related syscalls:** `eventfd`, `eventfd2`, `pipe`, `pipe2`, `socketpair`;
   `timerfd_create`, `timerfd_settime`, `timerfd_gettime`; `epoll_create`,
   `epoll_create1`, `epoll_ctl`, `epoll_wait`, `epoll_pwait`; `poll`, `ppoll`,
   `select`, `pselect6`. Include generic descriptor calls on these objects.
   Sharing through ancillary `sendmsg`/`recvmsg` data is not assumed supported:
   the current send path rejects ancillary data.

   **Deliverable:** access-control enforcement and stability for the covered
   IPC objects and their common reference checks; mapping/futex proofs are deferred.
2. **Network access control.** Start with socket creation and normalized
   destination checks, which already have explicit authorization functions in
   [`policy.rs`](../litebox_broker_core/src/policy.rs). Extend to socket-reference
   rights and all supported bind, connect, listen/accept, and send/receive paths.
   Include per-message destinations and newly accepted sockets; a check on one
   endpoint cannot justify effects on another. Prove X's network actions preserve
   Y's fixed network-policy decision even when connection state or I/O results
   change. Cover the supported address families separately rather than assuming
   an IPv4 proof also covers Unix-domain sockets or vsock. Preserve the earlier
   IPC-object invariants when sockets use the common object tables.

   **Related syscalls:** `socket`, `bind`, `connect`, `listen`, `accept`,
   `accept4`, `sendto`, `sendmsg`, `sendmmsg`, `recvfrom`, `recvmsg`, `recvmmsg`,
   `shutdown`, `getsockname`, `getpeername`, `setsockopt`, `getsockopt`.
   Socket use of generic descriptor calls is included below; Unix-domain
   `socketpair` also belongs to the IPC milestone.

   **Deliverable:** network access-control enforcement and stability for the
   covered families/operations under explicit backend contracts; no TCP-stack
   correctness claim.
3. **File access control.** Start with policy checks for open/path access and
   read/write through file references. Model configured filesystem scopes,
   resource identity, reference rights, and mutable filesystem state. Connect
   the model to the filesystem service and the concrete authorization helpers
   it uses. Prove that effects stay within the permitted scope and rights,
   guessed foreign handles do not grant access, and X's file operations preserve
   Y's fixed file-policy decision. Include authorized `chmod`/`chown`: they may
   change filesystem checks and returned errors, not broker-policy permission.
   Extend this milestone to create, rename, unlink, duplication, close, and
   retained leases; state any provider/path-resolution assumptions explicitly.

   **Related syscalls:** `open`, `openat`, `creat`; `read`, `write`, `readv`,
   `writev`, `pread64`, `pwrite64`, `preadv`, `pwritev`, `lseek`, `sendfile`,
   `ftruncate`; `stat`, `lstat`, `fstat`, `newfstatat`/`fstatat`, `statx`,
   `statfs`, `fstatfs`, `getdents64`; `access`, `faccessat`, `faccessat2`;
   `mkdir`, `mkdirat`, `mknod`, `mknodat`, `symlink`, `symlinkat`, `readlink`,
   `readlinkat`, `rename`, `renameat`, `renameat2`, `unlink`, `unlinkat`,
   `rmdir`; `chmod`, `fchmodat`, `chown`, `fchownat`, `umask`, `utime`,
   `utimes`, `futimesat`, `utimensat`; `getcwd`, `chdir`, `fchdir`, `flock`,
   `mount`. Current `mount` handling is restricted to fresh tmpfs mounts, not
   arbitrary host mounts. File-backed `mmap` also needs the mapping milestone.

   **Deliverable:** verified file access-control enforcement and its stability
   theorem for the covered operations, not a proof of all filesystem semantics.
4. **Process access control.** Add creation/parent-child relationships, target
   process identity, and process-operation permissions. Verify child creation,
   inheritance/transfer, signaling, wait/inspection, and retirement for the
   supported APIs. Children must use the sealed sandbox policy; requests cannot
   forge another runner's principal or target a recycled process identity.
   Distinguish unchanged policy permission from legitimate lifecycle results,
   such as a permitted request finding that its target has exited. Verify
   process steps preserve file/network policy and reference invariants,
   including effects of inheritance and cleanup.

   **Related syscalls:** `clone`, `clone3`, `fork`, `vfork`, `execve`, `exit`,
   `exit_group`, `wait4`, `waitid`; `kill`, `tkill`, `tgkill`, `pidfd_open`,
   `pidfd_send_signal`; `getpid`, `getppid`, `gettid`, `set_tid_address`,
   `setpgid`, `getpgid`, `getpgrp`, `setsid`, `getsid`; `unshare`, `prctl`,
   `arch_prctl`, `set_thread_area`; `getuid`, `geteuid`, `getgid`, `getegid`,
   `getgroups`, `capget`; `getrlimit`, `setrlimit`, `prlimit64`, `getrusage`,
   `sched_getaffinity`, `sched_getparam`, `sched_getscheduler`, `sched_yield`.
   Signal-state/lifecycle entry points also include `rt_sigaction`,
   `rt_sigprocmask`, `rt_sigpending`, `rt_sigtimedwait`, `rt_sigsuspend`,
   `rt_sigreturn`, `sigaltstack`, `alarm`, `setitimer`, `getitimer`, `pause`,
   and `restart_syscall`. Local identity/ABI queries are related entry points,
   not evidence of broker-enforced per-UID policy or a broker round trip.

   **Deliverable:** process access-control enforcement and stability, with
   lifecycle-dependent results separated from policy decisions.
5. **Shared mappings and synchronization.** Verify authority for mapped
   resources, ranges, access modes, retained references, and lifetime across
   remap/unmap, process creation, and teardown. Account for guest-controlled
   aliases and bytes without treating them as trusted broker metadata. Cover
   futex/robust-list interactions and delivered host descriptors/mappings
   against the earlier file/network/process results. Separate runner-local
   memory semantics from broker-owned resource authority and native confinement.

   **Related syscalls:** `mmap`, `mprotect`, `munmap`, `mremap`, `msync`,
   `madvise`, `brk`; `futex`, `set_robust_list`, `get_robust_list`. Cross-component
   entry points include `clone`, `clone3`, `fork`, `execve`, `exit`, and
   `exit_group`. This list does not imply support for System V shared-memory
   syscalls or all Linux futex operations.

   **Deliverable:** mapped-resource and synchronization access-control
   enforcement under explicit kernel/platform contracts, not full memory-model
   correctness or absence of intentional shared-memory communication.

**Descriptor syscalls belong to every applicable component.** Include `close`,
`close_range`, `dup`, `dup2`, `dup3`, `fcntl`, and `ioctl` for each supported
descriptor kind and subcommand. `read`, `write`, `readv`, and `writev` can target
files, sockets, pipes, or event/timer objects; `sendfile` spans input/output
resource checks. Readiness calls also span descriptor kinds. Classify by actual
object and operation, not just by which shim source file contains the handler.

**Inventory limits:** these are access-control-related syscall groups, not a
claim to implement the entire Linux syscall table. For example, `openat2`,
`execveat`, `ptrace`, and `process_vm_readv`/`process_vm_writev` are not decoded by
the current Linux request parser. Likewise, a libc wrapper name such as
`futimens` need not be a separate syscall entry; it can use `utimensat`. Add
newly supported entries to the relevant component before extending its claim.

For **each component**, use Verus `spec fn` definitions and ghost maps for just
its relevant state, prove action-specific invariant preservation and finite-trace
policy stability, and connect the actual policy checks to `BrokerPolicyAllows`.
Prove executable code or helpers actually called by it, not just a disconnected
model. Handle relevant interleavings, leases, cancellation, rollback/accounting,
and hostile request bytes within that milestone rather than postponing all
concurrency or input-safety questions until every service has a model.

Each milestone must name its covered operations, proved entry points, remaining
unverified wrappers, and assumed identity/transport/provider/kernel contracts.
Other components are not implicitly verified: any reliance on their behavior is
an explicit proof boundary. When adding a component, prove its steps preserve
the earlier components' invariants, and check earlier steps against the new
invariants. Only then compose their trace theorems.

Add component proof targets to the existing `cargo verus focus` workflow as
they become executable; the current LVBS target does not cover the broker.
Require proof success without admitted lemmas inside the claimed component
boundary, plus focused runtime regressions for policy denials and permitted
operations whose results can change. End-to-end sandbox claims additionally
require discharging the remaining endpoint, provider, native-confinement, and
shared enforcement contracts. Do not label an early component-only milestone as a
verified broker or a verified whole sandbox.

## 10. Worked reference example

Suppose `B.H[h]` names file object `r`, is owned by `p`, and has `WAIT` but not
`WRITE`; the file's typed access mode also permits reads. The association is
bound to `p`.

- A bounded read using this exact `h` can obtain a lease and satisfy `Grant`.
  Its disclosed bytes must come from the authorized resource/range.
- A write does not satisfy `Grant`: lack of `WRITE` cannot be repaired by a
  runner field claiming more rights.
- A different runner `q` guessing `h` has no reference grant through it, even
  if `q` happens to own another handle to the same shared object.
- If `p` closes `h` after the read acquired a lease, that read may finish.
  A new lookup of `h` cannot reuse the closed reference's authority.
- Racing changes to the request bytes cannot change the lease's trusted target
  into another object; the endpoint must prove how the consumed values are fixed
  or revalidated.

The confinement goal constrains the resulting resource access. Broker-integrity
and enforcement proofs show that admission, lease creation, read, close, errors,
and completion preserve `Inv` and produce only their permitted effects.

### Shared filesystem permissions versus broker policy

Suppose the launch policy permits both X and Y to request `chmod` and read/open
operations within a shared filesystem scope. X successfully changes a shared
file's mode to `000`. Assume Y is subject to the resulting filesystem permission
check, with no credential-based bypass, and is opening the same resource anew
rather than using an already-open descriptor. Then the following is valid:

| Y's request | Broker-policy permission before / after X's `chmod` | Example operation result before / after |
| --- | --- | --- |
| Open the shared file for reading | Permit / Permit | Success / filesystem permission error |
| `chmod` the shared file | Permit / Permit | Determined by filesystem ownership and credentials in each state |
| Open a file outside the permitted scope | Deny / Deny | Policy rejection / policy rejection |

X has changed filesystem state, not Y's broker-policy permission to invoke
`chmod`, open, or read. The broker may itself execute the filesystem checks and
return the resulting error; an error returned by the broker is not necessarily
a broker-policy rejection. The property is equality of `BrokerPolicyAllows`,
not equality of replies or of every check encountered while serving a request.

## 11. Current limits and unproved assumptions

**Guest credentials:** filesystem operations accept request-supplied `FileUser`;
guest UID/GID settings are provisional. Do not assume these are authenticated
process credentials when defining a grant. A stronger UID-based isolation
property requires broker-owned credentials and broker-validated transitions.

**Host filesystem:** the current
[`LocalFs`](../litebox_broker_userland/src/fs/mod.rs) trusts host namespace
administration not to race path checks with renames/replacements/symlink swaps.
Its path-based handles are not pinned directory capabilities. End-to-end path
confinement is conditional on that contract until strengthened.

**Immutable-policy target:** the filesystem service exposes `chmod` and `chown`
and forwards permitted requests to providers. Those operations are not by
themselves a gap in policy immutability: filesystem metadata is allowed to
change. The proof must establish that their implementations and provider
effects cannot change broker policy, authenticated principal bindings, or
existing broker reference rights. This remains a verification target, not a
claim that the concrete paths have already been verified.

**Sharing and quotas:** authorized IPC, shared objects/filesystems, and guest
network access are intentional. Existing quotas cover selected resources, not
all memory, disk, CPU, or effects on other tenants. The fixed-policy decision
property is not full information-flow noninterference or a complete
denial-of-service theorem.

**Deployment:** native containerd mode does not implement all OCI namespace,
user, cgroup, read-only-root, or security-profile settings. Do not derive a
kernel confinement premise from an ignored Docker/OCI option.

**Verification status:** the current workflow verifies `litebox_platform_lvbs`,
not these broker theorems. This document defines the targets and exposes the
contracts still needed; it introduces no executable proof or verified claim.
