# cwfd Phase 2 — next product fixes

## Where we are

The branches landed:
- `wportnoy/cwfd-p2-refactor` (P2.0): `BrokerSubscribable` + `BrokerBackedCommon` + `FdKind` tag
- `wportnoy/cwfd-p2-stubs` (P2.0.5): SubsystemTag/opcode ranges + StateObject trait subscribe/unsubscribe
- `wportnoy/cwfd-p2-pidfd` (P2.B): broker pidfd plumbing (PidfdState + provider + shim variant + sys_pidfd_open routing for remote targets)
- `wportnoy/cwfd-p2-signalfd` (P2.C): broker signalfd plumbing (SignalfdState + payload-variant NotificationFrame + shim variant)
- `wportnoy/cwfd-p2-integration` (this branch): bundles P2.0/0.5/B/C + pidfd-signalfd-tests

Already merged to amalgamation: `wportnoy/pidfd-signalfd-tests` (the 22 new test cases).

## Two product gaps the new tests pin

### Gap #1: `PIDF.exit_inherit.nonpie-glibc` + `non-pie-static-musl` (2 fails, plus legacy `PIF.<bt>` non-PIE = 4 total)

**Symptom**: Child process polls inherited pidfd, gets `POLLNVAL`
(revents=32).

**Cause**: `sys_pidfd_open` on a local fork-child returns an
`EventFile::Pidfd` whose state (`exited: AtomicBool`,
`subject: Subject<Events>`) lives in the parent worker's
`process_registry`. When the parent fork+execvs into a non-PIE
binary, the child migrates to a different host worker. The child's
fd table is reconstructed from a fork-snapshot. The Pidfd's
state isn't serializable — it points into the parent worker's
memory.

**Fix**: extend the fork-snapshot bridge to carry a broker pidfd
handle when migrating across workers:

1. At `commit_delayed_fork` snapshot time, iterate the parent's
   fd table. For each `EventFileInner::Pidfd { exited, subject }`
   entry, get the target's host PID from
   `global.fork_child_host_pids` and call
   `broker_pidfd_provider().create_pidfd(host_pid)` to mint a
   broker handle. Record the handle ID in `FdEntrySnapshot`
   alongside the existing fields.

2. At restore time, for `FdKind::EventFd` entries with a recorded
   broker pidfd handle, construct an
   `EventFileInner::PidfdBrokerBacked { provider, handle, common }`
   using the worker-side `broker_pidfd_provider()` and the
   recorded handle id.

**Subtleties** (must be designed before implementing):
- Refcounting: parent's broker handle creation increments the
  broker's refcount. The parent must NOT release it before the
  child's restore opens its own reference (broker's `dup_handle`).
- Parent's view: should the parent's fd entry remain a local Pidfd
  (so the parent's tokio doesn't see a behavior change) and the
  broker handle exist only in the snapshot record? Yes — the
  snapshot is child-side; parent's view stays put.
- `FdEntrySnapshot` wire format: needs a new optional field for
  the broker-handle id. The structure has a `FdMetadataSnapshot`
  carrying per-fd metadata — extend that with
  `broker_pidfd_handle: Option<u64>`.
- What about non-fork-child pidfds (e.g. tokio's pidfds for its
  own subprocess management)? Only enter the broker path when the
  target IS in `fork_child_host_pids`. Tokio's children are also
  in this map though — so we need a finer check (maybe "only when
  the parent is about to migrate workers", which is the
  delayed-fork case).

This is essentially restricted P2.B step-7 routing — only at
fork-bridge time, not on every `sys_pidfd_open`.

### Gap #2: `SFD.*` × 10 fails

**Symptom**: on amalgamation, sys_signalfd4 returns ENOSYS. On
`cwfd-p2-integration` (with P2.C plumbing), broker call hangs and
the agent times out.

**Cause**: P2.C's broker SignalfdState uses a kernel signalfd
watching host signals. But litebox virtualizes signal delivery in
the shim — the guest's `raise(SIGUSR1)` and `kill(child_pid,
SIGUSR1)` produce *guest* signals that the shim queues internally,
never reaching the host kernel. So the broker signalfd is never
ready.

**Fix**: hook the shim's signal-delivery path so that when a
signal is delivered to a guest process that has subscribed broker
signalfds matching the signal mask, the shim pushes the
`signalfd_siginfo` to the broker signalfd's
SubscriptionList via the existing NotificationDispatcher.

The shim already has a signal-delivery point (search for
`deliver_signal` or `pending_signals`). At that point, check if
any descriptor table entry is a `SignalfdState::BrokerBacked` with
a matching mask, and if so, forward the siginfo.

This is ~2-3 days of work in the shim signal layer.

## Recommended sequence

1. **Design pass for Gap #1's fork-snapshot extension** (~half day).
   Specifically design the FdEntrySnapshot extension + lifetime
   semantics for the broker handle through serialization. Then
   implement (~1-2 days).

2. **Land P2.0 + P2.0.5 + P2.B + Gap #1 fix as a coherent bundle**
   into the amalgamation. Together this flips 4 tests
   FAIL→PASS (2 PIDF + 2 legacy PIF non-PIE).

3. **Land P2.C + Gap #2 fix as a second bundle**. Flips 10 SFD
   tests FAIL→PASS.

4. **P2.A (AF_UNIX) as a separate phase**. Closes BSF + SCM.pass_tcp_socket family.

Net pass-rate impact when all three bundles land: ~18 litebox
tests flipped, plus the substrate for future broker-managed-fd
work.
