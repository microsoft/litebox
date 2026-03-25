// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Multi-host control-plane state for Linux shim process ownership and exec handoff.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicU32, Ordering};

use litebox::{
    process::{ExitNotification, ExitNotificationWire, ExitNotificationWireError, ProcessId},
    sync::{Mutex, RawSyncPrimitivesProvider},
};
use zerocopy::byteorder::{LE, U16};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Stable identifier for a host process participating in one sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct HostId(u32);

impl HostId {
    pub(crate) const ROOT: Self = Self(1);

    pub(crate) fn as_u32(self) -> u32 {
        self.0
    }
}

/// Role of a registered host in the multi-host control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostRole {
    /// The original/root host process that also runs the first coordinator.
    RootCoordinator,
    /// A non-root worker host that can own guest processes after handoff.
    Worker,
}

/// Routing decision for a guest process exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecRoute {
    /// Continue exec in the current host process.
    Local { host: HostId },
}

/// Identifier for a prepared exec-handoff transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ExecHandoffId(u32);

/// Non-terminal stages of the exec-handoff transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecHandoffStage {
    Prepared,
    SourceTornDown,
    StateTransferred,
    TargetLoaded,
    Failed,
}

impl ExecHandoffStage {
    fn next(self) -> Option<Self> {
        match self {
            Self::Prepared => Some(Self::SourceTornDown),
            Self::SourceTornDown => Some(Self::StateTransferred),
            Self::StateTransferred => Some(Self::TargetLoaded),
            Self::TargetLoaded | Self::Failed => None,
        }
    }
}

/// Snapshot of an in-flight exec handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecHandoffSnapshot {
    pub(crate) id: ExecHandoffId,
    pub(crate) process_id: ProcessId,
    pub(crate) source_host: HostId,
    pub(crate) target_host: HostId,
    pub(crate) stage: ExecHandoffStage,
}

/// Semantic outbound control-plane message before transport encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutboundControlPlaneMessage {
    ChildExit(ExitNotification),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum OutboundControlPlaneMessageKind {
    ChildExit = 1,
}

impl TryFrom<u16> for OutboundControlPlaneMessageKind {
    type Error = OutboundControlPlaneMessageWireError;

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        match raw {
            1 => Ok(Self::ChildExit),
            _ => Err(OutboundControlPlaneMessageWireError::UnknownKind(raw)),
        }
    }
}

const OUTBOUND_CONTROL_PLANE_WIRE_VERSION: u16 = 1;

/// Versioned wire record for one outbound control-plane message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub(crate) struct OutboundControlPlaneMessageWire {
    version: U16<LE>,
    kind: U16<LE>,
    child_exit: ExitNotificationWire,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutboundControlPlaneMessageWireError {
    UnsupportedVersion(u16),
    UnknownKind(u16),
    InvalidChildExit(ExitNotificationWireError),
}

/// Envelope queued for transport, including the authenticated sender metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutboundControlPlaneEnvelope {
    pub(crate) source_host: HostId,
    pub(crate) message: OutboundControlPlaneMessageWire,
    pub(crate) local_delivery_completed: bool,
}

impl TryFrom<OutboundControlPlaneMessage> for OutboundControlPlaneMessageWire {
    type Error = OutboundControlPlaneMessageWireError;

    fn try_from(message: OutboundControlPlaneMessage) -> Result<Self, Self::Error> {
        match message {
            OutboundControlPlaneMessage::ChildExit(notification) => Ok(Self {
                version: U16::new(OUTBOUND_CONTROL_PLANE_WIRE_VERSION),
                kind: U16::new(OutboundControlPlaneMessageKind::ChildExit as u16),
                child_exit: ExitNotificationWire::try_from(notification)
                    .map_err(OutboundControlPlaneMessageWireError::InvalidChildExit)?,
            }),
        }
    }
}

impl TryFrom<OutboundControlPlaneMessageWire> for OutboundControlPlaneMessage {
    type Error = OutboundControlPlaneMessageWireError;

    fn try_from(message: OutboundControlPlaneMessageWire) -> Result<Self, Self::Error> {
        let version = message.version.get();
        if version != OUTBOUND_CONTROL_PLANE_WIRE_VERSION {
            return Err(OutboundControlPlaneMessageWireError::UnsupportedVersion(
                version,
            ));
        }

        let kind = OutboundControlPlaneMessageKind::try_from(message.kind.get())?;
        match kind {
            OutboundControlPlaneMessageKind::ChildExit => Ok(Self::ChildExit(
                ExitNotification::try_from(message.child_exit)
                    .map_err(OutboundControlPlaneMessageWireError::InvalidChildExit)?,
            )),
        }
    }
}

/// Control-plane errors while the runtime is still single-host/local-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlPlaneError {
    UnknownHost(HostId),
    UnknownProcess(ProcessId),
    DuplicateProcess(ProcessId),
    HandoffAlreadyActive(ProcessId),
    ProcessOwnedByDifferentHost {
        process_id: ProcessId,
        owner_host: HostId,
        local_host: HostId,
    },
    UnknownHandoff(ExecHandoffId),
    InvalidHandoffTransition {
        current: ExecHandoffStage,
        next: ExecHandoffStage,
    },
    InvalidHandoffAbort(ExecHandoffStage),
    InvalidHandoffCommit(ExecHandoffStage),
    InvalidHandoffCommitOwner {
        process_id: ProcessId,
        expected_source_host: HostId,
        actual_owner: Option<HostId>,
    },
    HandoffTargetMatchesSource {
        process_id: ProcessId,
        host: HostId,
    },
    InvalidOutboundMessage(OutboundControlPlaneMessageWireError),
    OutboundMessageQueueFull {
        target_host: HostId,
        limit: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostEntry {
    role: HostRole,
    parent_host: Option<HostId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChildExitProvenance {
    pub(crate) source_host: HostId,
    pub(crate) notification: ExitNotification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildExitRoute {
    DeliverLocal,
    NoRunningOwner,
    QueuedRemote { target_host: HostId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExecHandoff {
    process_id: ProcessId,
    source_host: HostId,
    target_host: HostId,
    stage: ExecHandoffStage,
}

impl ExecHandoff {
    fn snapshot(self, id: ExecHandoffId) -> ExecHandoffSnapshot {
        ExecHandoffSnapshot {
            id,
            process_id: self.process_id,
            source_host: self.source_host,
            target_host: self.target_host,
            stage: self.stage,
        }
    }
}

const MAX_PENDING_OUTBOUND_CONTROL_PLANE_MESSAGES_PER_HOST: usize = 64;

struct ControlPlaneState {
    hosts: BTreeMap<HostId, HostEntry>,
    running_process_owners: BTreeMap<ProcessId, HostId>,
    child_exit_provenance: BTreeMap<ProcessId, ChildExitProvenance>,
    active_handoffs_by_process: BTreeMap<ProcessId, ExecHandoffId>,
    handoffs: BTreeMap<ExecHandoffId, ExecHandoff>,
    pending_outbound_messages: BTreeMap<HostId, Vec<OutboundControlPlaneEnvelope>>,
}

/// Root-host-owned control-plane state for the multi-host process model.
///
/// The current implementation still runs everything in one host process, but it
/// centralizes the ownership and transaction state that a later `ET_EXEC`
/// handoff will consume.
pub(crate) struct ControlPlane<Platform: RawSyncPrimitivesProvider> {
    root_host: HostId,
    local_host: HostId,
    next_host_id: AtomicU32,
    next_handoff_id: AtomicU32,
    state: Mutex<Platform, ControlPlaneState>,
}

impl<Platform: RawSyncPrimitivesProvider> Default for ControlPlane<Platform> {
    fn default() -> Self {
        Self::new_root_local()
    }
}

impl<Platform: RawSyncPrimitivesProvider> ControlPlane<Platform> {
    /// Create the initial control plane for the root host.
    pub(crate) fn new_root_local() -> Self {
        let root_host = HostId::ROOT;
        let mut hosts = BTreeMap::new();
        hosts.insert(
            root_host,
            HostEntry {
                role: HostRole::RootCoordinator,
                parent_host: None,
            },
        );
        Self {
            root_host,
            local_host: root_host,
            next_host_id: AtomicU32::new(root_host.as_u32() + 1),
            next_handoff_id: AtomicU32::new(1),
            state: Mutex::new(ControlPlaneState {
                hosts,
                running_process_owners: BTreeMap::new(),
                child_exit_provenance: BTreeMap::new(),
                active_handoffs_by_process: BTreeMap::new(),
                handoffs: BTreeMap::new(),
                pending_outbound_messages: BTreeMap::new(),
            }),
        }
    }

    pub(crate) fn root_host(&self) -> HostId {
        self.root_host
    }

    pub(crate) fn local_host(&self) -> HostId {
        self.local_host
    }

    /// Register a worker host under the root coordinator.
    pub(crate) fn register_worker_host(
        &self,
        parent_host: HostId,
    ) -> Result<HostId, ControlPlaneError> {
        let mut state = self.state.lock();
        if !state.hosts.contains_key(&parent_host) {
            return Err(ControlPlaneError::UnknownHost(parent_host));
        }
        let host_id = HostId(self.next_host_id.fetch_add(1, Ordering::Relaxed));
        let replaced = state.hosts.insert(
            host_id,
            HostEntry {
                role: HostRole::Worker,
                parent_host: Some(parent_host),
            },
        );
        debug_assert!(replaced.is_none(), "host ids are monotonically allocated");
        Ok(host_id)
    }

    /// Register a running guest process to the local host.
    pub(crate) fn register_running_process_local(
        &self,
        process_id: ProcessId,
    ) -> Result<(), ControlPlaneError> {
        self.register_running_process(process_id, self.local_host)
    }

    /// Register a running guest process to an arbitrary host.
    pub(crate) fn register_running_process(
        &self,
        process_id: ProcessId,
        host_id: HostId,
    ) -> Result<(), ControlPlaneError> {
        let mut state = self.state.lock();
        if !state.hosts.contains_key(&host_id) {
            return Err(ControlPlaneError::UnknownHost(host_id));
        }
        if state.active_handoffs_by_process.contains_key(&process_id) {
            return Err(ControlPlaneError::HandoffAlreadyActive(process_id));
        }
        if state.running_process_owners.contains_key(&process_id) {
            return Err(ControlPlaneError::DuplicateProcess(process_id));
        }
        state.running_process_owners.insert(process_id, host_id);
        Ok(())
    }

    /// Remove the running-owner entry for a process that has exited or failed to start.
    ///
    /// A handoff that never advanced past `Prepared` can be discarded here. Once
    /// teardown has started, exit converts it into an explicit terminal failure
    /// state so later code can still observe what happened without leaving the
    /// handoff active forever.
    pub(crate) fn unregister_running_process(&self, process_id: ProcessId) -> Option<HostId> {
        let mut state = self.state.lock();
        if let Some(&handoff_id) = state.active_handoffs_by_process.get(&process_id) {
            let handoff_stage = state.handoffs.get(&handoff_id).map(|handoff| handoff.stage);
            match handoff_stage {
                Some(ExecHandoffStage::Prepared) => {
                    state.active_handoffs_by_process.remove(&process_id);
                    state.handoffs.remove(&handoff_id);
                }
                Some(_) => {
                    state.active_handoffs_by_process.remove(&process_id);
                    if let Some(handoff) = state.handoffs.get_mut(&handoff_id) {
                        handoff.stage = ExecHandoffStage::Failed;
                    }
                }
                None => {
                    state.active_handoffs_by_process.remove(&process_id);
                }
            }
        }
        state.running_process_owners.remove(&process_id)
    }

    /// Record the authoritative child-exit facts until the notification is consumed.
    pub(crate) fn record_child_exit_provenance(
        &self,
        source_host: HostId,
        notification: ExitNotification,
    ) {
        let mut state = self.state.lock();
        let previous = state.child_exit_provenance.insert(
            notification.child_pid,
            ChildExitProvenance {
                source_host,
                notification,
            },
        );
        debug_assert!(
            previous.is_none()
                || previous
                    == Some(ChildExitProvenance {
                        source_host,
                        notification,
                    }),
            "child exit provenance should be unique per exited child"
        );
    }

    /// Return the current owner host for a running guest process.
    pub(crate) fn owner_of_running_process(&self, process_id: ProcessId) -> Option<HostId> {
        self.state
            .lock()
            .running_process_owners
            .get(&process_id)
            .copied()
    }

    /// Return the authoritative child-exit facts for a not-yet-consumed notification.
    pub(crate) fn child_exit_provenance(
        &self,
        process_id: ProcessId,
    ) -> Option<ChildExitProvenance> {
        self.state
            .lock()
            .child_exit_provenance
            .get(&process_id)
            .copied()
    }

    /// Clear the child-exit proof once the notification has been consumed locally.
    pub(crate) fn clear_child_exit_provenance(
        &self,
        process_id: ProcessId,
    ) -> Option<ChildExitProvenance> {
        self.state.lock().child_exit_provenance.remove(&process_id)
    }

    /// Drop any pending child-exit proofs targeted at a parent that is exiting.
    pub(crate) fn clear_child_exit_provenance_for_parent(&self, parent_pid: ProcessId) {
        self.state
            .lock()
            .child_exit_provenance
            .retain(|_, proof| proof.notification.parent_pid != parent_pid);
    }

    /// Return whether a host id is currently registered in this control plane.
    pub(crate) fn is_registered_host(&self, host_id: HostId) -> bool {
        self.state.lock().hosts.contains_key(&host_id)
    }

    /// Route a child-exit notification based on the parent's current owner.
    ///
    /// This re-reads the owner and queues any remote delivery while holding the
    /// control-plane lock so ownership changes cannot race between lookup and enqueue.
    pub(crate) fn route_child_exit_notification(
        &self,
        source_host: HostId,
        local_host: HostId,
        notification: ExitNotification,
        local_delivery_completed: bool,
    ) -> Result<ChildExitRoute, ControlPlaneError> {
        let wire_message = OutboundControlPlaneMessageWire::try_from(
            OutboundControlPlaneMessage::ChildExit(notification),
        )
        .map_err(ControlPlaneError::InvalidOutboundMessage)?;
        let mut state = self.state.lock();
        if !state.hosts.contains_key(&source_host) {
            return Err(ControlPlaneError::UnknownHost(source_host));
        }
        if !state.hosts.contains_key(&local_host) {
            return Err(ControlPlaneError::UnknownHost(local_host));
        }
        let Some(owner_host) = state
            .running_process_owners
            .get(&notification.parent_pid)
            .copied()
        else {
            return Ok(ChildExitRoute::NoRunningOwner);
        };
        if owner_host == local_host {
            return Ok(ChildExitRoute::DeliverLocal);
        }
        let queue = state
            .pending_outbound_messages
            .entry(owner_host)
            .or_default();
        if queue.len() >= MAX_PENDING_OUTBOUND_CONTROL_PLANE_MESSAGES_PER_HOST {
            return Err(ControlPlaneError::OutboundMessageQueueFull {
                target_host: owner_host,
                limit: MAX_PENDING_OUTBOUND_CONTROL_PLANE_MESSAGES_PER_HOST,
            });
        }
        queue.push(OutboundControlPlaneEnvelope {
            source_host,
            message: wire_message,
            local_delivery_completed,
        });
        Ok(ChildExitRoute::QueuedRemote {
            target_host: owner_host,
        })
    }

    /// Queue a child-exit notification as a wire record for later remote delivery.
    pub(crate) fn queue_remote_child_exit_notification(
        &self,
        source_host: HostId,
        target_host: HostId,
        notification: ExitNotification,
    ) -> Result<(), ControlPlaneError> {
        let wire_message = OutboundControlPlaneMessageWire::try_from(
            OutboundControlPlaneMessage::ChildExit(notification),
        )
        .map_err(ControlPlaneError::InvalidOutboundMessage)?;
        let mut state = self.state.lock();
        if !state.hosts.contains_key(&source_host) {
            return Err(ControlPlaneError::UnknownHost(source_host));
        }
        if !state.hosts.contains_key(&target_host) {
            return Err(ControlPlaneError::UnknownHost(target_host));
        }
        let queue = state
            .pending_outbound_messages
            .entry(target_host)
            .or_default();
        if queue.len() >= MAX_PENDING_OUTBOUND_CONTROL_PLANE_MESSAGES_PER_HOST {
            return Err(ControlPlaneError::OutboundMessageQueueFull {
                target_host,
                limit: MAX_PENDING_OUTBOUND_CONTROL_PLANE_MESSAGES_PER_HOST,
            });
        }
        queue.push(OutboundControlPlaneEnvelope {
            source_host,
            message: wire_message,
            local_delivery_completed: false,
        });
        Ok(())
    }

    /// Queue a pre-encoded outbound envelope for a host to retry or consume later.
    pub(crate) fn queue_outbound_envelope_for_host(
        &self,
        target_host: HostId,
        envelope: OutboundControlPlaneEnvelope,
    ) -> Result<(), ControlPlaneError> {
        let mut state = self.state.lock();
        if !state.hosts.contains_key(&envelope.source_host) {
            return Err(ControlPlaneError::UnknownHost(envelope.source_host));
        }
        if !state.hosts.contains_key(&target_host) {
            return Err(ControlPlaneError::UnknownHost(target_host));
        }
        let queue = state
            .pending_outbound_messages
            .entry(target_host)
            .or_default();
        if queue.len() >= MAX_PENDING_OUTBOUND_CONTROL_PLANE_MESSAGES_PER_HOST {
            return Err(ControlPlaneError::OutboundMessageQueueFull {
                target_host,
                limit: MAX_PENDING_OUTBOUND_CONTROL_PLANE_MESSAGES_PER_HOST,
            });
        }
        queue.push(envelope);
        Ok(())
    }

    /// Restore one in-flight local envelope to the front of the local queue.
    pub(crate) fn restore_local_outbound_envelope(
        &self,
        envelope: OutboundControlPlaneEnvelope,
    ) -> Result<(), ControlPlaneError> {
        let mut state = self.state.lock();
        if !state.hosts.contains_key(&envelope.source_host) {
            return Err(ControlPlaneError::UnknownHost(envelope.source_host));
        }
        let queue = state
            .pending_outbound_messages
            .entry(self.local_host)
            .or_default();
        queue.insert(0, envelope);
        Ok(())
    }

    /// Drain any queued outbound control-plane wire records for a specific host.
    pub(crate) fn poll_outbound_messages_for_host(
        &self,
        target_host: HostId,
    ) -> Result<Vec<OutboundControlPlaneEnvelope>, ControlPlaneError> {
        let mut state = self.state.lock();
        if !state.hosts.contains_key(&target_host) {
            return Err(ControlPlaneError::UnknownHost(target_host));
        }
        Ok(state
            .pending_outbound_messages
            .remove(&target_host)
            .unwrap_or_default())
    }

    /// Pop one queued outbound control-plane envelope for a specific host.
    pub(crate) fn take_next_outbound_message_for_host(
        &self,
        target_host: HostId,
    ) -> Result<Option<OutboundControlPlaneEnvelope>, ControlPlaneError> {
        let mut state = self.state.lock();
        if !state.hosts.contains_key(&target_host) {
            return Err(ControlPlaneError::UnknownHost(target_host));
        }
        let Some(queue) = state.pending_outbound_messages.get_mut(&target_host) else {
            return Ok(None);
        };
        if queue.is_empty() {
            return Ok(None);
        }
        let next = queue.remove(0);
        if queue.is_empty() {
            state.pending_outbound_messages.remove(&target_host);
        }
        Ok(Some(next))
    }

    /// Returns whether a host currently has any queued outbound envelopes.
    pub(crate) fn has_outbound_messages_for_host(
        &self,
        target_host: HostId,
    ) -> Result<bool, ControlPlaneError> {
        let state = self.state.lock();
        if !state.hosts.contains_key(&target_host) {
            return Err(ControlPlaneError::UnknownHost(target_host));
        }
        Ok(state
            .pending_outbound_messages
            .get(&target_host)
            .is_some_and(|queue| !queue.is_empty()))
    }

    /// Resolve whether exec continues locally or needs a future host handoff.
    pub(crate) fn route_exec(
        &self,
        process_id: ProcessId,
        _path: &str,
    ) -> Result<ExecRoute, ControlPlaneError> {
        let owner_host = self
            .owner_of_running_process(process_id)
            .ok_or(ControlPlaneError::UnknownProcess(process_id))?;
        if owner_host != self.local_host {
            return Err(ControlPlaneError::ProcessOwnedByDifferentHost {
                process_id,
                owner_host,
                local_host: self.local_host,
            });
        }
        Ok(ExecRoute::Local { host: owner_host })
    }

    /// Begin a future exec handoff for a process that currently lives in this host.
    pub(crate) fn begin_exec_handoff(
        &self,
        process_id: ProcessId,
        target_host: HostId,
    ) -> Result<ExecHandoffSnapshot, ControlPlaneError> {
        let mut state = self.state.lock();
        if !state.hosts.contains_key(&target_host) {
            return Err(ControlPlaneError::UnknownHost(target_host));
        }
        if let Some(&handoff_id) = state.active_handoffs_by_process.get(&process_id) {
            let _ = handoff_id;
            return Err(ControlPlaneError::HandoffAlreadyActive(process_id));
        }
        let source_host = *state
            .running_process_owners
            .get(&process_id)
            .ok_or(ControlPlaneError::UnknownProcess(process_id))?;
        if source_host == target_host {
            return Err(ControlPlaneError::HandoffTargetMatchesSource {
                process_id,
                host: source_host,
            });
        }
        let handoff_id = ExecHandoffId(self.next_handoff_id.fetch_add(1, Ordering::Relaxed));
        let handoff = ExecHandoff {
            process_id,
            source_host,
            target_host,
            stage: ExecHandoffStage::Prepared,
        };
        state
            .active_handoffs_by_process
            .insert(process_id, handoff_id);
        state.handoffs.insert(handoff_id, handoff);
        Ok(handoff.snapshot(handoff_id))
    }

    /// Advance an exec handoff through the ordered prepare/teardown/transfer/load flow.
    pub(crate) fn advance_exec_handoff(
        &self,
        handoff_id: ExecHandoffId,
        next_stage: ExecHandoffStage,
    ) -> Result<ExecHandoffSnapshot, ControlPlaneError> {
        let mut state = self.state.lock();
        let handoff = state
            .handoffs
            .get_mut(&handoff_id)
            .ok_or(ControlPlaneError::UnknownHandoff(handoff_id))?;
        if handoff.stage.next() != Some(next_stage) {
            return Err(ControlPlaneError::InvalidHandoffTransition {
                current: handoff.stage,
                next: next_stage,
            });
        }
        handoff.stage = next_stage;
        Ok((*handoff).snapshot(handoff_id))
    }

    /// Commit a fully loaded exec handoff and transfer ownership to the target host.
    pub(crate) fn commit_exec_handoff(
        &self,
        handoff_id: ExecHandoffId,
    ) -> Result<ExecHandoffSnapshot, ControlPlaneError> {
        let mut state = self.state.lock();
        let handoff = *state
            .handoffs
            .get(&handoff_id)
            .ok_or(ControlPlaneError::UnknownHandoff(handoff_id))?;
        if handoff.stage != ExecHandoffStage::TargetLoaded {
            return Err(ControlPlaneError::InvalidHandoffCommit(handoff.stage));
        }
        let actual_owner = state
            .running_process_owners
            .get(&handoff.process_id)
            .copied();
        if actual_owner != Some(handoff.source_host) {
            return Err(ControlPlaneError::InvalidHandoffCommitOwner {
                process_id: handoff.process_id,
                expected_source_host: handoff.source_host,
                actual_owner,
            });
        }
        state.handoffs.remove(&handoff_id);
        state.active_handoffs_by_process.remove(&handoff.process_id);
        state
            .running_process_owners
            .insert(handoff.process_id, handoff.target_host);
        Ok(handoff.snapshot(handoff_id))
    }

    /// Abort an in-flight exec handoff without changing the process owner.
    pub(crate) fn abort_exec_handoff(
        &self,
        handoff_id: ExecHandoffId,
    ) -> Result<ExecHandoffSnapshot, ControlPlaneError> {
        let mut state = self.state.lock();
        let handoff = *state
            .handoffs
            .get(&handoff_id)
            .ok_or(ControlPlaneError::UnknownHandoff(handoff_id))?;
        if handoff.stage != ExecHandoffStage::Prepared {
            return Err(ControlPlaneError::InvalidHandoffAbort(handoff.stage));
        }
        state.handoffs.remove(&handoff_id);
        state.active_handoffs_by_process.remove(&handoff.process_id);
        Ok(handoff.snapshot(handoff_id))
    }

    #[cfg(test)]
    fn host_entry(&self, host_id: HostId) -> Option<HostEntry> {
        self.state.lock().hosts.get(&host_id).copied()
    }

    #[cfg(test)]
    fn handoff_snapshot(&self, handoff_id: ExecHandoffId) -> Option<ExecHandoffSnapshot> {
        self.state
            .lock()
            .handoffs
            .get(&handoff_id)
            .copied()
            .map(|handoff| handoff.snapshot(handoff_id))
    }

    #[cfg(test)]
    fn pending_outbound_messages_for_host(
        &self,
        target_host: HostId,
    ) -> Vec<OutboundControlPlaneEnvelope> {
        self.state
            .lock()
            .pending_outbound_messages
            .get(&target_host)
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn decode_outbound_message(
        envelope: OutboundControlPlaneEnvelope,
    ) -> OutboundControlPlaneMessage {
        OutboundControlPlaneMessage::try_from(envelope.message)
            .expect("decode outbound wire message")
    }

    #[test]
    fn root_control_plane_starts_with_registered_root_host() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        assert_eq!(plane.root_host(), HostId::ROOT);
        assert_eq!(plane.local_host(), HostId::ROOT);
        assert_eq!(
            plane.host_entry(HostId::ROOT),
            Some(HostEntry {
                role: HostRole::RootCoordinator,
                parent_host: None,
            })
        );
    }

    #[test]
    fn running_process_registration_tracks_local_owner() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let pid = ProcessId(42);
        plane
            .register_running_process_local(pid)
            .expect("register running process");
        assert_eq!(plane.owner_of_running_process(pid), Some(HostId::ROOT));
        assert_eq!(
            plane.route_exec(pid, "/bin/sh"),
            Ok(ExecRoute::Local { host: HostId::ROOT })
        );
        assert_eq!(plane.unregister_running_process(pid), Some(HostId::ROOT));
        assert_eq!(plane.owner_of_running_process(pid), None);
    }

    #[test]
    fn worker_hosts_can_be_registered_under_root() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");
        assert_eq!(
            plane.host_entry(worker),
            Some(HostEntry {
                role: HostRole::Worker,
                parent_host: Some(HostId::ROOT),
            })
        );
    }

    #[test]
    fn exec_handoff_commit_moves_running_process_owner() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let pid = ProcessId(7);
        plane
            .register_running_process_local(pid)
            .expect("register running process");
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");
        let handoff = plane
            .begin_exec_handoff(pid, worker)
            .expect("prepare handoff");
        assert_eq!(handoff.stage, ExecHandoffStage::Prepared);
        let handoff = plane
            .advance_exec_handoff(handoff.id, ExecHandoffStage::SourceTornDown)
            .expect("advance to teardown");
        assert_eq!(handoff.stage, ExecHandoffStage::SourceTornDown);
        let handoff = plane
            .advance_exec_handoff(handoff.id, ExecHandoffStage::StateTransferred)
            .expect("advance to transfer");
        assert_eq!(handoff.stage, ExecHandoffStage::StateTransferred);
        let handoff = plane
            .advance_exec_handoff(handoff.id, ExecHandoffStage::TargetLoaded)
            .expect("advance to load");
        assert_eq!(handoff.stage, ExecHandoffStage::TargetLoaded);
        let committed = plane
            .commit_exec_handoff(handoff.id)
            .expect("commit handoff");
        assert_eq!(committed.process_id, pid);
        assert_eq!(plane.owner_of_running_process(pid), Some(worker));
        assert!(plane.handoff_snapshot(handoff.id).is_none());
    }

    #[test]
    fn exec_handoff_rejects_out_of_order_transitions() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let pid = ProcessId(9);
        plane
            .register_running_process_local(pid)
            .expect("register running process");
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");
        let handoff = plane
            .begin_exec_handoff(pid, worker)
            .expect("prepare handoff");
        assert_eq!(
            plane.advance_exec_handoff(handoff.id, ExecHandoffStage::StateTransferred),
            Err(ControlPlaneError::InvalidHandoffTransition {
                current: ExecHandoffStage::Prepared,
                next: ExecHandoffStage::StateTransferred,
            })
        );
        assert_eq!(plane.owner_of_running_process(pid), Some(HostId::ROOT));
    }

    #[test]
    fn exec_handoff_abort_keeps_original_owner() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let pid = ProcessId(11);
        plane
            .register_running_process_local(pid)
            .expect("register running process");
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");
        let handoff = plane
            .begin_exec_handoff(pid, worker)
            .expect("prepare handoff");
        let aborted = plane.abort_exec_handoff(handoff.id).expect("abort handoff");
        assert_eq!(aborted.process_id, pid);
        assert_eq!(plane.owner_of_running_process(pid), Some(HostId::ROOT));
        assert!(plane.handoff_snapshot(handoff.id).is_none());
    }

    #[test]
    fn exec_handoff_cannot_abort_after_source_teardown() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let pid = ProcessId(13);
        plane
            .register_running_process_local(pid)
            .expect("register running process");
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");
        let handoff = plane
            .begin_exec_handoff(pid, worker)
            .expect("prepare handoff");
        let handoff = plane
            .advance_exec_handoff(handoff.id, ExecHandoffStage::SourceTornDown)
            .expect("advance to teardown");
        assert_eq!(
            plane.abort_exec_handoff(handoff.id),
            Err(ControlPlaneError::InvalidHandoffAbort(
                ExecHandoffStage::SourceTornDown
            ))
        );
        assert_eq!(plane.owner_of_running_process(pid), Some(HostId::ROOT));
        assert!(plane.handoff_snapshot(handoff.id).is_some());
    }

    #[test]
    fn unregister_marks_post_teardown_handoff_failed() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let pid = ProcessId(15);
        plane
            .register_running_process_local(pid)
            .expect("register running process");
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");
        let handoff = plane
            .begin_exec_handoff(pid, worker)
            .expect("prepare handoff");
        let handoff = plane
            .advance_exec_handoff(handoff.id, ExecHandoffStage::SourceTornDown)
            .expect("advance to teardown");
        assert_eq!(plane.unregister_running_process(pid), Some(HostId::ROOT));
        assert_eq!(plane.owner_of_running_process(pid), None);
        assert_eq!(
            plane
                .handoff_snapshot(handoff.id)
                .map(|snapshot| snapshot.stage),
            Some(ExecHandoffStage::Failed)
        );
    }

    #[test]
    fn active_handoff_blocks_process_reregistration() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let pid = ProcessId(17);
        plane
            .register_running_process_local(pid)
            .expect("register running process");
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");
        let handoff = plane
            .begin_exec_handoff(pid, worker)
            .expect("prepare handoff");
        let handoff = plane
            .advance_exec_handoff(handoff.id, ExecHandoffStage::SourceTornDown)
            .expect("advance to teardown");
        assert_eq!(
            plane.register_running_process_local(pid),
            Err(ControlPlaneError::HandoffAlreadyActive(pid))
        );
        assert!(plane.handoff_snapshot(handoff.id).is_some());
    }

    #[test]
    fn commit_requires_live_source_owner() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let pid = ProcessId(19);
        plane
            .register_running_process_local(pid)
            .expect("register running process");
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");
        let handoff = plane
            .begin_exec_handoff(pid, worker)
            .expect("prepare handoff");
        let handoff = plane
            .advance_exec_handoff(handoff.id, ExecHandoffStage::SourceTornDown)
            .expect("advance to teardown");
        let handoff = plane
            .advance_exec_handoff(handoff.id, ExecHandoffStage::StateTransferred)
            .expect("advance to transfer");
        let handoff = plane
            .advance_exec_handoff(handoff.id, ExecHandoffStage::TargetLoaded)
            .expect("advance to load");
        plane.state.lock().running_process_owners.remove(&pid);
        assert_eq!(
            plane.commit_exec_handoff(handoff.id),
            Err(ControlPlaneError::InvalidHandoffCommitOwner {
                process_id: pid,
                expected_source_host: HostId::ROOT,
                actual_owner: None,
            })
        );
        assert!(plane.handoff_snapshot(handoff.id).is_some());
        assert_eq!(plane.owner_of_running_process(pid), None);
    }

    #[test]
    fn outbound_message_wire_round_trips_child_exit() {
        let message = OutboundControlPlaneMessage::ChildExit(ExitNotification {
            parent_pid: ProcessId(21),
            exit_signal: 17,
            child_pid: ProcessId(22),
            exit_status: 23,
        });

        let wire = OutboundControlPlaneMessageWire::try_from(message).expect("encode message");
        assert_eq!(OutboundControlPlaneMessage::try_from(wire), Ok(message));
    }

    #[test]
    fn outbound_message_wire_rejects_unknown_version() {
        let child_exit = ExitNotificationWire::try_from(ExitNotification {
            parent_pid: ProcessId(21),
            exit_signal: 17,
            child_pid: ProcessId(22),
            exit_status: 23,
        })
        .expect("encode child exit");
        let wire = OutboundControlPlaneMessageWire {
            version: U16::new(OUTBOUND_CONTROL_PLANE_WIRE_VERSION + 1),
            kind: U16::new(OutboundControlPlaneMessageKind::ChildExit as u16),
            child_exit,
        };

        assert_eq!(
            OutboundControlPlaneMessage::try_from(wire),
            Err(OutboundControlPlaneMessageWireError::UnsupportedVersion(
                OUTBOUND_CONTROL_PLANE_WIRE_VERSION + 1
            ))
        );
    }

    #[test]
    fn outbound_message_wire_rejects_unknown_kind() {
        let child_exit = ExitNotificationWire::try_from(ExitNotification {
            parent_pid: ProcessId(21),
            exit_signal: 17,
            child_pid: ProcessId(22),
            exit_status: 23,
        })
        .expect("encode child exit");
        let wire = OutboundControlPlaneMessageWire {
            version: U16::new(OUTBOUND_CONTROL_PLANE_WIRE_VERSION),
            kind: U16::new(999),
            child_exit,
        };

        assert_eq!(
            OutboundControlPlaneMessage::try_from(wire),
            Err(OutboundControlPlaneMessageWireError::UnknownKind(999))
        );
    }

    #[test]
    fn outbound_messages_drain_in_fifo_order_per_host() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");
        let first = ExitNotification {
            parent_pid: ProcessId(31),
            exit_signal: 17,
            child_pid: ProcessId(32),
            exit_status: 23,
        };
        let second = ExitNotification {
            parent_pid: ProcessId(31),
            exit_signal: 17,
            child_pid: ProcessId(33),
            exit_status: 24,
        };

        plane
            .queue_remote_child_exit_notification(HostId::ROOT, worker, first)
            .expect("queue notification");
        plane
            .queue_remote_child_exit_notification(HostId::ROOT, worker, second)
            .expect("queue second notification");

        let pending = plane.pending_outbound_messages_for_host(worker);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].source_host, HostId::ROOT);
        assert_eq!(pending[1].source_host, HostId::ROOT);

        let drained = plane
            .poll_outbound_messages_for_host(worker)
            .expect("drain notifications");
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].source_host, HostId::ROOT);
        assert_eq!(drained[1].source_host, HostId::ROOT);
        match decode_outbound_message(drained[0]) {
            OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.parent_pid, first.parent_pid);
                assert_eq!(notification.child_pid, first.child_pid);
                assert_eq!(notification.exit_signal, first.exit_signal);
                assert_eq!(notification.exit_status, first.exit_status);
            }
        }
        match decode_outbound_message(drained[1]) {
            OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.parent_pid, second.parent_pid);
                assert_eq!(notification.child_pid, second.child_pid);
                assert_eq!(notification.exit_signal, second.exit_signal);
                assert_eq!(notification.exit_status, second.exit_status);
            }
        }
        assert!(plane.pending_outbound_messages_for_host(worker).is_empty());
    }

    #[test]
    fn take_next_outbound_message_preserves_tail_fifo() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");
        let first = ExitNotification {
            parent_pid: ProcessId(31),
            exit_signal: 17,
            child_pid: ProcessId(32),
            exit_status: 23,
        };
        let second = ExitNotification {
            parent_pid: ProcessId(31),
            exit_signal: 17,
            child_pid: ProcessId(33),
            exit_status: 24,
        };

        plane
            .queue_remote_child_exit_notification(HostId::ROOT, worker, first)
            .expect("queue first notification");
        plane
            .queue_remote_child_exit_notification(HostId::ROOT, worker, second)
            .expect("queue second notification");

        let next = plane
            .take_next_outbound_message_for_host(worker)
            .expect("take next queued message")
            .expect("first queued message should exist");
        assert_eq!(next.source_host, HostId::ROOT);
        match decode_outbound_message(next) {
            OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification, first);
            }
        }

        let remaining = plane
            .poll_outbound_messages_for_host(worker)
            .expect("drain remaining queued message");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].source_host, HostId::ROOT);
        match decode_outbound_message(remaining[0]) {
            OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification, second);
            }
        }
    }

    #[test]
    fn remote_child_exit_notification_queue_is_bounded() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let worker = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker host");

        for idx in 0..MAX_PENDING_OUTBOUND_CONTROL_PLANE_MESSAGES_PER_HOST {
            plane
                .queue_remote_child_exit_notification(
                    HostId::ROOT,
                    worker,
                    ExitNotification {
                        parent_pid: ProcessId(40),
                        exit_signal: 17,
                        child_pid: ProcessId(100 + u32::try_from(idx).unwrap()),
                        exit_status: i32::try_from(idx).unwrap(),
                    },
                )
                .expect("queue notification within bound");
        }

        assert_eq!(
            plane.queue_remote_child_exit_notification(
                HostId::ROOT,
                worker,
                ExitNotification {
                    parent_pid: ProcessId(40),
                    exit_signal: 17,
                    child_pid: ProcessId(999),
                    exit_status: 999,
                }
            ),
            Err(ControlPlaneError::OutboundMessageQueueFull {
                target_host: worker,
                limit: MAX_PENDING_OUTBOUND_CONTROL_PLANE_MESSAGES_PER_HOST,
            })
        );
        assert_eq!(
            plane.pending_outbound_messages_for_host(worker).len(),
            MAX_PENDING_OUTBOUND_CONTROL_PLANE_MESSAGES_PER_HOST
        );
    }

    #[test]
    fn outbound_messages_are_isolated_per_host() {
        let plane = ControlPlane::<crate::Platform>::new_root_local();
        let worker_a = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker a");
        let worker_b = plane
            .register_worker_host(HostId::ROOT)
            .expect("register worker b");

        plane
            .queue_remote_child_exit_notification(
                HostId::ROOT,
                worker_a,
                ExitNotification {
                    parent_pid: ProcessId(51),
                    exit_signal: 17,
                    child_pid: ProcessId(61),
                    exit_status: 1,
                },
            )
            .expect("queue worker a notification");
        plane
            .queue_remote_child_exit_notification(
                HostId::ROOT,
                worker_b,
                ExitNotification {
                    parent_pid: ProcessId(52),
                    exit_signal: 17,
                    child_pid: ProcessId(62),
                    exit_status: 2,
                },
            )
            .expect("queue worker b notification");

        let drained_a = plane
            .poll_outbound_messages_for_host(worker_a)
            .expect("poll worker a");
        assert_eq!(drained_a.len(), 1);
        assert_eq!(drained_a[0].source_host, HostId::ROOT);
        match decode_outbound_message(drained_a[0]) {
            OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.parent_pid, ProcessId(51));
                assert_eq!(notification.child_pid, ProcessId(61));
            }
        }

        let pending_b = plane.pending_outbound_messages_for_host(worker_b);
        assert_eq!(pending_b.len(), 1);
        assert_eq!(pending_b[0].source_host, HostId::ROOT);
        match decode_outbound_message(pending_b[0]) {
            OutboundControlPlaneMessage::ChildExit(notification) => {
                assert_eq!(notification.parent_pid, ProcessId(52));
                assert_eq!(notification.child_pid, ProcessId(62));
            }
        }
    }
}
