// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker authority core independent of protocol envelopes and channels.
//!
//! `litebox_broker_core` owns broker-side object identity, reference lifetime,
//! rights checks, handle validity checks, and policy calls. It may use
//! shared semantic DTOs from `litebox_broker_protocol` for values that both the
//! local core and broker understand, such as handles and readiness state. It
//! deliberately has no dependency on protocol envelopes, channel traits, wire
//! codecs, Unix sockets, shared-memory rings, kernel traps, or any other
//! channel implementation.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod error;
pub mod event;
pub mod pipe;
mod policy;
mod session;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::ObjectHandle;
use spin::rwlock::RwLock;

pub use error::BrokerError;
pub use policy::{PolicyEngine, PolicyProfile};
use session::ObjectReference;
pub use session::{BrokerSession, CallerCredential, ObjectRights};

/// BrokerCore result type.
pub type Result<T> = core::result::Result<T, BrokerError>;

/// Number of equal shares a global ceiling is split into when a limit set does
/// not state its per-session quota explicitly.
///
/// A session may hold one share, so several sessions must each spend their
/// whole quota before a global ceiling is reached, and no single session can
/// reach one on its own.
const DEFAULT_SESSION_QUOTA_SHARES: usize = 4;

/// Resource limits for broker-owned authority state.
///
/// Every budget has two limits. The global ceiling bounds what all sessions
/// hold together and keeps the broker process bounded. The per-session quota
/// bounds what any one session holds, so a malicious or malfunctioning session
/// cannot spend the whole ceiling and deny object and pipe creation to every
/// other session served by the same broker core. Both are enforced on every
/// allocation, with the global ceiling acting as the backstop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BrokerCoreLimits {
    /// Maximum live object references across all sessions.
    pub max_references: usize,
    /// Maximum total capacity in bytes reserved by live pipes across all
    /// sessions.
    pub max_total_pipe_capacity: usize,
    /// Maximum live object references held by any one session.
    pub max_session_references: usize,
    /// Maximum capacity in bytes reserved by the live pipes of any one session.
    pub max_session_pipe_capacity: usize,
}

impl BrokerCoreLimits {
    /// Conservative default limits for initial broker deployments.
    pub const DEFAULT: Self = Self::new(4096, 64 * 1024 * 1024);

    /// Creates a broker core limit set that gives each session an equal share
    /// of the global ceilings.
    ///
    /// Each session may hold up to a quarter of each ceiling, rounded up, so a
    /// caller that has not thought about per-session quotas still gets a core
    /// no single session can exhaust. Use
    /// [`BrokerCoreLimits::with_session_quotas`] to state the quotas
    /// explicitly.
    pub const fn new(max_references: usize, max_total_pipe_capacity: usize) -> Self {
        Self {
            max_references,
            max_total_pipe_capacity,
            max_session_references: max_references.div_ceil(DEFAULT_SESSION_QUOTA_SHARES),
            max_session_pipe_capacity: max_total_pipe_capacity
                .div_ceil(DEFAULT_SESSION_QUOTA_SHARES),
        }
    }

    /// Returns these limits with explicit per-session quotas.
    ///
    /// A quota above its global ceiling is accepted rather than rejected: the
    /// ceiling is still enforced, so the effective quota is whichever of the
    /// two is smaller. A deployment that knowingly serves one session can
    /// therefore hand it the whole core by raising each quota to its ceiling.
    ///
    /// ```
    /// use litebox_broker_core::BrokerCoreLimits;
    ///
    /// let shared = BrokerCoreLimits::DEFAULT;
    /// assert_eq!(shared.max_session_references, 1024);
    ///
    /// let single_tenant =
    ///     shared.with_session_quotas(shared.max_references, shared.max_total_pipe_capacity);
    /// assert_eq!(single_tenant.max_session_references, shared.max_references);
    /// ```
    #[must_use]
    pub const fn with_session_quotas(
        self,
        max_session_references: usize,
        max_session_pipe_capacity: usize,
    ) -> Self {
        Self {
            max_references: self.max_references,
            max_total_pipe_capacity: self.max_total_pipe_capacity,
            max_session_references,
            max_session_pipe_capacity,
        }
    }
}

impl Default for BrokerCoreLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Channel-independent broker authority handle.
///
/// A broker process may construct only one broker core for its process
/// lifetime. Constructors return [`BrokerError::BrokerCoreAlreadyExists`] if a
/// core has already been constructed.
#[derive(Clone)]
pub struct BrokerCore {
    pub(crate) policy: PolicyEngine,
    pub(crate) limits: BrokerCoreLimits,
    pub(crate) next_session_id: Arc<RwLock<u64>>,
    pub(crate) next_reference_handle: Arc<RwLock<u64>>,
    pub(crate) references: Arc<RwLock<HashMap<ObjectHandle, ObjectReference>>>,
    pub(crate) reserved_pipe_capacity: Arc<AtomicUsize>,
}

static BROKER_CORE_CREATED: AtomicBool = AtomicBool::new(false);

impl BrokerCore {
    /// Creates the broker core with the provided policy engine.
    pub fn new(policy: PolicyEngine) -> Result<Self> {
        Self::new_with_limits(policy, BrokerCoreLimits::DEFAULT)
    }

    /// Creates the broker core with explicit authority-state limits.
    pub fn new_with_limits(policy: PolicyEngine, limits: BrokerCoreLimits) -> Result<Self> {
        BROKER_CORE_CREATED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| BrokerError::BrokerCoreAlreadyExists)?;

        Ok(Self {
            policy,
            limits,
            next_session_id: Arc::new(RwLock::new(1)),
            next_reference_handle: Arc::new(RwLock::new(1)),
            references: Arc::new(RwLock::new(HashMap::new())),
            reserved_pipe_capacity: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub(crate) fn allocate_reference_handle(&self) -> Result<ObjectHandle> {
        let mut next_reference_handle = self.next_reference_handle.write();
        let handle = ObjectHandle(*next_reference_handle);
        *next_reference_handle = handle
            .0
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok(handle)
    }

    pub(crate) fn allocate_reference_handle_pair(&self) -> Result<(ObjectHandle, ObjectHandle)> {
        let mut next_reference_handle = self.next_reference_handle.write();
        let first = ObjectHandle(*next_reference_handle);
        let second = ObjectHandle(
            first
                .0
                .checked_add(1)
                .ok_or(BrokerError::ResourceExhausted)?,
        );
        *next_reference_handle = second
            .0
            .checked_add(1)
            .ok_or(BrokerError::ResourceExhausted)?;
        Ok((first, second))
    }

    /// Allocates broker authority state for one authenticated caller session.
    pub fn create_session(&self, caller_credential: CallerCredential) -> Result<BrokerSession> {
        // Release the identity lock before building the session: session
        // construction allocates the per-session capacity counter, and every
        // session creation contends for this lock.
        let session_id = {
            let mut next_session_id = self.next_session_id.write();
            let session_id = *next_session_id;
            *next_session_id = session_id
                .checked_add(1)
                .ok_or(BrokerError::ResourceExhausted)?;
            session_id
        };
        Ok(BrokerSession::new(
            self.clone(),
            session::SessionId(session_id),
            caller_credential,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{BrokerCoreLimits, DEFAULT_SESSION_QUOTA_SHARES};

    #[test]
    fn default_limits_bound_what_one_session_can_hold() {
        let limits = BrokerCoreLimits::DEFAULT;

        assert_eq!(limits.max_references, 4096);
        assert_eq!(limits.max_total_pipe_capacity, 64 * 1024 * 1024);
        assert_eq!(
            limits.max_session_references,
            limits.max_references / DEFAULT_SESSION_QUOTA_SHARES
        );
        assert_eq!(
            limits.max_session_pipe_capacity,
            limits.max_total_pipe_capacity / DEFAULT_SESSION_QUOTA_SHARES
        );
        // No single session can reach a global ceiling on its own.
        assert!(limits.max_session_references < limits.max_references);
        assert!(limits.max_session_pipe_capacity < limits.max_total_pipe_capacity);
    }

    #[test]
    fn derived_quotas_never_round_a_usable_ceiling_down_to_nothing() {
        let limits = BrokerCoreLimits::new(1, 1);

        assert_eq!(limits.max_session_references, 1);
        assert_eq!(limits.max_session_pipe_capacity, 1);
    }

    #[test]
    fn derived_quotas_stay_zero_for_a_ceiling_of_zero() {
        let limits = BrokerCoreLimits::new(0, 0);

        assert_eq!(limits.max_session_references, 0);
        assert_eq!(limits.max_session_pipe_capacity, 0);
    }

    #[test]
    fn explicit_quotas_replace_the_derived_ones_and_keep_the_ceilings() {
        let limits = BrokerCoreLimits::new(4096, 64 * 1024 * 1024).with_session_quotas(7, 9);

        assert_eq!(limits.max_references, 4096);
        assert_eq!(limits.max_total_pipe_capacity, 64 * 1024 * 1024);
        assert_eq!(limits.max_session_references, 7);
        assert_eq!(limits.max_session_pipe_capacity, 9);
    }
}
