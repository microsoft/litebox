// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-held credentials of this process.
//!
//! The broker owns each process's authority: the [`Term`]s describing the
//! subjects the process may act as. LiteBox can read a snapshot of it, propose
//! a restriction, and register a [`Subject`] for later requests. The broker
//! validates each step, so the values themselves grant nothing.

use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::authority::{
    AuthorityCodecError, EncodedSubject, EncodedTerms, TermsError,
};
pub use litebox_broker_protocol::authority::{
    DomainId, MAX_AUTHORITY_TERMS, MAX_SET_DOMAINS, MAX_SET_PRINCIPALS, Principal, PrincipalSet,
    Privileges, Scope, Slots, Subject, Term, sorted_set::SortedSet,
};
use litebox_broker_protocol::error::ErrorCode;
use litebox_platform::time::TimeProvider;

use crate::LiteBox;
use crate::broker::{BrokerControl, error::BrokerControlError};
use crate::sync::RawSyncPrimitivesProvider;

/// Error returned by the broker-backed credential service.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum CredentialError {
    /// This LiteBox process has no broker credential service.
    #[error("credentials are unavailable")]
    Unavailable,
    /// The broker association failed or this process is exiting.
    #[error("credential service failed")]
    ServiceFailed,
    /// The terms are invalid or do not restrict the current authority, or the
    /// current authority does not admit the subject.
    #[error("credential operation is denied")]
    PolicyDenied,
    /// The current authority no longer admits a previously registered subject.
    #[error("registered subject is no longer admissible")]
    StaleSubject,
    /// There are more than [`MAX_AUTHORITY_TERMS`] distinct canonical terms;
    /// see [`canonical_terms`](litebox_broker_protocol::authority::canonical_terms).
    #[error("too many distinct authority terms")]
    TooManyTerms,
    /// A set exceeds [`MAX_SET_PRINCIPALS`] or [`MAX_SET_DOMAINS`].
    #[error("a credential set is too large")]
    SetTooLarge,
    /// Broker capacity, such as for handles, is exhausted.
    #[error("credential capacity is exhausted")]
    ResourceExhausted,
    /// Memory capacity is exhausted.
    #[error("credential memory is exhausted")]
    OutOfMemory,
    /// The child process is not pending for this process.
    #[error("invalid child process")]
    InvalidChild,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    /// Returns a snapshot of this process's authority: its distinct terms in
    /// ascending order.
    pub fn authority(&self) -> Result<Vec<Term>, CredentialError> {
        let broker = self.broker_control().ok_or(CredentialError::Unavailable)?;
        Ok(broker.get_authority()?)
    }

    /// Replaces this process's authority with the canonical forms of `terms`,
    /// which may repeat and come in any order, if each fits one current term
    /// in both scopes. On failure the authority is unchanged.
    ///
    /// Invalid terms fail with [`CredentialError::PolicyDenied`] before
    /// reaching the broker, which validates the terms it receives again.
    ///
    /// Subjects already registered stay registered; requests naming one the
    /// new authority does not admit fail until it is replaced.
    pub fn restrict_authority(&self, terms: &[Term]) -> Result<(), CredentialError> {
        let broker = self.broker_control().ok_or(CredentialError::Unavailable)?;
        let terms = encode_terms(terms)?;
        Ok(broker.restrict_authority(&terms)?)
    }

    /// Registers `subject` for this process's later requests, if this
    /// process's authority admits it.
    pub fn register_subject(
        &self,
        subject: &Subject,
    ) -> Result<RegisteredSubject, CredentialError> {
        let broker = self.broker_control().ok_or(CredentialError::Unavailable)?;
        let encoded = EncodedSubject::new(subject).map_err(encoding_error)?;
        let handle = broker.create_subject(&encoded)?;
        Ok(RegisteredSubject { broker, handle })
    }
}

/// A subject registered with the broker for this process's requests.
///
/// It cannot be transferred to another process. Dropping it unregisters it.
pub struct RegisteredSubject {
    broker: Arc<dyn BrokerControl>,
    handle: ObjectHandle,
}

impl Drop for RegisteredSubject {
    fn drop(&mut self) {
        let _ = self.broker.close_object(self.handle);
    }
}

pub(crate) fn encode_terms(terms: &[Term]) -> Result<EncodedTerms, CredentialError> {
    EncodedTerms::new(terms).map_err(|error| match error {
        TermsError::TooManyTerms => CredentialError::TooManyTerms,
        TermsError::SetTooLarge => CredentialError::SetTooLarge,
        TermsError::OutOfMemory => CredentialError::OutOfMemory,
        TermsError::UnmappedPrincipal
        | TermsError::DenyOnlyOverlap
        | TermsError::InvalidPrivileges => CredentialError::PolicyDenied,
    })
}

fn encoding_error(error: AuthorityCodecError) -> CredentialError {
    match error {
        AuthorityCodecError::TooManyTerms => CredentialError::TooManyTerms,
        AuthorityCodecError::SetTooLarge => CredentialError::SetTooLarge,
        AuthorityCodecError::OutOfMemory => CredentialError::OutOfMemory,
        AuthorityCodecError::Malformed => CredentialError::PolicyDenied,
        error => unreachable!("encoding credentials failed: {error}"),
    }
}

impl From<BrokerControlError> for CredentialError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::AssociationFailed
            | BrokerControlError::Broker(ErrorCode::PeerClosed) => Self::ServiceFailed,
            BrokerControlError::Broker(ErrorCode::UnsupportedOperation) => Self::Unavailable,
            BrokerControlError::Broker(ErrorCode::PolicyDenied) => Self::PolicyDenied,
            BrokerControlError::Broker(ErrorCode::StaleSubject) => Self::StaleSubject,
            BrokerControlError::Broker(ErrorCode::ResourceExhausted) => Self::ResourceExhausted,
            BrokerControlError::Broker(ErrorCode::OutOfMemory) => Self::OutOfMemory,
            BrokerControlError::Broker(error) => {
                panic!("credential service returned unexpected error: {error}")
            }
            BrokerControlError::Fault => unreachable!("credential requests copy no guest bytes"),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;
    use std::sync::Mutex;

    use litebox_broker_local::test_support::test_broker_local;
    use litebox_broker_protocol::authority::{
        DomainId, MAX_AUTHORITY_TERMS, MAX_ENCODED_TERMS_SIZE, MAX_SET_DOMAINS, MAX_SET_PRINCIPALS,
        Principal, PrincipalSet, Privileges, Scope, Slots, decode_subject, decode_terms,
    };
    use litebox_broker_protocol::message::{
        BrokerOperation, BrokerRequest, BrokerResponse, BrokerResult, ProcessRequest,
        ProcessResponse,
    };
    use litebox_broker_protocol::process::ProcessIdentity;
    use litebox_broker_protocol::shared_buffer::{
        SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SHARED_BUFFER_SLOT_SIZE,
        SharedBufferSequence,
    };
    use litebox_broker_protocol::{ProcessId, ThreadId};
    use litebox_broker_transport::channel::LocalCallChannel;
    use litebox_broker_transport::shared_memory::{HeapSharedMemory, SharedBufferPool};

    use super::*;
    use crate::platform::mock::MockPlatform;

    const CHILD: ProcessId = ProcessId(3);
    const SUBJECT: ObjectHandle = ObjectHandle(7);

    #[derive(Default)]
    struct BrokerState {
        authority: Vec<Term>,
        subject: Option<Subject>,
        authority_buffer_lengths: Vec<u32>,
        credential_requests: usize,
        closed: Vec<ObjectHandle>,
        error: Option<ErrorCode>,
    }

    /// Serves credential requests from a broker-owned state, through shared
    /// buffers as a real broker would, and one pending child.
    struct CredentialBroker {
        buffers: SharedBufferPool<Arc<HeapSharedMemory>>,
        state: Mutex<BrokerState>,
    }

    impl CredentialBroker {
        fn read(&self, buffer: SharedBufferSequence) -> Vec<u8> {
            let mut data = vec![0; buffer.length() as usize];
            self.buffers.read_sequence(buffer, 0, &mut data).unwrap();
            data
        }

        fn serve(&self, state: &mut BrokerState, request: ProcessRequest) -> BrokerResult {
            if !matches!(
                request,
                ProcessRequest::AllocateChild(_)
                    | ProcessRequest::ExitChild(_)
                    | ProcessRequest::CancelChild(_)
            ) {
                state.credential_requests += 1;
                if let Some(error) = state.error {
                    return BrokerResult::Error(error);
                }
            }
            let response = match request {
                ProcessRequest::GetAuthority(buffer) => {
                    state.authority_buffer_lengths.push(buffer.length());
                    let terms = EncodedTerms::new(&state.authority).unwrap();
                    let terms = terms.as_bytes();
                    if terms.len() <= buffer.length() as usize {
                        self.buffers.write_sequence(buffer, 0, terms).unwrap();
                    }
                    ProcessResponse::GetAuthority(u32::try_from(terms.len()).unwrap())
                }
                ProcessRequest::RestrictAuthority(buffer) => {
                    state.authority = decode_terms(&self.read(buffer)).unwrap();
                    ProcessResponse::RestrictAuthority
                }
                ProcessRequest::RestrictChildAuthority(request) => {
                    assert_eq!(request.child_process_id, CHILD);
                    decode_terms(&self.read(request.terms)).unwrap();
                    ProcessResponse::RestrictChildAuthority
                }
                ProcessRequest::CreateSubject(buffer) => {
                    state.subject = Some(decode_subject(&self.read(buffer)).unwrap());
                    ProcessResponse::CreateSubject(SUBJECT)
                }
                ProcessRequest::AllocateChild(_) => {
                    ProcessResponse::AllocateChild(ProcessIdentity {
                        process_id: CHILD,
                        initial_thread_id: ThreadId(4),
                        own_process_id: CHILD,
                    })
                }
                ProcessRequest::CancelChild(CHILD) => ProcessResponse::CancelChild,
                ProcessRequest::ExitChild(_) => ProcessResponse::ExitChild,
                request => panic!("unexpected process request {request:?}"),
            };
            BrokerResult::Process(response)
        }
    }

    struct CredentialChannel(Arc<CredentialBroker>);

    impl LocalCallChannel for CredentialChannel {
        type Error = ();

        fn call(&self, request: BrokerRequest) -> Result<BrokerResponse, Self::Error> {
            let mut state = self.0.state.lock().unwrap();
            let result = match request.operation {
                BrokerOperation::Process(request) => self.0.serve(&mut state, request),
                BrokerOperation::CloseObject(handle) => {
                    state.closed.push(handle);
                    BrokerResult::ObjectClosed
                }
                operation => panic!("unexpected operation {operation:?}"),
            };
            Ok(BrokerResponse {
                request_id: request.request_id,
                result,
            })
        }
    }

    fn litebox_with_broker(authority: Vec<Term>) -> (LiteBox<MockPlatform>, Arc<CredentialBroker>) {
        let memory = Arc::new(HeapSharedMemory::new(SHARED_BUFFER_POOL_SIZE));
        let broker = Arc::new(CredentialBroker {
            buffers: SharedBufferPool::new(memory.clone(), SHARED_BUFFER_LAYOUT).unwrap(),
            state: Mutex::new(BrokerState {
                authority,
                ..BrokerState::default()
            }),
        });
        let litebox = LiteBox::new_with_broker_local(
            MockPlatform::new(),
            test_broker_local(CredentialChannel(broker.clone()), memory),
        );
        (litebox, broker)
    }

    fn user(id: u32) -> Principal {
        Principal {
            domain: DomainId::POSIX_USER,
            id,
        }
    }

    fn group(id: u32) -> Principal {
        Principal {
            domain: DomainId::POSIX_GROUP,
            id,
        }
    }

    fn exact(principals: impl IntoIterator<Item = Principal>) -> PrincipalSet {
        PrincipalSet {
            exact: SortedSet::try_from_iter(principals).unwrap(),
            domains: SortedSet::new(),
        }
    }

    fn term(owner: u32, privileges: Privileges) -> Term {
        let slots = Slots {
            owners: exact([user(owner)]),
            groups: exact([group(100)]),
        };
        Term {
            access: slots.clone(),
            identity: slots,
            required: SortedSet::new(),
            optional: exact([group(5)]),
            deny_only: SortedSet::new(),
            privileges,
        }
    }

    /// A term with every set at its ceiling, so two exceed one shared-buffer slot.
    fn largest_term(id: u32) -> Term {
        let principals = |domain| {
            SortedSet::try_from_iter((0..u32::try_from(MAX_SET_PRINCIPALS).unwrap()).map(
                |offset| Principal {
                    domain: DomainId(domain),
                    id: id + offset,
                },
            ))
            .unwrap()
        };
        let set = |domain| PrincipalSet {
            exact: principals(domain),
            domains: SortedSet::try_from_iter(
                (100..100 + u32::try_from(MAX_SET_DOMAINS).unwrap()).map(DomainId),
            )
            .unwrap(),
        };
        let slots = Slots {
            owners: set(10),
            groups: set(11),
        };
        Term {
            access: slots.clone(),
            identity: slots,
            required: principals(12),
            optional: set(13),
            deny_only: principals(14),
            privileges: Privileges::empty(),
        }
    }

    #[test]
    fn credentials_need_a_broker() {
        let litebox = LiteBox::new(MockPlatform::new());

        assert_eq!(litebox.authority(), Err(CredentialError::Unavailable));
        assert_eq!(
            litebox.restrict_authority(&[]),
            Err(CredentialError::Unavailable)
        );
    }

    #[test]
    fn authority_reads_a_broker_snapshot_of_any_size() {
        let small = vec![term(1000, Privileges::SIGNAL_ANY)];
        let (litebox, broker) = litebox_with_broker(small.clone());
        assert_eq!(litebox.authority().unwrap(), small);
        assert_eq!(
            broker.state.lock().unwrap().authority_buffer_lengths,
            [SHARED_BUFFER_SLOT_SIZE]
        );

        let large = vec![largest_term(0), largest_term(1)];
        let (litebox, broker) = litebox_with_broker(large.clone());
        assert_eq!(litebox.authority().unwrap(), large);
        assert_eq!(
            broker.state.lock().unwrap().authority_buffer_lengths,
            [SHARED_BUFFER_SLOT_SIZE, MAX_ENCODED_TERMS_SIZE]
        );
    }

    #[test]
    fn oversized_restrictions_fail_locally() {
        let (litebox, broker) = litebox_with_broker(Vec::new());
        let too_many: Vec<Term> = (0..=u32::try_from(MAX_AUTHORITY_TERMS).unwrap())
            .map(|owner| term(owner, Privileges::empty()))
            .collect();
        let mut too_large = term(0, Privileges::empty());
        too_large.optional.domains = SortedSet::try_from_iter(
            (1..=u32::try_from(MAX_SET_DOMAINS).unwrap() + 1).map(DomainId),
        )
        .unwrap();

        assert_eq!(
            litebox.restrict_authority(&too_many),
            Err(CredentialError::TooManyTerms)
        );
        assert_eq!(
            litebox.restrict_authority(&[too_large]),
            Err(CredentialError::SetTooLarge)
        );
        let mut child = litebox.allocate_child_process(None, false).unwrap();
        assert_eq!(
            child.restrict_authority(&too_many),
            Err(CredentialError::TooManyTerms)
        );
        assert_eq!(broker.state.lock().unwrap().credential_requests, 0);
    }

    #[test]
    fn invalid_restrictions_fail_locally() {
        let (litebox, broker) = litebox_with_broker(Vec::new());
        let valid = term(1000, Privileges::empty());
        // Group 5 is optional, so it cannot also be deny-only, even in a term
        // that is otherwise a repeat.
        let mut overlap = valid.clone();
        overlap.deny_only = [group(5)].into();

        assert_eq!(
            litebox.restrict_authority(&[valid.clone(), overlap.clone()]),
            Err(CredentialError::PolicyDenied)
        );
        let mut child = litebox.allocate_child_process(None, false).unwrap();
        assert_eq!(
            child.restrict_authority(&[overlap, valid]),
            Err(CredentialError::PolicyDenied)
        );
        assert_eq!(broker.state.lock().unwrap().credential_requests, 0);
    }

    #[test]
    fn broker_errors_map_to_credential_errors() {
        let (litebox, broker) = litebox_with_broker(Vec::new());
        let mut child = litebox.allocate_child_process(None, false).unwrap();
        let subject = Subject {
            scope: Scope::Access,
            owner: user(1000),
            group: group(100),
            identities: SortedSet::new(),
            deny_only: SortedSet::new(),
            privileges: Privileges::empty(),
        };
        for (error, expected) in [
            (ErrorCode::PolicyDenied, CredentialError::PolicyDenied),
            (ErrorCode::StaleSubject, CredentialError::StaleSubject),
            (
                ErrorCode::ResourceExhausted,
                CredentialError::ResourceExhausted,
            ),
            (ErrorCode::OutOfMemory, CredentialError::OutOfMemory),
            (
                ErrorCode::UnsupportedOperation,
                CredentialError::Unavailable,
            ),
            (ErrorCode::PeerClosed, CredentialError::ServiceFailed),
        ] {
            broker.state.lock().unwrap().error = Some(error);
            assert_eq!(litebox.authority(), Err(expected));
            assert_eq!(litebox.restrict_authority(&[]), Err(expected));
            assert_eq!(litebox.register_subject(&subject).map(drop), Err(expected));
        }
        for error in [ErrorCode::UnknownObject, ErrorCode::PeerClosed] {
            broker.state.lock().unwrap().error = Some(error);
            assert_eq!(
                child.restrict_authority(&[]),
                Err(CredentialError::InvalidChild)
            );
        }
        broker.state.lock().unwrap().error = Some(ErrorCode::PolicyDenied);
        assert_eq!(
            child.restrict_authority(&[]),
            Err(CredentialError::PolicyDenied)
        );
        broker.state.lock().unwrap().error = None;
    }

    #[test]
    fn finished_child_cannot_restrict_a_reused_id() {
        let (litebox, broker) = litebox_with_broker(Vec::new());
        let mut finished = litebox.allocate_child_process(None, false).unwrap();
        finished
            .exit(litebox_broker_protocol::process::ProcessExitStatus::Exited { code: 0 })
            .unwrap();
        let mut replacement = litebox.allocate_child_process(None, false).unwrap();
        assert_eq!(
            finished.identity().process_id,
            replacement.identity().process_id
        );
        assert_eq!(
            finished.restrict_authority(&[]),
            Err(CredentialError::InvalidChild)
        );
        assert_eq!(broker.state.lock().unwrap().credential_requests, 0);
        replacement.restrict_authority(&[]).unwrap();
    }

    #[test]
    fn dropping_a_registered_subject_unregisters_it() {
        let (litebox, broker) = litebox_with_broker(Vec::new());
        let subject = Subject {
            scope: Scope::Identity,
            owner: user(1000),
            group: group(100),
            identities: [group(5)].into(),
            deny_only: [group(6)].into(),
            privileges: Privileges::SIGNAL_ANY,
        };

        let registered = litebox.register_subject(&subject).unwrap();
        assert_eq!(broker.state.lock().unwrap().subject, Some(subject));
        assert_eq!(broker.state.lock().unwrap().closed, []);

        drop(registered);
        assert_eq!(broker.state.lock().unwrap().closed, [SUBJECT]);
    }

    /// Connects a LiteBox to a root process of a real in-process broker,
    /// created with `authority` as trusted broker configuration.
    fn litebox_with_in_process_broker(authority: &[Term]) -> LiteBox<MockPlatform> {
        use litebox_broker_core::authority::Authority;
        use litebox_broker_core::test_support::TestBrokerBuilder;
        use litebox_broker_core::{CallerCredential, ObjectRights, PolicyEngine};
        use litebox_broker_host::test_support::InProcessBrokerSetup;
        use litebox_broker_local::BrokerLocal;

        let broker = TestBrokerBuilder::new(
            PolicyEngine::with_unauthenticated_rights(ObjectRights::all())
                .with_process_duplication_enabled(true),
        )
        .build()
        .unwrap();
        let root = broker
            .core
            .create_process(
                CallerCredential::Unauthenticated,
                Arc::new(Authority::new(authority.iter().cloned()).unwrap()),
                &broker.pid_namespace,
                &broker.fs,
                &broker.job,
                broker.host_names.clone(),
                None,
            )
            .unwrap();
        let (local, _, ()) = BrokerLocal::negotiate(InProcessBrokerSetup::new(root), |setup| {
            let memory = setup.shared_memory();
            Ok((setup.activate(), memory, ()))
        })
        .unwrap();
        LiteBox::new_with_broker_local(MockPlatform::new(), local)
    }

    #[test]
    fn in_process_broker_enforces_authority_lifecycle() {
        let broad = [term(1000, Privileges::SIGNAL_ANY)];
        let narrow = [term(1000, Privileges::empty())];
        let litebox = litebox_with_in_process_broker(&broad);
        let signaller = Subject {
            scope: Scope::Identity,
            owner: user(1000),
            group: group(100),
            identities: [group(5)].into(),
            deny_only: SortedSet::new(),
            privileges: Privileges::SIGNAL_ANY,
        };
        assert_eq!(litebox.authority().unwrap(), broad);
        drop(litebox.register_subject(&signaller).unwrap());
        assert_eq!(
            litebox
                .register_subject(&Subject {
                    owner: user(0),
                    ..signaller.clone()
                })
                .map(drop),
            Err(CredentialError::PolicyDenied)
        );

        let mut child = litebox.allocate_child_process(None, false).unwrap();
        child.restrict_authority(&narrow).unwrap();
        assert_eq!(
            child.restrict_authority(&broad),
            Err(CredentialError::PolicyDenied)
        );
        assert_eq!(litebox.authority().unwrap(), broad);
        drop(child);

        litebox
            .restrict_authority(&[narrow[0].clone(), narrow[0].clone()])
            .unwrap();
        assert_eq!(
            litebox.restrict_authority(&broad),
            Err(CredentialError::PolicyDenied)
        );
        assert_eq!(litebox.authority().unwrap(), narrow);
        assert_eq!(
            litebox.register_subject(&signaller).map(drop),
            Err(CredentialError::PolicyDenied)
        );
        drop(
            litebox
                .register_subject(&Subject {
                    privileges: Privileges::empty(),
                    ..signaller
                })
                .unwrap(),
        );
    }

    #[test]
    fn in_process_broker_counts_canonical_terms() {
        let any_group = Term {
            optional: PrincipalSet {
                exact: SortedSet::new(),
                domains: [DomainId::POSIX_GROUP].into(),
            },
            ..term(1000, Privileges::empty())
        };
        let litebox = litebox_with_in_process_broker(core::slice::from_ref(&any_group));
        // Each names a group the wildcard already covers.
        let redundant: Vec<Term> = (0..=u32::try_from(MAX_AUTHORITY_TERMS).unwrap())
            .map(|id| {
                let mut term = any_group.clone();
                term.optional.exact = [group(id)].into();
                term
            })
            .collect();

        litebox.restrict_authority(&redundant).unwrap();
        assert_eq!(litebox.authority().unwrap(), [any_group]);
    }

    #[test]
    fn in_process_broker_returns_the_largest_authority() {
        let largest: Vec<Term> = (0..u32::try_from(MAX_AUTHORITY_TERMS).unwrap())
            .map(|term| largest_term(term * 2048))
            .collect();
        let litebox = litebox_with_in_process_broker(&largest);

        assert_eq!(litebox.authority().unwrap(), largest);
    }
}
