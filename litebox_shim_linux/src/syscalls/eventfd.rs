// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Event file for notification

use core::sync::atomic::AtomicU32;

use litebox::{
    event::{
        Events, IOPollable,
        counter::{EventCounter, EventCounterError, EventCounterReadMode},
        observer::Observer,
        polling::{Pollee, TryOpError},
        wait::WaitContext,
    },
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry},
    fs::OFlags,
    platform::TimeProvider,
    sync::{Mutex, RawSyncPrimitivesProvider},
};
use litebox_common_linux::{EfdFlags, errno::Errno};

use crate::{GlobalState, Platform, ShimFS};

pub(crate) struct EventfdSubsystem;
impl FdEnabledSubsystem for EventfdSubsystem {
    type Entry = EventFile<Platform>;
}
impl FdEnabledSubsystemEntry for EventFile<Platform> {}

/// Backing counter for a Linux eventfd file description.
///
/// New blocking eventfds use the shim-local path. Broker-backed counters stay
/// nonblocking even if file status flags are later changed, until broker
/// readiness notifications can wake local waiters.
enum EventFileCounter<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    ShimLocal {
        count: Mutex<Platform, u64>,
        pollee: Pollee<Platform>,
    },
    LocalCore(EventCounter<Platform>),
}

pub(crate) struct EventFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    counter: EventFileCounter<Platform>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
    semaphore: bool,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFileCounter<Platform> {
    fn shim_local(count: u64) -> Self {
        Self::ShimLocal {
            count: Mutex::new(count),
            pollee: Pollee::new(),
        }
    }

    fn read(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        semaphore: bool,
    ) -> Result<u64, Errno> {
        match self {
            Self::ShimLocal { count, pollee } => pollee
                .wait(cx, nonblock, Events::IN, || {
                    Self::try_read_local(count, pollee, semaphore)
                })
                .map_err(Errno::from),
            Self::LocalCore(counter) => counter
                .read(
                    cx,
                    // Broker-backed eventfds cannot safely park local waiters
                    // until broker readiness notifications exist.
                    true,
                    if semaphore {
                        EventCounterReadMode::One
                    } else {
                        EventCounterReadMode::All
                    },
                )
                .map_err(Errno::from),
        }
    }

    fn write(
        &self,
        cx: &WaitContext<'_, Platform>,
        nonblock: bool,
        value: u64,
    ) -> Result<usize, Errno> {
        match self {
            Self::ShimLocal { count, pollee } => pollee
                .wait(cx, nonblock, Events::OUT, || {
                    Self::try_write_local(count, pollee, value)
                })
                .map_err(Errno::from),
            // See the matching LocalCore read path for why this stays nonblocking.
            Self::LocalCore(counter) => counter.write(cx, true, value).map_err(Errno::from),
        }
    }

    fn try_read_local(
        count: &Mutex<Platform, u64>,
        pollee: &Pollee<Platform>,
        semaphore: bool,
    ) -> Result<u64, TryOpError<Errno>> {
        let mut count = count.lock();
        if *count == 0 {
            return Err(TryOpError::TryAgain);
        }

        let res = if semaphore { 1 } else { *count };
        *count -= res;

        drop(count);
        pollee.notify_observers(Events::OUT);
        Ok(res)
    }

    fn try_write_local(
        count: &Mutex<Platform, u64>,
        pollee: &Pollee<Platform>,
        value: u64,
    ) -> Result<usize, TryOpError<Errno>> {
        if value == u64::MAX {
            return Err(TryOpError::Other(Errno::EINVAL));
        }

        let mut count = count.lock();
        if let Some(new_value) = (*count).checked_add(value)
            && new_value != u64::MAX
        {
            *count = new_value;
            drop(count);
            pollee.notify_observers(Events::IN);
            return Ok(core::mem::size_of::<u64>());
        }

        Err(TryOpError::TryAgain)
    }

    fn check_io_events(&self) -> Events {
        match self {
            Self::ShimLocal { count, .. } => {
                let count = count.lock();
                let mut events = Events::empty();
                if *count != 0 {
                    events |= Events::IN;
                }
                if *count < u64::MAX - 1 {
                    events |= Events::OUT;
                }
                events
            }
            Self::LocalCore(counter) => counter.check_io_events(),
        }
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        match self {
            Self::ShimLocal { pollee, .. } => pollee.register_observer(observer, mask),
            Self::LocalCore(counter) => counter.register_observer(observer, mask),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> EventFile<Platform> {
    fn new(counter: EventFileCounter<Platform>, flags: EfdFlags) -> Self {
        let mut status = OFlags::RDWR;
        status.set(OFlags::NONBLOCK, flags.contains(EfdFlags::NONBLOCK));
        Self {
            counter,
            status: AtomicU32::new(status.bits()),
            semaphore: flags.contains(EfdFlags::SEMAPHORE),
        }
    }

    pub(crate) fn read(&self, cx: &WaitContext<'_, Platform>) -> Result<u64, Errno> {
        self.counter.read(cx, self.is_nonblocking(), self.semaphore)
    }

    pub(crate) fn write(&self, cx: &WaitContext<'_, Platform>, value: u64) -> Result<usize, Errno> {
        self.counter.write(cx, self.is_nonblocking(), value)
    }

    super::common_functions_for_file_status!();

    fn is_nonblocking(&self) -> bool {
        self.get_status().contains(OFlags::NONBLOCK)
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for EventFile<Platform> {
    fn check_io_events(&self) -> Events {
        self.counter.check_io_events()
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.counter.register_observer(observer, mask);
    }
}

impl<FS: ShimFS> GlobalState<FS> {
    pub(crate) fn create_linux_eventfd(
        &self,
        initval: u32,
        flags: EfdFlags,
    ) -> Result<EventFile<Platform>, Errno> {
        if flags
            .intersects((EfdFlags::SEMAPHORE | EfdFlags::CLOEXEC | EfdFlags::NONBLOCK).complement())
        {
            return Err(Errno::EINVAL);
        }

        let count = u64::from(initval);
        let counter = if flags.contains(EfdFlags::NONBLOCK) {
            match EventCounter::new(&self.litebox, count) {
                Ok(counter) => EventFileCounter::LocalCore(counter),
                Err(EventCounterError::Unavailable) => EventFileCounter::shim_local(count),
                Err(error) => return Err(error.into()),
            }
        } else {
            EventFileCounter::shim_local(count)
        };
        Ok(EventFile::new(counter, flags))
    }
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use litebox::event::wait::WaitState;
    use litebox::fs::OFlags;
    use litebox_broker_local::BrokerLocal;
    use litebox_broker_protocol::channel::LocalControlChannel;
    use litebox_broker_protocol::error::ErrorCode;
    use litebox_broker_protocol::event::{
        AddEventResponse, CreateEventResponse, EventConsumeMode, EventConsumption, ReadinessState,
        WaitEventResponse,
    };
    use litebox_broker_protocol::message::{
        BrokerHandshakeRequest, BrokerHandshakeResponse, BrokerRequest, BrokerResponse,
        EventRequest, EventResponse,
    };
    use litebox_broker_protocol::{BROKER_PROTOCOL_VERSION, ObjectHandle};
    use litebox_common_linux::{EfdFlags, FcntlArg, FileDescriptorFlags, errno::Errno};
    use litebox_platform_multiplex::platform;

    extern crate std;

    const MAX_EVENT_COUNT: u64 = u64::MAX - 1;

    #[derive(Default)]
    struct TestBrokerState {
        next_handle: u64,
        events: std::collections::BTreeMap<ObjectHandle, u64>,
        close_requests: usize,
    }

    struct TestBrokerChannel {
        state: std::sync::Arc<std::sync::Mutex<TestBrokerState>>,
        pending_response: Option<BrokerResponse>,
    }

    impl TestBrokerChannel {
        fn new(state: std::sync::Arc<std::sync::Mutex<TestBrokerState>>) -> Self {
            Self {
                state,
                pending_response: None,
            }
        }

        fn handle_request(state: &mut TestBrokerState, request: &BrokerRequest) -> BrokerResponse {
            match request {
                BrokerRequest::CloseObject(handle) => {
                    state.close_requests += 1;
                    if state.events.remove(handle).is_some() {
                        BrokerResponse::ObjectClosed
                    } else {
                        BrokerResponse::Error(ErrorCode::UnknownObject)
                    }
                }
                BrokerRequest::Event(request) => Self::handle_event_request(state, request),
            }
        }

        fn handle_event_request(
            state: &mut TestBrokerState,
            request: &EventRequest,
        ) -> BrokerResponse {
            match request {
                EventRequest::Create(request) => {
                    if request.initial_count > MAX_EVENT_COUNT {
                        return BrokerResponse::Error(ErrorCode::ResourceExhausted);
                    }
                    state.next_handle += 1;
                    let handle = ObjectHandle(state.next_handle);
                    state.events.insert(handle, request.initial_count);
                    BrokerResponse::Event(EventResponse::Create(CreateEventResponse { handle }))
                }
                EventRequest::Wait(request) => {
                    let Some(count) = state.events.get(&request.handle) else {
                        return BrokerResponse::Error(ErrorCode::UnknownObject);
                    };
                    BrokerResponse::Event(EventResponse::Wait(WaitEventResponse {
                        readiness: readiness(*count),
                    }))
                }
                EventRequest::Add(request) => {
                    let Some(count) = state.events.get_mut(&request.handle) else {
                        return BrokerResponse::Error(ErrorCode::UnknownObject);
                    };
                    let Some(new_count) = count
                        .checked_add(request.value)
                        .filter(|count| *count <= MAX_EVENT_COUNT)
                    else {
                        return BrokerResponse::Error(ErrorCode::WouldBlock);
                    };
                    *count = new_count;
                    BrokerResponse::Event(EventResponse::Add(AddEventResponse {
                        readiness: readiness(*count),
                    }))
                }
                EventRequest::Consume(request) => {
                    let Some(count) = state.events.get_mut(&request.handle) else {
                        return BrokerResponse::Error(ErrorCode::UnknownObject);
                    };
                    if *count == 0 {
                        return BrokerResponse::Error(ErrorCode::WouldBlock);
                    }
                    let value = match request.mode {
                        EventConsumeMode::All => *count,
                        EventConsumeMode::One => 1,
                    };
                    *count -= value;
                    BrokerResponse::Event(EventResponse::Consume(EventConsumption {
                        value,
                        readiness: readiness(*count),
                    }))
                }
            }
        }
    }

    impl LocalControlChannel for TestBrokerChannel {
        type Error = Infallible;

        fn send_handshake_request(
            &mut self,
            _request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }))
        }

        fn send_request(
            &mut self,
            request: &BrokerRequest,
        ) -> core::result::Result<(), Self::Error> {
            let mut state = self.state.lock().unwrap();
            self.pending_response = Some(Self::handle_request(&mut state, request));
            Ok(())
        }

        fn recv_response(&mut self) -> core::result::Result<Option<BrokerResponse>, Self::Error> {
            Ok(self.pending_response.take())
        }
    }

    fn readiness(count: u64) -> ReadinessState {
        ReadinessState {
            read_ready: count > 0,
            write_ready: count < MAX_EVENT_COUNT,
        }
    }

    fn broker_backed_task() -> (
        crate::Task<crate::DefaultFS>,
        std::sync::Arc<std::sync::Mutex<TestBrokerState>>,
    ) {
        let state = std::sync::Arc::new(std::sync::Mutex::new(TestBrokerState::default()));
        let channel = TestBrokerChannel::new(state.clone());
        let broker_local = BrokerLocal::negotiate(channel).unwrap();
        let litebox = litebox::LiteBox::new_with_broker_local(
            crate::syscalls::tests::platform_for_tests(None),
            broker_local,
        );
        (
            crate::syscalls::tests::init_platform_with_litebox(litebox, None),
            state,
        )
    }

    fn read_eventfd(task: &crate::Task<crate::DefaultFS>, fd: u32) -> Result<u64, Errno> {
        let mut buf = [0; size_of::<u64>()];
        let bytes = task.sys_read(fd.try_into().unwrap(), &mut buf, None)?;
        assert_eq!(bytes, size_of::<u64>());
        Ok(u64::from_le_bytes(buf))
    }

    fn write_eventfd(
        task: &crate::Task<crate::DefaultFS>,
        fd: u32,
        value: u64,
    ) -> Result<usize, Errno> {
        task.sys_write(fd.try_into().unwrap(), &value.to_le_bytes(), None)
    }

    fn assert_fd_flags(
        task: &crate::Task<crate::DefaultFS>,
        fd: u32,
        expected: FileDescriptorFlags,
    ) {
        assert_eq!(
            task.sys_fcntl(fd.try_into().unwrap(), FcntlArg::GETFD)
                .unwrap(),
            expected.bits()
        );
    }

    fn assert_status_flags(task: &crate::Task<crate::DefaultFS>, fd: u32, expected: OFlags) {
        assert_eq!(
            task.sys_fcntl(fd.try_into().unwrap(), FcntlArg::GETFL)
                .unwrap(),
            expected.bits()
        );
    }

    fn assert_broker_state(
        state: &std::sync::Arc<std::sync::Mutex<TestBrokerState>>,
        live_events: usize,
        close_requests: usize,
    ) {
        let state = state.lock().unwrap();
        assert_eq!(state.events.len(), live_events);
        assert_eq!(state.close_requests, close_requests);
    }

    #[test]
    fn test_semaphore_eventfd() {
        let _task = crate::syscalls::tests::init_platform(None);

        let eventfd = alloc::sync::Arc::new(super::EventFile::new(
            super::EventFileCounter::shim_local(0),
            EfdFlags::SEMAPHORE,
        ));
        let total = 8;
        let handles: std::vec::Vec<_> = (0..total)
            .map(|_| {
                let copied_eventfd = eventfd.clone();
                std::thread::spawn(move || {
                    copied_eventfd
                        .read(&WaitState::new(platform()).context())
                        .unwrap();
                })
            })
            .collect();

        std::thread::sleep(core::time::Duration::from_millis(500));
        eventfd
            .write(&WaitState::new(platform()).context(), total)
            .unwrap();
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_blocking_eventfd() {
        let _task = crate::syscalls::tests::init_platform(None);

        let eventfd = alloc::sync::Arc::new(super::EventFile::new(
            super::EventFileCounter::shim_local(0),
            EfdFlags::empty(),
        ));
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            copied_eventfd
                .write(&WaitState::new(platform()).context(), 1)
                .unwrap();
            // block until the first read finishes
            copied_eventfd
                .write(&WaitState::new(platform()).context(), u64::MAX - 1)
                .unwrap();
        });

        // block until the first write
        let ret = eventfd.read(&WaitState::new(platform()).context()).unwrap();
        assert_eq!(ret, 1);

        // block until the second write
        let ret = eventfd.read(&WaitState::new(platform()).context()).unwrap();
        assert_eq!(ret, u64::MAX - 1);
    }

    #[test]
    fn test_blocking_eventfd_no_race_on_massive_readwrite() {
        let _task = crate::syscalls::tests::init_platform(None);

        let eventfd = alloc::sync::Arc::new(super::EventFile::new(
            super::EventFileCounter::shim_local(0),
            EfdFlags::empty(),
        ));
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            for _ in 0..10000 {
                copied_eventfd
                    .write(&WaitState::new(platform()).context(), u64::MAX - 1)
                    .unwrap();
            }
        });

        for _ in 0..10000 {
            let ret = eventfd.read(&WaitState::new(platform()).context()).unwrap();
            assert_eq!(ret, u64::MAX - 1);
        }
    }

    #[test]
    fn test_nonblocking_eventfd_uses_shim_local_without_broker_control() {
        let task = crate::syscalls::tests::init_platform(None);

        let eventfd = task
            .global
            .create_linux_eventfd(0, EfdFlags::NONBLOCK)
            .unwrap();
        assert_eq!(
            eventfd.read(&WaitState::new(platform()).context()),
            Err(Errno::EAGAIN)
        );
        assert_eq!(
            eventfd.write(&WaitState::new(platform()).context(), 1),
            Ok(8)
        );
        assert_eq!(eventfd.read(&WaitState::new(platform()).context()), Ok(1));
    }

    #[test]
    fn broker_backed_eventfd_dup_closes_object_on_final_close() {
        let (task, broker) = broker_backed_task();
        let fd = task.sys_eventfd2(0, EfdFlags::NONBLOCK).unwrap();
        let dup_fd = task.sys_dup(fd.try_into().unwrap(), None, None).unwrap();

        assert_broker_state(&broker, 1, 0);
        assert_eq!(write_eventfd(&task, fd, 7), Ok(size_of::<u64>()));
        assert_eq!(read_eventfd(&task, dup_fd), Ok(7));

        task.sys_close(fd.try_into().unwrap()).unwrap();
        assert_broker_state(&broker, 1, 0);
        assert_eq!(write_eventfd(&task, fd, 1), Err(Errno::EBADF));
        assert_eq!(write_eventfd(&task, dup_fd, 3), Ok(size_of::<u64>()));
        assert_eq!(read_eventfd(&task, dup_fd), Ok(3));

        task.sys_close(dup_fd.try_into().unwrap()).unwrap();
        assert_broker_state(&broker, 0, 1);
        assert_eq!(
            task.sys_close(dup_fd.try_into().unwrap()),
            Err(Errno::EBADF)
        );
        assert_eq!(read_eventfd(&task, dup_fd), Err(Errno::EBADF));
    }

    #[test]
    fn broker_backed_eventfd_closing_duplicate_first_keeps_original_live() {
        let (task, broker) = broker_backed_task();
        let fd = task.sys_eventfd2(0, EfdFlags::NONBLOCK).unwrap();
        let dup_fd = task.sys_dup(fd.try_into().unwrap(), None, None).unwrap();

        task.sys_close(dup_fd.try_into().unwrap()).unwrap();
        assert_broker_state(&broker, 1, 0);
        assert_eq!(write_eventfd(&task, fd, 5), Ok(size_of::<u64>()));
        assert_eq!(read_eventfd(&task, fd), Ok(5));

        task.sys_close(fd.try_into().unwrap()).unwrap();
        assert_broker_state(&broker, 0, 1);
    }

    #[test]
    fn broker_backed_eventfd_dup2_replaces_existing_eventfd() {
        let (task, broker) = broker_backed_task();
        let fd = task.sys_eventfd2(0, EfdFlags::NONBLOCK).unwrap();
        let replaced_fd = task.sys_eventfd2(0, EfdFlags::NONBLOCK).unwrap();

        assert_broker_state(&broker, 2, 0);
        assert_eq!(
            task.sys_dup(
                fd.try_into().unwrap(),
                Some(replaced_fd.try_into().unwrap()),
                None
            ),
            Ok(replaced_fd)
        );
        assert_broker_state(&broker, 1, 1);

        task.sys_close(fd.try_into().unwrap()).unwrap();
        assert_broker_state(&broker, 1, 1);
        assert_eq!(write_eventfd(&task, replaced_fd, 11), Ok(size_of::<u64>()));
        assert_eq!(read_eventfd(&task, replaced_fd), Ok(11));

        task.sys_close(replaced_fd.try_into().unwrap()).unwrap();
        assert_broker_state(&broker, 0, 2);
    }

    #[test]
    fn broker_backed_eventfd_dup3_and_fcntl_dupfd_handle_fd_flags() {
        let (task, broker) = broker_backed_task();
        let fd = task.sys_eventfd2(0, EfdFlags::NONBLOCK).unwrap();

        let dup3_fd = task
            .sys_dup(
                fd.try_into().unwrap(),
                Some((fd + 10).try_into().unwrap()),
                Some(OFlags::CLOEXEC),
            )
            .unwrap();
        assert_fd_flags(&task, dup3_fd, FileDescriptorFlags::FD_CLOEXEC);

        let fdup_fd = task
            .sys_fcntl(
                fd.try_into().unwrap(),
                FcntlArg::DUPFD {
                    cloexec: false,
                    min_fd: dup3_fd + 1,
                },
            )
            .unwrap();
        assert_eq!(fdup_fd, dup3_fd + 1);
        assert_fd_flags(&task, fdup_fd, FileDescriptorFlags::empty());

        let fdup_cloexec_fd = task
            .sys_fcntl(
                fd.try_into().unwrap(),
                FcntlArg::DUPFD {
                    cloexec: true,
                    min_fd: fdup_fd + 1,
                },
            )
            .unwrap();
        assert_eq!(fdup_cloexec_fd, fdup_fd + 1);
        assert_fd_flags(&task, fdup_cloexec_fd, FileDescriptorFlags::FD_CLOEXEC);
        assert_broker_state(&broker, 1, 0);

        for fd in [fd, dup3_fd, fdup_fd] {
            task.sys_close(fd.try_into().unwrap()).unwrap();
            assert_broker_state(&broker, 1, 0);
        }
        task.sys_close(fdup_cloexec_fd.try_into().unwrap()).unwrap();
        assert_broker_state(&broker, 0, 1);
    }

    #[test]
    fn broker_backed_eventfd_duplicates_share_status_flags() {
        let (task, _broker) = broker_backed_task();
        let fd = task.sys_eventfd2(0, EfdFlags::NONBLOCK).unwrap();
        let dup_fd = task.sys_dup(fd.try_into().unwrap(), None, None).unwrap();

        assert_status_flags(&task, fd, OFlags::RDWR | OFlags::NONBLOCK);
        assert_status_flags(&task, dup_fd, OFlags::RDWR | OFlags::NONBLOCK);

        task.sys_fcntl(dup_fd.try_into().unwrap(), FcntlArg::SETFL(OFlags::empty()))
            .unwrap();
        assert_status_flags(&task, fd, OFlags::RDWR);
        assert_status_flags(&task, dup_fd, OFlags::RDWR);
        assert_eq!(read_eventfd(&task, fd), Err(Errno::EAGAIN));

        task.sys_fcntl(fd.try_into().unwrap(), FcntlArg::SETFL(OFlags::NONBLOCK))
            .unwrap();
        assert_status_flags(&task, fd, OFlags::RDWR | OFlags::NONBLOCK);
        assert_status_flags(&task, dup_fd, OFlags::RDWR | OFlags::NONBLOCK);
    }
}
