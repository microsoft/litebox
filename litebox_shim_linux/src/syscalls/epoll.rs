use core::{sync::atomic::AtomicBool, time::Duration};

use alloc::{
    collections::{btree_map::BTreeMap, vec_deque::VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
use litebox::{
    LiteBox,
    event::{Events, observer::Observer, polling::Pollee},
};
use litebox_common_linux::{EpollEvent, EpollOp, errno::Errno};
use litebox_platform_multiplex::Platform;

use crate::Descriptor;

bitflags::bitflags! {
    /// Linux's epoll flags.
    #[derive(Debug)]
    struct EpollFlags: u32 {
        const EXCLUSIVE      = (1 << 28);
        const WAKE_UP        = (1 << 29);
        const ONE_SHOT       = (1 << 30);
        const EDGE_TRIGGER   = (1 << 31);
    }
}

enum DescriptorRef {
    PipeReader(Weak<crate::channel::Consumer<u8>>),
    PipeWriter(Weak<crate::channel::Producer<u8>>),
    Eventfd(Weak<crate::syscalls::eventfd::EventFile<litebox_platform_multiplex::Platform>>),
    Socket(Weak<crate::syscalls::net::Socket>),
}

impl DescriptorRef {
    fn from(value: &Descriptor) -> Self {
        match value {
            Descriptor::PipeReader { consumer, .. } => {
                DescriptorRef::PipeReader(Arc::downgrade(consumer))
            }
            Descriptor::PipeWriter { producer, .. } => {
                DescriptorRef::PipeWriter(Arc::downgrade(producer))
            }
            Descriptor::Eventfd { file, .. } => DescriptorRef::Eventfd(Arc::downgrade(file)),
            Descriptor::Socket(socket) => DescriptorRef::Socket(Arc::downgrade(socket)),
            _ => todo!(),
        }
    }

    fn upgrade(&self) -> Option<Descriptor> {
        match self {
            DescriptorRef::PipeReader(pipe) => {
                pipe.upgrade().map(|consumer| Descriptor::PipeReader {
                    consumer,
                    close_on_exec: AtomicBool::new(false),
                })
            }
            DescriptorRef::PipeWriter(pipe) => {
                pipe.upgrade().map(|producer| Descriptor::PipeWriter {
                    producer,
                    close_on_exec: AtomicBool::new(false),
                })
            }
            DescriptorRef::Eventfd(eventfd) => eventfd.upgrade().map(|file| Descriptor::Eventfd {
                file,
                close_on_exec: AtomicBool::new(false),
            }),
            DescriptorRef::Socket(socket) => socket.upgrade().map(Descriptor::Socket),
            _ => todo!(),
        }
    }
}

impl Descriptor {
    /// Returns the interesting events now and monitors their occurrence in the future if the
    /// observer is provided.
    fn poll(&self, mask: Events, observer: Option<Weak<dyn Observer<Events>>>) -> Events {
        let io_pollable: &dyn IOPollable = match self {
            Descriptor::PipeReader { consumer, .. } => consumer,
            Descriptor::PipeWriter { producer, .. } => producer,
            Descriptor::Eventfd { file, .. } => file,
            Descriptor::Socket(socket) => socket,
            _ => todo!(),
        };
        if let Some(observer) = observer {
            io_pollable.register_observer(observer, mask);
        }
        io_pollable.check_io_events() & (mask | Events::ALWAYS_POLLED)
    }
}

pub(crate) trait IOPollable {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events);
    fn check_io_events(&self) -> Events;
}
impl<T: IOPollable> IOPollable for Arc<T> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.as_ref().register_observer(observer, mask);
    }
    fn check_io_events(&self) -> Events {
        self.as_ref().check_io_events()
    }
}

pub(crate) struct EpollFile {
    interests: litebox::sync::Mutex<
        litebox_platform_multiplex::Platform,
        BTreeMap<EpollEntryKey, alloc::sync::Arc<EpollEntry>>,
    >,
    ready: Arc<ReadySet>,
    status: core::sync::atomic::AtomicU32,
}

impl EpollFile {
    pub(crate) fn new(litebox: &LiteBox<Platform>) -> Self {
        EpollFile {
            interests: litebox.sync().new_mutex(BTreeMap::new()),
            ready: Arc::new(ReadySet::new(litebox)),
            status: core::sync::atomic::AtomicU32::new(0),
        }
    }

    pub(crate) fn wait(
        &self,
        maxevents: usize,
        timeout: Option<Duration>,
    ) -> Result<Vec<EpollEvent>, Errno> {
        let mut events = Vec::new();
        match self.ready.pollee.wait_or_timeout(
            timeout,
            || {
                self.ready.pop_multiple(maxevents, &mut events);
                if events.is_empty() {
                    return Err(litebox::event::polling::TryOpError::TryAgain);
                }
                Ok(())
            },
            || self.ready.check_io_events().contains(Events::IN),
        ) {
            Ok(()) | Err(litebox::event::polling::TryOpError::TimedOut) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(events)
    }

    pub(crate) fn epoll_ctl(
        &self,
        op: EpollOp,
        fd: u32,
        file: &Descriptor,
        event: Option<EpollEvent>,
    ) -> Result<(), Errno> {
        match op {
            EpollOp::EpollCtlAdd => self.add_interest(fd, file, event.unwrap()),
            EpollOp::EpollCtlMod => todo!(),
            EpollOp::EpollCtlDel => {
                let mut interests = self.interests.lock();
                let _ = interests
                    .remove(&EpollEntryKey::new(fd, file))
                    .ok_or(Errno::ENOENT)?;
                Ok(())
            }
        }
    }

    fn add_interest(&self, fd: u32, file: &Descriptor, event: EpollEvent) -> Result<(), Errno> {
        let mut interests = self.interests.lock();
        let key = EpollEntryKey::new(fd, file);
        if let Some(entry) = interests.get(&key) {
            if entry.desc.upgrade().is_some() {
                return Err(Errno::EEXIST);
            }
            // find stale entry because we don't remove it immediately after the file is closed;
            // `insert` below will replace it with a new entry.
        }
        let mask = Events::from_bits_truncate(event.events);
        let entry = EpollEntry::new(
            DescriptorRef::from(file),
            mask,
            EpollFlags::from_bits_truncate(event.events),
            event.data,
            self.ready.clone(),
        );
        let events = file.poll(mask, Some(entry.weak_self.clone() as _));
        // Add the new entry to the ready list if the file is ready
        if !events.is_empty() {
            self.ready.push(&entry);
        }
        interests.insert(key, entry);
        Ok(())
    }

    fn mod_interest(&self, fd: u32, file: &Descriptor, event: EpollEvent) -> Result<(), Errno> {
        // EPOLLEXCLUSIVE is not allowed for a EPOLL_CTL_MOD operation
        let flags = EpollFlags::from_bits_truncate(event.events);
        if flags.contains(EpollFlags::EXCLUSIVE) {
            return Err(Errno::EINVAL);
        }

        let mut interests = self.interests.lock();
        let key = EpollEntryKey::new(fd, file);
        let entry = interests.get(&key).ok_or(Errno::ENOENT)?;
        if entry.desc.upgrade().is_none() {
            // The file descriptor is closed, remove the entry
            interests.remove(&key);
            return Err(Errno::ENOENT);
        }

        let mut inner = entry.inner.lock();
        if inner.flags.contains(EpollFlags::EXCLUSIVE) {
            // If EPOLLEXCLUSIVE has been set using epoll_ctl(), then a
            // subsequent EPOLL_CTL_MOD on the same epfd, fd pair yields an error.
            return Err(Errno::EINVAL);
        }

        let mask = Events::from_bits_truncate(event.events);
        inner.mask = mask;
        inner.flags = flags;
        inner.data = event.data;

        entry
            .is_enabled
            .store(true, core::sync::atomic::Ordering::Relaxed);

        // re-register the observer with the new mask
        let events = file.poll(mask, Some(entry.weak_self.clone() as _));
        if !events.is_empty() {
            // Add the updated entry to the ready list if the file is ready
            self.ready.push(entry);
        }

        Ok(())
    }

    super::common_functions_for_file_status!();
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct EpollEntryKey(u32, *const ());
impl EpollEntryKey {
    fn new(fd: u32, desc: &Descriptor) -> Self {
        let ptr = match desc {
            Descriptor::PipeReader { consumer, .. } => Arc::as_ptr(consumer).cast(),
            Descriptor::PipeWriter { producer, .. } => Arc::as_ptr(producer).cast(),
            Descriptor::Eventfd { file, .. } => Arc::as_ptr(file).cast(),
            Descriptor::Stdio(crate::stdio::StdioFile { inner, .. }) => Arc::as_ptr(inner).cast(),
            Descriptor::Socket(socket) => Arc::as_ptr(socket).cast(),
            _ => todo!(),
        };
        Self(fd, ptr)
    }
}

struct EpollEntry {
    desc: DescriptorRef,
    inner: litebox::sync::Mutex<litebox_platform_multiplex::Platform, EpollEntryInner>,
    ready: Arc<ReadySet>,
    is_ready: AtomicBool,
    is_enabled: AtomicBool,
    weak_self: Weak<Self>,
}

struct EpollEntryInner {
    mask: Events,
    flags: EpollFlags,
    data: u64,
}

impl EpollEntry {
    fn new(
        desc: DescriptorRef,
        mask: Events,
        flags: EpollFlags,
        data: u64,
        ready: Arc<ReadySet>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| EpollEntry {
            desc,
            inner: crate::litebox()
                .sync()
                .new_mutex(EpollEntryInner { mask, flags, data }),
            ready,
            is_ready: AtomicBool::new(false),
            is_enabled: AtomicBool::new(true),
            weak_self: weak_self.clone(),
        })
    }

    fn poll(&self) -> Option<(Option<EpollEvent>, bool)> {
        let file = self.desc.upgrade()?;
        let inner = self.inner.lock();

        if !self.is_enabled.load(core::sync::atomic::Ordering::Relaxed) {
            // the entry is disabled
            return None;
        }

        let events = file.poll(inner.mask, None);
        if events.is_empty() {
            Some((None, false))
        } else {
            let event = Some(EpollEvent {
                events: events.bits(),
                data: inner.data,
            });

            // keep the entry in the ready list if it is not edge-triggered or one-shot
            let is_still_ready = event.is_some()
                && !inner
                    .flags
                    .intersects(EpollFlags::EDGE_TRIGGER | EpollFlags::ONE_SHOT);

            // disable the entry if it is one-shot
            if inner.flags.contains(EpollFlags::ONE_SHOT) {
                self.is_enabled
                    .store(false, core::sync::atomic::Ordering::Relaxed);
            }

            Some((event, is_still_ready))
        }
    }
}

impl Observer<Events> for EpollEntry {
    fn on_events(&self, events: &Events) {
        self.ready.push(self);
    }
}

struct ReadySet {
    entries: litebox::sync::Mutex<
        litebox_platform_multiplex::Platform,
        VecDeque<alloc::sync::Weak<EpollEntry>>,
    >,
    pollee: Pollee<Platform>,
}

impl ReadySet {
    fn new(litebox: &LiteBox<Platform>) -> Self {
        Self {
            entries: litebox.sync().new_mutex(VecDeque::new()),
            pollee: Pollee::new(litebox),
        }
    }

    fn push(&self, entry: &EpollEntry) {
        if !entry.is_enabled.load(core::sync::atomic::Ordering::Relaxed) {
            // the entry is disabled
            return;
        }

        let mut entries = self.entries.lock();
        if !entry
            .is_ready
            .swap(true, core::sync::atomic::Ordering::Relaxed)
        {
            entries.push_back(entry.weak_self.clone());
        }
        drop(entries);

        self.pollee.notify_observers(Events::IN);
    }

    fn pop_multiple(&self, maxevents: usize, events: &mut Vec<EpollEvent>) {
        let mut entries = self.entries.lock();
        let mut nums = entries.len();
        while nums > 0 {
            nums -= 1;
            if events.len() >= maxevents {
                break;
            }

            let Some(weak_entry) = entries.pop_front() else {
                // no more entries
                break;
            };

            let Some(entry) = weak_entry.upgrade() else {
                // the entry has been deleted
                continue;
            };
            entry
                .is_ready
                .store(false, core::sync::atomic::Ordering::Relaxed);

            let Some((event, is_still_ready)) = entry.poll() else {
                // the entry is disabled or the associated file is closed
                continue;
            };

            if let Some(event) = event {
                events.push(event);
            }

            if is_still_ready {
                entry
                    .is_ready
                    .store(true, core::sync::atomic::Ordering::Relaxed);
                entries.push_back(weak_entry);
            }
        }
    }

    fn check_io_events(&self) -> Events {
        if self.entries.lock().is_empty() {
            Events::empty()
        } else {
            Events::IN
        }
    }
}

#[cfg(test)]
mod test {
    use alloc::sync::Arc;
    use litebox::{event::Events, fs::OFlags};
    use litebox_common_linux::{EfdFlags, EpollEvent};

    use super::EpollFile;

    extern crate std;

    fn setup_epoll() -> EpollFile {
        crate::syscalls::tests::init_platform(None);

        EpollFile::new(crate::litebox())
    }

    #[test]
    fn test_epoll_with_eventfd() {
        let epoll = setup_epoll();
        let eventfd = Arc::new(crate::syscalls::eventfd::EventFile::new(
            0,
            EfdFlags::CLOEXEC,
            crate::litebox(),
        ));
        epoll
            .add_interest(
                10,
                &crate::Descriptor::Eventfd {
                    file: eventfd.clone(),
                    close_on_exec: core::sync::atomic::AtomicBool::new(false),
                },
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 0,
                },
            )
            .unwrap();

        // spawn a thread to write to the eventfd
        let copied_eventfd = eventfd.clone();
        std::thread::spawn(move || {
            copied_eventfd.write(1).unwrap();
        });
        epoll.wait(1024, None).unwrap();
    }

    #[test]
    fn test_epoll_with_pipe() {
        let epoll = setup_epoll();
        let (producer, consumer) =
            crate::channel::Channel::<u8>::new(2, OFlags::empty(), crate::litebox()).split();
        let reader = crate::Descriptor::PipeReader {
            consumer,
            close_on_exec: core::sync::atomic::AtomicBool::new(false),
        };
        epoll
            .add_interest(
                10,
                &reader,
                EpollEvent {
                    events: Events::IN.bits(),
                    data: 0,
                },
            )
            .unwrap();

        // spawn a thread to write to the pipe
        std::thread::spawn(move || {
            std::thread::sleep(core::time::Duration::from_millis(100));
            assert_eq!(producer.write(&[1, 2]).unwrap(), 2);
        });
        epoll.wait(1024, None).unwrap();
        let mut buf = [0; 2];
        let crate::Descriptor::PipeReader { consumer, .. } = reader else {
            unreachable!();
        };
        consumer.read(&mut buf).unwrap();
        assert_eq!(buf, [1, 2]);
    }
}
