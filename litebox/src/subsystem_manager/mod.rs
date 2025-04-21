//! Managing various LiteBox subsystems; see [`LiteBox`]

use alloc::{boxed::Box, sync::Arc};
use hashbrown::HashMap;

use crate::sync;

type Subsystems<Platform> =
    sync::RwLock<Platform, HashMap<SubsystemKind, Arc<sync::RwLock<Platform, Box<dyn Subsystem>>>>>;

/// A full LiteBox system, managing registered subsytems.
///
/// For now, we assume that synchronization support is a hard requirement in every LiteBox based
/// system. In the future, this may be relaxed. Other requirements from the platform are dependent
/// on the particular subsystems registered.
pub struct LiteBox<Platform: sync::RawSyncPrimitivesProvider> {
    pub(crate) platform: &'static Platform,
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    pub(crate) sync: sync::Synchronization<Platform>,
    subsystems: Subsystems<Platform>,
}

/// Each subsystem is a specific "kind", and there can only be one subsystem for each "kind". This
/// enum is used as the key to access the subsystem's "kind".
#[doc(hidden)]
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum SubsystemKind {
    Network,
    FileSystem,
    Descriptors,
}

mod private {
    use super::SubsystemKind;

    /// Ensuring that this crate is the only one who can define subsystems, we declare all the
    /// things we need out of a subsystem here. We have public sub-trait [`super::Subsystem`] which
    /// has this as a super-trait, so that external users are unable to look inside this particular
    /// trait or depend upon it, but crate-internal users can work with the details inside.
    ///
    /// Sealed via public-trait-inside-private-module
    pub trait SealedSubsystem: core::any::Any {
        /// Name of the subsystem, used purely for diagnostic purposes.
        fn name(&self) -> &'static str;
        /// The kind of subsystem this is; this is used as a key into the subsystem map.
        fn kind(&self) -> SubsystemKind;
        /// Which subsystems are required by this subsystem.
        fn requirements(&self) -> smallvec::SmallVec<[SubsystemKind; 2]>;
    }

    impl<Platform> SealedSubsystem for crate::net::Network<Platform>
    where
        Platform: crate::platform::IPInterfaceProvider
            + crate::platform::TimeProvider
            + crate::platform::RawMutexProvider,
    {
        fn name(&self) -> &'static str {
            "net"
        }
        fn kind(&self) -> SubsystemKind {
            SubsystemKind::Network
        }
        fn requirements(&self) -> smallvec::SmallVec<[SubsystemKind; 2]> {
            [SubsystemKind::Descriptors].into_iter().collect()
        }
    }
    impl<Platform> super::Subsystem for crate::net::Network<Platform> where
        Platform: crate::platform::IPInterfaceProvider
            + crate::platform::TimeProvider
            + crate::platform::RawMutexProvider
    {
    }

    impl<Platform: crate::sync::RawSyncPrimitivesProvider> SealedSubsystem
        for crate::fs::in_mem::FileSystem<Platform>
    {
        fn name(&self) -> &'static str {
            "in_mem::fs"
        }
        fn kind(&self) -> SubsystemKind {
            SubsystemKind::FileSystem
        }
        fn requirements(&self) -> smallvec::SmallVec<[SubsystemKind; 2]> {
            [SubsystemKind::Descriptors].into_iter().collect()
        }
    }
    impl<Platform: crate::sync::RawSyncPrimitivesProvider> super::Subsystem
        for crate::fs::in_mem::FileSystem<Platform>
    {
    }

    impl<Platform: crate::sync::RawSyncPrimitivesProvider> SealedSubsystem
        for crate::fs::tar_ro::FileSystem<Platform>
    {
        fn name(&self) -> &'static str {
            "tar_ro::fs"
        }
        fn kind(&self) -> SubsystemKind {
            SubsystemKind::FileSystem
        }
        fn requirements(&self) -> smallvec::SmallVec<[SubsystemKind; 2]> {
            [SubsystemKind::Descriptors].into_iter().collect()
        }
    }
    impl<Platform: crate::sync::RawSyncPrimitivesProvider> super::Subsystem
        for crate::fs::tar_ro::FileSystem<Platform>
    {
    }

    impl<Platform: crate::platform::Provider> SealedSubsystem
        for crate::fs::nine_p::FileSystem<Platform>
    {
        fn name(&self) -> &'static str {
            "nine_p::fs"
        }
        fn kind(&self) -> SubsystemKind {
            SubsystemKind::FileSystem
        }
        fn requirements(&self) -> smallvec::SmallVec<[SubsystemKind; 2]> {
            [SubsystemKind::Descriptors, SubsystemKind::Network]
                .into_iter()
                .collect()
        }
    }
    impl<Platform: crate::platform::Provider> super::Subsystem
        for crate::fs::nine_p::FileSystem<Platform>
    {
    }

    impl<
        Platform: crate::platform::Provider + 'static,
        Upper: crate::fs::FileSystem + SealedSubsystem + 'static,
        Lower: crate::fs::FileSystem + SealedSubsystem + 'static,
    > SealedSubsystem for crate::fs::layered::FileSystem<Platform, Upper, Lower>
    {
        fn name(&self) -> &'static str {
            "layered::fs"
        }
        fn kind(&self) -> SubsystemKind {
            SubsystemKind::FileSystem
        }
        fn requirements(&self) -> smallvec::SmallVec<[SubsystemKind; 2]> {
            self.upper
                .requirements()
                .into_iter()
                .chain(self.lower.requirements())
                .collect()
        }
    }
    impl<
        Platform: crate::platform::Provider + 'static,
        Upper: crate::fs::FileSystem + SealedSubsystem + 'static,
        Lower: crate::fs::FileSystem + SealedSubsystem + 'static,
    > super::Subsystem for crate::fs::layered::FileSystem<Platform, Upper, Lower>
    {
    }
}

/// A LiteBox subsystem, that can be registered via [`LiteBox::register`].
///
/// Note: this trait is explicitly empty (thus, provides nothing), but is sealed to only be
/// implementable by the `litebox` crate.
pub trait Subsystem: private::SealedSubsystem {}

impl<Platform: sync::RawSyncPrimitivesProvider> LiteBox<Platform> {
    /// Instantiate a new LiteBox system, with no [`register`](Self::register)ed subsystems.
    pub fn new(platform: &'static Platform) -> Self {
        let sync = sync::Synchronization::new(platform);
        let subsystems = sync.new_rwlock(HashMap::new());
        Self {
            platform,
            sync,
            subsystems,
        }
    }

    /// Register a subsystem into this LiteBox system.
    ///
    /// With this, LiteBox assumes full control over managing this subsystem, as well as interaction
    /// of this subsystem with other subsystems that are available.
    ///
    /// # Panics
    ///
    /// This function will panic if the subsystem believes that one of its required sub-systems has
    /// not yet been registered. The panic will tell you which subsystem it requires. If a subsystem
    /// does not panic upon registration, it is guaranteed that all its necessary subsystems have
    /// been successfully registered already.
    ///
    /// This function will also panic if the subsystem being registered conflicts with an already
    /// reigstered subsystem. The panic will tell you which subsystem it clashes with. If a
    /// subsystem does not panic upon registration, it is guaranteed to not conflict with any
    /// previously registered subsystems.
    pub fn register<S: Subsystem + 'static>(&mut self, subsystem: S) {
        let mut subsystems = self.subsystems.write();
        let new_name = subsystem.name();
        for r in &subsystem.requirements() {
            assert!(
                subsystems.contains_key(r),
                "Attempted to register {new_name}, but no {r:?} subsystem found",
            );
        }
        let old = subsystems.insert(
            subsystem.kind(),
            Arc::new(self.sync.new_rwlock(Box::new(subsystem))),
        );
        if let Some(old) = old {
            let old = old.read();
            let old_name = old.name();
            let kind = old.kind();
            panic!(
                "Attempted to register {new_name}, but conflicting {old_name}, of same kind ({kind:?}) already exists",
            );
        }
    }

    /// Crate-internal: register a subsystem if it has not already been registered. Silently ignore
    /// already registered subsystems.
    ///
    /// This is intended to be used by common subsystems that the user shouldn't really be bothered
    /// with. Most likely, these common subsystems will themselves be `pub(crate)` or such, rather
    /// than being `pub`.
    ///
    /// # Panics
    ///
    /// If any requirements of the newly registered subsystem are not satisfied, this will panic.
    /// However, since this is meant to be a crate-internal detail, this is never meant to be seen
    /// by a user, and should be considered a high-priority panic to fix.
    pub(crate) fn register_if_not_already<S: Subsystem + 'static>(
        &self,
        kind: SubsystemKind,
        init_subsystem: fn() -> S,
    ) {
        let mut subsystems = self.subsystems.write();
        if subsystems.contains_key(&kind) {
            return;
        }
        let s = init_subsystem();
        for r in &s.requirements() {
            if !subsystems.contains_key(r) {
                unreachable!(
                    "Attempted to register {}, but no {:?} subsystem found",
                    s.name(),
                    r
                );
            }
        }
        subsystems.insert(kind, Arc::new(self.sync.new_rwlock(Box::new(s))));
    }

    /// Crate-internal: get the registered subsystem of a particular kind.
    ///
    /// # Panics
    ///
    /// This function will panic if the requested subsystem is of the wrong type, or if the
    /// subsystem does not even exist.
    pub(crate) fn get<S: Subsystem>(&self, kind: SubsystemKind) -> LockedSubsystem<Platform, S> {
        let subsystem = Arc::clone(self.subsystems.read().get(&kind).unwrap());
        LockedSubsystem {
            _phantom: core::marker::PhantomData,
            subsystem,
        }
    }
}

/// A locked subsystem `S`
pub(crate) struct LockedSubsystem<Platform: sync::RawSyncPrimitivesProvider, S: Subsystem> {
    // Invariant: the `dyn Subsystem` must be an `S` specifically.
    _phantom: core::marker::PhantomData<S>,
    subsystem: Arc<sync::RwLock<Platform, Box<dyn Subsystem>>>,
}

impl<Platform: sync::RawSyncPrimitivesProvider, S: Subsystem> LockedSubsystem<Platform, S> {
    /// Make a new `LockedSubsystem`.
    ///
    /// # Panics
    ///
    /// This function panics if the requested subsystem is of the wrong type.
    fn new(subsystem: &Arc<sync::RwLock<Platform, Box<dyn Subsystem>>>) -> Self {
        assert!((&*subsystem.read() as &dyn core::any::Any).is::<S>());
        Self {
            _phantom: core::marker::PhantomData,
            subsystem: Arc::clone(subsystem),
        }
    }

    /// Obtain read-only access to `S`
    pub(crate) fn read(&self) -> impl core::ops::Deref<Target = S> {
        sync::RwLockReadGuard::map(self.subsystem.read(), |x| {
            (x as &dyn core::any::Any).downcast_ref().unwrap()
        })
    }

    /// Obtain read/write access to `S`
    pub(crate) fn write(&self) -> impl core::ops::DerefMut<Target = S> {
        sync::RwLockWriteGuard::map(self.subsystem.write(), |x| {
            (x as &mut dyn core::any::Any).downcast_mut().unwrap()
        })
    }
}
