//! Crate-internal shared functionality between file system implementations

use crate::fd::FileFd;
use crate::fd::OwnedFd;
use alloc::vec;
use alloc::vec::Vec;

/// A collection of descriptors for files, parameterized by what is actually stored in the
/// descriptors.
pub(crate) struct Descriptors<Descriptor> {
    descriptors: Vec<Option<Descriptor>>,
}

impl<Descriptor> Descriptors<Descriptor> {
    pub(crate) fn new() -> Self {
        Self {
            descriptors: vec![],
        }
    }

    pub(crate) fn insert(&mut self, descriptor: Descriptor) -> FileFd {
        let idx = self
            .descriptors
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.descriptors.push(None);
                self.descriptors.len() - 1
            });
        let old = self.descriptors[idx].replace(descriptor);
        assert!(old.is_none());
        FileFd {
            x: OwnedFd::new(idx),
        }
    }

    pub(crate) fn remove(&mut self, mut fd: FileFd) -> Descriptor {
        let old = self.descriptors[fd.x.as_usize()].take();
        assert!(old.is_some());
        fd.x.mark_as_closed();
        old.unwrap()
    }

    pub(crate) fn get(&self, fd: &FileFd) -> &Descriptor {
        // Since the `fd` is borrowed, it must still exist, thus this index will always exist, as
        // well as have a value within it.
        self.descriptors[fd.x.as_usize()].as_ref().unwrap()
    }

    pub(crate) fn get_mut(&mut self, fd: &FileFd) -> &mut Descriptor {
        // Since the `fd` is borrowed, it must still exist, thus this index will always exist, as
        // well as have a value within it.
        self.descriptors[fd.x.as_usize()].as_mut().unwrap()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Descriptor> {
        self.descriptors.iter_mut().flatten()
    }
}
