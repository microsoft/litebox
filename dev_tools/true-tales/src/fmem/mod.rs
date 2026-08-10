// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The true-tales foreign memory subsystem
//!
//! As opposed to Rust-memory, true-tales models foreign memory as a shared
//! resource, accessible to all hardware threads. The foreign memory subsystem
//! supports multiple distinct and disjoint domains (which operate under their
//! own semantics, and are implemented with different types). Each domain can
//! have multiple contiguous memory regions. Rust or the CPU models can then use
//! these domains to perform loads and stores towards foreign memory.
//!
//! This is the general, layered architecture of the foreign memory subsystem:
//!
//! ```text
//!   CPU model      Amd64Thread / HardwareThread
//!    machine/        .cpu.regs[r] = ForeignMemPtr(ForeignPtr)       ptr.rs
//!                    .fmem        = DomainMap                         |
//!  -------------------- | ------------------------- fmem -------------|--
//!                       v                                             |
//!   routing        DomainMap          domain ID -> live domain object |
//!     map.rs            |             mapping, can be stored in       |
//!                       |             ThreadLocal state, referenced   |
//!                       |             by ForeignPtr        <----------/
//!                       v
//!   handle          ErasedArc         refcounted, type-erased ForeignDomain
//!     erasure.rs        |             instance. Cloned and held when running
//!                       |             an operation on a foreign domain
//!                       v
//!   object           D::Obj           state of one ForeignDomain instance
//!     domains/          |             (ForeignDomain itself isn't object safe)
//!                       v
//!   session    BoundSession<D::Session<'a>>
//!     capability.rs     |             a foreign domain ready to run load/store
//!     session.rs        |             (may include locking)
//!                       |
//!                       v
//!   backing        TransactionalVec   the modeled bytes (e.g., for Miri tests)
//!     backing.rs
//! ```
//!
//! # Routing and Erasure
//!
//! The map can contain multiple different types of domains concurrently, so it
//! holds a `dyn` object representation of their state ([`erasure::DynState`]
//! makes this possible in Verus). A CPU register carries a thin, type-erased
//! [`ptr::ForeignPtr`] to address the domain. The pointer does not ensure
//! liveness of the domain.
//!
//! Going from this representation to a usable ForeignDomain handle requires two
//! steps:
//!
//! 1. Extract the domain from the map (routing).
//!
//!    [`map::DomainMap::take_handle`] returns a clone of the `ErasedArc` stored
//!    in the map for a given [`ForeignDomainId`], which can be recovered from
//!    the [`ForeignPtr`] stored in a CPU register.
//!
//!    This ensures that even if the domain is being removed from the map with
//!    [`map::DomainMap::remove_domain`]
//!    concurrently (after this step), the user still holds a reference to it
//!    that can be used for as long as the foreign memory is accessed. Removal
//!    from the map just prevents _new_ users from acquiring a reference.
//!
//!    Practically, this meshes well with how OSes reason about non-static
//!    foreign memory domains: for instance, when a userspace's memory regions
//!    are unmapped and freed, a kernel has to ensure that no new concurrent
//!    threads may try to access it, and then wait for all existing accessors to
//!    finish. [`erasure::RetiredDomain`] reports when those accessors have
//!    released their handles and the address space or device may be freed.
//!
//! 2. Downcast from the erased to the concrete type.
//!
//!    Given some foreign domain type `D: ForeignDomain`, use
//!    [`capability::handle_obj`] to go from the erased Arc to a concrete
//!    foreign domain state.
//!
//! The map addresses domains by a [`ForeignDomainId`], which in practice is
//! just a (provenance-carrying) pointer. This is fine for verification (in
//! Verus we can't assume that two objects, even if not live at the same time,
//! are allocated at the same address). However, for OSes, in practice, a domain
//! with an identical type may well be allocated at the same address in memory.
//! To avoid the model falsely accessing e.g., a new userspace process from a
//! stale pointer, references also carry a "cookie". This is a simple, u64 nonce
//! that the OS assigns to domains. It can be derived from other OS state. It
//! must never be re-used between two domains that are allocated at the same
//! address. [`map::DomainMap::remove_domain`] checks the cookie at runtime in the same
//! mutable map operation that removes the route, preventing stale teardown
//! authority from removing a replacement domain.
//!
//! # Sessions
//!
//! Some foreign memory domains can always be accessed (e.g., an uncooperative
//! userspace domain). Others have global state, that must not be accessed
//! concurrently, as this would be unsound in practice and inexpressible in this
//! model.
//!
//! To solve this, we introduce `Sessions`: a [`BoundSession`] can be opened on
//! a [`ForeignDomain`] to perform loads and stores on its memory. Depending on
//! the domain, this may e.g., aquire an exclusive lock, or be a no-op. Notably,
//! this code is intended to run both in the model, and on a real system, and
//! thus gives equivalent guarantees and can serve as a proper synchronization
//! primitive for things like DMA device drivers.
//!
//! Between two bus transactions the environment (the device, a DMA engine,
//! another core on the bus) may change the state of the [`ForeignDomain`].
//! Every domain therefore declares an *interference* relation saying what may
//! happen without the CPU's involvement. Interfere is folded into every single
//! bus-transaction. This is different from state-drift that can occur between
//! sessions (e.g., a DMA device's interfere may modify the DMA memory region,
//! but it's enable MMIO register is purely software controlled, and stable
//! within a session).
//!
//! Sessions are closed explicitly.
//!
//! # Capabilities
//!
//! A [`HardwareThread`] stores [`ForeignPtr`]s in its registers, which are
//! derived from a domain. Each memory instruction then also takes the
//! aforementioned session object to perform the loads / stores. To prevent a
//! [`ForeignPtr`] from previous domain instance to be used on another domain
//! instance of identical type, registers also carry a gost handle
//! [`ptr::ForeignPtr::cap`] relating to the object it came from, and minted
//! when the domain is injected into the hardware thread.
//!
//! # Domains
//!
//! [`domains`] contains multiple foreign domain implementations. Each domain is
//! implemented as a triple of a state object, a session type, and a zero-sized
//! namespace type tying them together:
//!
//! * `stable_session`: private, exclusive region of memory
//! * `uncoop`: adversarial, contents may change at any time, accesses
//!   always guaranteed to succeed
//! * `uncoop_fault`: `uncoop`, but any access may fault
//! * `dma`: modeling a fictional DMA device with a shared memory region and
//!   an `enable` MMIO register

pub mod backing;
pub mod capability;
pub mod erasure;
pub mod extent;
pub mod ids;
pub mod map;
pub mod ptr;
pub mod session;
pub mod test_domains;

#[cfg(test)]
mod tests;
