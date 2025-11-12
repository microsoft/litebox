//! Thread-local storage support for shims.
//!
//! Shims can use [`shim_thread_local!`](crate::shim_thread_local) to define
//! thread-local static variables.

use crate::platform::ThreadLocalStorageProvider;
use alloc::boxed::Box;
use core::cell::Cell;
use core::marker::PhantomData;
use core::ptr;
use core::sync::atomic::AtomicU8;

/// Defines a thread-local static variable for shim use, with the given
/// platform.
///
/// The TLS value must be set before first use via [`TlsKey::init`] and manually
/// torn down before thread exit via [`TlsKey::deinit`].
///
/// Currently, only one thread local variable can be initialized on a thread at
/// a time. This restriction may be lifted in the future.
///
/// # Example
///
/// ```no_run
/// # struct MyPlatform;
/// # unsafe impl litebox::platform::ThreadLocalStorageProvider for MyPlatform {
/// #     fn get_thread_local_storage() -> *mut () { todo!() }
/// #     unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () { todo!() }
/// # }
/// litebox::shim_thread_local! {
///     #[platform = MyPlatform]
///     static MY_TLS: core::cell::Cell<u32>;
/// }
///
/// MY_TLS.init(42.into());
/// MY_TLS.with(|tls| {
///     assert_eq!(tls.get(), 42);
/// });
/// let v = MY_TLS.deinit();
/// ```
#[macro_export]
macro_rules! shim_thread_local {
    (#[platform = $platform:ty] static $name:ident: $ty:ty;) => {
        static $name: $crate::tls::TlsKey<$ty, $platform> =
            unsafe { $crate::tls::TlsKey::new_unchecked() };
    };
}

/// A key used to access thread local storage of type `T` for `Platform`.
pub struct TlsKey<T, Platform> {
    // Used to ensure there's a unique address for this.
    _dummy: AtomicU8,
    _phantom: PhantomData<fn(T, &Platform) -> T>,
}

#[repr(C)] // needed so that the offset of `key` is predictable across different `T` and `Platform`.
struct Tls<T: 'static, Platform: 'static> {
    /// Tracks which TLS key this value is for.
    ///
    /// FUTURE: consider allowing multiple TLS keys to be active at once. This
    /// could work by using linker tricks to determine how many keys are defined
    /// for a process and storing an array of pointers (or even values) in the
    /// TLS pointer.
    ///
    /// This could be useful to give shims more flexibility or to improve
    /// performance of getting the TLS value (removing a branch).
    key: &'static TlsKey<T, Platform>,
    /// Tracks the number of active `with` calls.
    ///
    /// FUTURE: consider a scoped initialization model that will statically
    /// guarantee the variable isn't in use during deinit. This will put
    /// additional burdens on the shim to maintain the stack, but there may be
    /// other good reasons for that anyway.
    users: Cell<usize>,
    data: T,
}

impl<T: 'static, Platform: ThreadLocalStorageProvider> TlsKey<T, Platform> {
    /// Don't use. Use [`shim_thread_local!`] instead.
    #[doc(hidden)]
    pub const unsafe fn new_unchecked() -> Self {
        Self {
            _dummy: AtomicU8::new(0),
            _phantom: PhantomData,
        }
    }

    /// Initialize the value for this thread.
    ///
    /// # Panics
    /// Panics if any shim TLS is already initialized on this thread.
    pub fn init(&'static self, value: T) {
        let tls = Box::new(Tls {
            key: self,
            users: 0.into(),
            data: value,
        });
        unsafe {
            let old_tls = Platform::replace_thread_local_storage(Box::into_raw(tls).cast());
            if !old_tls.is_null() {
                // Put it back in case panic unwinds and something is
                // referencing it.
                let _value = Box::from_raw(
                    Platform::replace_thread_local_storage(old_tls).cast::<Tls<T, Platform>>(),
                );
                panic!("tls is already in use on this thread");
            }
        }
    }

    /// Deinitialize the value for this thread, returning the contained value.
    ///
    /// # Panics
    /// Panics if this TLS is not initialized on this thread, or if it is still
    /// in use via calls to `with`.
    pub fn deinit(&'static self) -> T {
        // Validate the TLS is set and of the right type before taking it out.
        let _ = self.get_ptr();
        let tls = unsafe {
            let ptr =
                Platform::replace_thread_local_storage(ptr::null_mut()).cast::<Tls<T, Platform>>();
            Box::from_raw(ptr)
        };
        let users = tls.users.get();
        if users != 0 {
            // Put it back in case panic unwinds and something is
            // referencing it.
            unsafe { Platform::replace_thread_local_storage(Box::into_raw(tls).cast()) };
            panic!("tls is still in use on this thread");
        }
        tls.data
    }

    fn get_ptr(&'static self) -> *const Tls<T, Platform> {
        let ptr = Platform::get_thread_local_storage();
        assert!(!ptr.is_null(), "tls is not set");
        let key = unsafe {
            *ptr.wrapping_byte_add(core::mem::offset_of!(Tls<T, Platform>, key))
                .cast::<*const TlsKey<T, Platform>>()
        };
        assert!(ptr::addr_eq(key, self), "tls type mismatch");
        ptr.cast()
    }

    /// Access the value for this thread.
    ///
    /// # Panics
    /// Panics if this TLS is not initialized on this thread.
    pub fn with<R>(&'static self, f: impl FnOnce(&T) -> R) -> R {
        let tls = unsafe { &*self.get_ptr() };
        tls.users.set(tls.users.get().checked_add(1).unwrap());
        let _guard = crate::utils::defer(|| {
            tls.users.set(tls.users.get().checked_sub(1).unwrap());
        });
        f(&tls.data)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::platform::mock::MockPlatform;
    use core::cell::Cell;

    shim_thread_local! {
        #[platform = MockPlatform]
        static SHIM_TLS: Cell<u32>;
    }

    shim_thread_local! {
        #[platform = MockPlatform]
        static OTHER_TLS: Cell<u32>;
    }

    #[test]
    fn test_tls() {
        SHIM_TLS.init(42.into());
        SHIM_TLS.with(|tls| {
            assert_eq!(tls.get(), 42);
        });
        let v = SHIM_TLS.deinit();
        assert_eq!(v.into_inner(), 42);
    }

    #[test]
    #[should_panic(expected = "tls is not set")]
    fn test_no_tls() {
        SHIM_TLS.with(|tls| {
            tls.set(42);
        });
    }

    #[test]
    #[should_panic(expected = "tls is not set")]
    fn test_tls_gone() {
        SHIM_TLS.init(42.into());
        SHIM_TLS.deinit();
        SHIM_TLS.with(|tls| {
            tls.set(42);
        });
    }

    #[test]
    #[should_panic(expected = "tls is not set")]
    fn test_no_tls_deinit() {
        SHIM_TLS.deinit();
    }

    #[test]
    #[should_panic(expected = "tls type mismatch")]
    fn test_foreign_tls() {
        SHIM_TLS.init(42.into());
        OTHER_TLS.with(|tls| {
            tls.set(43);
        });
    }

    #[test]
    #[should_panic(expected = "tls is still in use on this thread")]
    fn test_in_use_tls() {
        SHIM_TLS.init(42.into());
        SHIM_TLS.with(|_tls| {
            SHIM_TLS.deinit();
        });
    }
}
