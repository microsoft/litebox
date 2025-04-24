//! Syscalls Handlers

pub mod file;
pub(crate) mod mm;

macro_rules! common_functions_for_file_status {
    () => {
        pub(crate) fn get_status(&self) -> litebox::fs::OFlags {
            litebox::fs::OFlags::from_bits(self.status.load(core::sync::atomic::Ordering::Relaxed))
                .unwrap()
        }

        pub(crate) fn set_status(&self, flag: litebox::fs::OFlags, on: bool) {
            if on {
                self.status
                    .fetch_or(flag.bits(), core::sync::atomic::Ordering::Relaxed);
            } else {
                self.status.fetch_and(
                    flag.complement().bits(),
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
    };
}

pub(crate) use common_functions_for_file_status;
