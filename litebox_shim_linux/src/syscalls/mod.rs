//! Syscalls Handlers

pub(crate) mod eventfd;
pub mod file;
pub(crate) mod misc;
pub mod mm;
pub(crate) mod net;
pub(crate) mod process;

#[cfg(test)]
pub(crate) mod tests;

macro_rules! common_functions_for_file_status {
    () => {
        pub(crate) fn get_status(&self) -> litebox::fs::OFlags {
            litebox::fs::OFlags::from_bits(self.status.load(core::sync::atomic::Ordering::Relaxed))
                .unwrap()
                & litebox::fs::OFlags::STATUS_FLAGS_MASK
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

#[cfg(debug_assertions)]
macro_rules! log_println {
    ($($tt:tt)*) => {{
        use core::fmt::Write;
        let mut t: arrayvec::ArrayString<1024> = arrayvec::ArrayString::new();
        writeln!(t, $($tt)*).unwrap();
        litebox::platform::DebugLogProvider::debug_log_print(
            litebox_platform_multiplex::platform(),
            t.as_str(),
        );
    }};
}
#[cfg(debug_assertions)]
pub(crate) use log_println;
