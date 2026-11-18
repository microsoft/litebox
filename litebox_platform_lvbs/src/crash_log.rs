// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Crash logger: the platform diagnostic logger.
//!
//! Every message is logged to:
//!
//! - the serial (COM) port, which can be turned on or off at runtime with
//!   [`CrashLogger::set_serial_enabled`], and
//! - the VTL0 crash ring buffer, once VTL0 has provided one through
//!   [`Vtl0Gate::install_ringbuffer`](litebox_common_lvbs::Vtl0Gate::install_ringbuffer),
//!   so that VTL0 can recover VTL1's most recent logs after a VTL1 crash.
//!
//! [`CrashLogger`] implements [`log::Log`]. `&CrashLogger` also implements
//! [`fmt::Write`] for writing preformatted text without the `log` facade
//! (e.g., `HostInterface::log`). Panic messages and the `serial_print!`
//! family of macros go to the serial port only.

use crate::mshv::ringbuffer::RingBuffer;
use core::fmt::{self, Write as _};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::{Mutex, Once};
use x86_64::PhysAddr;

/// Formatted [`log::Record`]s longer than this are truncated.
const MAX_RECORD_SIZE: usize = 1024;

static CRASH_LOGGER: CrashLogger = CrashLogger::new();

/// Returns the platform's crash logger, e.g., to pass to [`log::set_logger`].
pub fn crash_logger() -> &'static CrashLogger {
    &CRASH_LOGGER
}

/// Writes diagnostic output to the serial port and the VTL0 crash ring buffer.
pub struct CrashLogger {
    serial_enabled: AtomicBool,
    ringbuffer: Once<Mutex<RingBuffer>>,
}

impl CrashLogger {
    const fn new() -> Self {
        Self {
            serial_enabled: AtomicBool::new(true),
            ringbuffer: Once::new(),
        }
    }

    /// Turns this logger's serial output on or off. It is on by default.
    /// The `serial_print!` macros, panic messages, and the VTL0 crash ring
    /// buffer are unaffected.
    pub fn set_serial_enabled(&self, enabled: bool) {
        self.serial_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Whether output is written to the serial port.
    pub fn serial_enabled(&self) -> bool {
        self.serial_enabled.load(Ordering::Relaxed)
    }

    /// Installs the `size`-byte VTL0 buffer at `pa` as the crash ring buffer.
    /// Only the first call takes effect.
    pub(crate) fn install_ringbuffer(
        &self,
        platform: &'static crate::host::LvbsLinuxKernel,
        pa: PhysAddr,
        size: usize,
    ) {
        self.ringbuffer
            .call_once(|| Mutex::new(RingBuffer::new(platform, pa, size)));
    }
}

/// Writes to every enabled sink. Implemented on `&CrashLogger`, like
/// `io::Write` for `&File`, so writing needs only a shared reference. That is
/// safe because the serial switch is atomic and the serial port and ring
/// buffer are each behind a lock.
impl fmt::Write for &CrashLogger {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.serial_enabled() {
            crate::arch::ioport::serial_print_string(s);
        }
        if let Some(ringbuffer) = self.ringbuffer.get() {
            ringbuffer.lock().write(s.as_bytes());
        }
        Ok(())
    }
}

impl log::Log for CrashLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        self.serial_enabled() || self.ringbuffer.get().is_some()
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut buf = arrayvec::ArrayString::<MAX_RECORD_SIZE>::new();
        let _ = litebox_util_log::format_record(&mut buf, record);
        let mut logger = self;
        let _ = logger.write_str(&buf);
    }

    fn flush(&self) {}
}
