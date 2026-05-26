// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shared panic diagnostics for Litebox host processes.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install a panic hook that writes panic info to /tmp/rst-diag.log
/// and then chains to the default hook.
///
/// Idempotent: if already installed by this process, second call is a no-op.
/// `process_label` is a short tag like "broker" / "runner" / "tool_executor"
/// for log line disambiguation.
pub fn install(process_label: &'static str) {
    install_with_path(process_label, "/tmp/rst-diag.log");
}

/// Install the Litebox panic hook with a custom destination path.
///
/// This is primarily useful for tests. Idempotency is process-wide, so the
/// first successful install fixes the destination path for the process.
pub fn install_with_path(process_label: &'static str, path: impl Into<PathBuf>) {
    if INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let path = path.into();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        use std::io::Write as _;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let bt = std::backtrace::Backtrace::force_capture();
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let payload = if let Some(s) = info.payload().downcast_ref::<&'static str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_string()
        };
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>");
        let pid = std::process::id();

        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(
                f,
                "[litebox-panic] ts={ts} process={process_label} pid={pid} thread={thread_name} at {location}: {payload}\nbacktrace:\n{bt}"
            );
        }

        default_hook(info);
    }));
}

#[cfg(test)]
mod tests {
    #[test]
    fn hook_writes_payload_location_and_backtrace() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("panic-hook-test.log");
        let _ = std::fs::create_dir_all(path.parent().expect("path has parent"));
        let _ = std::fs::remove_file(&path);

        super::install_with_path("unit_test", &path);
        let _ = std::panic::catch_unwind(|| panic!("LITEBOX_PANIC_HOOK_UNIT_TEST"));

        let log = std::fs::read_to_string(&path).expect("panic hook log should be readable");
        assert!(log.contains("[litebox-panic]"), "log was: {log}");
        assert!(log.contains("process=unit_test"), "log was: {log}");
        assert!(
            log.contains("LITEBOX_PANIC_HOOK_UNIT_TEST"),
            "log was: {log}"
        );
        assert!(log.contains("pid="), "log was: {log}");
        assert!(log.contains("backtrace:"), "log was: {log}");
    }
}
