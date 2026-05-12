//! Argv-dispatched leaf programs for the M1-M4 + BS1-BS3 minimal
//! canary tests in platform_fixes.rs. These stay as argv subcommands
//! because they specifically test fresh-process stdio inheritance
//! (stdout/stderr capture, stdin echo, large output) across fork+exec
//! into a non-PIE child — an agent's stdin/stdout is the protocol
//! pipe, not the parent-inherited fds.
//!
//! Bodies were moved verbatim from `main.rs` during Wave-8 Phase C;
//! they preserve the original stdio semantics including any direct
//! `std::process::exit(N)` calls.

/// Resolve the M-suite "target" binary path. By default it's the
/// non-PIE harness binary. Tests can override via the env var
/// `LITEBOX_M_TARGET_BINARY` (set on the child via the Exec command).
fn m_target_binary() -> String {
    if let Ok(p) = std::env::var("LITEBOX_M_TARGET_BINARY")
        && !p.is_empty()
    {
        return p;
    }
    crate::nonpie_binary()
}

pub(crate) fn subcmd_m1_tokio_spawn_nonpie(_args: &[String]) -> i32 {
    // M1: PIE process, current_thread tokio runtime, spawn one
    // non-PIE child, wait, verify parent still alive.
    let nonpie = m_target_binary();
    let parent_pid = std::process::id();
    eprintln!("[M1] pid={parent_pid} spawning nonpie={nonpie}");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result: Result<(), String> = rt.block_on(async {
        let out = tokio::process::Command::new(&nonpie)
            .arg("echo-test")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("spawn: {e}"))?;
        if !out.status.success() {
            return Err(format!("child exit: {:?}", out.status));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !stdout.contains("ECHO_TEST_OK") {
            return Err(format!("child stdout missing ECHO_TEST_OK: {stdout:?}"));
        }
        Ok(())
    });
    match result {
        Ok(()) => {
            eprintln!("[M1] pid={parent_pid} child OK, parent surviving");
            println!("M1_OK pid={parent_pid}");
        }
        Err(e) => {
            eprintln!("[M1] pid={parent_pid} FAIL: {e}");
            println!("M1_FAIL:{e}");
            std::process::exit(1);
        }
    }
    0
}

pub(crate) fn subcmd_m2_libc_spawn_nonpie(_args: &[String]) -> i32 {
    // M2: PIE process, NO tokio. Raw libc fork+execve(nonpie),
    // waitpid, verify parent still alive. Isolates whether
    // tokio is required to trigger the bug.
    let nonpie = m_target_binary();
    let parent_pid = std::process::id();
    eprintln!("[M2] pid={parent_pid} libc fork+execve nonpie={nonpie}");

    // Pipe so we can read child stdout from parent.
    let mut pipefd = [-1i32; 2];
    if unsafe { libc::pipe(pipefd.as_mut_ptr()) } != 0 {
        println!("M2_FAIL:pipe");
        std::process::exit(1);
    }
    let pipe_r = pipefd[0];
    let pipe_w = pipefd[1];

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("M2_FAIL:fork");
        std::process::exit(1);
    }
    if pid == 0 {
        // Child: dup pipe_w to stdout, close fds, execve.
        unsafe {
            libc::dup2(pipe_w, 1);
            libc::close(pipe_r);
            libc::close(pipe_w);
        }
        use std::ffi::CString;
        let bin = CString::new(nonpie.as_str()).unwrap();
        let arg_sub = CString::new("echo-test").unwrap();
        let argv = [bin.as_ptr(), arg_sub.as_ptr(), core::ptr::null()];
        unsafe { libc::execv(bin.as_ptr(), argv.as_ptr()) };
        std::process::exit(127);
    }
    // Parent: close write end, read child stdout, waitpid.
    unsafe { libc::close(pipe_w) };
    let mut buf = [0u8; 4096];
    let n = unsafe { libc::read(pipe_r, buf.as_mut_ptr() as *mut _, buf.len()) };
    unsafe { libc::close(pipe_r) };
    let mut status = 0i32;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let ret = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if ret > 0 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            println!("M2_FAIL:wait_timeout");
            std::process::exit(1);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        println!("M2_FAIL:child_status={status}");
        std::process::exit(1);
    }
    if n <= 0 {
        println!("M2_FAIL:no_child_stdout");
        std::process::exit(1);
    }
    let out = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
    if !out.contains("ECHO_TEST_OK") {
        println!("M2_FAIL:bad_stdout:{out:?}");
        std::process::exit(1);
    }
    eprintln!("[M2] pid={parent_pid} child OK, parent surviving");
    println!("M2_OK pid={parent_pid}");
    0
}

pub(crate) fn subcmd_m3_tokio_spawn_nonpie_then_work(_args: &[String]) -> i32 {
    // M3: M1 + parent does post-spawn syscalls. If parent is
    // "almost dead" after the spawn (e.g. relay threads gone
    // but main thread still serving), the post-work step
    // catches it.
    let nonpie = m_target_binary();
    let parent_pid = std::process::id();
    eprintln!("[M3] pid={parent_pid} step 1: spawn nonpie");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let m1_result: Result<(), String> = rt.block_on(async {
        let out = tokio::process::Command::new(&nonpie)
            .arg("echo-test")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("spawn: {e}"))?;
        if !out.status.success() {
            return Err(format!("child exit: {:?}", out.status));
        }
        Ok(())
    });
    if let Err(e) = m1_result {
        println!("M3_FAIL:step1:{e}");
        std::process::exit(1);
    }
    eprintln!("[M3] pid={parent_pid} step 2: post-spawn work");
    // Several real syscalls to verify parent is still
    // functional. Drop the tokio runtime first to sever any
    // dependency on its threads.
    drop(rt);
    // Read /proc/self/stat — exercises FS path.
    let stat = std::fs::read_to_string("/proc/self/stat")
        .map_err(|e| format!("read /proc/self/stat: {e}"));
    // Write to a file in /tmp and read it back.
    let scratch = format!("/tmp/m3-{parent_pid}.txt");
    let write_res =
        std::fs::write(&scratch, b"M3_PARENT_ALIVE\n").map_err(|e| format!("write {scratch}: {e}"));
    let read_back = std::fs::read_to_string(&scratch).map_err(|e| format!("read {scratch}: {e}"));
    let _ = std::fs::remove_file(&scratch);
    match (stat, write_res, read_back) {
        (Ok(_), Ok(()), Ok(s)) if s.contains("M3_PARENT_ALIVE") => {
            eprintln!("[M3] pid={parent_pid} step 2 OK");
            println!("M3_OK pid={parent_pid}");
        }
        (s, w, r) => {
            println!("M3_FAIL:step2:stat={s:?},write={w:?},read={r:?}");
            std::process::exit(1);
        }
    }
    0
}

pub(crate) fn subcmd_m4_tokio_spawn_nonpie_repeated(args: &[String]) -> i32 {
    // M4: spawn non-PIE N times in sequence from one parent
    // tokio runtime. Counts how many spawns the parent
    // survives before dying.
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let nonpie = m_target_binary();
    let parent_pid = std::process::id();
    eprintln!("[M4] pid={parent_pid} N={n} spawning nonpie={nonpie}");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result: Result<usize, String> = rt.block_on(async {
        for i in 0..n {
            let out = tokio::process::Command::new(&nonpie)
                .arg("echo-test")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await
                .map_err(|e| format!("spawn iter={i}: {e}"))?;
            if !out.status.success() {
                return Err(format!("iter={i} child exit: {:?}", out.status));
            }
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.contains("ECHO_TEST_OK") {
                return Err(format!("iter={i} bad stdout: {stdout:?}"));
            }
            eprintln!("[M4] pid={parent_pid} iter={i} OK");
        }
        Ok(n)
    });
    match result {
        Ok(k) => {
            eprintln!("[M4] pid={parent_pid} all {k} iterations OK");
            println!("M4_OK pid={parent_pid} iterations={k}");
        }
        Err(e) => {
            println!("M4_FAIL:{e}");
            std::process::exit(1);
        }
    }
    0
}

pub(crate) fn subcmd_bs1_tokio_spawn_nonpie_stderr(_args: &[String]) -> i32 {
    // BS1: PIE process, tokio runtime, spawns non-PIE child that
    // writes only to stderr. Tests whether STDERR bridging from
    // a non-PIE worker has the same Bug-B shape as STDOUT (which
    // M1 covers). If BS1 passes but M1 fails (or vice versa),
    // the bug is direction-specific.
    let nonpie = m_target_binary();
    let parent_pid = std::process::id();
    eprintln!("[BS1] pid={parent_pid} spawning nonpie={nonpie} stderr-only-test");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result: Result<(), String> = rt.block_on(async {
        let out = tokio::process::Command::new(&nonpie)
            .arg("stderr-only-test")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("spawn: {e}"))?;
        if !out.status.success() {
            return Err(format!("child exit: {:?}", out.status));
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.contains("STDERR_ONLY_OK") {
            return Err(format!("child stderr missing STDERR_ONLY_OK: {stderr:?}"));
        }
        Ok(())
    });
    match result {
        Ok(()) => {
            eprintln!("[BS1] pid={parent_pid} OK");
            println!("BS1_OK pid={parent_pid}");
        }
        Err(e) => {
            println!("BS1_FAIL:{e}");
            std::process::exit(1);
        }
    }
    0
}

pub(crate) fn subcmd_bs2_tokio_spawn_nonpie_stdin_echo(_args: &[String]) -> i32 {
    // BS2: PIE process, tokio, spawns non-PIE child with stdin
    // piped + stdout piped. Parent writes "BS2_PING\n" to child
    // stdin; child echoes back to stdout. Parent verifies it
    // reads "BS2_PING\n" from stdout. Tests bidirectional
    // bridging: parent → child stdin AND child → parent stdout.
    let nonpie = m_target_binary();
    let parent_pid = std::process::id();
    eprintln!("[BS2] pid={parent_pid} spawning nonpie={nonpie} stdin-echo-test");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result: Result<(), String> = rt.block_on(async {
        use tokio::io::AsyncWriteExt;
        let mut child = tokio::process::Command::new(&nonpie)
            .arg("stdin-echo-test")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(b"BS2_PING\n")
                .await
                .map_err(|e| format!("write stdin: {e}"))?;
            drop(stdin);
        }
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| format!("wait: {e}"))?;
        if !out.status.success() {
            return Err(format!("child exit: {:?}", out.status));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !stdout.contains("BS2_PING") {
            return Err(format!("child stdout missing BS2_PING: {stdout:?}"));
        }
        Ok(())
    });
    match result {
        Ok(()) => {
            eprintln!("[BS2] pid={parent_pid} OK");
            println!("BS2_OK pid={parent_pid}");
        }
        Err(e) => {
            println!("BS2_FAIL:{e}");
            std::process::exit(1);
        }
    }
    0
}

pub(crate) fn subcmd_bs3_tokio_spawn_nonpie_large_stdout(_args: &[String]) -> i32 {
    // BS3: PIE process, tokio, spawns non-PIE child that writes
    // 65536 bytes to stdout. Tests whether stdout bridging works
    // for payloads larger than typical pipe buffers (~64K). If
    // M1 fails (small) but BS3 passes (large), the bug is
    // small-payload-specific (e.g. lost wakeup before EOF).
    // If both fail, the bug is general.
    let nonpie = m_target_binary();
    let parent_pid = std::process::id();
    eprintln!("[BS3] pid={parent_pid} spawning nonpie={nonpie} large-stdout-test");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result: Result<(), String> = rt.block_on(async {
        let out = tokio::process::Command::new(&nonpie)
            .arg("large-stdout-test")
            .arg("65536")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("spawn: {e}"))?;
        if !out.status.success() {
            return Err(format!("child exit: {:?}", out.status));
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !stdout.contains("LARGE_STDOUT_OK") {
            return Err(format!(
                "child stdout missing LARGE_STDOUT_OK (got {} bytes)",
                stdout.len()
            ));
        }
        Ok(())
    });
    match result {
        Ok(()) => {
            eprintln!("[BS3] pid={parent_pid} OK");
            println!("BS3_OK pid={parent_pid}");
        }
        Err(e) => {
            println!("BS3_FAIL:{e}");
            std::process::exit(1);
        }
    }
    0
}
