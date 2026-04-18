// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! LiteBox process tree test harness.
//!
//! Two modes:
//! - `spawn-tree` — coordinator: spawns tree, drives tests through pipes
//! - `agent` — command executor: reads commands from stdin, responds on stdout

mod agent;
mod coordinator;
mod protocol;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("spawn-tree");
    let self_exe = &args[0];

    match cmd {
        "spawn-tree" => {
            let results = coordinator::run_all(self_exe);
            let pass_count = results.iter().filter(|r| r.outcome() == "pass").count();
            let fail_count = results.iter().filter(|r| r.outcome() == "FAIL").count();
            let xfail_count = results.iter().filter(|r| r.outcome() == "xfail").count();
            let xpass_count = results.iter().filter(|r| r.outcome() == "XPASS").count();
            // Print JSON results to stdout.
            for r in &results {
                println!(
                    "{}",
                    serde_json::json!({
                        "test": r.id,
                        "agent": r.agent,
                        "result": r.outcome(),
                        "detail": r.detail,
                    })
                );
            }
            eprintln!(
                "\n=== SUMMARY: {} total, {} passed, {} failed, {} xfail, {} xpass ===",
                results.len(),
                pass_count,
                fail_count,
                xfail_count,
                xpass_count
            );
            // Exit non-zero only for unexpected results.
            if fail_count > 0 || xpass_count > 0 {
                std::process::exit(1);
            }
        }
        "agent" => {
            agent::run(self_exe);
        }
        "echo-test" => {
            println!("ECHO_TEST_OK");
        }
        "stress-exec" => {
            // Bypass test harness protocol entirely. Directly fork+exec
            // from a single process to test if litebox's fork/exec leaks
            // state between sequential calls.
            //
            // Usage: stress-exec <count> <pie|nonpie|mixed> [sync|tokio]
            // Outputs results to BOTH stdout and stderr.
            let count: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
            let mode = args.get(3).map(String::as_str).unwrap_or("pie");
            let use_tokio = args.get(4).map(String::as_str) == Some("tokio");
            let mut failures = 0;
            println!("STRESS_START mode={mode} count={count} tokio={use_tokio}");
            if use_tokio {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                failures = rt.block_on(async {
                    let mut failures = 0;
                    for i in 0..count {
                        let (cmd_args, expected): (Vec<&str>, &str) = match mode {
                            "nonpie" => (vec!["/nonpie-echo"], "NONPIE_OK"),
                            "mixed" if i % 2 == 0 => (vec![self_exe, "echo-test"], "ECHO_TEST_OK"),
                            "mixed" => (vec!["/nonpie-echo"], "NONPIE_OK"),
                            _ => (vec![self_exe, "echo-test"], "ECHO_TEST_OK"),
                        };
                        let result = tokio::process::Command::new(cmd_args[0])
                            .args(&cmd_args[1..])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .output()
                            .await;
                        match result {
                            Ok(out) => {
                                let stdout =
                                    String::from_utf8_lossy(&out.stdout).trim().to_string();
                                if stdout == expected {
                                    eprintln!("i={i} ok={stdout}");
                                } else {
                                    eprintln!(
                                        "i={i} FAIL: expected={expected:?} got={stdout:?} exit={}",
                                        out.status
                                    );
                                    failures += 1;
                                }
                            }
                            Err(e) => {
                                eprintln!("i={i} FAIL: spawn error: {e}");
                                failures += 1;
                            }
                        }
                    }
                    failures
                });
            } else {
                for i in 0..count {
                    let (cmd_args, expected): (Vec<&str>, &str) = match mode {
                        "nonpie" => (vec!["/nonpie-echo"], "NONPIE_OK"),
                        "mixed" if i % 2 == 0 => (vec![self_exe, "echo-test"], "ECHO_TEST_OK"),
                        "mixed" => (vec!["/nonpie-echo"], "NONPIE_OK"),
                        _ => (vec![self_exe, "echo-test"], "ECHO_TEST_OK"),
                    };
                    let result = std::process::Command::new(cmd_args[0])
                        .args(&cmd_args[1..])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .output();
                    match result {
                        Ok(out) => {
                            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                            if stdout == expected {
                                eprintln!("i={i} ok={stdout}");
                            } else {
                                eprintln!(
                                    "i={i} FAIL: expected={expected:?} got={stdout:?} exit={}",
                                    out.status
                                );
                                failures += 1;
                            }
                        }
                        Err(e) => {
                            eprintln!("i={i} FAIL: spawn error: {e}");
                            failures += 1;
                        }
                    }
                }
            }
            println!("STRESS_END failures={failures}");
            eprintln!("stress-exec: {count} execs, {failures} failures");
            if failures > 0 {
                std::process::exit(1);
            }
        }
        "exit-with" => {
            let code: i32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            std::process::exit(code);
        }
        // --- Subcommands used as child-process behaviors by tests ---
        "unix-echo-server" => {
            // Usage: unix-echo-server <path>
            // Binds a Unix domain socket, accepts ONE connection, echoes
            // received data back, then exits. Prints LISTENING when ready.
            let path = args.get(2).expect("unix-echo-server requires <path>");
            let _ = std::fs::remove_file(path);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                let listener = tokio::net::UnixListener::bind(path).expect("bind failed");
                println!("LISTENING");
                let (mut stream, _) = listener.accept().await.expect("accept failed");
                let mut buf = [0u8; 4096];
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let _ = stream.write_all(&buf[..n]).await;
                        let _ = stream.flush().await;
                    }
                    _ => {}
                }
            });
            let _ = std::fs::remove_file(path);
        }
        "unix-echo-client" => {
            // Usage: unix-echo-client <path> <data>
            // Connects to a Unix domain socket, sends data, reads response,
            // prints it to stdout.
            let path = args.get(2).expect("unix-echo-client requires <path>");
            let data = args.get(3).expect("unix-echo-client requires <data>");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut stream = tokio::net::UnixStream::connect(path)
                    .await
                    .expect("connect failed");
                stream
                    .write_all(data.as_bytes())
                    .await
                    .expect("write failed");
                stream.flush().await.expect("flush failed");
                let mut buf = [0u8; 4096];
                match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
                    .await
                {
                    Ok(Ok(n)) => {
                        let resp = String::from_utf8_lossy(&buf[..n]);
                        println!("{resp}");
                    }
                    Ok(Err(e)) => {
                        eprintln!("read error: {e}");
                        std::process::exit(1);
                    }
                    Err(_) => {
                        eprintln!("read timeout");
                        std::process::exit(1);
                    }
                }
            });
        }
        "trigger-delayed-fork" => {
            // Usage: trigger-delayed-fork <cmd> [args...]
            // Triggers a delayed-fork by doing a non-pre-exec syscall (mmap
            // via Vec allocation), then fork+execs the given command.
            // Used to test nested delayed-fork: the parent forks this process,
            // which migrates to a worker, then fork+execs <cmd>.
            if args.len() < 3 {
                eprintln!("usage: trigger-delayed-fork <cmd> [args...]");
                std::process::exit(1);
            }

            // Force a non-pre-exec syscall to trigger delayed-fork migration.
            let _trigger: Vec<u8> = vec![0u8; 64 * 1024];
            assert_eq!(_trigger[0], 0);

            // Fork+exec the given command from within the delayed-fork child.
            let output = std::process::Command::new(&args[2])
                .args(&args[3..])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .expect("nested fork+exec failed");
            let stdout = String::from_utf8_lossy(&output.stdout);
            print!("{stdout}");
        }
        "trigger-delayed-fork-thread" => {
            // Usage: trigger-delayed-fork-thread <cmd> [args...]
            // Like trigger-delayed-fork but uses thread creation (clone3)
            // instead of mmap to trigger delayed-fork. This is how Node.js
            // triggers it (V8 creates worker threads on startup).
            if args.len() < 3 {
                eprintln!("usage: trigger-delayed-fork-thread <cmd> [args...]");
                std::process::exit(1);
            }

            // Trigger delayed-fork via thread creation (clone3).
            let handle = std::thread::spawn(|| {
                // Thread does nothing — just its creation triggers delayed-fork.
            });
            handle.join().expect("thread join failed");

            // Fork+exec the given command from within the delayed-fork child.
            let output = std::process::Command::new(&args[2])
                .args(&args[3..])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .expect("nested fork+exec failed");
            let stdout = String::from_utf8_lossy(&output.stdout);
            print!("{stdout}");
        }
        "getifaddrs-test" => {
            let sub = args.get(2).map(String::as_str).unwrap_or("full");
            std::process::exit(netlink_tests::run(sub));
        }
        "unix-socket-test" => {
            let sub = args.get(2).map(String::as_str).unwrap_or("cross-process");
            std::process::exit(unix_socket_tests::run(sub));
        }
        "exit-test" => {
            let sub = args.get(2).map(String::as_str).unwrap_or("single");
            exit_tests::run(sub);
            eprintln!("EXIT_TEST_BUG: run() returned instead of exiting");
            std::process::exit(99);
        }
        "net-test" => {
            let sub = args.get(2).map(String::as_str).unwrap_or("ipv6-socket");
            std::process::exit(net_tests::run(sub));
        }
        "fs-test" => {
            let sub = args.get(2).map(String::as_str).unwrap_or("help");
            std::process::exit(fs_tests::run(sub, &args));
        }
        // Check if the pre-warmed code-server is running (reads pid.txt + log.txt)
        "check-prewarm" => {
            let sdir =
                "/root/.vscode-server/cli/servers/Stable-ae130017f8afe532557dbb8539a6ef3bdaec6389";
            let pid_path = format!("{sdir}/pid.txt");
            let log_path = format!("{sdir}/log.txt");

            let pid_content = std::fs::read_to_string(&pid_path).unwrap_or_default();
            let pid_content = pid_content.trim();
            println!("PREWARM_PID_FILE:{pid_content}");

            if let Ok(pid) = pid_content.parse::<i32>() {
                let alive = unsafe { libc::kill(pid, 0) } == 0;
                println!("PREWARM_PID_ALIVE:{alive}");
            } else {
                println!("PREWARM_PID_ALIVE:no_pid");
            }

            match std::fs::read_to_string(&log_path) {
                Ok(log) => {
                    let lines: Vec<&str> = log.lines().collect();
                    println!("PREWARM_LOG_LINES:{}", lines.len());
                    let has_bound = log.contains("Server bound to");
                    println!("PREWARM_LOG_BOUND:{has_bound}");
                    if let Some(line) = lines.iter().find(|l| l.contains("Server bound to")) {
                        println!("PREWARM_SOCKET:{}", line.trim());
                    }
                }
                Err(e) => println!("PREWARM_LOG_ERR:{e}"),
            }
            std::process::exit(0);
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    }
}

mod netlink_tests {
    pub fn run(sub: &str) -> i32 {
        match sub {
            "socket" => test_socket(),
            "bind" => test_bind(),
            "getlink" => test_getlink(),
            "getaddr" => test_getaddr(),
            "sendmsg" => test_sendmsg_recvmsg(),
            "double" => test_double_request(),
            "peek-trunc" => test_peek_trunc(),
            "glibc-flow" => test_glibc_flow(),
            "full" => test_full(),
            other => {
                eprintln!("unknown: {other}");
                1
            }
        }
    }

    fn test_socket() -> i32 {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL:{}", errno());
            return 1;
        }
        println!("NETLINK_SOCKET_OK:{fd}");
        unsafe { libc::close(fd) };
        0
    }

    fn test_bind() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        if unsafe { libc::getsockname(fd, &mut sa as *mut _ as *mut libc::sockaddr, &mut len) } < 0
        {
            println!("NETLINK_GETSOCKNAME_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }
        unsafe { libc::close(fd) };
        println!(
            "NETLINK_BIND_OK:family={},pid={},groups={}",
            sa.nl_family, sa.nl_pid, sa.nl_groups
        );
        if sa.nl_family != libc::AF_NETLINK as u16 {
            return 1;
        }
        0
    }

    fn test_getlink() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }
        let mut req = [0u8; 32]; // nlmsghdr(16) + ifinfomsg(16)
        req[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req[4..6].copy_from_slice(&(libc::RTM_GETLINK as u16).to_ne_bytes());
        req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        if unsafe { libc::send(fd, req.as_ptr() as *const _, req.len(), 0) } < 0 {
            println!("NETLINK_SEND_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }
        let (found, done) = recv_check(fd, libc::RTM_NEWLINK as u16);
        unsafe { libc::close(fd) };
        if found && done {
            println!("NETLINK_GETLINK_OK");
            0
        } else {
            println!("NETLINK_GETLINK_FAIL:newlink={found},done={done}");
            1
        }
    }

    fn test_getaddr() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }
        let mut req = [0u8; 24]; // nlmsghdr(16) + ifaddrmsg(8)
        req[0..4].copy_from_slice(&24u32.to_ne_bytes());
        req[4..6].copy_from_slice(&(libc::RTM_GETADDR as u16).to_ne_bytes());
        req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req[8..12].copy_from_slice(&2u32.to_ne_bytes());
        if unsafe { libc::send(fd, req.as_ptr() as *const _, req.len(), 0) } < 0 {
            println!("NETLINK_SEND_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }
        let (found, done) = recv_check(fd, libc::RTM_NEWADDR as u16);
        unsafe { libc::close(fd) };
        if found && done {
            println!("NETLINK_GETADDR_OK");
            0
        } else {
            println!("NETLINK_GETADDR_FAIL:newaddr={found},done={done}");
            1
        }
    }

    /// Mimics glibc's exact getifaddrs flow: sendmsg + recvmsg(PEEK|TRUNC) + recvmsg(0)
    /// for sequential RTM_GETLINK and RTM_GETADDR requests.
    fn test_glibc_flow() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("GLIBC_FLOW_SOCKET_FAIL");
            return 1;
        }

        // Helper: do one glibc-style request cycle
        fn do_request(fd: i32, req: &[u8], label: &str) -> bool {
            // sendmsg (glibc pattern)
            let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            dst.nl_family = libc::AF_NETLINK as u16;
            let mut iov_send = libc::iovec {
                iov_base: req.as_ptr() as *mut _,
                iov_len: req.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut dst as *mut _ as *mut _;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
            msg.msg_iov = &mut iov_send;
            msg.msg_iovlen = 1;
            let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
            eprintln!("[glibc-flow] {label}: sendmsg returned {sent}");
            if sent < 0 {
                return false;
            }

            // recvmsg(MSG_PEEK | MSG_TRUNC) with iov_len=0
            let mut iov_peek = libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            };
            let mut src: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut rmsg: libc::msghdr = unsafe { std::mem::zeroed() };
            rmsg.msg_name = &mut src as *mut _ as *mut _;
            rmsg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
            rmsg.msg_iov = &mut iov_peek;
            rmsg.msg_iovlen = 1;
            let peek_len =
                unsafe { libc::recvmsg(fd, &mut rmsg, libc::MSG_PEEK | libc::MSG_TRUNC) };
            eprintln!("[glibc-flow] {label}: peek returned {peek_len}");
            if peek_len <= 0 {
                return false;
            }

            // recvmsg(0) with properly sized buffer
            let mut buf = vec![0u8; peek_len as usize];
            let mut iov_read = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            let mut rmsg2: libc::msghdr = unsafe { std::mem::zeroed() };
            rmsg2.msg_name = &mut src as *mut _ as *mut _;
            rmsg2.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
            rmsg2.msg_iov = &mut iov_read;
            rmsg2.msg_iovlen = 1;
            let read_len = unsafe { libc::recvmsg(fd, &mut rmsg2, 0) };
            eprintln!("[glibc-flow] {label}: read returned {read_len}");
            if read_len <= 0 {
                return false;
            }

            // Parse for NLMSG_DONE
            let n = read_len as usize;
            let mut off = 0;
            let mut found_done = false;
            while off + 16 <= n {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                eprintln!("[glibc-flow] {label}: msg at off={off} len={len} type={mtype}");
                if len < 16 || off + len > n {
                    break;
                }
                if mtype == libc::NLMSG_DONE as u16 {
                    found_done = true;
                }
                off += (len + 3) & !3;
            }
            eprintln!("[glibc-flow] {label}: done={found_done}");
            found_done
        }

        // Request 1: RTM_GETLINK
        let mut req1 = [0u8; 32];
        req1[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req1[4..6].copy_from_slice(&(libc::RTM_GETLINK as u16).to_ne_bytes());
        req1[6..8]
            .copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req1[8..12].copy_from_slice(&1u32.to_ne_bytes());
        let ok1 = do_request(fd, &req1, "GETLINK");
        if !ok1 {
            println!("GLIBC_FLOW_FAIL:GETLINK");
            unsafe { libc::close(fd) };
            return 1;
        }

        // Request 2: RTM_GETADDR
        let mut req2 = [0u8; 24];
        req2[0..4].copy_from_slice(&24u32.to_ne_bytes());
        req2[4..6].copy_from_slice(&(libc::RTM_GETADDR as u16).to_ne_bytes());
        req2[6..8]
            .copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req2[8..12].copy_from_slice(&2u32.to_ne_bytes());
        let ok2 = do_request(fd, &req2, "GETADDR");
        if !ok2 {
            println!("GLIBC_FLOW_FAIL:GETADDR");
            unsafe { libc::close(fd) };
            return 1;
        }

        unsafe { libc::close(fd) };
        println!("GLIBC_FLOW_OK");
        0
    }

    fn test_full() -> i32 {
        let mut ifaddr: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut ifaddr) } != 0 {
            println!("GETIFADDRS_FAIL:{}", errno());
            return 1;
        }
        let mut count = 0;
        let mut ptr = ifaddr;
        while !ptr.is_null() {
            count += 1;
            ptr = unsafe { (*ptr).ifa_next };
        }
        unsafe { libc::freeifaddrs(ifaddr) };
        println!("GETIFADDRS_OK:{count}");
        0
    }

    fn open_nl() -> i32 {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return fd;
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        fd
    }

    /// NL3b: Mimics glibc's __netlink_request — uses sendmsg/recvmsg
    /// with sockaddr_nl, iov, and msghdr. This is the exact path
    /// getifaddrs() takes internally.
    fn test_sendmsg_recvmsg() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }

        // Send RTM_GETLINK via sendmsg (glibc pattern)
        let mut req = [0u8; 32]; // nlmsghdr(16) + ifinfomsg(16)
        req[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req[4..6].copy_from_slice(&(libc::RTM_GETLINK as u16).to_ne_bytes());
        req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());

        let mut dst_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst_addr.nl_family = libc::AF_NETLINK as u16;

        let mut iov = libc::iovec {
            iov_base: req.as_mut_ptr() as *mut _,
            iov_len: req.len(),
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut dst_addr as *mut _ as *mut _;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
        if sent < 0 {
            println!("NETLINK_SENDMSG_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }
        eprintln!("[sendmsg] sent {sent} bytes");

        // Recv via recvmsg (glibc pattern) — loop until NLMSG_DONE
        let mut found_newlink = false;
        let mut found_done = false;
        let mut recv_count = 0;
        let mut buf = [0u8; 8192];
        loop {
            let mut iov_recv = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            let mut src_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut rmsg: libc::msghdr = unsafe { std::mem::zeroed() };
            rmsg.msg_name = &mut src_addr as *mut _ as *mut _;
            rmsg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
            rmsg.msg_iov = &mut iov_recv;
            rmsg.msg_iovlen = 1;

            let n = unsafe { libc::recvmsg(fd, &mut rmsg, 0) };
            recv_count += 1;
            eprintln!("[recvmsg] call #{recv_count}: returned {n}");
            if n <= 0 {
                break;
            }
            let n = n as usize;

            let mut off = 0;
            while off + 16 <= n {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                eprintln!("[recvmsg] msg at off={off}: len={len} type={mtype}");
                if len < 16 || off + len > n {
                    break;
                }
                if mtype == libc::RTM_NEWLINK as u16 {
                    found_newlink = true;
                }
                if mtype == libc::NLMSG_DONE as u16 {
                    found_done = true;
                }
                off += (len + 3) & !3;
            }
            if found_done {
                break;
            }
        }
        unsafe { libc::close(fd) };
        if found_newlink && found_done {
            println!("NETLINK_SENDMSG_RECVMSG_OK");
            0
        } else {
            println!(
                "NETLINK_SENDMSG_RECVMSG_FAIL:newlink={found_newlink},done={found_done},recvs={recv_count}"
            );
            1
        }
    }

    /// NL3c: Two sequential requests on the same socket (like getifaddrs).
    /// Send RTM_GETLINK, read response. Then send RTM_GETADDR, read response.
    fn test_double_request() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }

        // Request 1: RTM_GETLINK via sendto (glibc pattern)
        let mut req1 = [0u8; 32];
        req1[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req1[4..6].copy_from_slice(&(libc::RTM_GETLINK as u16).to_ne_bytes());
        req1[6..8]
            .copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req1[8..12].copy_from_slice(&1u32.to_ne_bytes());

        let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        dst.nl_family = libc::AF_NETLINK as u16;

        eprintln!("[double] sending RTM_GETLINK via sendto");
        let sent = unsafe {
            libc::sendto(
                fd,
                req1.as_ptr() as *const _,
                req1.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        eprintln!("[double] sendto returned {sent}");
        if sent < 0 {
            println!("DOUBLE_SEND1_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }

        let (link_ok, link_done) = recv_check(fd, libc::RTM_NEWLINK as u16);
        eprintln!("[double] getlink: ok={link_ok} done={link_done}");
        if !link_ok || !link_done {
            println!("DOUBLE_GETLINK_FAIL:ok={link_ok},done={link_done}");
            unsafe { libc::close(fd) };
            return 1;
        }

        // Request 2: RTM_GETADDR via sendto
        let mut req2 = [0u8; 24];
        req2[0..4].copy_from_slice(&24u32.to_ne_bytes());
        req2[4..6].copy_from_slice(&(libc::RTM_GETADDR as u16).to_ne_bytes());
        req2[6..8]
            .copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req2[8..12].copy_from_slice(&2u32.to_ne_bytes());

        eprintln!("[double] sending RTM_GETADDR via sendto");
        let sent = unsafe {
            libc::sendto(
                fd,
                req2.as_ptr() as *const _,
                req2.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        eprintln!("[double] sendto returned {sent}");
        if sent < 0 {
            println!("DOUBLE_SEND2_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }

        let (addr_ok, addr_done) = recv_check(fd, libc::RTM_NEWADDR as u16);
        eprintln!("[double] getaddr: ok={addr_ok} done={addr_done}");

        unsafe { libc::close(fd) };
        if link_ok && link_done && addr_ok && addr_done {
            println!("NETLINK_DOUBLE_OK");
            0
        } else {
            println!("NETLINK_DOUBLE_FAIL:link={link_ok}/{link_done},addr={addr_ok}/{addr_done}");
            1
        }
    }

    /// NL3d: MSG_PEEK + MSG_TRUNC pattern — mimics glibc's __netlink_request.
    /// glibc first does recvmsg(MSG_PEEK|MSG_TRUNC) with iov_len=0 to query
    /// the response size, then recvmsg(0) with a properly sized buffer.
    fn test_peek_trunc() -> i32 {
        let fd = open_nl();
        if fd < 0 {
            println!("NETLINK_SOCKET_FAIL");
            return 1;
        }

        // Send RTM_GETLINK request
        let mut req = [0u8; 32];
        req[0..4].copy_from_slice(&32u32.to_ne_bytes());
        req[4..6].copy_from_slice(&(libc::RTM_GETLINK as u16).to_ne_bytes());
        req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        if unsafe { libc::send(fd, req.as_ptr() as *const _, req.len(), 0) } < 0 {
            println!("PEEK_SEND_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }

        // Step 1: recvmsg(MSG_PEEK | MSG_TRUNC) with zero-length iov
        let mut iov = libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
        let mut src_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut src_addr as *mut _ as *mut _;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        let peek_size = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_PEEK | libc::MSG_TRUNC) };
        eprintln!("[peek-trunc] peek returned {peek_size}");
        if peek_size <= 0 {
            println!(
                "PEEK_TRUNC_FAIL:peek_returned={peek_size},errno={}",
                errno()
            );
            unsafe { libc::close(fd) };
            return 1;
        }

        // Step 2: recvmsg(0) with properly sized buffer
        let mut buf = vec![0u8; peek_size as usize];
        let mut iov2 = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut msg2: libc::msghdr = unsafe { std::mem::zeroed() };
        msg2.msg_name = &mut src_addr as *mut _ as *mut _;
        msg2.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg2.msg_iov = &mut iov2;
        msg2.msg_iovlen = 1;

        let read_size = unsafe { libc::recvmsg(fd, &mut msg2, 0) };
        eprintln!("[peek-trunc] read returned {read_size}");
        if read_size <= 0 {
            println!(
                "PEEK_TRUNC_FAIL:read_returned={read_size},errno={}",
                errno()
            );
            unsafe { libc::close(fd) };
            return 1;
        }

        // Verify we got NLMSG_DONE
        let mut found_done = false;
        let n = read_size as usize;
        let mut off = 0;
        while off + 16 <= n {
            let len =
                u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
            let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
            if len < 16 || off + len > n {
                break;
            }
            if mtype == libc::NLMSG_DONE as u16 {
                found_done = true;
            }
            off += (len + 3) & !3;
        }

        unsafe { libc::close(fd) };
        if found_done && peek_size == read_size {
            println!("NETLINK_PEEK_TRUNC_OK:size={peek_size}");
            0
        } else {
            println!("PEEK_TRUNC_FAIL:done={found_done},peek={peek_size},read={read_size}");
            1
        }
    }

    fn recv_check(fd: i32, expected: u16) -> (bool, bool) {
        let mut buf = [0u8; 8192];
        let mut found = false;
        let mut done = false;
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if n <= 0 {
                eprintln!("[recv_check] recv returned {n}");
                break;
            }
            let n = n as usize;
            // Dump first 80 bytes for debugging
            let dump_len = n.min(80);
            let hex: Vec<String> = buf[..dump_len].iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("[recv_check] recv {n} bytes: {}", hex.join(" "));

            let mut off = 0;
            while off + 16 <= n {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                let mtype = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                eprintln!("[recv_check] msg at off={off}: len={len} type={mtype}");
                if len < 16 || off + len > n {
                    break;
                }
                if mtype == expected {
                    found = true;
                }
                if mtype == libc::NLMSG_DONE as u16 {
                    done = true;
                }
                off += (len + 3) & !3;
            }
            if done {
                break;
            }
        }
        (found, done)
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

mod unix_socket_tests {
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};

    pub fn run(sub: &str) -> i32 {
        match sub {
            "cross-process" => test_cross_process(),
            "cross-exec" => test_cross_exec(),
            "bidirectional" => test_bidirectional(),
            "multi-conn" => test_multi_conn(),
            "abstract" => test_abstract_socket(),
            "race" => test_socket_race(),
            "mac" => test_mac_address(),
            // Called by the test harness binary after fork+exec for US2
            "us2-server" => us2_server(),
            other => {
                eprintln!("unknown: {other}");
                1
            }
        }
    }

    /// US1: Unix socket cross-process bind+listen+connect+accept.
    /// Reproduces the code-server ↔ CLI pattern:
    ///   child = server: bind → listen → accept → read
    ///   parent = client: connect → write
    fn test_cross_process() -> i32 {
        let sock_path = "/tmp/litebox-us1-test.sock";
        let _ = std::fs::remove_file(sock_path);

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("US1_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            // Child = server: bind + listen + accept + read
            eprintln!("[US1-server] binding to {sock_path}");
            let listener = match UnixListener::bind(sock_path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[US1-server] bind failed: {e}");
                    std::process::exit(1);
                }
            };
            eprintln!("[US1-server] listening, waiting for connection...");
            match listener.accept() {
                Ok((mut stream, _addr)) => {
                    let mut buf = [0u8; 64];
                    match stream.read(&mut buf) {
                        Ok(n) => {
                            let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                            eprintln!("[US1-server] received: {msg}");
                            if msg == "HELLO_FROM_CLIENT" {
                                std::process::exit(0);
                            } else {
                                eprintln!("[US1-server] unexpected message");
                                std::process::exit(2);
                            }
                        }
                        Err(e) => {
                            eprintln!("[US1-server] read failed: {e}");
                            std::process::exit(3);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[US1-server] accept failed: {e}");
                    std::process::exit(4);
                }
            }
        }

        // Parent = client: wait a bit for server, then connect + write
        eprintln!("[US1-client] waiting for server to start (pid={pid})...");
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Retry connect up to 10 times
        let mut stream = None;
        for attempt in 0..10 {
            match UnixStream::connect(sock_path) {
                Ok(s) => {
                    eprintln!("[US1-client] connected on attempt {attempt}");
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    eprintln!("[US1-client] connect attempt {attempt} failed: {e}");
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }

        let Some(mut stream) = stream else {
            println!("US1_CONNECT_FAIL");
            let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            return 1;
        };

        if let Err(e) = stream.write_all(b"HELLO_FROM_CLIENT") {
            println!("US1_WRITE_FAIL:{e}");
            let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            return 1;
        }
        drop(stream);

        // Wait for server child
        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        eprintln!("[US1-client] server exited with code {exit_code}");

        let _ = std::fs::remove_file(sock_path);
        if exit_code == 0 {
            println!("US1_CROSS_PROCESS_OK");
            0
        } else {
            println!("US1_CROSS_PROCESS_FAIL:exit={exit_code}");
            1
        }
    }

    /// VS1: Socket timing race — child delays bind, parent connects immediately.
    /// Reproduces the code-server startup race.
    fn test_socket_race() -> i32 {
        let sock_path = "/tmp/litebox-vs1-race.sock";
        let _ = std::fs::remove_file(sock_path);

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("VS1_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            // Child = server: DELAY then bind + listen
            eprintln!("[VS1-server] sleeping 500ms before bind...");
            std::thread::sleep(std::time::Duration::from_millis(500));
            eprintln!("[VS1-server] binding to {sock_path}");
            let listener = match UnixListener::bind(sock_path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[VS1-server] bind failed: {e}");
                    std::process::exit(1);
                }
            };
            eprintln!("[VS1-server] waiting for connection...");
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 64];
                    match stream.read(&mut buf) {
                        Ok(n) => {
                            let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                            eprintln!("[VS1-server] got: {msg}");
                            std::process::exit(if msg == "RACE_OK" { 0 } else { 2 });
                        }
                        Err(_) => std::process::exit(3),
                    }
                }
                Err(_) => std::process::exit(4),
            }
        }

        // Parent = client: try connecting immediately (should fail initially, then succeed)
        eprintln!("[VS1-client] connecting immediately (server hasn't bound yet)...");
        let mut connected = false;
        let start = std::time::Instant::now();
        for attempt in 0..20 {
            match UnixStream::connect(sock_path) {
                Ok(mut s) => {
                    let elapsed = start.elapsed().as_millis();
                    eprintln!("[VS1-client] connected after {elapsed}ms (attempt {attempt})");
                    let _ = s.write_all(b"RACE_OK");
                    connected = true;
                    break;
                }
                Err(e) => {
                    if attempt == 0 {
                        eprintln!("[VS1-client] first connect failed (expected): {e}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }

        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        let _ = std::fs::remove_file(sock_path);

        if connected && exit_code == 0 {
            println!("VS1_RACE_OK");
            0
        } else {
            println!("VS1_RACE_FAIL:connected={connected},exit={exit_code}");
            1
        }
    }

    /// NL6: Check if os.networkInterfaces() returns a MAC address.
    /// Uses getifaddrs to check for AF_PACKET/link-layer entries.
    fn test_mac_address() -> i32 {
        let mut ifaddr: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut ifaddr) } != 0 {
            println!("NL6_GETIFADDRS_FAIL:{}", errno());
            return 1;
        }

        let mut has_packet = false;
        let mut has_inet = false;
        let mut iface_count = 0;
        let mut ptr = ifaddr;
        while !ptr.is_null() {
            let ifa = unsafe { &*ptr };
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
            if !ifa.ifa_addr.is_null() {
                let family = unsafe { (*ifa.ifa_addr).sa_family };
                eprintln!("[NL6] interface={name} family={family}");
                if family == libc::AF_PACKET as u16 {
                    has_packet = true;
                }
                if family == libc::AF_INET as u16 {
                    has_inet = true;
                }
            }
            iface_count += 1;
            ptr = ifa.ifa_next;
        }
        unsafe { libc::freeifaddrs(ifaddr) };

        println!("NL6_MAC_CHECK:count={iface_count},has_packet={has_packet},has_inet={has_inet}");
        // has_packet=true means there's a link-layer entry with MAC
        if has_packet { 0 } else { 1 }
    }

    /// US2: Fork+exec cross-process unix socket — tests the exec migration path.
    /// Parent fork+execs a server process, then connects to its socket.
    /// This is the exact pattern used by VS Code CLI → code-server.
    fn test_cross_exec() -> i32 {
        let sock_path = "/tmp/litebox-us2-test.sock";
        let _ = std::fs::remove_file(sock_path);

        let self_exe = std::env::current_exe().unwrap();
        let self_exe = self_exe.to_str().unwrap();

        // Spawn child via fork+exec (this triggers remote worker migration)
        let child = std::process::Command::new(self_exe)
            .args(["unix-socket-test", "us2-server", sock_path])
            .spawn();

        let Ok(mut child) = child else {
            println!("US2_SPAWN_FAIL");
            return 1;
        };

        // Wait for server to start, then try connecting
        eprintln!(
            "[US2-client] child spawned (pid={}), retrying connect...",
            child.id()
        );
        let mut stream = None;
        for attempt in 0..30 {
            match UnixStream::connect(sock_path) {
                Ok(s) => {
                    eprintln!("[US2-client] connected on attempt {attempt}");
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    if attempt % 5 == 0 {
                        eprintln!("[US2-client] attempt {attempt}: {e}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            }
        }

        let Some(mut stream) = stream else {
            println!("US2_CONNECT_FAIL");
            let _ = child.kill();
            return 1;
        };

        if let Err(e) = stream.write_all(b"US2_HELLO") {
            println!("US2_WRITE_FAIL:{e}");
            let _ = child.kill();
            return 1;
        }
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).unwrap_or(0);
        let reply = std::str::from_utf8(&buf[..n]).unwrap_or("?");
        drop(stream);

        let status = child.wait().unwrap();
        let _ = std::fs::remove_file(sock_path);

        if reply == "US2_REPLY" && status.success() {
            println!("US2_CROSS_EXEC_OK");
            0
        } else {
            println!("US2_CROSS_EXEC_FAIL:reply={reply},status={status}");
            1
        }
    }

    /// Server half for US2 — called after fork+exec.
    fn us2_server() -> i32 {
        let sock_path = std::env::args().nth(3).unwrap_or_default();
        if sock_path.is_empty() {
            eprintln!("[US2-server] no path argument");
            return 1;
        }
        let _ = std::fs::remove_file(&sock_path);
        eprintln!("[US2-server] binding to {sock_path}");
        let listener = match UnixListener::bind(&sock_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[US2-server] bind failed: {e}");
                return 1;
            }
        };
        eprintln!("[US2-server] listening...");
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).unwrap_or(0);
                let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                eprintln!("[US2-server] got: {msg}");
                if msg == "US2_HELLO" {
                    let _ = stream.write_all(b"US2_REPLY");
                    0
                } else {
                    1
                }
            }
            Err(e) => {
                eprintln!("[US2-server] accept failed: {e}");
                1
            }
        }
    }

    /// US3: Bidirectional data transfer — server sends + client sends, both read.
    fn test_bidirectional() -> i32 {
        let sock_path = "/tmp/litebox-us3-test.sock";
        let _ = std::fs::remove_file(sock_path);

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("US3_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            // Child = server
            let listener = match UnixListener::bind(sock_path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[US3-server] bind: {e}");
                    std::process::exit(1);
                }
            };
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Read from client
                    let mut buf = [0u8; 64];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    // Send reply
                    let _ = stream.write_all(b"SERVER_DATA");
                    let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                    std::process::exit(if msg == "CLIENT_DATA" { 0 } else { 2 });
                }
                Err(_) => std::process::exit(3),
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut stream = None;
        for _ in 0..10 {
            if let Ok(s) = UnixStream::connect(sock_path) {
                stream = Some(s);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        let Some(mut stream) = stream else {
            println!("US3_CONNECT_FAIL");
            let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            return 1;
        };

        let _ = stream.write_all(b"CLIENT_DATA");
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).unwrap_or(0);
        let reply = std::str::from_utf8(&buf[..n]).unwrap_or("?");
        drop(stream);

        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        let _ = std::fs::remove_file(sock_path);

        if reply == "SERVER_DATA" && exit_code == 0 {
            println!("US3_BIDI_OK");
            0
        } else {
            println!("US3_BIDI_FAIL:reply={reply},exit={exit_code}");
            1
        }
    }

    /// US4: Multiple concurrent connections to the same unix socket.
    fn test_multi_conn() -> i32 {
        let sock_path = "/tmp/litebox-us4-test.sock";
        let _ = std::fs::remove_file(sock_path);

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("US4_FORK_FAIL:{}", errno());
            return 1;
        }

        if pid == 0 {
            // Child = server: accept 3 connections
            let listener = match UnixListener::bind(sock_path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[US4-server] bind: {e}");
                    std::process::exit(1);
                }
            };
            let mut count = 0;
            for i in 0..3 {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 64];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let msg = std::str::from_utf8(&buf[..n]).unwrap_or("?");
                        eprintln!("[US4-server] conn {i}: {msg}");
                        if msg == format!("CONN_{i}") {
                            count += 1;
                        }
                    }
                    Err(e) => eprintln!("[US4-server] accept {i}: {e}"),
                }
            }
            std::process::exit(if count == 3 { 0 } else { 2 });
        }

        std::thread::sleep(std::time::Duration::from_millis(200));
        let mut ok_count = 0;
        for i in 0..3 {
            let mut connected = false;
            for _ in 0..10 {
                if let Ok(mut s) = UnixStream::connect(sock_path) {
                    let _ = s.write_all(format!("CONN_{i}").as_bytes());
                    drop(s);
                    ok_count += 1;
                    connected = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if !connected {
                eprintln!("[US4-client] conn {i} failed");
            }
        }

        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        let _ = std::fs::remove_file(sock_path);

        if ok_count == 3 && exit_code == 0 {
            println!("US4_MULTI_OK");
            0
        } else {
            println!("US4_MULTI_FAIL:conns={ok_count},exit={exit_code}");
            1
        }
    }

    /// US5: Abstract unix socket cross-process.
    fn test_abstract_socket() -> i32 {
        let abstract_name = b"\0litebox-us5-test";

        // Create socket manually for abstract namespace
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            println!("US5_SOCKET_FAIL:{}", errno());
            return 1;
        }

        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as u16;
        addr.sun_path[..abstract_name.len()]
            .copy_from_slice(unsafe { &*(abstract_name as *const [u8] as *const [i8]) });
        let addr_len =
            (std::mem::size_of::<libc::sa_family_t>() + abstract_name.len()) as libc::socklen_t;

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("US5_FORK_FAIL:{}", errno());
            unsafe { libc::close(fd) };
            return 1;
        }

        if pid == 0 {
            // Child = server: bind + listen + accept
            if unsafe { libc::bind(fd, &addr as *const _ as *const libc::sockaddr, addr_len) } < 0 {
                eprintln!("[US5-server] bind: {}", errno());
                std::process::exit(1);
            }
            if unsafe { libc::listen(fd, 5) } < 0 {
                eprintln!("[US5-server] listen: {}", errno());
                std::process::exit(2);
            }
            eprintln!("[US5-server] waiting for connection...");
            let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if client_fd < 0 {
                eprintln!("[US5-server] accept: {}", errno());
                std::process::exit(3);
            }
            let mut buf = [0u8; 64];
            let n = unsafe { libc::read(client_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            unsafe {
                libc::close(client_fd);
                libc::close(fd);
            }
            let msg = std::str::from_utf8(&buf[..n.max(0) as usize]).unwrap_or("?");
            std::process::exit(if msg == "US5_HELLO" { 0 } else { 4 });
        }

        // Parent = client
        unsafe { libc::close(fd) }; // close the server socket in parent
        std::thread::sleep(std::time::Duration::from_millis(300));

        let cfd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        if cfd < 0 {
            println!("US5_CLIENT_SOCKET_FAIL:{}", errno());
            let _ = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
            return 1;
        }

        let mut connected = false;
        for attempt in 0..10 {
            if unsafe { libc::connect(cfd, &addr as *const _ as *const libc::sockaddr, addr_len) }
                == 0
            {
                eprintln!("[US5-client] connected on attempt {attempt}");
                connected = true;
                break;
            }
            eprintln!("[US5-client] attempt {attempt}: errno={}", errno());
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        if connected {
            unsafe { libc::write(cfd, b"US5_HELLO".as_ptr() as *const _, 9) };
        }
        unsafe { libc::close(cfd) };

        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };

        if connected && exit_code == 0 {
            println!("US5_ABSTRACT_OK");
            0
        } else {
            println!("US5_ABSTRACT_FAIL:connected={connected},exit={exit_code}");
            1
        }
    }

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    }
}

mod exit_tests {
    fn test_single_exit() {
        println!("EX1_BEFORE_EXIT");
        std::process::exit(0);
    }

    fn test_multithread_exit() {
        for i in 0..4 {
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    eprintln!("[EX2] thread {i} alive");
                }
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        println!("EX2_BEFORE_EXIT");
        std::process::exit(0);
    }

    fn test_fork_exit() {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            println!("EX3_FORK_FAIL");
            std::process::exit(1);
        }
        if pid == 0 {
            eprintln!("[EX3] child exiting");
            std::process::exit(42);
        }
        let mut status: i32 = 0;
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret == pid && libc::WIFEXITED(status) {
            let code = libc::WEXITSTATUS(status);
            println!("EX3_CHILD_EXITED:{code}");
            std::process::exit(0);
        } else {
            println!("EX3_WAIT_FAIL:ret={ret},status={status}");
            std::process::exit(1);
        }
    }

    fn test_raw_exit_group() {
        println!("EX4_BEFORE_EXIT");
        unsafe { libc::syscall(libc::SYS_exit_group, 0) };
    }

    /// Terminal ioctl tests — run as: exit-test term <op> <fd>
    /// ops: tcgets, tcsets, tcsetsw, tcsetsf, tiocgwinsz
    /// fds: 0, 1, 2
    fn test_terminal_ioctl(op: &str, fd_num: i32) {
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };

        match op {
            "tcgets" => {
                let ret = unsafe { libc::tcgetattr(fd_num, &mut termios) };
                if ret == 0 {
                    println!("TERM_OK:op={op},fd={fd_num}");
                } else {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                    println!("TERM_ERR:op={op},fd={fd_num},errno={e}");
                }
            }
            "tcsets" | "tcsetsw" | "tcsetsf" => {
                // First get current attrs
                if unsafe { libc::tcgetattr(fd_num, &mut termios) } != 0 {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                    println!("TERM_ERR:op={op},fd={fd_num},errno={e},phase=tcgetattr");
                    std::process::exit(1);
                }
                let when = match op {
                    "tcsets" => libc::TCSANOW,
                    "tcsetsw" => libc::TCSADRAIN,
                    "tcsetsf" => libc::TCSAFLUSH,
                    _ => unreachable!(),
                };
                let ret = unsafe { libc::tcsetattr(fd_num, when, &termios) };
                if ret == 0 {
                    println!("TERM_OK:op={op},fd={fd_num}");
                } else {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                    println!("TERM_ERR:op={op},fd={fd_num},errno={e}");
                }
            }
            "tiocgwinsz" => {
                let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
                let ret = unsafe { libc::ioctl(fd_num, libc::TIOCGWINSZ, &mut ws) };
                if ret == 0 {
                    println!(
                        "TERM_OK:op={op},fd={fd_num},rows={},cols={}",
                        ws.ws_row, ws.ws_col
                    );
                } else {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                    println!("TERM_ERR:op={op},fd={fd_num},errno={e}");
                }
            }
            _ => {
                println!("TERM_ERR:unknown_op={op}");
                std::process::exit(1);
            }
        }
        std::process::exit(0);
    }

    fn test_exec_exit() {
        let self_exe = std::env::current_exe().unwrap();
        let output = std::process::Command::new(&self_exe)
            .args(["exit-test", "single"])
            .output();
        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let code = out.status.code().unwrap_or(-1);
                if stdout.contains("EX1_BEFORE_EXIT") && code == 0 {
                    println!("EX5_EXEC_EXIT_OK");
                } else {
                    println!("EX5_EXEC_EXIT_FAIL:code={code},stdout={}", stdout.trim());
                }
                std::process::exit(0);
            }
            Err(e) => {
                println!("EX5_SPAWN_FAIL:{e}");
                std::process::exit(1);
            }
        }
    }

    pub fn run(sub: &str) {
        match sub {
            "single" => test_single_exit(),
            "multithread" => test_multithread_exit(),
            "fork-exit" => test_fork_exit(),
            "raw-exit-group" => test_raw_exit_group(),
            "exec-exit" => test_exec_exit(),
            // Matrix-style: exit-test term <op> <fd>
            "term" => {
                let op = std::env::args().nth(3).unwrap_or_default();
                let fd: i32 = std::env::args()
                    .nth(4)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                test_terminal_ioctl(&op, fd);
            }
            other => {
                eprintln!("unknown exit test: {other}");
                std::process::exit(1);
            }
        }
    }
}

mod net_tests {
    pub fn run(sub: &str) -> i32 {
        match sub {
            "ipv6-socket" => test_ipv6_socket(),
            "ipv6-listen" => test_ipv6_listen(),
            "ipv6-connect" => test_ipv6_connect(),
            "ipv6-getaddrinfo" => test_ipv6_getaddrinfo(),
            "ipv6-v6only" => test_ipv6_v6only(),
            "ipv4-listen" => test_ipv4_listen(),
            other => {
                eprintln!("unknown net test: {other}");
                1
            }
        }
    }

    /// NET5: getaddrinfo("::1") + bind + listen — the exact Node.js pattern.
    fn test_ipv6_getaddrinfo() -> i32 {
        // Step 1: getaddrinfo for "::1"
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_family = libc::AF_INET6;
        hints.ai_socktype = libc::SOCK_STREAM;
        hints.ai_flags = libc::AI_NUMERICHOST;

        let mut result: *mut libc::addrinfo = std::ptr::null_mut();
        let host = std::ffi::CString::new("::1").unwrap();
        let port = std::ffi::CString::new("0").unwrap();
        let ret = unsafe { libc::getaddrinfo(host.as_ptr(), port.as_ptr(), &hints, &mut result) };
        if ret != 0 {
            let err = unsafe { std::ffi::CStr::from_ptr(libc::gai_strerror(ret)) };
            println!("NET5_GAI_FAIL:ret={ret},err={}", err.to_string_lossy());
            return 1;
        }
        if result.is_null() {
            println!("NET5_GAI_NULL");
            return 1;
        }

        let ai = unsafe { &*result };
        eprintln!(
            "[NET5] getaddrinfo: family={}, socktype={}, addrlen={}",
            ai.ai_family, ai.ai_socktype, ai.ai_addrlen
        );

        // Step 2: socket
        let fd = unsafe { libc::socket(ai.ai_family, ai.ai_socktype, ai.ai_protocol) };
        if fd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET5_SOCKET_FAIL:errno={e}");
            unsafe { libc::freeaddrinfo(result) };
            return 1;
        }

        // Step 3: setsockopt IPV6_V6ONLY (Node.js does this)
        let v6only: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &v6only as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as u32,
            )
        };
        eprintln!("[NET5] setsockopt IPV6_V6ONLY: ret={ret}");

        // Step 4: bind
        let ret = unsafe { libc::bind(fd, ai.ai_addr, ai.ai_addrlen) };
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET5_BIND_FAIL:errno={e}");
            unsafe {
                libc::close(fd);
                libc::freeaddrinfo(result);
            };
            return 1;
        }

        // Step 5: listen
        let ret = unsafe { libc::listen(fd, 128) };
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET5_LISTEN_FAIL:errno={e}");
            unsafe {
                libc::close(fd);
                libc::freeaddrinfo(result);
            };
            return 1;
        }

        unsafe {
            libc::close(fd);
            libc::freeaddrinfo(result);
        };
        println!("NET5_OK");
        0
    }

    /// NET6: setsockopt(IPV6_V6ONLY) — Node.js sets this before bind.
    fn test_ipv6_v6only() -> i32 {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET6_SOCKET_FAIL:errno={e}");
            return 1;
        }
        let v6only: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &v6only as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as u32,
            )
        };
        unsafe { libc::close(fd) };
        if ret == 0 {
            println!("NET6_OK");
            0
        } else {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET6_FAIL:errno={e}");
            1
        }
    }

    /// NET1: socket(AF_INET6, SOCK_STREAM) — can we create an IPv6 socket?
    fn test_ipv6_socket() -> i32 {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            println!("NET1_OK:fd={fd}");
            0
        } else {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET1_FAIL:errno={e}");
            1
        }
    }

    /// NET2: bind(::1, 0) + listen — the exact pattern VS Code extension host uses.
    fn test_ipv6_listen() -> i32 {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET2_SOCKET_FAIL:errno={e}");
            return 1;
        }

        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = libc::AF_INET6 as u16;
        addr.sin6_port = 0; // kernel picks port
        addr.sin6_addr = libc::in6_addr {
            s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], // ::1
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        };
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            unsafe { libc::close(fd) };
            println!("NET2_BIND_FAIL:errno={e}");
            return 1;
        }

        let ret = unsafe { libc::listen(fd, 5) };
        if ret < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            unsafe { libc::close(fd) };
            println!("NET2_LISTEN_FAIL:errno={e}");
            return 1;
        }

        // Get the assigned port
        let mut bound: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as u32;
        unsafe {
            libc::getsockname(fd, &mut bound as *mut _ as *mut libc::sockaddr, &mut len);
        }
        let port = u16::from_be(bound.sin6_port);
        unsafe { libc::close(fd) };
        println!("NET2_OK:port={port}");
        0
    }

    /// NET3: Full IPv6 loopback: listen + fork + child connects + data exchange.
    fn test_ipv6_connect() -> i32 {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET3_SOCKET_FAIL:errno={e}");
            return 1;
        }

        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = libc::AF_INET6 as u16;
        addr.sin6_port = 0;
        addr.sin6_addr = libc::in6_addr {
            s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };

        if unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        } < 0
        {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            unsafe { libc::close(fd) };
            println!("NET3_BIND_FAIL:errno={e}");
            return 1;
        }

        if unsafe { libc::listen(fd, 5) } < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            unsafe { libc::close(fd) };
            println!("NET3_LISTEN_FAIL:errno={e}");
            return 1;
        }

        let mut bound: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as u32;
        unsafe {
            libc::getsockname(fd, &mut bound as *mut _ as *mut libc::sockaddr, &mut len);
        }
        let port = u16::from_be(bound.sin6_port);
        eprintln!("[NET3] listening on [::1]:{port}");

        let pid = unsafe { libc::fork() };
        if pid == 0 {
            // Child: connect to [::1]:port, send data
            unsafe { libc::close(fd) };
            let cfd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
            let mut dst = addr;
            dst.sin6_port = bound.sin6_port;
            std::thread::sleep(std::time::Duration::from_millis(100));
            if unsafe {
                libc::connect(
                    cfd,
                    &dst as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as u32,
                )
            } < 0
            {
                std::process::exit(1);
            }
            let msg = b"NET3_DATA";
            unsafe { libc::write(cfd, msg.as_ptr() as *const _, msg.len()) };
            unsafe { libc::close(cfd) };
            std::process::exit(0);
        }

        let client = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            println!("NET3_ACCEPT_FAIL:errno={e}");
            unsafe {
                libc::close(fd);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return 1;
        }

        let mut buf = [0u8; 64];
        let n = unsafe { libc::read(client, buf.as_mut_ptr() as *mut _, buf.len()) };
        unsafe {
            libc::close(client);
            libc::close(fd);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }

        let msg = std::str::from_utf8(&buf[..n.max(0) as usize]).unwrap_or("?");
        if msg == "NET3_DATA" {
            println!("NET3_OK:port={port}");
            0
        } else {
            println!("NET3_FAIL:got={msg}");
            1
        }
    }

    /// NET4: IPv4 listen+connect baseline (should already work).
    fn test_ipv4_listen() -> i32 {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            println!("NET4_SOCKET_FAIL");
            return 1;
        }
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as u16;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = u32::from_be(0x7f000001); // 127.0.0.1

        if unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        } < 0
        {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            unsafe { libc::close(fd) };
            println!("NET4_BIND_FAIL:errno={e}");
            return 1;
        }

        if unsafe { libc::listen(fd, 5) } < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
            unsafe { libc::close(fd) };
            println!("NET4_LISTEN_FAIL:errno={e}");
            return 1;
        }

        let mut bound: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as u32;
        unsafe {
            libc::getsockname(fd, &mut bound as *mut _ as *mut libc::sockaddr, &mut len);
        }
        let port = u16::from_be(bound.sin_port);
        unsafe { libc::close(fd) };
        println!("NET4_OK:port={port}");
        0
    }
}

mod fs_tests {
    use std::io::{Read, Write};

    pub fn run(sub: &str, args: &[String]) -> i32 {
        match sub {
            "io" => {
                let op = args.get(3).map(String::as_str).unwrap_or("write-read");
                let path = args
                    .get(4)
                    .map(String::as_str)
                    .unwrap_or("/tmp/fs-test.txt");
                test_io(op, path)
            }
            "exec-write" => {
                let bin_type = args.get(3).map(String::as_str).unwrap_or("pie");
                let path = args
                    .get(4)
                    .map(String::as_str)
                    .unwrap_or("/tmp/fs-exec.txt");
                test_exec_write(bin_type, path)
            }
            // fs-test exec-open-read <binary-type> <path>
            // Fork+exec child that writes AND keeps fd open; parent reads while child alive.
            "exec-open-read" => {
                let bin_type = args.get(3).map(String::as_str).unwrap_or("pie");
                let path = args
                    .get(4)
                    .map(String::as_str)
                    .unwrap_or("/tmp/fs-open.txt");
                test_exec_open_read(bin_type, path)
            }
            // Helper: write to file then sleep (keeps process alive with file written)
            "do-write-sleep" => {
                let path = args
                    .get(3)
                    .map(String::as_str)
                    .unwrap_or("/tmp/fs-open.txt");
                let data = args.get(4).map(String::as_str).unwrap_or("OPEN_WRITE_DATA");
                std::fs::write(path, data.as_bytes()).unwrap_or_else(|e| {
                    eprintln!("do-write-sleep: write failed: {e}");
                    std::process::exit(1);
                });
                // Keep alive so the parent can read while we're still running
                std::thread::sleep(std::time::Duration::from_secs(30));
                0
            }
            // Called by exec-write to actually write the file
            "do-write" => {
                let path = args
                    .get(3)
                    .map(String::as_str)
                    .unwrap_or("/tmp/fs-exec.txt");
                let data = args.get(4).map(String::as_str).unwrap_or("EXEC_WRITE_DATA");
                match std::fs::write(path, data.as_bytes()) {
                    Ok(_) => 0,
                    Err(e) => {
                        eprintln!("do-write: {e}");
                        1
                    }
                }
            }
            _ => {
                eprintln!("fs-test subcommands: io, exec-write, do-write");
                1
            }
        }
    }

    /// Fork+exec a binary to write a file, then read it from the parent.
    fn test_exec_write(bin_type: &str, path: &str) -> i32 {
        let _ = std::fs::remove_file(path);
        let self_exe = std::env::current_exe().unwrap();
        let self_exe = self_exe.to_str().unwrap();
        let data = "EXEC_WRITE_OK";

        let child = match bin_type {
            "pie" => std::process::Command::new(self_exe)
                .args(["fs-test", "do-write", path, data])
                .output(),
            "nonpie" => {
                // Use the ELF-header-patched copy (ET_EXEC) to force remote worker
                std::process::Command::new("/litebox-test-harness-nonpie")
                    .args(["fs-test", "do-write", path, data])
                    .output()
            }
            other => {
                println!("FS_ERR:op=exec-write,unknown_bin_type={other}");
                return 1;
            }
        };

        match child {
            Ok(out) if !out.status.success() => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                println!(
                    "FS_ERR:op=exec-write,bin={bin_type},path={path},exit={},err={}",
                    out.status.code().unwrap_or(-1),
                    stderr.lines().next().unwrap_or("")
                );
                return 1;
            }
            Err(e) => {
                println!("FS_ERR:op=exec-write,bin={bin_type},path={path},spawn_err={e}");
                return 1;
            }
            _ => {}
        }

        match std::fs::read_to_string(path) {
            Ok(s) if s == data => {
                println!("FS_OK:op=exec-write,bin={bin_type},path={path}");
                0
            }
            Ok(s) => {
                println!(
                    "FS_ERR:op=exec-write,bin={bin_type},path={path},got={}",
                    s.escape_default()
                );
                1
            }
            Err(e) => {
                println!("FS_ERR:op=exec-write,bin={bin_type},path={path},read_err={e}");
                1
            }
        }
    }

    /// Fork+exec child that writes AND keeps running; parent reads while child alive.
    /// This is the exact pre-warm pattern — tests 9P coherence for open files on remote workers.
    fn test_exec_open_read(bin_type: &str, path: &str) -> i32 {
        let _ = std::fs::remove_file(path);
        let self_exe = std::env::current_exe().unwrap();
        let self_exe = self_exe.to_str().unwrap();
        let data = "OPEN_READ_DATA";

        let bin = match bin_type {
            "pie" => self_exe.to_string(),
            "nonpie" => "/litebox-test-harness-nonpie".to_string(),
            other => {
                println!("FS_ERR:op=exec-open-read,unknown_bin_type={other}");
                return 1;
            }
        };

        // Spawn child that writes then sleeps (keeps process alive)
        let mut child = match std::process::Command::new(&bin)
            .args(["fs-test", "do-write-sleep", path, data])
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                println!("FS_ERR:op=exec-open-read,bin={bin_type},path={path},spawn_err={e}");
                return 1;
            }
        };

        // Wait for child to write the file
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Read while child still alive
        let result = std::fs::read_to_string(path);
        let _ = child.kill();
        let _ = child.wait();

        match result {
            Ok(s) if s == data => {
                println!("FS_OK:op=exec-open-read,bin={bin_type},path={path}");
                0
            }
            Ok(s) => {
                println!(
                    "FS_ERR:op=exec-open-read,bin={bin_type},path={path},got={}",
                    s.escape_default()
                );
                1
            }
            Err(e) => {
                println!("FS_ERR:op=exec-open-read,bin={bin_type},path={path},read_err={e}");
                1
            }
        }
    }

    fn test_io(op: &str, path: &str) -> i32 {
        let _ = std::fs::remove_file(path);
        match op {
            // FS1: Simple write then read (same process, sequential)
            "write-read" => {
                std::fs::write(path, b"FS_DATA_42").unwrap_or_else(|e| {
                    println!("FS_ERR:op={op},path={path},phase=write,err={e}");
                    std::process::exit(1);
                });
                match std::fs::read_to_string(path) {
                    Ok(s) if s == "FS_DATA_42" => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!("FS_ERR:op={op},path={path},phase=read,got={s}");
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS2: Append then read
            "append-read" => {
                std::fs::write(path, b"LINE1\n").unwrap_or_else(|e| {
                    println!("FS_ERR:op={op},path={path},phase=write1,err={e}");
                    std::process::exit(1);
                });
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .open(path)
                    .unwrap_or_else(|e| {
                        println!("FS_ERR:op={op},path={path},phase=open-append,err={e}");
                        std::process::exit(1);
                    });
                f.write_all(b"LINE2\n").unwrap();
                drop(f);
                match std::fs::read_to_string(path) {
                    Ok(s) if s == "LINE1\nLINE2\n" => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!(
                            "FS_ERR:op={op},path={path},phase=read,got={}",
                            s.escape_default()
                        );
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS3: Write in background thread, read from main thread (concurrent)
            "write-bg-read" => {
                let p = path.to_string();
                let handle = std::thread::spawn(move || {
                    let mut f = std::fs::File::create(&p).unwrap();
                    f.write_all(b"BG_DATA").unwrap();
                    f.sync_all().unwrap();
                });
                handle.join().unwrap();
                // Writer is done and joined — file should be readable
                match std::fs::read_to_string(path) {
                    Ok(s) if s == "BG_DATA" => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!("FS_ERR:op={op},path={path},phase=read,got={s}");
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS4: Shell redirect (like code-server pre-warm) — background write, foreground read
            // This is the exact pattern: `cmd > file &` then `cat file`
            "redirect-bg-read" => {
                let p = path.to_string();
                // Write via a child process with stdout redirected to file
                let child = std::process::Command::new("/usr/bin/bash")
                    .args(["-c", &format!("echo REDIRECT_DATA > {p}")])
                    .output();
                match child {
                    Ok(out) if out.status.success() => {}
                    Ok(out) => {
                        println!(
                            "FS_ERR:op={op},path={path},phase=write,exit={}",
                            out.status.code().unwrap_or(-1)
                        );
                        return 1;
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=spawn,err={e}");
                        return 1;
                    }
                }
                match std::fs::read_to_string(path) {
                    Ok(s) if s.trim() == "REDIRECT_DATA" => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!(
                            "FS_ERR:op={op},path={path},phase=read,got={}",
                            s.escape_default()
                        );
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS5: Fork child writes, parent reads (cross-process, still open fd)
            "fork-write-read" => {
                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    println!("FS_ERR:op={op},path={path},phase=fork");
                    return 1;
                }
                if pid == 0 {
                    // Child: write to file and exit
                    match std::fs::write(path, b"FORK_DATA") {
                        Ok(_) => std::process::exit(0),
                        Err(_) => std::process::exit(1),
                    }
                }
                // Parent: wait for child, then read
                let mut status: i32 = 0;
                unsafe { libc::waitpid(pid, &mut status, 0) };
                match std::fs::read_to_string(path) {
                    Ok(s) if s == "FORK_DATA" => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!("FS_ERR:op={op},path={path},phase=read,got={s}");
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS6: Background process writes to file via redirect, WHILE file is still open,
            // another process reads. This is the exact code-server pre-warm pattern.
            "bg-open-read" => {
                let p = path.to_string();
                // Start a background writer that keeps the file open
                let mut child = std::process::Command::new("/usr/bin/bash")
                    .args([
                        "-c",
                        &format!("echo LINE1 > {p}; sleep 1; echo LINE2 >> {p}; sleep 5"),
                    ])
                    .spawn()
                    .unwrap_or_else(|e| {
                        println!("FS_ERR:op={op},path={path},phase=spawn,err={e}");
                        std::process::exit(1);
                    });

                // Wait for first line to be written
                std::thread::sleep(std::time::Duration::from_millis(500));

                // Try to read while writer still has file open
                let result = std::fs::read_to_string(path);
                let _ = child.kill();
                let _ = child.wait();

                match result {
                    Ok(s) if s.contains("LINE1") => {
                        println!(
                            "FS_OK:op={op},path={path},content={}",
                            s.trim().escape_default()
                        );
                        0
                    }
                    Ok(s) => {
                        println!(
                            "FS_ERR:op={op},path={path},phase=read,got={}",
                            s.escape_default()
                        );
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            // FS7: Parent opens file for writing, forks, child writes via inherited fd,
            // parent reads. This is the pre-warm pattern: bash opens log.txt with >,
            // backgrounds code-server (fork), child writes to inherited stdout=log.txt,
            // later the CLI reads log.txt.
            "parent-open-fork-read" => {
                let f = std::fs::File::create(path).unwrap_or_else(|e| {
                    println!("FS_ERR:op={op},path={path},phase=create,err={e}");
                    std::process::exit(1);
                });
                let fd = {
                    use std::os::unix::io::AsRawFd;
                    f.as_raw_fd()
                };

                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    println!("FS_ERR:op={op},path={path},phase=fork");
                    return 1;
                }
                if pid == 0 {
                    // Child: write to inherited fd, then sleep (keep fd open)
                    let msg = b"CHILD_WROTE_THIS\n";
                    unsafe { libc::write(fd, msg.as_ptr() as *const _, msg.len()) };
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    std::process::exit(0);
                }

                // Parent: close our copy of the write fd, wait a bit, then read
                drop(f);
                std::thread::sleep(std::time::Duration::from_millis(500));

                let result = std::fs::read_to_string(path);
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
                match result {
                    Ok(s) if s.contains("CHILD_WROTE_THIS") => {
                        println!("FS_OK:op={op},path={path}");
                        0
                    }
                    Ok(s) => {
                        println!(
                            "FS_ERR:op={op},path={path},phase=read,got={}",
                            s.escape_default()
                        );
                        1
                    }
                    Err(e) => {
                        println!("FS_ERR:op={op},path={path},phase=read,err={e}");
                        1
                    }
                }
            }
            other => {
                println!("FS_ERR:unknown_op={other}");
                1
            }
        }
    }
}
