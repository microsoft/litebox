// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that waitid reports and reaps terminated children selected by PID, process group, or any,
// including with a NULL infop as glibc's posix_spawn passes when reaping a child whose exec failed,
// and that it validates its arguments like Linux.

#include "helpers.h"

#include <sys/resource.h>

// The raw syscall, which unlike glibc's wrapper also takes a resource usage pointer.
static long raw_waitid(int idtype, long id, siginfo_t *info, int options, struct rusage *usage) {
    return syscall(SYS_waitid, idtype, id, info, options, usage);
}

static void expect_no_children(void) {
    siginfo_t info;
    expect_errno(raw_waitid(P_ALL, 0, &info, WEXITED | WNOHANG, NULL), ECHILD,
                 "children are left");
}

static siginfo_t filled_info(void) {
    siginfo_t info;
    memset(&info, 0xa5, sizeof(info));
    return info;
}

static int reports(const siginfo_t *info, pid_t child, int code, int status) {
    return info->si_signo == SIGCHLD && info->si_errno == 0 && info->si_code == code &&
           info->si_pid == child && info->si_uid == getuid() && info->si_status == status;
}

static int is_zeroed(const siginfo_t *info) {
    return info->si_signo == 0 && info->si_errno == 0 && info->si_code == 0 &&
           info->si_pid == 0 && info->si_uid == 0 && info->si_status == 0;
}

static pid_t fork_exiting(int code) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        _exit(code);
    }
    TEST_ASSERT(child > 0, "fork");
    return child;
}

// Forks a child that exits with `code` once `*release` is closed, in its own process group if
// `own_group` is set.
static pid_t fork_held(int code, int own_group, int *release) {
    int fds[2];
    TEST_ASSERT(pipe(fds) == 0, "pipe");
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        if (own_group) {
            setpgid(0, 0);
        }
        close(fds[1]);
        char byte;
        while (read(fds[0], &byte, 1) < 0 && errno == EINTR) {
        }
        _exit(code);
    }
    TEST_ASSERT(child > 0, "fork");
    if (own_group) {
        // Both sides set the group, so it is set whichever runs first.
        TEST_ASSERT(setpgid(child, child) == 0, "setpgid");
    }
    close(fds[0]);
    *release = fds[1];
    return child;
}

static void check_invalid(void) {
    siginfo_t info;
    expect_errno(raw_waitid(P_ALL, 0, &info, 0, NULL), EINVAL, "no options");
    expect_errno(raw_waitid(P_ALL, 0, &info, WNOHANG, NULL), EINVAL, "only WNOHANG");
    expect_errno(raw_waitid(P_ALL, 0, &info, WEXITED | 0x10, NULL), EINVAL, "unknown option");
    expect_errno(raw_waitid(99, 0, &info, WEXITED, NULL), EINVAL, "unknown idtype");
    expect_errno(raw_waitid(P_PID, 0, &info, WEXITED, NULL), EINVAL, "P_PID 0");
    expect_errno(raw_waitid(P_PID, -1, &info, WEXITED, NULL), EINVAL, "P_PID -1");
    expect_errno(raw_waitid(P_PGID, -1, &info, WEXITED, NULL), EINVAL, "P_PGID -1");
    // Options are checked before looking for children.
    expect_errno(raw_waitid(P_PID, getpid(), &info, 0, NULL), EINVAL, "options before ID");
    // Only the ID's low 32 bits are the PID.
    expect_errno(raw_waitid(P_PID, 0x100000000L, &info, WEXITED, NULL), EINVAL, "64-bit PID");

    // Even when failing, the information is zeroed.
    info = filled_info();
    expect_no_children();
    expect_errno(raw_waitid(P_ALL, 0, &info, WEXITED | WNOHANG, NULL), ECHILD, "no children");
    TEST_ASSERT(is_zeroed(&info), "info not zeroed on ECHILD");
    info = filled_info();
    expect_errno(raw_waitid(P_PID, 0, &info, WEXITED, NULL), EINVAL, "P_PID 0");
    TEST_ASSERT(is_zeroed(&info), "info not zeroed on invalid ID");
    info = filled_info();
    expect_errno(raw_waitid(99, 0, &info, WEXITED, NULL), EINVAL, "unknown idtype");
    TEST_ASSERT(is_zeroed(&info), "info not zeroed on invalid idtype");
    expect_errno(waitid(P_PID, getpid(), &info, WEXITED), ECHILD, "waiting for self");
    expect_errno(waitid(P_PGID, 0, &info, WEXITED), ECHILD, "own group without children");
}

static void check_exited(void) {
    pid_t child = fork_exiting(7);
    siginfo_t info = filled_info();
    TEST_ASSERT(waitid(P_PID, child, &info, WEXITED) == 0, "waitid P_PID");
    TEST_ASSERT(reports(&info, child, CLD_EXITED, 7), "exit by PID");
    expect_no_children();

    child = fork_exiting(0x1ff);
    info = filled_info();
    TEST_ASSERT(waitid(P_ALL, 0, &info, WEXITED) == 0, "waitid P_ALL");
    TEST_ASSERT(reports(&info, child, CLD_EXITED, 0xff), "truncated exit status");
    expect_no_children();
}

static void check_null_infop(void) {
    pid_t child = fork_exiting(3);
    TEST_ASSERT(raw_waitid(P_PID, child, NULL, WEXITED, NULL) == 0, "NULL infop");
    expect_no_children();

    fork_exiting(4);
    struct rusage usage;
    memset(&usage, 0xa5, sizeof(usage));
    TEST_ASSERT(raw_waitid(P_ALL, 0, NULL, WEXITED, &usage) == 0, "NULL infop with usage");
    TEST_ASSERT(usage.ru_utime.tv_usec >= 0 && usage.ru_utime.tv_usec < 1000000, "ru_utime");
    TEST_ASSERT(usage.ru_stime.tv_usec >= 0 && usage.ru_stime.tv_usec < 1000000, "ru_stime");
    expect_no_children();
}

static void check_killed(void) {
    int release;
    pid_t child = fork_held(0, 0, &release);
    TEST_ASSERT(kill(child, SIGTERM) == 0, "kill");
    siginfo_t info = filled_info();
    TEST_ASSERT(waitid(P_PID, child, &info, WEXITED) == 0, "waitid killed child");
    TEST_ASSERT(reports(&info, child, CLD_KILLED, SIGTERM), "killed report");
    close(release);
    expect_no_children();
}

static void check_nohang(void) {
    int release;
    pid_t child = fork_held(9, 0, &release);
    // With no terminated child, the information is zeroed and the usage is left alone.
    siginfo_t info = filled_info();
    struct rusage usage;
    memset(&usage, 0xa5, sizeof(usage));
    TEST_ASSERT(raw_waitid(P_PID, child, &info, WEXITED | WNOHANG, &usage) == 0, "WNOHANG");
    TEST_ASSERT(is_zeroed(&info), "info not zeroed on WNOHANG");
    TEST_ASSERT(((unsigned char *)&usage)[0] == 0xa5, "usage written on WNOHANG");
    TEST_ASSERT(raw_waitid(P_ALL, 0, NULL, WEXITED | WNOHANG, NULL) == 0, "WNOHANG NULL infop");

    close(release);
    info = filled_info();
    TEST_ASSERT(waitid(P_PID, child, &info, WEXITED) == 0, "waitid released child");
    TEST_ASSERT(reports(&info, child, CLD_EXITED, 9), "released child report");
    expect_no_children();
}

static void check_process_group(void) {
    int release;
    pid_t other = fork_held(11, 1, &release);
    siginfo_t info;
    // The only child is in another group.
    expect_errno(waitid(P_PGID, 0, &info, WEXITED | WNOHANG), ECHILD, "own group");
    expect_errno(waitid(P_PGID, getpgrp(), &info, WEXITED | WNOHANG), ECHILD, "own group ID");

    // Group 0 is this process's group.
    pid_t own = fork_exiting(12);
    info = filled_info();
    TEST_ASSERT(waitid(P_PGID, 0, &info, WEXITED) == 0, "waitid own group");
    TEST_ASSERT(reports(&info, own, CLD_EXITED, 12), "own group report");

    close(release);
    info = filled_info();
    TEST_ASSERT(waitid(P_PGID, other, &info, WEXITED) == 0, "waitid other group");
    TEST_ASSERT(reports(&info, other, CLD_EXITED, 11), "other group report");
    expect_no_children();
}

static void check_clone_options(void) {
    // A forked child has the default exit signal, so only __WALL selects it with __WCLONE.
    pid_t child = fork_exiting(13);
    siginfo_t info;
    expect_errno(raw_waitid(P_ALL, 0, &info, WEXITED | __WCLONE, NULL), ECHILD, "__WCLONE");
    info = filled_info();
    TEST_ASSERT(raw_waitid(P_ALL, 0, &info, WEXITED | __WCLONE | __WALL, NULL) == 0,
                "__WCLONE | __WALL");
    TEST_ASSERT(reports(&info, child, CLD_EXITED, 13), "__WALL report");

    child = fork_exiting(14);
    info = filled_info();
    TEST_ASSERT(raw_waitid(P_PID, child, &info, WEXITED | __WALL | __WNOTHREAD, NULL) == 0,
                "__WALL | __WNOTHREAD");
    TEST_ASSERT(reports(&info, child, CLD_EXITED, 14), "__WNOTHREAD report");
    expect_no_children();
}

static void check_fault(void) {
    // Like Linux, the child is reaped even though its information cannot be stored.
    pid_t child = fork_exiting(0);
    expect_errno(raw_waitid(P_PID, child, (siginfo_t *)8, WEXITED, NULL), EFAULT, "bad infop");
    expect_no_children();

    child = fork_exiting(0);
    siginfo_t info = filled_info();
    expect_errno(raw_waitid(P_PID, child, &info, WEXITED, (struct rusage *)8), EFAULT,
                 "bad rusage");
    expect_no_children();

    expect_errno(raw_waitid(P_ALL, 0, (siginfo_t *)8, WEXITED, NULL), EFAULT,
                 "bad infop without children");
}

int main(void) {
    check_invalid();
    check_exited();
    check_null_infop();
    check_killed();
    check_nohang();
    check_process_group();
    check_clone_options();
    check_fault();
    return 0;
}
