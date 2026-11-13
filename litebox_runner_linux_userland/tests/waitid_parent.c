// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that waitid reports and reaps terminated children selected by PID, process group, or any,
// including with a NULL infop as glibc's posix_spawn passes when reaping a child whose exec failed,
// and that it validates its arguments like Linux.

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif

static int failures;

#define CHECK(condition)                                                                    \
    do {                                                                                    \
        if (!(condition)) {                                                                 \
            printf("FAIL line %d: %s\n", __LINE__, #condition);                             \
            failures++;                                                                     \
        }                                                                                   \
    } while (0)

// The raw syscall, which unlike glibc's wrapper also takes a resource usage pointer.
static long raw_waitid(int idtype, long id, siginfo_t *info, int options, struct rusage *usage) {
    return syscall(SYS_waitid, idtype, id, info, options, usage);
}

static int fails_with(long ret, int error) {
    return ret == -1 && errno == error;
}

static int no_children_left(void) {
    siginfo_t info;
    return fails_with(raw_waitid(P_ALL, 0, &info, WEXITED | WNOHANG, NULL), ECHILD);
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

static pid_t fork_exiting(int code) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        _exit(code);
    }
    CHECK(child > 0);
    return child;
}

// Forks a child that exits with `code` once `*release` is closed, in its own process group if
// `own_group` is set.
static pid_t fork_held(int code, int own_group, int *release) {
    int fds[2];
    CHECK(pipe(fds) == 0);
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
    CHECK(child > 0);
    if (own_group) {
        // Both sides set the group, so it is set whichever runs first.
        CHECK(setpgid(child, child) == 0 || errno == EACCES);
    }
    close(fds[0]);
    *release = fds[1];
    return child;
}

static void check_invalid(void) {
    siginfo_t info;
    CHECK(fails_with(raw_waitid(P_ALL, 0, &info, 0, NULL), EINVAL));
    CHECK(fails_with(raw_waitid(P_ALL, 0, &info, WNOHANG, NULL), EINVAL));
    CHECK(fails_with(raw_waitid(P_ALL, 0, &info, WEXITED | 0x10, NULL), EINVAL));
    CHECK(fails_with(raw_waitid(99, 0, &info, WEXITED, NULL), EINVAL));
    CHECK(fails_with(raw_waitid(P_PID, 0, &info, WEXITED, NULL), EINVAL));
    CHECK(fails_with(raw_waitid(P_PID, -1, &info, WEXITED, NULL), EINVAL));
    CHECK(fails_with(raw_waitid(P_PGID, -1, &info, WEXITED, NULL), EINVAL));
    CHECK(fails_with(raw_waitid(P_PIDFD, -1, &info, WEXITED, NULL), EINVAL));
    CHECK(fails_with(raw_waitid(P_PIDFD, 1000, &info, WEXITED, NULL), EBADF));
    // Options are checked before the ID.
    CHECK(fails_with(raw_waitid(P_PIDFD, 1000, &info, 0, NULL), EINVAL));
    // A descriptor that is not a pidfd is a bad one.
    CHECK(fails_with(raw_waitid(P_PIDFD, STDOUT_FILENO, &info, WEXITED, NULL), EBADF));
    // Only the ID's low 32 bits are the PID.
    CHECK(fails_with(raw_waitid(P_PID, 0x100000000L, &info, WEXITED, NULL), EINVAL));

    // Even when failing, the information is zeroed.
    info = filled_info();
    CHECK(no_children_left());
    CHECK(fails_with(raw_waitid(P_ALL, 0, &info, WEXITED | WNOHANG, NULL), ECHILD));
    CHECK(info.si_signo == 0 && info.si_errno == 0 && info.si_code == 0 && info.si_pid == 0 &&
          info.si_uid == 0 && info.si_status == 0);
    info = filled_info();
    CHECK(fails_with(raw_waitid(P_PID, 0, &info, WEXITED, NULL), EINVAL));
    CHECK(info.si_signo == 0 && info.si_pid == 0);
    CHECK(fails_with(waitid(P_PID, getpid(), &info, WEXITED), ECHILD));
    CHECK(fails_with(waitid(P_PGID, 0, &info, WEXITED), ECHILD));
}

static void check_exited(void) {
    pid_t child = fork_exiting(7);
    siginfo_t info = filled_info();
    CHECK(waitid(P_PID, child, &info, WEXITED) == 0);
    CHECK(reports(&info, child, CLD_EXITED, 7));
    CHECK(no_children_left());

    child = fork_exiting(0x1ff);
    info = filled_info();
    CHECK(waitid(P_ALL, 0, &info, WEXITED) == 0);
    CHECK(reports(&info, child, CLD_EXITED, 0xff));
    CHECK(no_children_left());
}

static void check_null_infop(void) {
    pid_t child = fork_exiting(3);
    CHECK(raw_waitid(P_PID, child, NULL, WEXITED, NULL) == 0);
    CHECK(no_children_left());

    fork_exiting(4);
    struct rusage usage;
    memset(&usage, 0xa5, sizeof(usage));
    CHECK(raw_waitid(P_ALL, 0, NULL, WEXITED, &usage) == 0);
    CHECK(usage.ru_utime.tv_usec >= 0 && usage.ru_utime.tv_usec < 1000000);
    CHECK(usage.ru_stime.tv_usec >= 0 && usage.ru_stime.tv_usec < 1000000);
    CHECK(no_children_left());
}

static void check_killed(void) {
    int release;
    pid_t child = fork_held(0, 0, &release);
    CHECK(kill(child, SIGTERM) == 0);
    siginfo_t info = filled_info();
    CHECK(waitid(P_PID, child, &info, WEXITED) == 0);
    CHECK(reports(&info, child, CLD_KILLED, SIGTERM));
    close(release);
    CHECK(no_children_left());
}

static void check_nohang(void) {
    int release;
    pid_t child = fork_held(9, 0, &release);
    // With no terminated child, the information is zeroed and the usage is left alone.
    siginfo_t info = filled_info();
    struct rusage usage;
    memset(&usage, 0xa5, sizeof(usage));
    CHECK(raw_waitid(P_PID, child, &info, WEXITED | WNOHANG, &usage) == 0);
    CHECK(info.si_signo == 0 && info.si_errno == 0 && info.si_code == 0 && info.si_pid == 0 &&
          info.si_uid == 0 && info.si_status == 0);
    CHECK(((unsigned char *)&usage)[0] == 0xa5);
    CHECK(raw_waitid(P_ALL, 0, NULL, WEXITED | WNOHANG, NULL) == 0);

    close(release);
    info = filled_info();
    CHECK(waitid(P_PID, child, &info, WEXITED) == 0);
    CHECK(reports(&info, child, CLD_EXITED, 9));
    CHECK(no_children_left());
}

static void check_process_group(void) {
    int release;
    pid_t other = fork_held(11, 1, &release);
    siginfo_t info;
    // The only child is in another group.
    CHECK(fails_with(waitid(P_PGID, 0, &info, WEXITED | WNOHANG), ECHILD));
    CHECK(fails_with(waitid(P_PGID, getpgrp(), &info, WEXITED | WNOHANG), ECHILD));

    // Group 0 is this process's group.
    pid_t own = fork_exiting(12);
    info = filled_info();
    CHECK(waitid(P_PGID, 0, &info, WEXITED) == 0);
    CHECK(reports(&info, own, CLD_EXITED, 12));

    close(release);
    info = filled_info();
    CHECK(waitid(P_PGID, other, &info, WEXITED) == 0);
    CHECK(reports(&info, other, CLD_EXITED, 11));
    CHECK(no_children_left());
}

static void check_clone_options(void) {
    // A forked child has the default exit signal, so only __WALL selects it with __WCLONE.
    pid_t child = fork_exiting(13);
    siginfo_t info;
    CHECK(fails_with(raw_waitid(P_ALL, 0, &info, WEXITED | __WCLONE, NULL), ECHILD));
    info = filled_info();
    CHECK(raw_waitid(P_ALL, 0, &info, WEXITED | __WCLONE | __WALL, NULL) == 0);
    CHECK(reports(&info, child, CLD_EXITED, 13));

    child = fork_exiting(14);
    info = filled_info();
    CHECK(raw_waitid(P_PID, child, &info, WEXITED | __WALL | __WNOTHREAD, NULL) == 0);
    CHECK(reports(&info, child, CLD_EXITED, 14));
    CHECK(no_children_left());
}

static void check_fault(void) {
    // Like Linux, the child is reaped even though its information cannot be stored.
    pid_t child = fork_exiting(0);
    CHECK(fails_with(raw_waitid(P_PID, child, (siginfo_t *)8, WEXITED, NULL), EFAULT));
    CHECK(no_children_left());

    child = fork_exiting(0);
    siginfo_t info = filled_info();
    CHECK(fails_with(raw_waitid(P_PID, child, &info, WEXITED, (struct rusage *)8), EFAULT));
    CHECK(no_children_left());

    CHECK(fails_with(raw_waitid(P_ALL, 0, (siginfo_t *)8, WEXITED, NULL), EFAULT));
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
    printf("waitid failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
