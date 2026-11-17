// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks pidfds: opening them, signalling and polling the process they name, reaping it with
// waitid(P_PIDFD), getting them from clone and clone3, and inheriting them across fork.

#include "helpers.h"

#include <limits.h>
#include <linux/sched.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/mman.h>

#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif

static char child_stack[64 * 1024] __attribute__((aligned(16)));
static int vfork_pidfd = -1;

static long sys_pidfd_open(pid_t pid, unsigned int flags) {
    return syscall(SYS_pidfd_open, pid, flags);
}

static long sys_pidfd_send_signal(int pidfd, int signal, siginfo_t *info, unsigned int flags) {
    return syscall(SYS_pidfd_send_signal, pidfd, signal, info, flags);
}

static long waitid_pidfd(int pidfd, siginfo_t *info, int options) {
    memset(info, 0xa5, sizeof(*info));
    return syscall(SYS_waitid, P_PIDFD, pidfd, info, options, NULL);
}

// Forks a child that exits with `code` once `*release` is closed.
static pid_t fork_held(int code, int *release) {
    int fds[2];
    TEST_ASSERT(pipe(fds) == 0, "pipe");
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        close(fds[1]);
        char byte;
        while (read(fds[0], &byte, 1) < 0 && errno == EINTR) {
        }
        _exit(code);
    }
    TEST_ASSERT(child > 0, "fork");
    close(fds[0]);
    *release = fds[1];
    return child;
}

// Returns the lowest free descriptor, which the next new descriptor gets.
static int next_fd(void) {
    int fd = dup(STDOUT_FILENO);
    TEST_ASSERT(fd >= 0, "dup");
    close(fd);
    return fd;
}

static void wait_readable(int pidfd, const char *msg) {
    struct pollfd pfd = {.fd = pidfd, .events = POLLIN};
    int ready;
    do {
        ready = poll(&pfd, 1, 10000);
    } while (ready < 0 && errno == EINTR);
    TEST_ASSERT(ready == 1 && (pfd.revents & POLLIN), msg);
}

static void expect_reaped(int pidfd, pid_t child, int code, int status) {
    siginfo_t info;
    TEST_ASSERT(waitid_pidfd(pidfd, &info, WEXITED) == 0, "waitid on a pidfd");
    TEST_ASSERT(info.si_signo == SIGCHLD && info.si_pid == child && info.si_code == code &&
                    info.si_status == status,
                "waitid on a pidfd reports the child");
}

static void *open_own_thread(void *arg) {
    (void)arg;
    long pidfd = sys_pidfd_open(gettid(), 0);
    return (void *)(intptr_t)(pidfd == -1 && errno == ENOENT);
}

static void check_arguments(void) {
    int pidfd = sys_pidfd_open(getpid(), 0);
    TEST_ASSERT(pidfd >= 0, "pidfd_open on this process");
    TEST_ASSERT(fcntl(pidfd, F_GETFD) == FD_CLOEXEC, "pidfds are close-on-exec");
    TEST_ASSERT((fcntl(pidfd, F_GETFL) & O_ACCMODE) == O_RDWR, "pidfds are read-write");
    TEST_ASSERT((fcntl(pidfd, F_GETFL) & O_NONBLOCK) == 0, "pidfds block by default");

    char path[64];
    char target[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", pidfd);
    ssize_t len = readlink(path, target, sizeof(target) - 1);
    TEST_ASSERT(len >= 0, "readlink on a pidfd");
    target[len] = '\0';
    TEST_ASSERT(strcmp(target, "anon_inode:[pidfd]") == 0, "pidfds are anonymous inodes");

    char byte = 0;
    expect_errno(read(pidfd, &byte, 1), EINVAL, "read on a pidfd");
    expect_errno(write(pidfd, &byte, 1), EINVAL, "write on a pidfd");
    TEST_ASSERT(sys_pidfd_send_signal(pidfd, 0, NULL, 0) == 0, "probe this process");
    siginfo_t info;
    expect_errno(waitid_pidfd(pidfd, &info, WEXITED | WNOHANG), ECHILD, "wait for this process");

    expect_errno(sys_pidfd_open(0, 0), EINVAL, "pidfd_open on PID 0");
    expect_errno(sys_pidfd_open(-1, 0), EINVAL, "pidfd_open on a negative PID");
    expect_errno(sys_pidfd_open(getpid(), 0x1), EINVAL, "pidfd_open with an unknown flag");
    expect_errno(sys_pidfd_open(INT_MAX, 0), ESRCH, "pidfd_open on a missing process");
    // Like Linux 6.15+, only a main thread's ID names a process.
    pthread_t thread;
    void *refused = NULL;
    TEST_ASSERT(pthread_create(&thread, NULL, open_own_thread, NULL) == 0, "pthread_create");
    TEST_ASSERT(pthread_join(thread, &refused) == 0 && refused, "pidfd_open on a non-main thread");

    int fds[2];
    TEST_ASSERT(pipe(fds) == 0, "pipe");
    expect_errno(sys_pidfd_send_signal(fds[0], 0, NULL, 0), EBADF, "signal through a pipe");
    expect_errno(sys_pidfd_send_signal(-1, 0, NULL, 0), EBADF, "signal through no descriptor");
    expect_errno(waitid_pidfd(fds[0], &info, WEXITED), EBADF, "wait through a pipe");
    expect_errno(sys_pidfd_send_signal(pidfd, 65, NULL, 0), EINVAL, "an invalid signal");
    expect_errno(sys_pidfd_send_signal(pidfd, 0, NULL, 0x80), EINVAL, "an unknown flag");
    close(fds[0]);
    close(fds[1]);
    close(pidfd);
}

static void check_lifecycle(void) {
    int release;
    pid_t child = fork_held(0, &release);
    int pidfd = sys_pidfd_open(child, 0);
    TEST_ASSERT(pidfd >= 0, "pidfd_open on a child");
    expect_poll_lacks(pidfd, POLLIN, POLLIN | POLLHUP, "a live child");
    TEST_ASSERT(sys_pidfd_send_signal(pidfd, 0, NULL, 0) == 0, "probe a live child");

    // Like Linux 5.10+, a nonblocking pidfd reports a live child with EAGAIN.
    int nonblocking = sys_pidfd_open(child, PIDFD_NONBLOCK);
    TEST_ASSERT(nonblocking >= 0, "pidfd_open with PIDFD_NONBLOCK");
    TEST_ASSERT(fcntl(nonblocking, F_GETFL) & O_NONBLOCK, "PIDFD_NONBLOCK sets O_NONBLOCK");
    siginfo_t info;
    expect_errno(waitid_pidfd(nonblocking, &info, WEXITED), EAGAIN, "wait for a live child");
    TEST_ASSERT(waitid_pidfd(nonblocking, &info, WEXITED | WNOHANG) == 0,
                "WNOHANG wait for a live child");
    close(nonblocking);

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    TEST_ASSERT(epfd >= 0, "epoll_create1");
    struct epoll_event event = {.events = EPOLLIN, .data.u32 = 7};
    TEST_ASSERT(epoll_ctl(epfd, EPOLL_CTL_ADD, pidfd, &event) == 0, "epoll_ctl on a pidfd");
    TEST_ASSERT(epoll_wait(epfd, &event, 1, 0) == 0, "epoll on a live child");

    TEST_ASSERT(sys_pidfd_send_signal(pidfd, SIGTERM, NULL, 0) == 0, "signal a child");
    wait_readable(pidfd, "poll on an exited child");
    TEST_ASSERT(epoll_wait(epfd, &event, 1, 10000) == 1 && (event.events & EPOLLIN) &&
                    event.data.u32 == 7,
                "epoll on an exited child");
    close(epfd);

    // A zombie can still be opened and signalled.
    int zombie = sys_pidfd_open(child, 0);
    TEST_ASSERT(zombie >= 0, "pidfd_open on a zombie");
    TEST_ASSERT(sys_pidfd_send_signal(zombie, SIGTERM, NULL, 0) == 0, "signal a zombie");

    expect_reaped(pidfd, child, CLD_KILLED, SIGTERM);
    // Like Linux 6.9+, a reaped process's pidfd reports a hangup.
    expect_poll_has(zombie, POLLIN, POLLIN | POLLHUP, "a reaped child");
    expect_errno(sys_pidfd_send_signal(zombie, 0, NULL, 0), ESRCH, "probe a reaped child");
    expect_errno(sys_pidfd_open(child, 0), ESRCH, "pidfd_open on a reaped child");
    expect_errno(waitid_pidfd(pidfd, &info, WEXITED), ECHILD, "wait for a reaped child");
    close(zombie);
    close(pidfd);
    close(release);
}

static int vfork_child(void *arg) {
    (void)arg;
    // The child's descriptors are copied before the pidfd is made.
    return fcntl(vfork_pidfd, F_GETFD) == -1 && errno == EBADF ? 0 : 1;
}

static void check_clone_pidfd(void) {
    int pidfd = -1;
    expect_errno(syscall(SYS_clone, CLONE_PIDFD | CLONE_PARENT_SETTID | SIGCHLD, NULL, &pidfd,
                         NULL, 0),
                 EINVAL, "clone with CLONE_PIDFD and CLONE_PARENT_SETTID");
    expect_errno(syscall(SYS_clone, CLONE_PIDFD | CLONE_DETACHED | SIGCHLD, NULL, &pidfd, NULL, 0),
                 EINVAL, "clone with CLONE_PIDFD and CLONE_DETACHED");
    struct clone_args args = {
        .flags = CLONE_PIDFD | CLONE_PARENT_SETTID,
        .pidfd = (uintptr_t)&pidfd,
        .parent_tid = (uintptr_t)&pidfd,
        .exit_signal = SIGCHLD,
    };
    expect_errno(syscall(SYS_clone3, &args, sizeof(args)), EINVAL,
                 "clone3 with one destination for both");
    TEST_ASSERT(pidfd == -1, "failed clones leave the destination alone");

    // The pidfd takes the lowest free descriptor in the parent only.
    int expected = next_fd();
    args.flags = CLONE_PIDFD;
    args.parent_tid = 0;
    fflush(stdout);
    pid_t child = syscall(SYS_clone3, &args, sizeof(args));
    if (child == 0) {
        _exit(fcntl(expected, F_GETFD) == -1 && errno == EBADF ? 0 : 1);
    }
    TEST_ASSERT(child > 0, "clone3 with CLONE_PIDFD");
    TEST_ASSERT(pidfd == expected, "clone3 stores the pidfd");
    TEST_ASSERT(fcntl(pidfd, F_GETFD) == FD_CLOEXEC, "clone3's pidfd is close-on-exec");
    expect_reaped(pidfd, child, CLD_EXITED, 0);
    close(pidfd);

    // glibc's `pidfd_spawn` gets the pidfd of a vfork child.
    child = clone(vfork_child, child_stack + sizeof(child_stack),
                  CLONE_VM | CLONE_VFORK | CLONE_PIDFD | SIGCHLD, NULL, &vfork_pidfd);
    TEST_ASSERT(child > 0, "clone with CLONE_VFORK and CLONE_PIDFD");
    TEST_ASSERT(vfork_pidfd >= 0, "clone stores the pidfd");
    expect_reaped(vfork_pidfd, child, CLD_EXITED, 0);
    close(vfork_pidfd);
}

// Like Linux, a pidfd destination that faults fails the clone without creating a child or
// changing the caller's descriptors.
static void check_clone_pidfd_fault(void) {
    int *fault = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(fault != MAP_FAILED, "mmap");
    int fds[2];
    TEST_ASSERT(pipe(fds) == 0, "pipe");
    int expected = next_fd();

    struct clone_args args = {
        .flags = CLONE_PIDFD,
        .pidfd = (uintptr_t)fault,
        .exit_signal = SIGCHLD,
    };
    fflush(stdout);
    long child = syscall(SYS_clone3, &args, sizeof(args));
    if (child == 0) {
        _exit(1);
    }
    expect_errno(child, EFAULT, "fork with a faulting pidfd destination");
    expect_errno(clone(vfork_child, child_stack + sizeof(child_stack),
                       CLONE_VM | CLONE_VFORK | CLONE_PIDFD | SIGCHLD, NULL, fault),
                 EFAULT, "vfork with a faulting pidfd destination");

    siginfo_t info;
    expect_errno(waitid(P_ALL, 0, &info, WEXITED | WNOHANG), ECHILD, "no child was created");
    TEST_ASSERT(next_fd() == expected, "no pidfd was left behind");
    // The pipe reports EOF only if no copy of its write end was left behind either.
    close(fds[1]);
    TEST_ASSERT(fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0, "fcntl");
    char byte;
    TEST_ASSERT(read(fds[0], &byte, 1) == 0, "no descriptors were copied");
    close(fds[0]);
    munmap(fault, 4096);
}

static void check_inherited(void) {
    int release;
    pid_t child = fork_held(0, &release);
    int pidfd = sys_pidfd_open(child, 0);
    TEST_ASSERT(pidfd >= 0, "pidfd_open on a child");
    TEST_ASSERT(fcntl(pidfd, F_SETFD, 0) == 0, "clear FD_CLOEXEC");

    // The sibling shares the open pidfd, including its status flags, and can signal but not wait
    // for the child it names.
    fflush(stdout);
    pid_t sibling = fork();
    if (sibling == 0) {
        siginfo_t info;
        int ok = fcntl(pidfd, F_GETFD) == 0 && fcntl(pidfd, F_SETFL, O_NONBLOCK) == 0 &&
                 waitid_pidfd(pidfd, &info, WEXITED | WNOHANG) == -1 && errno == ECHILD &&
                 sys_pidfd_send_signal(pidfd, SIGKILL, NULL, 0) == 0;
        _exit(ok ? 0 : 1);
    }
    TEST_ASSERT(sibling > 0, "fork");
    TEST_ASSERT(reap(sibling, 1) == 0, "the sibling uses the inherited pidfd");
    TEST_ASSERT(fcntl(pidfd, F_GETFL) & O_NONBLOCK, "status flags are shared");
    wait_readable(pidfd, "poll on a child killed through an inherited pidfd");
    expect_reaped(pidfd, child, CLD_KILLED, SIGKILL);
    close(pidfd);
    close(release);
}

int main(void) {
    check_arguments();
    check_lifecycle();
    check_clone_pidfd();
    check_clone_pidfd_fault();
    check_inherited();
    return 0;
}
