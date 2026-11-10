// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks working directories, which the broker keeps per thread: the working directory itself
// through an empty path, threads with and without `CLONE_FS`, a non-leader `execve`,
// `posix_spawn` changing the child's working directory before a relative program path, relative
// Unix socket paths, and a relative `/proc/self/fd` path.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <sched.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define DIR "/tmp/lb_cwd"

extern char **environ;

static int failures;
static const char *self_path;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            printf("failed line=%d errno=%d\n", __LINE__, errno);                                  \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

// Returns whether the working directory is `expected`.
static int cwd_is(const char *expected) {
    char cwd[4096];
    return getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, expected) == 0;
}

// Waits for `child` to exit with code 0.
static int exits_cleanly(pid_t child) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// A thread made with raw `clone`, with its own stack and thread pointer target, which, like
// x86-64's thread control block, points to itself. Threads use only system calls that succeed, as
// they have no C library thread state.
struct thread {
    char stack[64 * 1024] __attribute__((aligned(16)));
    void *tls[512] __attribute__((aligned(64)));
    _Atomic pid_t tid;
};

static struct thread threads[3];

// Starts `fn` in `thread`, sharing this thread's working directory if `share_fs`.
static int start_thread(struct thread *thread, int (*fn)(void *), int share_fs) {
    int flags = CLONE_VM | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM |
                CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
    if (share_fs) {
        flags |= CLONE_FS;
    }
    thread->tls[0] = thread->tls;
    return clone(fn, thread->stack + sizeof thread->stack, flags, NULL, (pid_t *)&thread->tid,
                 thread->tls, (pid_t *)&thread->tid) > 0;
}

// Waits for `thread` to exit, which clears its thread ID.
static void join_thread(struct thread *thread) {
    for (;;) {
        pid_t tid = atomic_load(&thread->tid);
        if (tid == 0) {
            return;
        }
        syscall(SYS_futex, &thread->tid, FUTEX_WAIT, tid, NULL, NULL, 0);
    }
}

// An empty path with `AT_EMPTY_PATH` names the working directory itself, which needs no search
// permission, unlike `.`.
static void check_empty_path(void) {
    struct stat by_path;
    struct stat st;
    CHECK(mkdir(DIR "/closed", 0700) == 0);
    CHECK(stat(DIR "/closed", &by_path) == 0);
    CHECK(chdir(DIR "/closed") == 0);
    CHECK(chmod(DIR "/closed", 0600) == 0);
    CHECK(fstatat(AT_FDCWD, "", &st, AT_EMPTY_PATH) == 0 && S_ISDIR(st.st_mode) &&
          st.st_ino == by_path.st_ino);
    CHECK(syscall(SYS_faccessat2, AT_FDCWD, "", F_OK, AT_EMPTY_PATH) == 0);
    // Root may search any directory.
    if (geteuid() != 0) {
        errno = 0;
        CHECK(stat(".", &st) == -1 && errno == EACCES);
    }
    CHECK(chdir(DIR) == 0);
    CHECK(chmod(DIR "/closed", 0700) == 0);
}

static char own_cwd[4096];
static char shared_cwd[4096];

static int change_to_b(void *arg) {
    (void)arg;
    if (syscall(SYS_chdir, DIR "/b") == 0) {
        syscall(SYS_getcwd, shared_cwd, sizeof shared_cwd);
    }
    return 0;
}

// Changes its own working directory, then makes a thread that shares it and changes it again.
static int change_to_a(void *arg) {
    (void)arg;
    if (syscall(SYS_chdir, DIR "/a") == 0 && start_thread(&threads[1], change_to_b, 1)) {
        join_thread(&threads[1]);
        syscall(SYS_getcwd, own_cwd, sizeof own_cwd);
    }
    return 0;
}

// A thread made without `CLONE_FS` has its own working directory, and one it makes with
// `CLONE_FS` shares it.
static void check_threads(void) {
    CHECK(mkdir(DIR "/a", 0700) == 0);
    CHECK(mkdir(DIR "/b", 0700) == 0);
    CHECK(start_thread(&threads[0], change_to_a, 0));
    join_thread(&threads[0]);
    CHECK(strcmp(shared_cwd, DIR "/b") == 0);
    CHECK(strcmp(own_cwd, DIR "/b") == 0);
    CHECK(cwd_is(DIR));
}

static int exec_from_thread(void *arg) {
    (void)arg;
    char *args[] = {(char *)self_path, "cwd-is", DIR "/exec", NULL};
    if (syscall(SYS_chdir, DIR "/exec") == 0) {
        syscall(SYS_execve, self_path, args, environ);
    }
    syscall(SYS_exit_group, 2);
    return 0;
}

// A thread other than the leader keeps its own working directory across `execve`.
static void check_non_leader_exec(void) {
    CHECK(mkdir(DIR "/exec", 0700) == 0);
    pid_t child = fork();
    if (child == 0) {
        if (!start_thread(&threads[2], exec_from_thread, 0)) {
            _exit(3);
        }
        for (;;) {
            pause();
        }
    }
    CHECK(child > 0 && exits_cleanly(child));
}

// A spawned child's working directory changes before it opens a relative path and runs a relative
// program path; the parent's stays.
static void check_spawn(void) {
    CHECK(mkdir(DIR "/spawn", 0700) == 0);
    CHECK(symlink(self_path, DIR "/spawn/program") == 0);
    posix_spawn_file_actions_t actions;
    CHECK(posix_spawn_file_actions_init(&actions) == 0);
    CHECK(posix_spawn_file_actions_addchdir_np(&actions, DIR "/spawn") == 0);
    CHECK(posix_spawn_file_actions_addopen(&actions, 3, "opened", O_WRONLY | O_CREAT, 0600) ==
          0);
    char *args[] = {"program", "cwd-is", DIR "/spawn", NULL};
    pid_t child;
    CHECK(posix_spawn(&child, "./program", &actions, NULL, args, environ) == 0);
    CHECK(exits_cleanly(child));
    CHECK(posix_spawn_file_actions_destroy(&actions) == 0);
    struct stat st;
    CHECK(stat(DIR "/spawn/opened", &st) == 0);
    CHECK(cwd_is(DIR));
}

// Binds, connects and sends to Unix socket paths relative to the working directory.
static void check_unix_sockets(void) {
    CHECK(mkdir(DIR "/sockets", 0700) == 0);
    CHECK(chdir(DIR "/sockets") == 0);
    struct sockaddr_un stream = {.sun_family = AF_UNIX, .sun_path = "stream"};
    struct sockaddr_un datagram = {.sun_family = AF_UNIX, .sun_path = "datagram"};
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(bind(listener, (struct sockaddr *)&stream, sizeof stream) == 0);
    CHECK(listen(listener, 1) == 0);
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(client, (struct sockaddr *)&stream, sizeof stream) == 0);
    int receiver = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(bind(receiver, (struct sockaddr *)&datagram, sizeof datagram) == 0);
    int sender = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(sendto(sender, "x", 1, 0, (struct sockaddr *)&datagram, sizeof datagram) == 1);
    char byte = 0;
    CHECK(recv(receiver, &byte, 1, 0) == 1 && byte == 'x');
    struct stat st;
    CHECK(stat(DIR "/sockets/stream", &st) == 0);
    close(sender);
    close(receiver);
    close(client);
    close(listener);
    CHECK(chdir(DIR) == 0);
}

// A relative path to `/proc/self/fd/<fd>` names the descriptor too.
static void check_relative_proc_self_fd(void) {
    char absolute[4096];
    char relative[4096];
    CHECK(chdir("/") == 0);
    ssize_t absolute_length = readlink("/proc/self/fd/1", absolute, sizeof absolute);
    ssize_t relative_length = readlink("proc/self/fd/1", relative, sizeof relative);
    CHECK(absolute_length > 0 && relative_length == absolute_length &&
          memcmp(absolute, relative, (size_t)absolute_length) == 0);
    CHECK(chdir(DIR) == 0);
    // Like any relative path, it can't start from a descriptor that isn't a directory.
    int file = open(DIR "/plain", O_WRONLY | O_CREAT, 0600);
    struct stat st;
    CHECK(file >= 0);
    CHECK(fstatat(file, "../../../../../../../../proc/self/fd/1", &st, 0) == -1 && errno == ENOTDIR);
    CHECK(close(file) == 0 && unlink(DIR "/plain") == 0);
}

int main(int argc, char **argv) {
    // Run as a new program, exit with whether the working directory is `argv[2]`.
    if (argc == 3 && strcmp(argv[1], "cwd-is") == 0) {
        return cwd_is(argv[2]) ? 0 : 1;
    }
    self_path = argv[0];
    CHECK(mkdir(DIR, 0700) == 0);
    CHECK(chdir(DIR) == 0);

    check_empty_path();
    check_threads();
    check_non_leader_exec();
    check_spawn();
    check_unix_sockets();
    check_relative_proc_self_fd();

    printf("cwd failures=%d\n", failures);
    return failures != 0;
}
