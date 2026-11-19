// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test execve behavior:
//
// Phase 1:
//   - Open two file descriptors: one with O_CLOEXEC, one without.
//   - Have a nonleader thread exec self, passing their numeric values as
//     argv[1] (cloexec) and argv[2] (keep), and its thread ID as argv[3].
// Phase 2 (after exec):
//   - Verify that the exec caller became the process leader, and that its
//     former thread ID names no thread.
//   - Verify the CLOEXEC fd is closed (fcntl -> EBADF).
//   - Verify the non‑CLOEXEC fd is still open.
// Exit status 0 on success; nonzero on failure.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static void die(const char *msg) {
    perror(msg);
    exit(2);
}

// Keep these copies in sync with helpers.h; including it would redefine die().
static const char *test_dir(void) {
    const char *directory = getenv("TMPDIR");
    return directory != NULL && directory[0] != 0 ? directory : "/tmp";
}

static char *test_path(const char *name) {
    char *path = NULL;
    if (asprintf(&path, "%s/%s", test_dir(), name) < 0) die("asprintf");
    return path;
}

#if defined(__x86_64__) || defined(__i386__)
#define SPIN_HINT() __asm__ __volatile__("pause")
#elif defined(__aarch64__)
#define SPIN_HINT() __asm__ __volatile__("yield")
#else
#define SPIN_HINT() __asm__ __volatile__("")
#endif

void* spin_thread(void* arg) {
    for (;;) {
        SPIN_HINT();
    }
}

struct exec_args {
    char *path;
    char **argv;
    char **envp;
    // Receives the exec caller's thread ID, which `argv` passes.
    char tid_buf[32];
};

void* exec_thread(void* arg) {
    struct exec_args *args = arg;
    pid_t pid = getpid();
    pid_t tid = syscall(SYS_gettid);
    if (tid == pid) {
        fprintf(stderr, "exec thread unexpectedly has leader TID %d\n", tid);
        abort();
    }
    snprintf(args->tid_buf, sizeof args->tid_buf, "%d", tid);

    execve("nonsense", args->argv, args->envp);
    if (errno != ENOENT) {
        die("execve nonsense");
    }
    if (getpid() != pid || syscall(SYS_gettid) != tid) {
        fprintf(stderr, "failed exec changed nonleader identity\n");
        abort();
    }

    execve(args->path, args->argv, args->envp);
    die("execve");
}

int main(int argc, char *argv[], char *envp[]) {
    const char *phase = getenv("PHASE");
    char *clo_path = test_path("execve_clo");
    char *keep_path = test_path("execve_keep");

    if (!phase) {
        // Phase 1: set up descriptors and exec self.
        int fd_clo = open(clo_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd_clo < 0) die("open cloexec");
        int fd_keep = open(keep_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd_keep < 0) die("open keep");

        char clo_buf[32], keep_buf[32];
        snprintf(clo_buf, sizeof clo_buf, "%d", fd_clo);
        snprintf(keep_buf, sizeof keep_buf, "%d", fd_keep);

        struct exec_args exec_args = {
            .path = argv[0],
        };

        // Build new argv: prog fd_clo fd_keep exec_tid
        char *new_argv[5];
        new_argv[0] = argv[0];
        new_argv[1] = clo_buf;
        new_argv[2] = keep_buf;
        new_argv[3] = exec_args.tid_buf;
        new_argv[4] = NULL;

        // Pass on TMPDIR, if set, so that phase 2 resolves the same paths.
        char *new_envp[3];
        int envc = 0;
        new_envp[envc++] = "PHASE=after_exec";
        const char *tmpdir = getenv("TMPDIR");
        char *tmpdir_env = NULL;
        if (tmpdir != NULL && tmpdir[0] != 0) {
            if (asprintf(&tmpdir_env, "TMPDIR=%s", tmpdir) < 0) die("asprintf");
            new_envp[envc++] = tmpdir_env;
        }
        new_envp[envc] = NULL;
        exec_args.argv = new_argv;
        exec_args.envp = new_envp;

        // Spawn some threads that should be terminated on exec.
        for (int i = 0; i < 20; i++) {
            pthread_t thread;
            int rc = pthread_create(&thread, NULL, spin_thread, NULL);
            if (rc) {
                fprintf(stderr, "pthread_create: %s\n", strerror(rc));
                abort();
            }
            pthread_detach(thread);
        }

        pthread_t execer;
        int rc = pthread_create(&execer, NULL, exec_thread, &exec_args);
        if (rc) {
            fprintf(stderr, "pthread_create execer: %s\n", strerror(rc));
            abort();
        }
        pthread_detach(execer);

        // The nonleader exec caller terminates this leader and the spin threads.
        for (;;) {
            pause();
        }
    }

    // Phase 2: verify.
    if (argc < 4) {
        fprintf(stderr, "After exec: need argv[1]=fd_clo argv[2]=fd_keep argv[3]=exec_tid\n");
        return 2;
    }
    int fd_clo = atoi(argv[1]);
    int fd_keep = atoi(argv[2]);
    pid_t exec_tid = atoi(argv[3]);

    errno = 0;
    int clo_flags = fcntl(fd_clo, F_GETFD);
    int clo_errno = errno;

    errno = 0;
    int keep_flags = fcntl(fd_keep, F_GETFD);
    int keep_errno = errno;

    int ok = 1;

    // A nonleader exec caller becomes the process leader.
    pid_t pid = getpid();
    pid_t tid = syscall(SYS_gettid);
    if (tid != pid) {
        fprintf(stderr, "[FAIL] gettid %d does not match getpid %d after exec\n",
                tid, pid);
        ok = 0;
    }
    // Its former thread ID no longer names a thread.
    errno = 0;
    if (kill(exec_tid, 0) != -1 || errno != ESRCH) {
        fprintf(stderr, "[FAIL] former exec caller TID %d still names a thread (errno=%d)\n",
                exec_tid, errno);
        ok = 0;
    }

    // CLOEXEC one should be closed.
    if (!(clo_flags == -1 && clo_errno == EBADF)) {
        fprintf(stderr,
                "[FAIL] CLOEXEC fd %d still open (res=%d errno=%d)\n",
                fd_clo, clo_flags, clo_errno);
        ok = 0;
    }

    // Non-CLOEXEC one should remain open.
    if (keep_flags == -1) {
        fprintf(stderr,
                "[FAIL] keep fd %d unexpectedly closed (errno=%d)\n",
                fd_keep, keep_errno);
        ok = 0;
    }
    if (keep_flags != -1) {
        close(fd_keep);
    }
    unlink(clo_path);
    unlink(keep_path);

    if (ok) {
        printf("[OK] exec caller became leader; cloexec fd %d closed; keep fd %d open\n",
               fd_clo, fd_keep);
        return 0;
    }
    return 1;
}
