// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test execve behavior:
//
// Phase 1:
//   - Open two file descriptors: one with O_CLOEXEC, one without.
//   - Have a nonleader thread exec self, passing their numeric values as
//     argv[1] (cloexec) and argv[2] (keep).
// Phase 2 (after exec):
//   - Verify that the exec caller became the process leader.
//   - Verify the CLOEXEC fd is closed (fcntl -> EBADF).
//   - Verify the non‑CLOEXEC fd is still open.
// Exit status 0 on success; nonzero on failure.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#define CLO_PATH "/tmp/execve_clo"
#define KEEP_PATH "/tmp/execve_keep"

static void die(const char *msg) {
    perror(msg);
    exit(2);
}

// Keep this copy in sync with helpers.h; including it would redefine die().
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
};

void* exec_thread(void* arg) {
    struct exec_args *args = arg;
    pid_t pid = getpid();
    pid_t tid = syscall(SYS_gettid);
    if (tid == pid) {
        fprintf(stderr, "exec thread unexpectedly has leader TID %d\n", tid);
        abort();
    }

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

    if (!phase) {
        // Phase 1: set up descriptors and exec self.
        int fd_clo = open(CLO_PATH, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd_clo < 0) die("open cloexec");
        int fd_keep = open(KEEP_PATH, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd_keep < 0) die("open keep");

        char clo_buf[32], keep_buf[32];
        snprintf(clo_buf, sizeof clo_buf, "%d", fd_clo);
        snprintf(keep_buf, sizeof keep_buf, "%d", fd_keep);

        // Build new argv: prog fd_clo fd_keep
        char *new_argv[4];
        new_argv[0] = argv[0];
        new_argv[1] = clo_buf;
        new_argv[2] = keep_buf;
        new_argv[3] = NULL;

        char *new_envp[2];
        new_envp[0] = "PHASE=after_exec";
        new_envp[1] = NULL;

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

        struct exec_args exec_args = {
            .path = argv[0],
            .argv = new_argv,
            .envp = new_envp,
        };
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
    if (argc < 3) {
        fprintf(stderr, "After exec: need argv[1]=fd_clo argv[2]=fd_keep\n");
        return 2;
    }
    int fd_clo = atoi(argv[1]);
    int fd_keep = atoi(argv[2]);

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
    unlink(CLO_PATH);
    unlink(KEEP_PATH);

    if (ok) {
        printf("[OK] exec caller became leader; cloexec fd %d closed; keep fd %d open\n",
               fd_clo, fd_keep);
        return 0;
    }
    return 1;
}
