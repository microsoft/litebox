// Test execve behavior:
//
// Phase 1:
//   - Create two eventfds: one with EFD_CLOEXEC, one without.
//   - Exec self, passing their numeric values as argv[1] (cloexec) and argv[2] (keep).
// Phase 2 (after exec):
//   - Verify the CLOEXEC fd is closed (fcntl -> EBADF).
//   - Verify the non‑CLOEXEC fd is still open.
// Exit status 0 on success; nonzero on failure.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/stat.h>

static void die(const char *msg) {
    perror(msg);
    exit(2);
}

int main(int argc, char *argv[], char *envp[]) {
    const char *phase = getenv("PHASE");

    if (!phase) {
        // Phase 1: set up descriptors and exec self.
        int fd_clo = eventfd(0, EFD_CLOEXEC);
        if (fd_clo < 0) die("eventfd cloexec");
        int fd_keep = eventfd(0, 0);
        if (fd_keep < 0) die("eventfd keep");

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

        execve(argv[0], new_argv, new_envp);
        die("execve");
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

    if (ok) {
        printf("[OK] cloexec fd %d closed; keep fd %d open\n", fd_clo, fd_keep);
        return 0;
    }
    return 1;
}