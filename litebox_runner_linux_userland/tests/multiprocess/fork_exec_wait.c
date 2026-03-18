// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// End-to-end test for fork -> exec -> waitpid lifecycle.
//
// Phase 1 (parent, no PHASE env):
//   - Record own PID.
//   - Call vfork(). Child execs self with PHASE=child.
//   - Parent calls waitpid(), verifies child PID and exit status.
//
// Phase 2 (child, PHASE=child):
//   - Verify getpid() != parent PID (passed via argv[1]).
//   - Verify getppid() == parent PID.
//   - Exit with status 42.
//
// Note: uses vfork() libc wrapper (not raw SYS_fork/SYS_vfork) because
// the syscall rewriter's trampoline does not support fork-return-twice
// semantics for raw syscall() calls. The Sysno::fork and Sysno::vfork
// dispatch paths are identical aside from clone flags.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static void die(const char *msg) {
    perror(msg);
    _exit(2);
}

int main(int argc, char *argv[]) {
    const char *phase = getenv("PHASE");

    if (phase && strcmp(phase, "child") == 0) {
        // --- Phase 2: child after exec ---
        if (argc < 2) {
            fprintf(stderr, "[FAIL] child: expected parent PID in argv[1]\n");
            return 3;
        }
        pid_t parent_pid = (pid_t)atoi(argv[1]);
        pid_t my_pid = getpid();
        pid_t my_ppid = getppid();

        int ok = 1;

        if (my_pid == parent_pid) {
            fprintf(stderr, "[FAIL] child getpid() == parent PID %d\n", parent_pid);
            ok = 0;
        }
        if (my_ppid != parent_pid) {
            fprintf(stderr, "[FAIL] child getppid() = %d, expected %d\n",
                    my_ppid, parent_pid);
            ok = 0;
        }

        if (ok) {
            printf("[OK] child: pid=%d ppid=%d (parent=%d)\n",
                   my_pid, my_ppid, parent_pid);
        }
        return ok ? 42 : 3;
    }

    // --- Phase 1: parent ---
    pid_t my_pid = getpid();
    char pid_buf[32];
    snprintf(pid_buf, sizeof pid_buf, "%d", my_pid);

    pid_t child = vfork();
    if (child < 0) {
        die("vfork");
    }

    if (child == 0) {
        // In child (vfork): exec self with PHASE=child.
        char *new_argv[] = { argv[0], pid_buf, NULL };
        char *new_envp[] = { "PHASE=child", NULL };
        execve(argv[0], new_argv, new_envp);
        die("execve");
    }

    // Parent: wait for child.
    int wstatus = 0;
    pid_t waited = waitpid(child, &wstatus, 0);
    if (waited < 0) {
        die("waitpid");
    }

    int ok = 1;

    if (waited != child) {
        fprintf(stderr, "[FAIL] waitpid returned %d, expected %d\n",
                waited, child);
        ok = 0;
    }

    if (!WIFEXITED(wstatus)) {
        fprintf(stderr, "[FAIL] child did not exit normally (wstatus=0x%x)\n",
                wstatus);
        ok = 0;
    } else if (WEXITSTATUS(wstatus) != 42) {
        fprintf(stderr, "[FAIL] child exit status = %d, expected 42\n",
                WEXITSTATUS(wstatus));
        ok = 0;
    }

    if (ok) {
        printf("[OK] parent: child pid=%d exited with status 42\n", child);
    }

    return ok ? 0 : 1;
}
