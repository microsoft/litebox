// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks parents, orphan adoption, and child subreapers across forked children.

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int failures;
static volatile sig_atomic_t sigchld_count;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            printf("failed line=%d errno=%d\n", __LINE__, errno);                                  \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

static void on_sigchld(int signal) {
    (void)signal;
    sigchld_count++;
}

// Reaps a child selected by `pid`, returning its process ID and storing its exit code.
static pid_t reap(pid_t pid, int *code) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited == -1 && errno == EINTR);
    *code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return waited;
}

// Reads a process ID from `report`, waiting up to five seconds for it, so a child that fails to
// report one fails the test instead of hanging it.
static int read_report(int report, pid_t *pid) {
    struct pollfd readable = {.fd = report, .events = POLLIN};
    int ready;
    do {
        ready = poll(&readable, 1, 5000);
    } while (ready == -1 && errno == EINTR);
    return ready == 1 && read(report, pid, sizeof *pid) == sizeof *pid;
}

// Waits up to five seconds for this process's parent to stop being `parent`, returning the new
// parent.
static pid_t wait_for_new_parent(pid_t parent) {
    const struct timespec delay = {.tv_nsec = 1000000};
    for (int i = 0; i < 5000 && getppid() == parent; i++) {
        nanosleep(&delay, NULL);
    }
    return getppid();
}

// Returns the subreaper attribute of this process, or -1 if it cannot be read.
static int subreaper(void) {
    int value = -1;
    return prctl(PR_GET_CHILD_SUBREAPER, &value) == 0 ? value : -1;
}

// Forks a child that forks an orphan and exits, writing the orphan's ID to `report`. The orphan
// exits with `adopted_code` if `adopter` adopts it, and the child exits with `parent_code`.
static pid_t orphan_child(pid_t adopter, int report, int parent_code, int adopted_code) {
    pid_t parent = fork();
    if (parent == 0) {
        pid_t self = getpid();
        // Like Linux, a child does not inherit its parent's subreaper attribute.
        int code = subreaper() == 0 ? parent_code : 1;
        pid_t orphan = fork();
        if (orphan == 0) {
            _exit(wait_for_new_parent(self) == adopter ? adopted_code : 2);
        }
        if (orphan < 0 || write(report, &orphan, sizeof orphan) != sizeof orphan) {
            code = 3;
        }
        _exit(code);
    }
    return parent;
}

// Forks a child that forks a grandchild and exits only once the grandchild has exited, so the
// grandchild is orphaned as a zombie. Writes the grandchild's ID to `report`.
static pid_t zombie_child(int report, int parent_code, int zombie_code) {
    pid_t parent = fork();
    if (parent == 0) {
        struct sigaction action = {0};
        action.sa_handler = on_sigchld;
        sigaction(SIGCHLD, &action, NULL);
        int code = parent_code;
        pid_t zombie = fork();
        if (zombie == 0) {
            _exit(zombie_code);
        }
        if (zombie < 0 || write(report, &zombie, sizeof zombie) != sizeof zombie) {
            code = 3;
        }
        // The grandchild has terminated once its `SIGCHLD` is handled.
        const struct timespec delay = {.tv_nsec = 1000000};
        for (int i = 0; i < 5000 && sigchld_count == 0; i++) {
            nanosleep(&delay, NULL);
        }
        _exit(sigchld_count == 0 ? 4 : code);
    }
    return parent;
}

int main(void) {
    pid_t self = getpid();
    int code = 0;
    int report[2];
    CHECK(pipe(report) == 0);

    // LiteBox's initial process has no parent, like a container's init.
    CHECK(getppid() == 0);
    CHECK(subreaper() == 0);
    pid_t child = fork();
    if (child == 0) {
        _exit(getppid() == self ? 10 : 11);
    }
    CHECK(reap(child, &code) == child && code == 10);

    // The initial process adopts orphans even after setting and clearing the subreaper attribute.
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0 && subreaper() == 1);
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 0) == 0 && subreaper() == 0);
    pid_t parent = orphan_child(self, report[1], 20, 21);
    pid_t orphan = -1;
    CHECK(read_report(report[0], &orphan));
    CHECK(reap(parent, &code) == parent && code == 20);
    CHECK(reap(orphan, &code) == orphan && code == 21);

    // An orphaned zombie is reported to its adopter.
    parent = zombie_child(report[1], 30, 31);
    pid_t zombie = -1;
    CHECK(read_report(report[0], &zombie));
    CHECK(reap(parent, &code) == parent && code == 30);
    CHECK(reap(zombie, &code) == zombie && code == 31);

    // A subreaper adopts the orphans of its descendants instead of the initial process.
    pid_t reaper = fork();
    if (reaper == 0) {
        pid_t reaper_self = getpid();
        int ok = getppid() == self && subreaper() == 0;
        ok = ok && prctl(PR_SET_CHILD_SUBREAPER, 1) == 0 && subreaper() == 1;
        pid_t reaper_parent = orphan_child(reaper_self, report[1], 40, 41);
        pid_t reaper_orphan = -1;
        int reaper_code = 0;
        ok = ok && read_report(report[0], &reaper_orphan);
        ok = ok && reap(reaper_parent, &reaper_code) == reaper_parent && reaper_code == 40;
        ok = ok && reap(reaper_orphan, &reaper_code) == reaper_orphan && reaper_code == 41;
        ok = ok && prctl(PR_SET_CHILD_SUBREAPER, 0) == 0 && subreaper() == 0;
        _exit(ok ? 50 : 51);
    }
    CHECK(reap(reaper, &code) == reaper && code == 50);

    // No child remains to wait for.
    CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);

    printf("process-tree failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
