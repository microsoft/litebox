// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// For the kernel's scheduling of processes' brokers (see brokers.json and
// brokers_progress.json). The first argument picks a mode:
// - "fair N CALLS SPIN_MS MAX_GAP_MS": starts N children of its own
//   (posix_spawn), which, once all are ready, make CALLS broker calls each
//   (one-byte writes to /dev/null), reporting their progress in eighths
//   through a pipe, and one more, which then spins for SPIN_MS milliseconds,
//   with no syscalls but clock reads (which the runner serves without the
//   kernel). Fails unless, as the first caller finishes, each has made at
//   least a quarter of its calls (no process's broker starves another's,
//   whatever the order they were created in), the longest gap between the
//   spinner's clock reads is at most MAX_GAP_MS (the brokers do not starve a
//   thread), and all exit 0.
// - "block READERS BUSY CALLS": starts READERS children that open
//   /mnt/host/greeting.txt, then, once all are ready, read it a byte at a
//   time until it stops them (9P round trips, which the share's server makes
//   slow: see dev_tools/run_linux_on_vm_userland.sh), and meanwhile BUSY
//   children that make CALLS one-byte writes to /dev/null and round trips
//   through a pipe each. Fails unless the busy children all exit 0 while the
//   readers still read (brokers waiting for 9P do not stop the others), and,
//   once it killed the first reader (which waits for 9P, or is about to) and
//   stopped the others, they exit 0. Prints "busy first" and the readers'
//   ends, and how long each part took to standard error.
// - "calls INDEX CALLS", "spin INDEX MS MAX_GAP_MS", "read" and "busy CALLS":
//   such children, the first two the INDEXth.

#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define MAX_CHILDREN 16
// Progress reports per caller.
#define STEPS 8
// A child's report that it is ready: its index, with this bit.
#define READY 0x80

// Reports the child ready, then waits until every child is: the parent then
// closes the pipe on standard input.
static int report_ready(int index) {
    char byte = (char)(index | READY);
    if (write(STDOUT_FILENO, &byte, 1) != 1) {
        return 1;
    }
    while (read(STDIN_FILENO, &byte, 1) > 0) {
    }
    return 0;
}

static long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static int calls_mode(int index, long calls) {
    if (report_ready(index) != 0) {
        return 1;
    }
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0) {
        return 1;
    }
    char byte = (char)index;
    for (long call = 1; call <= calls; call++) {
        if (write(fd, &byte, 1) != 1) {
            return 1;
        }
        if (call * STEPS / calls != (call - 1) * STEPS / calls &&
            write(STDOUT_FILENO, &byte, 1) != 1) {
            return 1;
        }
    }
    return 0;
}

static int spin_mode(int index, long long ms, long long max_gap_ms) {
    if (report_ready(index) != 0) {
        return 1;
    }
    long long start = now_us(), last = start, max_gap = 0;
    while (last - start < ms * 1000) {
        long long now = now_us();
        if (now - last > max_gap) {
            max_gap = now - last;
        }
        last = now;
    }
    if (max_gap > max_gap_ms * 1000) {
        fprintf(stderr, "spin: max gap %lld us\n", max_gap);
        return 1;
    }
    return 0;
}

static int fair_mode(char *self, int callers, char *calls, char *spin_ms, char *max_gap_ms) {
    if (callers < 1 || callers > MAX_CHILDREN || atol(calls) < STEPS) {
        return 2;
    }
    int go[2], progress[2];
    if (pipe(go) != 0 || pipe(progress) != 0) {
        perror("pipe");
        return 1;
    }
    // The callers, then the spinner.
    int children = callers + 1;
    pid_t pids[MAX_CHILDREN + 1];
    for (int i = 0; i < children; i++) {
        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(&actions, go[0], STDIN_FILENO);
        posix_spawn_file_actions_adddup2(&actions, progress[1], STDOUT_FILENO);
        posix_spawn_file_actions_addclose(&actions, go[0]);
        posix_spawn_file_actions_addclose(&actions, go[1]);
        posix_spawn_file_actions_addclose(&actions, progress[0]);
        posix_spawn_file_actions_addclose(&actions, progress[1]);
        char index[16];
        snprintf(index, sizeof index, "%d", i);
        char *caller[] = {self, "calls", index, calls, NULL};
        char *spinner[] = {self, "spin", index, spin_ms, max_gap_ms, NULL};
        int err =
            posix_spawn(&pids[i], self, &actions, NULL, i < callers ? caller : spinner, environ);
        posix_spawn_file_actions_destroy(&actions);
        if (err != 0) {
            fprintf(stderr, "fair: posix_spawn: %s\n", strerror(err));
            return 1;
        }
    }
    close(go[0]);
    close(progress[1]);
    unsigned char index;
    for (int ready = 0; ready < children; ready++) {
        if (read(progress[0], &index, 1) != 1 || !(index & READY)) {
            fprintf(stderr, "fair: a child failed to start\n");
            return 1;
        }
    }
    // All ready: they begin at once.
    close(go[1]);
    int done[MAX_CHILDREN] = {0};
    int failed = 0, first = -1;
    while (read(progress[0], &index, 1) == 1) {
        if (index >= callers) {
            fprintf(stderr, "fair: bad progress report %d\n", index);
            failed = 1;
            break;
        }
        if (++done[index] == STEPS && first < 0) {
            first = index;
            for (int i = 0; i < callers; i++) {
                if (done[i] * 4 < STEPS) {
                    fprintf(stderr, "fair: caller %d made %d/%d of its calls as caller %d finished\n",
                            i, done[i], STEPS, first);
                    failed = 1;
                }
            }
        }
    }
    for (int i = 0; i < children; i++) {
        int status;
        if (waitpid(pids[i], &status, 0) != pids[i] || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0 || (i < callers && done[i] != STEPS)) {
            fprintf(stderr, "fair: child %d failed\n", i);
            failed = 1;
        }
    }
    return failed || first < 0;
}

// The file descriptor a reader ("read") is stopped through: at its end.
#define STOP_FILENO 3

// Starts this program in mode `argv`, with `in`, `out` and `stop` as its
// standard input, standard output and STOP_FILENO, if not -1.
static int start(pid_t *pid, char *argv[], int in, int out, int stop) {
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    if (in >= 0) {
        posix_spawn_file_actions_adddup2(&actions, in, STDIN_FILENO);
    }
    if (out >= 0) {
        posix_spawn_file_actions_adddup2(&actions, out, STDOUT_FILENO);
    }
    if (stop >= 0) {
        posix_spawn_file_actions_adddup2(&actions, stop, STOP_FILENO);
    }
    int err = posix_spawn(pid, argv[0], &actions, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    if (err != 0) {
        fprintf(stderr, "block: posix_spawn: %s\n", strerror(err));
        return 1;
    }
    return 0;
}

// Opens the share's file, reports it ready (see `report_ready`), then reads
// it a byte at a time until the end of STOP_FILENO.
static int read_mode(void) {
    int fd = open("/mnt/host/greeting.txt", O_RDONLY);
    if (fd < 0 || report_ready(0) != 0) {
        return 1;
    }
    struct pollfd stop = {.fd = STOP_FILENO, .events = POLLIN};
    char byte;
    for (long n = 0;; n++) {
        int stopped = poll(&stop, 1, 0);
        if (stopped != 0) {
            return stopped < 0;
        }
        if (pread(fd, &byte, 1, n % 8) != 1) {
            return 1;
        }
    }
}

static int busy_mode(long calls) {
    int null = open("/dev/null", O_WRONLY), round_trip[2];
    if (null < 0 || pipe(round_trip) != 0) {
        return 1;
    }
    char byte = 0;
    for (long call = 0; call < calls; call++) {
        if (write(null, &byte, 1) != 1 || write(round_trip[1], &byte, 1) != 1 ||
            read(round_trip[0], &byte, 1) != 1) {
            return 1;
        }
    }
    return 0;
}

static int block_mode(char *self, int readers, int busy, char *calls) {
    if (readers < 1 || readers > MAX_CHILDREN || busy < 1 || busy > MAX_CHILDREN) {
        return 2;
    }
    int go[2], ready[2], stop[2];
    if (pipe2(go, O_CLOEXEC) != 0 || pipe2(ready, O_CLOEXEC) != 0 ||
        pipe2(stop, O_CLOEXEC) != 0) {
        perror("pipe2");
        return 1;
    }
    pid_t reader_pids[MAX_CHILDREN], busy_pids[MAX_CHILDREN];
    char *reader[] = {self, "read", NULL};
    for (int i = 0; i < readers; i++) {
        if (start(&reader_pids[i], reader, go[0], ready[1], stop[0]) != 0) {
            return 1;
        }
    }
    close(go[0]);
    close(ready[1]);
    close(stop[0]);
    char byte;
    for (int i = 0; i < readers; i++) {
        if (read(ready[0], &byte, 1) != 1) {
            fprintf(stderr, "block: a reader failed to start\n");
            return 1;
        }
    }
    // The readers read, a byte a second between them, until stopped, while
    // the busy children start and run.
    close(go[1]);
    long long started = now_us();
    char *busy_child[] = {self, "busy", calls, NULL};
    for (int i = 0; i < busy; i++) {
        if (start(&busy_pids[i], busy_child, -1, -1, -1) != 0) {
            return 1;
        }
    }
    int failed = 0, status;
    for (int i = 0; i < busy; i++) {
        if (waitpid(busy_pids[i], &status, 0) != busy_pids[i] || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
            fprintf(stderr, "block: busy child %d failed\n", i);
            failed = 1;
        }
    }
    fprintf(stderr, "block: busy children done in %lld ms\n", (now_us() - started) / 1000);
    for (int i = 0; i < readers; i++) {
        pid_t ended = waitpid(reader_pids[i], &status, WNOHANG);
        if (ended != 0) {
            fprintf(stderr, "block: reader %d ended (%d, status %#x) before the busy children\n",
                    i, ended, ended > 0 ? status : 0);
            return 1;
        }
    }
    printf("busy first\n");
    if (kill(reader_pids[0], SIGKILL) != 0) {
        perror("kill");
        return 1;
    }
    int exited = 0, killed = 0;
    for (int i = 0; i < readers; i++) {
        if (waitpid(reader_pids[i], &status, 0) != reader_pids[i]) {
            perror("waitpid");
            return 1;
        }
        if (i == 0) {
            // Once the first is gone, which its request delays.
            close(stop[1]);
        }
        if (i == 0 && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
            killed++;
        } else if (i != 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            exited++;
        } else {
            fprintf(stderr, "block: reader %d ended with status %#x\n", i, status);
            failed = 1;
        }
    }
    fprintf(stderr, "block: readers done in %lld ms\n", (now_us() - started) / 1000);
    printf("readers: %d exited, %d killed\n", exited, killed);
    return failed;
}

int main(int argc, char *argv[]) {
    if (argc == 6 && strcmp(argv[1], "fair") == 0) {
        return fair_mode(argv[0], atoi(argv[2]), argv[3], argv[4], argv[5]);
    }
    if (argc == 5 && strcmp(argv[1], "block") == 0) {
        return block_mode(argv[0], atoi(argv[2]), atoi(argv[3]), argv[4]);
    }
    if (argc == 4 && strcmp(argv[1], "calls") == 0) {
        return calls_mode(atoi(argv[2]), atol(argv[3]));
    }
    if (argc == 5 && strcmp(argv[1], "spin") == 0) {
        return spin_mode(atoi(argv[2]), atoll(argv[3]), atoll(argv[4]));
    }
    if (argc == 2 && strcmp(argv[1], "read") == 0) {
        return read_mode();
    }
    if (argc == 3 && strcmp(argv[1], "busy") == 0) {
        return busy_mode(atol(argv[2]));
    }
    fprintf(stderr, "usage: brokers fair N CALLS SPIN_MS MAX_GAP_MS | block READERS BUSY CALLS | "
                    "calls INDEX CALLS | spin INDEX MS MAX_GAP_MS | read | busy CALLS\n");
    return 2;
}
