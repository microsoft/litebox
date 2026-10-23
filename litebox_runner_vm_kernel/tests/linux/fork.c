// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Forks as its first argument says (see fork.json and fork_stress.json),
// with what the hosted runner's fork tests (fork_hosted.json) do not cover:
// - "chain <n>": n generations, each the child of the one before, which each
//   waits for it; the last exits with n, which each passes on. Deeper (in
//   fork_stress.json) than the runner's stack would hold if each generation
//   kept the frames of the one before (some 38, in debug builds).
// - "many <n>": n children in turn, each exiting at once.
// - "thread": from a thread other than the main one; the child, whose one
//   thread is a copy of it, forks from a thread it starts, and the
//   grandchild starts a thread too.
// - "exec": the child runs /args.
// - "signal": kills the child, which waits for signals.
// - "alarm": with an alarm armed, which fires in the parent only.
// - "cow": both write all of a large buffer, each seeing its own writes only.
// - "shared": with a shared mapping, which the child shares, seeing the
//   parent the child's write, and once it is unmapped.
// - "spawned": in a child started with posix_spawn (a "chain 3").
// - "orphan": the child outlives the parent, and then sees init as its
//   parent.

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define BUFFER_SIZE (16 * 1024 * 1024)

extern char **environ;

// Forks, with standard output flushed, so that neither process writes what
// the other buffered.
static pid_t fork_flushed(void) {
    fflush(stdout);
    return fork();
}

// Reaps `child`; its exit code, or -1 if it did not exit.
static int wait_code(pid_t child) {
    int status;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int chain(int depth) {
    for (int generation = 0; generation < depth; generation++) {
        pid_t child = fork_flushed();
        if (child < 0) {
            perror("fork");
            return 1;
        }
        if (child > 0) {
            int code = wait_code(child);
            if (generation == 0) {
                printf("chain: %d\n", code);
                return code == depth ? 0 : 1;
            }
            _exit(code);
        }
    }
    _exit(depth);
}

static int many(int count) {
    for (int i = 0; i < count; i++) {
        pid_t child = fork_flushed();
        if (child == 0) {
            _exit(i % 256);
        }
        if (child < 0 || wait_code(child) != i % 256) {
            printf("fork %d failed\n", i);
            return 1;
        }
    }
    printf("forked %d times\n", count);
    return 0;
}

// What `start` returns on a thread of its own, or -1.
static long on_thread(void *(*start)(void *)) {
    pthread_t started;
    void *result;
    if (pthread_create(&started, NULL, start, NULL) != 0 || pthread_join(started, &result) != 0) {
        return -1;
    }
    return (long)result;
}

static void *returns_3(void *arg) {
    (void)arg;
    return (void *)3L;
}

static void *fork_in_child_thread(void *arg) {
    (void)arg;
    pid_t grandchild = fork_flushed();
    if (grandchild == 0) {
        _exit((int)on_thread(returns_3) + 1);
    }
    return (void *)(long)(grandchild < 0 ? -1 : wait_code(grandchild));
}

static void *fork_in_thread(void *arg) {
    (void)arg;
    pid_t child = fork_flushed();
    if (child == 0) {
        _exit((int)on_thread(fork_in_child_thread) + 1);
    }
    return (void *)(long)(child < 0 ? -1 : wait_code(child));
}

static int thread(void) {
    long code = on_thread(fork_in_thread);
    printf("thread: %ld\n", code);
    return code == 5 ? 0 : 1;
}

static int exec(void) {
    char *exits[] = {"/args", "exit", "5", NULL};
    pid_t child = fork_flushed();
    if (child == 0) {
        execve(exits[0], exits, environ);
        _exit(127);
    }
    int code = child < 0 ? -1 : wait_code(child);
    printf("child exited: %d\n", code);
    return code == 5 ? 0 : 1;
}

static int signal_child(void) {
    pid_t child = fork_flushed();
    if (child == 0) {
        for (;;) {
            pause();
        }
    }
    if (child < 0 || kill(child, SIGTERM) != 0) {
        perror("fork or kill");
        return 1;
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status)) {
        printf("child not killed\n");
        return 1;
    }
    printf("child killed: %d\n", WTERMSIG(status));
    return 0;
}

static volatile sig_atomic_t alarms;

static void on_alarm(int signal) {
    (void)signal;
    alarms++;
}

static int alarm_parent_only(void) {
    struct itimerval timer = {.it_value = {.tv_usec = 200 * 1000}};
    if (signal(SIGALRM, on_alarm) == SIG_ERR || setitimer(ITIMER_REAL, &timer, NULL) != 0) {
        perror("setitimer");
        return 1;
    }
    sigset_t blocked, original;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGALRM);
    // Blocked until the child counted the alarms it inherits, so that one it
    // gets itself is not among them.
    sigprocmask(SIG_BLOCK, &blocked, &original);
    pid_t child = fork_flushed();
    if (child == 0) {
        // Those the parent got before blocking them (e.g., if slow, under TCG).
        int inherited = alarms;
        sigprocmask(SIG_SETMASK, &original, NULL);
        struct itimerval left;
        int armed = getitimer(ITIMER_REAL, &left) != 0 || left.it_value.tv_sec != 0 ||
                    left.it_value.tv_usec != 0;
        // Past when the parent's alarm fires.
        struct timespec delay = {.tv_nsec = 400 * 1000 * 1000};
        while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        }
        _exit(armed ? 100 : alarms - inherited);
    }
    sigprocmask(SIG_SETMASK, &original, NULL);
    // Polls, as the alarm may fire between a check and a `pause`.
    while (alarms == 0) {
        struct timespec poll = {.tv_nsec = 10 * 1000 * 1000};
        nanosleep(&poll, NULL);
    }
    printf("alarm: parent %d child %d\n", alarms, child < 0 ? -1 : wait_code(child));
    return 0;
}

// Whether all of `buffer` is `value`.
static int all(const unsigned char *buffer, unsigned char value) {
    for (size_t i = 0; i < BUFFER_SIZE; i++) {
        if (buffer[i] != value) {
            return 0;
        }
    }
    return 1;
}

static int cow(void) {
    unsigned char *buffer = malloc(BUFFER_SIZE);
    int to_parent[2], to_child[2];
    if (buffer == NULL || pipe(to_parent) != 0 || pipe(to_child) != 0) {
        perror("setup");
        return 1;
    }
    memset(buffer, 'a', BUFFER_SIZE);
    char byte = 'x';
    pid_t child = fork_flushed();
    if (child == 0) {
        int ok = all(buffer, 'a');
        memset(buffer, 'b', BUFFER_SIZE);
        // The parent writes as this checks its own writes.
        ok &= write(to_parent[1], &byte, 1) == 1 && read(to_child[0], &byte, 1) == 1;
        _exit(ok && all(buffer, 'b') ? 0 : 1);
    }
    int ok = child > 0 && read(to_parent[0], &byte, 1) == 1 && all(buffer, 'a');
    memset(buffer, 'c', BUFFER_SIZE);
    ok &= write(to_child[1], &byte, 1) == 1;
    int code = child < 0 ? -1 : wait_code(child);
    printf("cow: child %d parent %d\n", code, ok && all(buffer, 'c'));
    return 0;
}

static int shared(void) {
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    *(volatile int *)page = 1;
    pid_t child = fork_flushed();
    if (child == 0) {
        *(volatile int *)page = 42;
        _exit(0);
    }
    if (child < 0) {
        printf("shared: %s\n", strerror(errno));
    } else {
        int code = wait_code(child);
        printf("shared: child %d parent sees %d\n", code, *(volatile int *)page);
    }
    munmap(page, 4096);
    child = fork_flushed();
    if (child == 0) {
        _exit(0);
    }
    printf("after unmap: %d\n", child < 0 ? -1 : wait_code(child));
    return 0;
}

static int spawned(void) {
    char *chain[] = {"/fork", "chain", "3", NULL};
    pid_t child;
    fflush(stdout);
    int error = posix_spawn(&child, chain[0], NULL, NULL, chain, environ);
    if (error != 0) {
        printf("posix_spawn: %s\n", strerror(error));
        return 1;
    }
    printf("spawned: %d\n", wait_code(child));
    return 0;
}

static int orphan(void) {
    pid_t parent = getpid();
    pid_t child = fork_flushed();
    if (child == 0) {
        // Until the parent exited, which reparents this.
        while (getppid() == parent) {
            usleep(1000);
        }
        printf("orphan's parent: %d\n", getppid());
        return 0;
    }
    printf("parent exits\n");
    return child < 0;
}

int main(int argc, char *argv[]) {
    const char *mode = argc > 1 ? argv[1] : "";
    int count = argc > 2 ? atoi(argv[2]) : 0;
    if (strcmp(mode, "chain") == 0) {
        return chain(count);
    }
    if (strcmp(mode, "many") == 0) {
        return many(count);
    }
    if (strcmp(mode, "thread") == 0) {
        return thread();
    }
    if (strcmp(mode, "exec") == 0) {
        return exec();
    }
    if (strcmp(mode, "signal") == 0) {
        return signal_child();
    }
    if (strcmp(mode, "alarm") == 0) {
        return alarm_parent_only();
    }
    if (strcmp(mode, "cow") == 0) {
        return cow();
    }
    if (strcmp(mode, "shared") == 0) {
        return shared();
    }
    if (strcmp(mode, "spawned") == 0) {
        return spawned();
    }
    if (strcmp(mode, "orphan") == 0) {
        return orphan();
    }
    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
}
