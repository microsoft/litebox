// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *child_path;

static volatile sig_atomic_t chld_count;
static volatile pid_t chld_pid;
static volatile int chld_code;
static volatile int chld_status;
static volatile int chld_uid_matches;
static volatile sig_atomic_t alarmed;

static void on_chld(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)context;
    chld_count++;
    chld_pid = info->si_pid;
    chld_code = info->si_code;
    chld_status = info->si_status;
    chld_uid_matches = info->si_uid == getuid();
}

static void on_alrm(int signal) {
    (void)signal;
    alarmed = 1;
}

static void set_action(int signal, struct sigaction *action) {
    if (sigaction(signal, action, NULL) != 0) {
        perror("sigaction");
        _exit(3);
    }
}

// Installs the recording `SIGCHLD` handler with `flags` and clears what it recorded.
static void catch_sigchld(int flags) {
    struct sigaction action = {.sa_sigaction = on_chld, .sa_flags = SA_SIGINFO | flags};
    set_action(SIGCHLD, &action);
    chld_count = 0;
    chld_pid = 0;
    chld_code = 0;
    chld_status = 0;
    chld_uid_matches = 0;
}

static pid_t spawn_exit(int code) {
    pid_t child = vfork();
    if (child == 0) {
        _exit(code);
    }
    if (child < 0) {
        perror("vfork");
        _exit(4);
    }
    return child;
}

// The exec'd child exits with code 42 shortly after it starts.
static pid_t spawn_sleeper(void) {
    pid_t child = vfork();
    if (child == 0) {
        execl(child_path, child_path, "sleep", (char *)NULL);
        _exit(111);
    }
    if (child < 0) {
        perror("vfork");
        _exit(5);
    }
    return child;
}

// Prints what the handler recorded for `child`, leaving the line open for extra fields.
static void report(const char *name, pid_t child, pid_t waited) {
    printf("%s child=%d waited=%d count=%d pid=%d code=%d status=%d uid=%d", name, child, waited,
           chld_count, chld_pid, chld_code, chld_status, chld_uid_matches);
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }
    child_path = argv[1];

    // A child exiting in its vfork window signals the parent.
    catch_sigchld(SA_RESTART);
    pid_t child = spawn_exit(7);
    pid_t waited = waitpid(child, NULL, 0);
    report("exited", child, waited);
    printf("\n");

    // A child killed in its vfork window signals the parent.
    catch_sigchld(SA_RESTART);
    child = vfork();
    if (child == 0) {
        __builtin_trap();
        _exit(111);
    }
    if (child < 0) {
        perror("vfork");
        return 4;
    }
    waited = waitpid(child, NULL, 0);
    report("killed", child, waited);
    printf("\n");

    // An exec'd child's exit interrupts the sleeping parent.
    catch_sigchld(0);
    child = spawn_sleeper();
    int early = chld_count;
    errno = 0;
    int paused = pause();
    int pause_eintr = paused == -1 && errno == EINTR;
    waited = waitpid(child, NULL, 0);
    report("paused", child, waited);
    printf(" early=%d eintr=%d\n", early, pause_eintr);

    // Like Linux, a wait interrupted by the waited child's SIGCHLD reports the child, even
    // without SA_RESTART.
    catch_sigchld(0);
    child = spawn_sleeper();
    int status = 0;
    waited = waitpid(child, &status, 0);
    report("waited", child, waited);
    printf(" exited=%d exit=%d\n", WIFEXITED(status), WEXITSTATUS(status));

    // A child reaped as it terminates still signals the parent's handler with its status.
    catch_sigchld(SA_RESTART | SA_NOCLDWAIT);
    child = spawn_exit(9);
    errno = 0;
    waited = waitpid(child, NULL, 0);
    report("nocldwait", child, waited);
    printf(" echild=%d\n", waited == -1 && errno == ECHILD);

    // The default SIGCHLD action does not interrupt the sleeping parent. This runs last since
    // vfork fails once an alarm has been set.
    struct sigaction action = {.sa_handler = SIG_DFL};
    set_action(SIGCHLD, &action);
    action.sa_handler = on_alrm;
    set_action(SIGALRM, &action);
    child = spawn_sleeper();
    alarm(1);
    errno = 0;
    paused = pause();
    pause_eintr = paused == -1 && errno == EINTR;
    waited = waitpid(child, &status, 0);
    printf("default child=%d waited=%d alarmed=%d eintr=%d exit=%d\n", child, waited, alarmed,
           pause_eintr, WEXITSTATUS(status));
    return 0;
}
