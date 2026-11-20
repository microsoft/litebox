// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// A vfork child's termination signals its parent, whose `SIGCHLD` handler learns the child's
// process ID, termination, and user, and interrupts the parent's `sigsuspend` or wait as on Linux.

#include "helpers.h"
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

// Waits up to a second for the SIGCHLD handler to run, returning how many times it ran. Linux
// resumes a vfork parent before the child finishes exiting, so the handler may run shortly after.
static int await_sigchld(void) {
    for (int i = 0; i < 1000 && chld_count == 0; i++) {
        usleep(1000);
    }
    return chld_count;
}

// Prints what the handler recorded for `child`, leaving the line open for extra fields.
static void report(const char *name, pid_t child, pid_t waited) {
    printf("%s child=%d waited=%d count=%d pid=%d code=%d status=%d uid=%d", name, child, waited,
           chld_count, chld_pid, chld_code, chld_status, chld_uid_matches);
}

// Returns whether the handler ran once, for `child`, which `code` and `status` ended, and named
// this process's user.
static int handled(pid_t child, int code, int status) {
    return chld_count == 1 && chld_pid == child && chld_code == code && chld_status == status &&
           chld_uid_matches;
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        fprintf(stderr, "usage: %s /absolute/child/path\n", argv[0]);
        return 2;
    }
    child_path = argv[1];

    // A child exiting in its vfork window signals the parent without any wait.
    catch_sigchld(SA_RESTART);
    pid_t child = spawn_exit(7);
    int early = await_sigchld();
    pid_t waited = waitpid(child, NULL, 0);
    report("exited", child, waited);
    printf(" early=%d\n", early);
    int failures = waited != child || !handled(child, CLD_EXITED, 7) || early != 1;

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
    early = await_sigchld();
    waited = waitpid(child, NULL, 0);
    report("killed", child, waited);
    printf(" early=%d\n", early);
    // Linux reports `CLD_DUMPED` instead when the host dumps the child's core.
    failures += waited != child ||
                !(handled(child, CLD_KILLED, TRAP_SIGNAL) || handled(child, CLD_DUMPED, TRAP_SIGNAL)) ||
                early != 1;

    // An exec'd child's exit interrupts the sleeping parent. SIGCHLD stays blocked until the
    // parent sleeps, so that it can't come first; the alarm, set once the child has exec'd, ends a
    // parent it never wakes.
    sigset_t chld_set;
    sigset_t unblocked;
    sigemptyset(&chld_set);
    sigaddset(&chld_set, SIGCHLD);
    catch_sigchld(0);
    if (sigprocmask(SIG_BLOCK, &chld_set, &unblocked) != 0) {
        perror("sigprocmask");
        return 6;
    }
    child = spawn_sleeper();
    alarm(10);
    errno = 0;
    int paused = sigsuspend(&unblocked);
    int pause_eintr = paused == -1 && errno == EINTR;
    alarm(0);
    if (sigprocmask(SIG_SETMASK, &unblocked, NULL) != 0) {
        perror("sigprocmask");
        return 6;
    }
    waited = waitpid(child, NULL, 0);
    report("paused", child, waited);
    printf(" eintr=%d\n", pause_eintr);
    failures += waited != child || !handled(child, CLD_EXITED, 42) || !pause_eintr;

    // Like Linux, a wait interrupted by the waited child's SIGCHLD reports the child, even
    // without SA_RESTART.
    catch_sigchld(0);
    child = spawn_sleeper();
    int status = 0;
    waited = waitpid(child, &status, 0);
    report("waited", child, waited);
    printf(" exited=%d exit=%d\n", WIFEXITED(status), WEXITSTATUS(status));
    failures += waited != child || !handled(child, CLD_EXITED, 42) || !WIFEXITED(status) ||
                WEXITSTATUS(status) != 42;

    // A child reaped as it terminates still signals the parent's handler with its status.
    catch_sigchld(SA_RESTART | SA_NOCLDWAIT);
    child = spawn_exit(9);
    early = await_sigchld();
    errno = 0;
    waited = waitpid(child, NULL, 0);
    int echild = waited == -1 && errno == ECHILD;
    report("nocldwait", child, waited);
    printf(" early=%d echild=%d\n", early, echild);
    failures += !handled(child, CLD_EXITED, 9) || early != 1 || !echild;

    // Like Linux, a child terminating while SIGCHLD is ignored sends no signal, even if blocked.
    struct sigaction ignore = {.sa_handler = SIG_IGN};
    if (sigprocmask(SIG_BLOCK, &chld_set, NULL) != 0) {
        perror("sigprocmask");
        return 6;
    }
    set_action(SIGCHLD, &ignore);
    child = spawn_exit(11);
    // Waiting while SIGCHLD is ignored returns ECHILD once the child is reaped.
    waited = waitpid(child, NULL, 0);
    catch_sigchld(SA_RESTART);
    if (sigprocmask(SIG_UNBLOCK, &chld_set, NULL) != 0) {
        perror("sigprocmask");
        return 6;
    }
    printf("ignored-blocked child=%d waited=%d count=%d\n", child, waited, chld_count);
    failures += waited != -1 || chld_count != 0;

    // The default SIGCHLD action does not interrupt the sleeping parent, which the alarm wakes.
    // SIGALRM stays blocked until the parent sleeps, so that it can't come first.
    struct sigaction action = {.sa_handler = SIG_DFL};
    set_action(SIGCHLD, &action);
    action.sa_handler = on_alrm;
    set_action(SIGALRM, &action);
    sigset_t alrm_set;
    sigemptyset(&alrm_set);
    sigaddset(&alrm_set, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &alrm_set, &unblocked) != 0) {
        perror("sigprocmask");
        return 6;
    }
    child = spawn_sleeper();
    alarm(1);
    errno = 0;
    paused = sigsuspend(&unblocked);
    pause_eintr = paused == -1 && errno == EINTR;
    waited = waitpid(child, &status, 0);
    printf("default child=%d waited=%d alarmed=%d eintr=%d exit=%d\n", child, waited, alarmed,
           pause_eintr, WEXITSTATUS(status));
    failures += waited != child || !alarmed || !pause_eintr || WEXITSTATUS(status) != 42;
    printf("vfork-sigchld failures=%d\n", failures);
    return failures != 0;
}
