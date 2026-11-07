// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks that a signal another process sent is pending as soon as that process's `kill` returns,
// so `sigpending` reports it and a zero-timeout `rt_sigtimedwait` takes it, exactly once.

#include "helpers.h"

static void read_byte(int fd) {
    char byte;
    ssize_t count;
    do {
        count = read(fd, &byte, 1);
    } while (count < 0 && errno == EINTR);
    TEST_ASSERT(count == 1, "read failed");
}

static void write_byte(int fd) {
    TEST_ASSERT(write(fd, "x", 1) == 1, "write failed");
}

int main(void) {
    sigset_t usr1, usr2, both;
    sigemptyset(&usr1);
    sigaddset(&usr1, SIGUSR1);
    sigemptyset(&usr2);
    sigaddset(&usr2, SIGUSR2);
    sigemptyset(&both);
    sigaddset(&both, SIGUSR1);
    sigaddset(&both, SIGUSR2);
    TEST_ASSERT(sigprocmask(SIG_BLOCK, &both, NULL) == 0, "block SIGUSR1 and SIGUSR2 failed");
    int sent[2], resume[2];
    TEST_ASSERT(pipe(sent) == 0 && pipe(resume) == 0, "pipe failed");
    pid_t parent = getpid();
    pid_t child = fork();
    TEST_ASSERT(child >= 0, "fork failed");
    if (child == 0) {
        close(sent[0]);
        close(resume[1]);
        // Each byte is written only after `kill` returned, so its signal is already pending.
        TEST_ASSERT(kill(parent, SIGUSR1) == 0, "kill SIGUSR1 failed");
        write_byte(sent[1]);
        read_byte(resume[0]);
        TEST_ASSERT(kill(parent, SIGUSR2) == 0, "kill SIGUSR2 failed");
        write_byte(sent[1]);
        _exit(0);
    }
    close(sent[1]);
    close(resume[0]);
    struct timespec zero = {0, 0};

    read_byte(sent[0]);
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    TEST_ASSERT(syscall(SYS_rt_sigtimedwait, &usr1, &info, &zero, _NSIG / 8) == SIGUSR1 &&
                    info.si_signo == SIGUSR1 && info.si_code == SI_USER &&
                    info.si_pid == child && info.si_uid == getuid(),
                "a zero-timeout wait should take a signal another process sent");
    errno = 0;
    TEST_ASSERT(syscall(SYS_rt_sigtimedwait, &usr1, NULL, &zero, _NSIG / 8) == -1 && errno == EAGAIN,
                "a zero-timeout wait should take the signal only once");

    // SIGUSR2 is sent only after the wait above, so `sigpending` must find it on its own.
    write_byte(resume[1]);
    read_byte(sent[0]);
    sigset_t pending;
    TEST_ASSERT(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR2),
                "sigpending should report a signal another process sent");
    TEST_ASSERT(syscall(SYS_rt_sigtimedwait, &usr2, NULL, &zero, _NSIG / 8) == SIGUSR2,
                "a zero-timeout wait should take the pending SIGUSR2");

    int status;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    TEST_ASSERT(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "the child should exit cleanly");
    puts("sigtimedwait-fork ok");
    return 0;
}
