// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define BUFFER_SIZE (4 * 1024 * 1024)

static int global_value = 1;
static volatile sig_atomic_t usr1_count;
static volatile sig_atomic_t sigchld_count;

static void on_usr1(int signal) {
    (void)signal;
    usr1_count++;
}

static void on_sigchld(int signal) {
    (void)signal;
    sigchld_count++;
}

static unsigned long checksum(const unsigned char *buffer, size_t size) {
    unsigned long sum = 0;
    for (size_t i = 0; i < size; i++) {
        sum = sum * 31 + buffer[i];
    }
    return sum;
}

static int wait_for(pid_t child, const char *name) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    printf("%s child=%d waited=%d exited=%d code=%d\n", name, child, waited, WIFEXITED(status),
           WEXITSTATUS(status));
    return waited == child ? 0 : 1;
}

// Runs in the child returned by glibc's `fork`.
static int run_child(pid_t parent, unsigned char *buffer, unsigned long expected_sum, int pipe_fd,
                     int (*exec_only)(void)) {
    int failures = 0;
    // The child sees the parent's memory as of the fork.
    failures += global_value != 2;
    failures += checksum(buffer, BUFFER_SIZE) != expected_sum;
    // Execute-only memory keeps its code.
    failures += exec_only() != 42;
    // Writes stay in the child.
    global_value = 3;
    memset(buffer, 0x5a, BUFFER_SIZE);
    // `raise` signals the thread ID glibc stored through `CLONE_CHILD_SETTID`.
    failures += raise(SIGUSR1) != 0;
    failures += usr1_count != 1;
    // The close-on-exec descriptor is inherited with its flag.
    failures += fcntl(pipe_fd, F_GETFD) != FD_CLOEXEC;
    pid_t pid = getpid();
    failures += pid == parent || getppid() != parent || gettid() != pid;

    pid_t grandchild = fork();
    if (grandchild == 0) {
        _exit(global_value == 3 ? 5 : 6);
    }
    int status = 0;
    failures += grandchild < 0 || waitpid(grandchild, &status, 0) != grandchild ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 5;

    char message[64];
    int length = snprintf(message, sizeof message, "child pid=%d failures=%d\n", pid, failures);
    failures += write(pipe_fd, message, length) != length;
    printf("child-stdout pid=%d\n", pid);
    fflush(stdout);
    return failures == 0 ? 7 : 8;
}

int main(void) {
    pid_t parent = getpid();
    signal(SIGUSR1, on_usr1);
    signal(SIGCHLD, on_sigchld);
    unsigned char *buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        return 2;
    }
    for (size_t i = 0; i < BUFFER_SIZE; i++) {
        buffer[i] = (unsigned char)(i * 7 + i / 4096);
    }
    unsigned long expected_sum = checksum(buffer, BUFFER_SIZE);
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
        return 3;
    }
    // `mov eax, 42; ret`
    static const unsigned char return_42[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3};
    unsigned char *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                               -1, 0);
    if (code == MAP_FAILED) {
        return 3;
    }
    memcpy(code, return_42, sizeof return_42);
    if (mprotect(code, 4096, PROT_EXEC) != 0) {
        return 3;
    }
    int (*exec_only)(void) = (int (*)(void))(void *)code;
    global_value = 2;
    fflush(stdout);

    pid_t child = fork();
    if (child == 0) {
        close(pipe_fds[0]);
        exit(run_child(parent, buffer, expected_sum, pipe_fds[1], exec_only));
    }
    if (child < 0) {
        printf("fork-failed errno=%d\n", errno);
        return 4;
    }
    close(pipe_fds[1]);
    char message[128] = {0};
    ssize_t received = 0;
    for (;;) {
        ssize_t n = read(pipe_fds[0], message + received, sizeof message - 1 - received);
        if (n > 0) {
            received += n;
        } else if (n == 0 || errno != EINTR) {
            break;
        }
    }
    printf("pipe %s", message);
    int failures = wait_for(child, "fork");

    pid_t raw_child = syscall(SYS_fork);
    if (raw_child == 0) {
        syscall(SYS_exit_group, global_value == 2 ? 9 : 10);
    }
    if (raw_child < 0) {
        perror("SYS_fork");
        return 5;
    }
    failures += wait_for(raw_child, "raw-fork");

    pid_t again = waitpid(-1, NULL, WNOHANG);
    int again_errno = errno;
    printf("parent pid=%d global=%d intact=%d usr1=%d sigchld=%d echild=%d\n", getpid(),
           global_value, checksum(buffer, BUFFER_SIZE) == expected_sum && exec_only() == 42,
           usr1_count, sigchld_count > 0, again == -1 && again_errno == ECHILD);
    return failures;
}
