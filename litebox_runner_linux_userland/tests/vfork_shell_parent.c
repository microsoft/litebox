// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Runs `/bin/sh` the ways programs commonly do, from a process with a second thread and its own
// working directory and umask.

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_mutex_t hold = PTHREAD_MUTEX_INITIALIZER;

static void *wait_for_release(void *arg) {
    (void)arg;
    pthread_mutex_lock(&hold);
    pthread_mutex_unlock(&hold);
    return NULL;
}

static void report_status(const char *label, int status) {
    printf("%s exited=%d code=%d\n", label, WIFEXITED(status), WEXITSTATUS(status));
    fflush(stdout);
}

int main(void) {
    pthread_t thread;
    if (pthread_mutex_lock(&hold) != 0 ||
        pthread_create(&thread, NULL, wait_for_release, NULL) != 0) {
        printf("thread-error\n");
        return 2;
    }
    if (chdir("/tmp") != 0) {
        perror("chdir");
        return 3;
    }
    umask(027);

    report_status("system", system("exit 7"));

    // The command's output is read back through a pipe.
    FILE *output = popen("printf 'popen-read cwd='; pwd; printf 'popen-read umask='; umask", "r");
    if (output == NULL) {
        perror("popen");
        return 4;
    }
    char line[256];
    while (fgets(line, sizeof line, output) != NULL) {
        fputs(line, stdout);
    }
    report_status("popen-read", pclose(output));

    FILE *input = popen("read line && test \"$line\" = hello", "w");
    if (input == NULL) {
        perror("popen");
        return 5;
    }
    fputs("hello\n", input);
    report_status("popen-write", pclose(input));

    // Like Python's `subprocess`, the child changes its own working directory and umask and closes
    // the descriptors it does not pass on before exec.
    int kept = dup(1);
    char command[256];
    snprintf(command, sizeof command,
             "printf 'vfork-child cwd='; pwd; printf 'vfork-child umask='; umask; "
             "if true >&%d; then echo vfork-child kept=open; else echo vfork-child kept=closed; fi",
             kept);
    fflush(stdout);
    pid_t child = vfork();
    if (child == 0) {
        if (chdir("/") != 0 || syscall(SYS_close_range, 3, ~0U, 0) != 0) {
            _exit(10);
        }
        umask(077);
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(11);
    }
    if (child < 0) {
        perror("vfork");
        return 6;
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        perror("waitpid");
        return 7;
    }
    report_status("vfork", status);

    char cwd[256];
    mode_t mask = umask(0);
    printf("parent cwd=%s umask=%03o kept=%d\n", getcwd(cwd, sizeof cwd) ? cwd : "?", mask,
           fcntl(kept, F_GETFD) != -1);
    fflush(stdout);

    pthread_mutex_unlock(&hold);
    pthread_join(thread, NULL);
    return 0;
}
