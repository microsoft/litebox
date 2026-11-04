// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Runs an interactive shell, which vforks its commands into their own foreground groups, on a
// pseudo-terminal that controls its session.

#define _GNU_SOURCE
#include <pty.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int manager, subsidiary;
    if (openpty(&manager, &subsidiary, NULL, NULL, NULL) != 0) {
        perror("openpty");
        return 1;
    }
    pid_t leader = fork();
    if (leader == 0) {
        close(manager);
        if (setsid() != getpid() || ioctl(subsidiary, TIOCSCTTY, 0) != 0) {
            _exit(90);
        }
        for (int fd = 0; fd < 3; fd++) {
            dup2(subsidiary, fd);
        }
        close(subsidiary);
        execl("/bin/sh", "sh", "-i", "-c",
              "echo before-cmd; /bin/sh -c 'echo in-cmd'; echo after-cmd; exit 5", (char *)NULL);
        _exit(91);
    }
    close(subsidiary);
    // Reads end once the leader's session hangs up.
    char buffer[512];
    ssize_t size;
    while ((size = read(manager, buffer, sizeof buffer)) > 0) {
        fwrite(buffer, 1, (size_t)size, stdout);
    }
    int status;
    if (waitpid(leader, &status, 0) != leader || !WIFEXITED(status)) {
        printf("\nleader did not exit\n");
        return 1;
    }
    printf("\nleader exited code=%d\n", WEXITSTATUS(status));
    return 0;
}
