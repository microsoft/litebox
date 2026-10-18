// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Starts programs as its first argument says (see exec.json):
// - "exec": /args in place of itself (execve).
// - "spawn": /args as a child (posix_spawn, i.e., vfork and execve), with its
//   standard output on a pipe this relays, then as one that dies of a
//   signal, and waits for each.
// - "vfork": /args as a child (vfork and execve), after a failed execve,
//   which the child sees, as Linux's does.
// - "orphan": starts itself as a child that lingers ("linger"), which it
//   leaves running as it exits; the run ends only once the orphan, which
//   then prints, exits too.
// - "eof": starts itself as a child that reads its standard input until its
//   end ("drain"), from a pipe whose write end this keeps open as it exits;
//   the child sees the end, and prints what it read, once this has exited.
// - "relay <port>" and "collect <port>", run at once: relay starts itself as
//   a child ("forward <port>") with its standard input on a pipe, writes to
//   the pipe, and exits keeping its write end open; the child sends what it
//   read, once it sees the end, to collect, listening on 127.0.0.1:<port>,
//   which exits 0 once it received it. So collect ends only once relay's
//   exit, before collect's, closed the pipe.

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int report(pid_t pid) {
    int status;
    if (waitpid(pid, &status, 0) != pid) {
        perror("waitpid");
        return 1;
    }
    if (WIFEXITED(status)) {
        printf("child exited: %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("child killed: %d\n", WTERMSIG(status));
    }
    return 0;
}

static int spawn(void) {
    int fds[2];
    if (pipe(fds) != 0) {
        perror("pipe");
        return 1;
    }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, fds[0]);
    posix_spawn_file_actions_addclose(&actions, fds[1]);
    char *exits[] = {"/args", "exit", "7", NULL};
    pid_t pid;
    int err = posix_spawn(&pid, exits[0], &actions, NULL, exits, environ);
    if (err != 0) {
        printf("posix_spawn: %s\n", strerror(err));
        return 1;
    }
    close(fds[1]);
    char buf[256];
    ssize_t n;
    while ((n = read(fds[0], buf, sizeof buf)) > 0) {
        printf("piped: %.*s", (int)n, buf);
    }
    if (report(pid) != 0) {
        return 1;
    }
    char *aborts[] = {"/args", "abort", NULL};
    err = posix_spawn(&pid, aborts[0], NULL, NULL, aborts, environ);
    if (err != 0) {
        printf("posix_spawn: %s\n", strerror(err));
        return 1;
    }
    return report(pid);
}

static int vfork_exec(void) {
    char *exits[] = {"/args", "exit", "3", NULL};
    pid_t pid = vfork();
    if (pid < 0) {
        perror("vfork");
        return 1;
    }
    if (pid == 0) {
        execve("/missing", exits, environ);
        if (errno != ENOENT) {
            _exit(126);
        }
        execve(exits[0], exits, environ);
        _exit(127);
    }
    return report(pid);
}

static int orphan(void) {
    char *lingers[] = {"/exec", "linger", NULL};
    pid_t pid;
    int err = posix_spawn(&pid, lingers[0], NULL, NULL, lingers, environ);
    if (err != 0) {
        printf("posix_spawn: %s\n", strerror(err));
        return 1;
    }
    printf("spawned\n");
    return 0;
}

// Starts `child` with its standard input on a pipe, writes "data\n" to the
// pipe, and returns, keeping the pipe's write end open.
static int feed(char *child[]) {
    int fds[2];
    if (pipe(fds) != 0) {
        perror("pipe");
        return 1;
    }
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fds[0], STDIN_FILENO);
    posix_spawn_file_actions_addclose(&actions, fds[0]);
    posix_spawn_file_actions_addclose(&actions, fds[1]);
    pid_t pid;
    int err = posix_spawn(&pid, child[0], &actions, NULL, child, environ);
    if (err != 0) {
        printf("posix_spawn: %s\n", strerror(err));
        return 1;
    }
    return write(fds[1], "data\n", 5) == 5 ? 0 : 1;
}

// Reads `fd` until its end into `buf`; the bytes read, or -1 on an error or
// more than `size`.
static ssize_t read_all(int fd, char *buf, size_t size) {
    size_t total = 0;
    for (;;) {
        ssize_t n = read(fd, buf + total, size - total);
        if (n <= 0 || (total += (size_t)n) == size) {
            return n == 0 ? (ssize_t)total : -1;
        }
    }
}

static struct sockaddr_in loopback(const char *port) {
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)atoi(port));
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return address;
}

static int forward(const char *port) {
    char buf[64];
    ssize_t total = read_all(STDIN_FILENO, buf, sizeof buf);
    if (total < 0) {
        return 1;
    }
    struct sockaddr_in to = loopback(port);
    // Until collect listens.
    for (int tries = 0; tries < 500; tries++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            return 1;
        }
        if (connect(s, (struct sockaddr *)&to, sizeof to) == 0) {
            int ok = write(s, buf, (size_t)total) == total;
            close(s);
            return ok ? 0 : 1;
        }
        close(s);
        usleep(10 * 1000);
    }
    return 1;
}

static int collect(const char *port) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in at = loopback(port);
    if (listener < 0 || bind(listener, (struct sockaddr *)&at, sizeof at) != 0 ||
        listen(listener, 1) != 0) {
        return 1;
    }
    int s = accept(listener, NULL, NULL);
    char buf[64];
    ssize_t total = s < 0 ? -1 : read_all(s, buf, sizeof buf);
    return total == 5 && memcmp(buf, "data\n", 5) == 0 ? 0 : 1;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "exec") == 0) {
        char *exits[] = {"/args", "exit", "7", NULL};
        printf("exec\n");
        fflush(stdout);
        execve(exits[0], exits, environ);
        perror("execve");
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "spawn") == 0) {
        return spawn();
    }
    if (argc > 1 && strcmp(argv[1], "vfork") == 0) {
        return vfork_exec();
    }
    if (argc > 1 && strcmp(argv[1], "orphan") == 0) {
        return orphan();
    }
    if (argc > 1 && strcmp(argv[1], "eof") == 0) {
        char *drains[] = {"/exec", "drain", NULL};
        return feed(drains);
    }
    if (argc > 1 && strcmp(argv[1], "drain") == 0) {
        char buf[64];
        printf("drained %zd bytes\n", read_all(STDIN_FILENO, buf, sizeof buf));
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "relay") == 0) {
        char *forwards[] = {"/exec", "forward", argv[2], NULL};
        return feed(forwards);
    }
    if (argc > 2 && strcmp(argv[1], "forward") == 0) {
        return forward(argv[2]);
    }
    if (argc > 2 && strcmp(argv[1], "collect") == 0) {
        return collect(argv[2]);
    }
    if (argc > 1 && strcmp(argv[1], "linger") == 0) {
        // Long enough for its parent to have exited.
        usleep(100 * 1000);
        printf("lingered\n");
        return 0;
    }
    return 2;
}
