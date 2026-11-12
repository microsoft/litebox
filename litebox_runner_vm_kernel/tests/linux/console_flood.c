// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Floods standard output from 4 writers, with 512 records of 256 bytes each
// (`w<writer> <seq>` padded with spaces, then a newline), each writer's more
// than the console holds, so that writes find it full and wait (see
// console_flood.json). The parent, writer 0, writes its records first, alone,
// then forks the others, which start together once all are forked: writer 1
// writes to the standard output it inherits, blocking, as writer 0 does;
// writers 2 and 3 to /dev/stdout opened anew, nonblocking, polling for room
// after each EAGAIN. A blocking writer's one write(2) writes all its records.
// Exits 0 once every writer did.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define WRITERS 4
#define RECORDS 512
#define RECORD_SIZE 256

static char records[RECORDS * RECORD_SIZE];

// Writes `writer`'s records to `fd`; 0 if all were written.
static int write_records(int writer, int fd, int blocking) {
    for (int seq = 0; seq < RECORDS; seq++) {
        char *record = &records[seq * RECORD_SIZE];
        int len = snprintf(record, RECORD_SIZE, "w%d %d", writer, seq);
        memset(record + len, ' ', RECORD_SIZE - 1 - len);
        record[RECORD_SIZE - 1] = '\n';
    }
    if (blocking) {
        ssize_t written = write(fd, records, sizeof(records));
        if (written < 0) {
            perror("write");
            return 1;
        }
        if ((size_t)written != sizeof(records)) {
            fprintf(stderr, "writer %d: a blocking write wrote %zd bytes\n", writer, written);
            return 1;
        }
        return 0;
    }
    size_t written = 0;
    while (written < sizeof(records)) {
        ssize_t n = write(fd, records + written, sizeof(records) - written);
        if (n > 0) {
            written += n;
        } else if (n < 0 && errno == EAGAIN) {
            struct pollfd room = {.fd = fd, .events = POLLOUT};
            if (poll(&room, 1, -1) != 1) {
                perror("poll");
                return 1;
            }
        } else {
            perror("write");
            return 1;
        }
    }
    return 0;
}

int main(void) {
    if (write_records(0, STDOUT_FILENO, 1) != 0) {
        return 1;
    }
    // Closed by the parent once all are forked, which ends their reads.
    int start[2];
    if (pipe(start) != 0) {
        perror("pipe");
        return 1;
    }
    pid_t children[WRITERS - 1];
    for (int writer = 1; writer < WRITERS; writer++) {
        pid_t child = fork();
        if (child < 0) {
            perror("fork");
            return 1;
        }
        if (child == 0) {
            char byte;
            close(start[1]);
            if (read(start[0], &byte, 1) != 0) {
                perror("read");
                _exit(1);
            }
            if (writer == 1) {
                _exit(write_records(writer, STDOUT_FILENO, 1));
            }
            int fd = open("/dev/stdout", O_WRONLY | O_NONBLOCK);
            if (fd < 0) {
                perror("open");
                _exit(1);
            }
            _exit(write_records(writer, fd, 0));
        }
        children[writer - 1] = child;
    }
    close(start[1]);
    int failed = 0;
    for (int i = 0; i < WRITERS - 1; i++) {
        int status;
        if (waitpid(children[i], &status, 0) != children[i] || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
            failed = 1;
        }
    }
    return failed;
}
