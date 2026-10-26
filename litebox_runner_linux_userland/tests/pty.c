// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Pseudo-terminal pairs: `/dev/ptmx`, `/dev/pts`, and their ioctls.

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <termios.h>
#include <unistd.h>

static void expect_read(int fd, const char *expected) {
    char buffer[64];
    size_t length = strlen(expected);
    ssize_t size = read(fd, buffer, sizeof(buffer));
    assert(size == (ssize_t)length && memcmp(buffer, expected, length) == 0);
}

static void expect_write(int fd, const char *bytes) {
    size_t length = strlen(bytes);
    assert(write(fd, bytes, length) == (ssize_t)length);
}

static short poll_events(int fd) {
    struct pollfd poll_fd = {.fd = fd, .events = POLLIN | POLLOUT};
    assert(poll(&poll_fd, 1, 0) == 1);
    return poll_fd.revents;
}

static int listed(const char *name) {
    DIR *dir = opendir("/dev/pts");
    assert(dir != NULL);
    int found = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        found |= strcmp(entry->d_name, name) == 0;
    }
    closedir(dir);
    return found;
}

int main(void) {
    alarm(10);
    int manager, subsidiary;
    char name[64], byte;
    assert(openpty(&manager, &subsidiary, name, NULL, NULL) == 0);

    // The subsidiary's names agree with its device numbers.
    unsigned int index;
    assert(ioctl(manager, TIOCGPTN, &index) == 0);
    char expected_name[64];
    snprintf(expected_name, sizeof(expected_name), "/dev/pts/%u", index);
    assert(strcmp(name, expected_name) == 0);
    assert(strcmp(ptsname(manager), name) == 0);
    assert(strcmp(ttyname(subsidiary), name) == 0);
    assert(isatty(manager) && isatty(subsidiary));
    struct stat status;
    assert(stat(name, &status) == 0 && S_ISCHR(status.st_mode));
    assert(major(status.st_rdev) == 136 && minor(status.st_rdev) == index);
    assert(stat("/dev/ptmx", &status) == 0 && S_ISCHR(status.st_mode));
    assert(major(status.st_rdev) == 5 && minor(status.st_rdev) == 2);
    assert(listed(name + strlen("/dev/pts/")));

    // Only managers answer the pseudo-terminal ioctls, and Linux rejects the
    // descriptor before the argument.
    int lock = 1;
    assert(ioctl(manager, TIOCGPTLCK, &lock) == 0 && lock == 0);
    assert(ioctl(subsidiary, TIOCGPTN, &index) == -1 && errno == ENOTTY);
    assert(ioctl(subsidiary, TIOCSPTLCK, (int *)1) == -1 && errno == ENOTTY);
    assert(ioctl(manager, TIOCSPTLCK, (int *)1) == -1 && errno == EFAULT);
    int null = open("/dev/null", O_RDWR);
    assert(null >= 0);
    assert(ioctl(null, TIOCGPTLCK, &lock) == -1 && errno == ENOTTY);
    close(null);

    // Bytes pass through the line discipline both ways.
    expect_write(manager, "hello\n");
    expect_read(subsidiary, "hello\n");
    expect_read(manager, "hello\r\n");
    expect_write(subsidiary, "out\n");
    expect_read(manager, "out\r\n");

    // Both ends share the settings and window size.
    struct termios attributes;
    assert(tcgetattr(manager, &attributes) == 0);
    cfmakeraw(&attributes);
    assert(tcsetattr(manager, TCSANOW, &attributes) == 0);
    assert(tcgetattr(subsidiary, &attributes) == 0);
    assert(!(attributes.c_lflag & (ICANON | ECHO)));
    expect_write(manager, "ab");
    assert(poll_events(subsidiary) == (POLLIN | POLLOUT));
    expect_read(subsidiary, "ab");
    struct winsize size = {.ws_row = 24, .ws_col = 80};
    assert(ioctl(manager, TIOCSWINSZ, &size) == 0);
    memset(&size, 0, sizeof(size));
    assert(ioctl(subsidiary, TIOCGWINSZ, &size) == 0);
    assert(size.ws_row == 24 && size.ws_col == 80);

    // Each `ptmx` open creates a pair, whose subsidiary opens once unlocked.
    int second = posix_openpt(O_RDWR | O_NOCTTY);
    assert(second >= 0);
    unsigned int second_index;
    assert(ioctl(second, TIOCGPTN, &second_index) == 0 && second_index != index);
    char second_name[64];
    assert(ptsname_r(second, second_name, sizeof(second_name)) == 0);
    assert(ioctl(second, TIOCGPTLCK, &lock) == 0 && lock == 1);
    assert(open(second_name, O_RDWR | O_NOCTTY) == -1 && errno == EIO);
    assert(unlockpt(second) == 0);
    assert(ioctl(second, TIOCGPTLCK, &lock) == 0 && lock == 0);
    int second_subsidiary = open(second_name, O_RDWR | O_NOCTTY);
    assert(second_subsidiary >= 0);
    close(second_subsidiary);
    close(second);

    // Once every subsidiary file closes, the manager reports hangup until one
    // opens again.
    assert(fcntl(manager, F_SETFL, O_NONBLOCK) == 0);
    assert(read(manager, &byte, 1) == -1 && errno == EAGAIN);
    close(subsidiary);
    assert(poll_events(manager) & POLLHUP);
    assert(read(manager, &byte, 1) == -1 && errno == EIO);
    subsidiary = open(name, O_RDWR | O_NOCTTY);
    assert(subsidiary >= 0);
    assert(read(manager, &byte, 1) == -1 && errno == EAGAIN);

    // Closing the manager hangs up the subsidiary and removes its name.
    close(manager);
    assert((poll_events(subsidiary) & (POLLIN | POLLHUP)) == (POLLIN | POLLHUP));
    assert(read(subsidiary, &byte, 1) == 0);
    assert(write(subsidiary, "x", 1) == -1 && errno == EIO);
    assert(tcgetattr(subsidiary, &attributes) == -1 && errno == EIO);
    assert(stat(name, &status) == -1 && errno == ENOENT);
    assert(!listed(name + strlen("/dev/pts/")));
    close(subsidiary);

    puts("pty ok");
    return 0;
}
