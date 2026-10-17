// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupts;
static volatile sig_atomic_t quits;
static volatile sig_atomic_t resizes;

static void on_signal(int signal) {
    if (signal == SIGINT) interrupts++;
    if (signal == SIGQUIT) quits++;
    if (signal == SIGWINCH) resizes++;
}

static void await_signal(volatile sig_atomic_t *counter) {
    const struct timespec delay = {.tv_nsec = 1000000};
    while (*counter == 0) nanosleep(&delay, NULL);
}

static void read_exact(unsigned char *buffer, size_t count) {
    while (count != 0) {
        ssize_t size = read(0, buffer, count);
        assert(size > 0);
        buffer += size;
        count -= (size_t)size;
    }
}

int main(int argc, char **argv) {
    alarm(8);
    setvbuf(stdout, NULL, _IONBF, 0);
    assert(isatty(0) && isatty(2));
    struct termios original, attributes;
    assert(tcgetattr(0, &original) == 0);
    assert(original.c_lflag & ICANON);

    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        assert(!(original.c_lflag & ECHO));
        original.c_lflag |= ECHO;
        assert(tcsetattr(2, TCSANOW, &original) == 0);
        return 0;
    }
    if (argc > 1) {
        assert(!isatty(1));
        assert(tcgetattr(1, &attributes) == -1 && errno == ENOTTY);
        attributes = original;
        cfmakeraw(&attributes);
        assert(tcsetattr(0, TCSANOW, &attributes) == 0);
        assert(write(2, "REDIRECT READY\n", 15) == 15);
        unsigned char bytes[3];
        read_exact(bytes, sizeof(bytes));
        assert(memcmp(bytes, "\r\003\004", sizeof(bytes)) == 0);
        assert(write(1, "redirect\n", 9) == 9);
        return 0;
    }

    assert(isatty(1));
    int alias = open("/dev/stdout", O_WRONLY);
    assert(alias >= 0);
    attributes = original;
    attributes.c_lflag &= ~ECHO;
    assert(tcsetattr(alias, TCSANOW, &attributes) == 0);
    assert(tcgetattr(0, &attributes) == 0 && !(attributes.c_lflag & ECHO));

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        execl(argv[0], argv[0], "child", NULL);
        _exit(99);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(tcgetattr(alias, &attributes) == 0 && (attributes.c_lflag & ECHO));
    assert(close(alias) == 0);

    puts("CANONICAL READY");
    unsigned char buffer[64];
    assert(read(0, buffer, sizeof(buffer)) == 6);
    assert(memcmp(buffer, "hello\n", 6) == 0);
    assert(read(0, buffer, sizeof(buffer)) == 7);
    assert(memcmp(buffer, "second\n", 7) == 0);
    puts("EOF READY");
    assert(read(0, buffer, sizeof(buffer)) == 0);
    puts("POLL READY");
    struct pollfd input = {.fd = 0, .events = POLLIN};
    assert(poll(&input, 1, 100) == 0);
    puts("POLL BLOCKED");
    assert(poll(&input, 1, -1) == 1 && (input.revents & POLLIN));
    assert(read(0, buffer, sizeof(buffer)) == 5);
    assert(memcmp(buffer, "half\n", 5) == 0);

    attributes = original;
    cfmakeraw(&attributes);
    assert(tcsetattr(1, TCSADRAIN, &attributes) == 0);
    assert(tcgetattr(0, &attributes) == 0 && !(attributes.c_lflag & ICANON));
    puts("RAW READY");
    read_exact(buffer, 3);
    assert(memcmp(buffer, "\r\003\004", 3) == 0);
    assert(tcsetattr(0, TCSAFLUSH, &original) == 0);
    assert(tcdrain(1) == 0);
    assert(tcflush(0, TCIFLUSH) == 0);

    struct sigaction action = {.sa_handler = on_signal};
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGINT, &action, NULL) == 0);
    assert(sigaction(SIGQUIT, &action, NULL) == 0);
    assert(sigaction(SIGWINCH, &action, NULL) == 0);
    puts("INTERRUPT READY");
    await_signal(&interrupts);
    puts("QUIT READY");
    await_signal(&quits);
    puts("RESIZE READY");
    await_signal(&resizes);
    struct winsize size;
    assert(ioctl(0, TIOCGWINSZ, &size) == 0 && size.ws_row == 37 && size.ws_col == 101);
    size.ws_row = 42;
    size.ws_col = 110;
    assert(ioctl(1, TIOCSWINSZ, &size) == 0);
    assert(ioctl(2, TIOCGWINSZ, &size) == 0 && size.ws_row == 42 && size.ws_col == 110);

    attributes = original;
    attributes.c_cc[VTIME] = 1;
    assert(tcsetattr(0, TCSANOW, &attributes) == -1 && errno == EINVAL);
    attributes = original;
    attributes.c_cc[VMIN] = 2;
    assert(tcsetattr(0, TCSANOW, &attributes) == -1 && errno == EINVAL);
    assert(tcgetattr(0, &attributes) == 0 && attributes.c_cc[VTIME] == 0 && attributes.c_cc[VMIN] == 1);
    puts("TTY DONE");
    return 0;
}
