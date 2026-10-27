// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupts;
static volatile sig_atomic_t quits;
static volatile sig_atomic_t resizes;

// The kernel's `struct termios2`, which glibc 2.42 uses to implement tcgetattr and tcsetattr.
struct kernel_termios2 {
    tcflag_t c_iflag, c_oflag, c_cflag, c_lflag;
    cc_t c_line;
    cc_t c_cc[19];
    speed_t c_ispeed, c_ospeed;
};
#define GET_TERMIOS2 _IOR('T', 0x2a, struct kernel_termios2)
#define SET_TERMIOS2_DRAIN _IOW('T', 0x2c, struct kernel_termios2)

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
    struct termios original, attributes;
    unsigned char bytes[6];
    const char *mode = argc > 1 ? argv[1] : "";

    if (strcmp(mode, "pipe") == 0) {
        // A job with a piped standard stream may share the terminal with the
        // rest of its pipeline, so the guest gets no terminal at all.
        assert(!isatty(0) && !isatty(1) && !isatty(2));
        assert(tcgetattr(0, &attributes) == -1 && errno == ENOTTY);
        memset(&attributes, 0, sizeof(attributes));
        assert(tcsetattr(0, TCSANOW, &attributes) == -1 && errno == ENOTTY);
        struct stat tty_status;
        assert(stat("/dev/tty", &tty_status) == 0 && S_ISCHR(tty_status.st_mode));
        assert(open("/dev/tty", O_RDWR) == -1 && errno == ENXIO);
        assert(write(2, "PIPE READY\n", 11) == 11);
        read_exact(bytes, sizeof(bytes));
        assert(memcmp(bytes, "input\n", sizeof(bytes)) == 0);
        assert(write(1, "pipe\n", 5) == 5);
        return 0;
    }
    if (strcmp(mode, "file") == 0) {
        // Standard input is a file, but the terminal stays the guest's.
        assert(!isatty(0) && isatty(1) && isatty(2));
        assert(tcgetattr(0, &attributes) == -1 && errno == ENOTTY);
        read_exact(bytes, 5);
        assert(memcmp(bytes, "file\n", 5) == 0);
        int tty = open("/dev/tty", O_RDWR);
        assert(tty >= 0 && tcgetattr(tty, &attributes) == 0 && (attributes.c_lflag & ICANON));
        puts("FILE READY");
        assert(read(tty, bytes, sizeof(bytes)) == 5 && memcmp(bytes, "keys\n", 5) == 0);
        puts("FILE DONE");
        return 0;
    }
    if (strcmp(mode, "detached") == 0) {
        // No standard stream is the terminal, yet it signals the guest.
        assert(!isatty(0) && !isatty(1) && !isatty(2));
        struct sigaction action = {.sa_handler = on_signal};
        sigemptyset(&action.sa_mask);
        assert(sigaction(SIGINT, &action, NULL) == 0);
        assert(write(1, "DETACHED READY\n", 15) == 15);
        await_signal(&interrupts);
        int tty = open("/dev/tty", O_RDWR);
        assert(tty >= 0 && isatty(tty));
        assert(write(1, "DETACHED DONE\n", 14) == 14);
        return 0;
    }

    if (strcmp(mode, "jobs") == 0) {
        // The session moves the terminal's events to its foreground process group. Like a shell,
        // ignore SIGTTOU, which Linux sends a background group that sets the foreground. An
        // interrupt reaching this process must kill it, whatever it inherited.
        assert(signal(SIGTTOU, SIG_IGN) != SIG_ERR && signal(SIGINT, SIG_DFL) != SIG_ERR);
        sigset_t interrupt;
        sigemptyset(&interrupt);
        sigaddset(&interrupt, SIGINT);
        assert(sigprocmask(SIG_UNBLOCK, &interrupt, NULL) == 0);
        pid_t self = getpid();
        assert(tcgetpgrp(0) == self && tcgetsid(0) == self);
        assert(tcsetpgrp(0, INT_MAX) == -1 && errno == ESRCH);
        int ready[2];
        assert(pipe(ready) == 0);
        assert(tcgetpgrp(ready[0]) == -1 && errno == ENOTTY);
        int status;
        pid_t outsider = fork();
        assert(outsider >= 0);
        if (outsider == 0) {
            // A new session has no controlling terminal.
            _exit(setsid() > 0 && tcgetpgrp(0) == -1 && errno == ENOTTY ? 0 : 1);
        }
        assert(waitpid(outsider, &status, 0) == outsider && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        pid_t job = fork();
        assert(job >= 0);
        if (job == 0) {
            struct sigaction action = {.sa_handler = on_signal};
            sigemptyset(&action.sa_mask);
            assert(sigaction(SIGINT, &action, NULL) == 0);
            assert(setpgid(0, 0) == 0);
            assert(write(ready[1], "", 1) == 1);
            await_signal(&interrupts);
            _exit(0);
        }
        assert(read(ready[0], bytes, 1) == 1);
        assert(tcsetpgrp(0, job) == 0 && tcgetpgrp(1) == job && tcgetsid(2) == self);
        // The interrupt reaches only the job.
        puts("JOB READY");
        assert(waitpid(job, &status, 0) == job && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        assert(tcsetpgrp(0, self) == 0 && tcgetpgrp(0) == self);
        puts("JOBS DONE");
        return 0;
    }

    assert(isatty(0) && isatty(2));
    assert(tcgetattr(0, &original) == 0);
    assert(original.c_lflag & ICANON);

    if (strcmp(mode, "child") == 0) {
        assert(!(original.c_lflag & ECHO));
        original.c_lflag |= ECHO;
        assert(tcsetattr(2, TCSANOW, &original) == 0);
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

    // The controlling terminal is the one behind the standard streams.
    int tty = open("/dev/tty", O_RDWR);
    assert(tty >= 0 && isatty(tty));
    const char *tty_name = ttyname(tty);
    assert(tty_name != NULL && strcmp(tty_name, "/dev/tty") == 0);
    struct stat tty_status;
    assert(fstat(tty, &tty_status) == 0 && S_ISCHR(tty_status.st_mode));
    assert(major(tty_status.st_rdev) == 5 && minor(tty_status.st_rdev) == 0);
    assert(write(tty, "CANONICAL READY\n", 16) == 16);
    unsigned char buffer[64];
    assert(read(0, buffer, sizeof(buffer)) == 6);
    assert(memcmp(buffer, "hello\n", 6) == 0);
    assert(read(tty, buffer, sizeof(buffer)) == 7);
    assert(memcmp(buffer, "second\n", 7) == 0);
    assert(close(tty) == 0);
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
    // Like Linux, the resize signals this foreground process before the ioctl returns.
    assert(resizes == 2);
    assert(ioctl(2, TIOCGWINSZ, &size) == 0 && size.ws_row == 42 && size.ws_col == 110);

    // Like a Linux pseudoterminal, canonical reads ignore VTIME and VMIN, but
    // noncanonical reads here support neither a timeout nor more than one byte.
    attributes = original;
    attributes.c_cc[VTIME] = 1;
    attributes.c_cc[VMIN] = 2;
    assert(tcsetattr(0, TCSANOW, &attributes) == 0);
    attributes.c_lflag &= ~ICANON;
    attributes.c_cc[VMIN] = 1;
    assert(tcsetattr(0, TCSANOW, &attributes) == -1 && errno == EINVAL);
    attributes.c_cc[VTIME] = 0;
    attributes.c_cc[VMIN] = 2;
    assert(tcsetattr(0, TCSANOW, &attributes) == -1 && errno == EINVAL);
    assert(tcgetattr(0, &attributes) == 0 && (attributes.c_lflag & ICANON));
    assert(attributes.c_cc[VTIME] == 1 && attributes.c_cc[VMIN] == 2);
    assert(tcsetattr(0, TCSANOW, &original) == 0);

    // Like a Linux pseudoterminal, the terminal reports and keeps settings it
    // never acts on, such as the line speed, parity checks, and delays.
    assert(original.c_cc[VSUSP] == 032 && original.c_cc[VDISCARD] == 017);
    assert(cfgetospeed(&original) == B38400 && (original.c_cflag & CSIZE) == CS8);
    attributes = original;
    attributes.c_iflag |= BRKINT | IGNPAR;
    attributes.c_oflag |= NL1 | TAB1;
    attributes.c_cflag |= CLOCAL;
    attributes.c_lflag |= FLUSHO;
    attributes.c_cc[VSUSP] = 0;
    attributes.c_cc[VDISCARD] = 0;
    assert(cfsetspeed(&attributes, B9600) == 0);
    assert(tcsetattr(1, TCSANOW, &attributes) == 0);
    struct termios reported;
    assert(tcgetattr(0, &reported) == 0);
    assert(reported.c_iflag == attributes.c_iflag && reported.c_oflag == attributes.c_oflag);
    assert(reported.c_lflag == attributes.c_lflag);
    assert((reported.c_cflag & ~(CBAUD | CIBAUD)) == (attributes.c_cflag & ~(CBAUD | CIBAUD)));
    assert(cfgetospeed(&reported) == B9600 && cfgetispeed(&reported) == B9600);
    assert(memcmp(reported.c_cc, attributes.c_cc, NCCS) == 0);
    // Settings Linux acts on but the terminal does not support are rejected.
    attributes = original;
    attributes.c_iflag |= PARMRK;
    assert(tcsetattr(0, TCSANOW, &attributes) == -1 && errno == EINVAL);
    assert(tcsetattr(0, TCSANOW, &original) == 0);

    // Like glibc 2.42, use termios2 and set the input speed explicitly.
    struct kernel_termios2 attributes2;
    assert(ioctl(0, GET_TERMIOS2, &attributes2) == 0);
    assert(attributes2.c_ispeed == 38400 && attributes2.c_ospeed == 38400);
    assert(attributes2.c_iflag == original.c_iflag && attributes2.c_oflag == original.c_oflag);
    // glibc 2.42's tcgetattr rewrites the input speed field (CIBAUD), so skip it.
    assert((attributes2.c_cflag & ~CIBAUD) == (original.c_cflag & ~CIBAUD));
    assert(attributes2.c_lflag == original.c_lflag);
    assert(memcmp(attributes2.c_cc, original.c_cc, sizeof(attributes2.c_cc)) == 0);
    // Copy the output speed's kernel code to CIBAUD; glibc 2.42 redefines B38400 as the plain rate.
    attributes2.c_cflag |= (attributes2.c_cflag & CBAUD) << 16;
    attributes2.c_lflag &= ~ECHO;
    // Like Linux, a pseudoterminal transports eight-bit bytes without parity.
    // (glibc's tcsetattr would report that change as EINVAL.)
    attributes2.c_cflag = (attributes2.c_cflag & ~CSIZE) | CS7 | PARENB;
    assert(ioctl(1, SET_TERMIOS2_DRAIN, &attributes2) == 0);
    assert(tcgetattr(0, &attributes) == 0 && !(attributes.c_lflag & ECHO));
    assert((attributes.c_cflag & (CSIZE | PARENB)) == CS8);
    assert(tcsetattr(0, TCSANOW, &original) == 0);
    // Like a Linux pseudoterminal, the terminal rejects requests it does not know with ENOTTY.
    assert(ioctl(1, TIOCGSERIAL, NULL) == -1 && errno == ENOTTY);

    // Pagers such as less request tab expansion.
    attributes = original;
    attributes.c_oflag |= TAB3;
    assert(tcsetattr(1, TCSANOW, &attributes) == 0);
    assert(write(1, "a\tb\n", 4) == 4);
    assert(tcsetattr(1, TCSADRAIN, &original) == 0);

    // An idle terminal reports one edge, not one per worker poll.
    int epoll = epoll_create1(0);
    struct epoll_event event = {.events = EPOLLOUT | EPOLLET};
    assert(epoll >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, 1, &event) == 0);
    assert(epoll_wait(epoll, &event, 1, -1) == 1 && (event.events & EPOLLOUT));
    assert(epoll_wait(epoll, &event, 1, 300) == 0);
    assert(close(epoll) == 0);
    puts("TTY DONE");
    return 0;
}
