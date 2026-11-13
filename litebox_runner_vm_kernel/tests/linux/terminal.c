// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Runs on the guest service's terminal (see terminal.json): checks that it
// is the controlling terminal of its standard streams, 24 by 80, then turns
// off echo, prints `ready`, and prints the line it reads.

#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

int main(void) {
    int tty = isatty(0) && isatty(1) && isatty(2);
    const char *name = ttyname(0);
    int pts = name && strncmp(name, "/dev/pts/", strlen("/dev/pts/")) == 0;
    int controlling = tcgetsid(0) == getsid(0) && tcgetpgrp(0) == getpgrp();
    struct winsize size = {0};
    int sized = ioctl(0, TIOCGWINSZ, &size) == 0;
    printf("tty %d pts %d controlling %d\n", tty, pts, controlling);
    printf("size %dx%d\n", sized ? size.ws_row : -1, sized ? size.ws_col : -1);
    struct termios attributes;
    if (tcgetattr(0, &attributes) != 0) {
        perror("tcgetattr");
        return 1;
    }
    attributes.c_lflag &= ~(tcflag_t)ECHO;
    if (tcsetattr(0, TCSANOW, &attributes) != 0) {
        perror("tcsetattr");
        return 1;
    }
    printf("ready\n");
    fflush(stdout);
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        perror("fgets");
        return 1;
    }
    printf("read: %s", line);
    return tty && pts && controlling && sized ? 0 : 1;
}
