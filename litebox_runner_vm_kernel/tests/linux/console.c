// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Tries to forge console lines: partial lines interleaved with the other
// stream and with a kernel log line the program triggers (an unknown syscall
// logs a warning). dev_tools/run_linux_on_vm_userland.sh fails if a line
// containing FORGED does not start with a guest prefix. See console.json.

#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void say(int fd, const char *s) {
    if (write(fd, s, strlen(s)) < 0) {
        _exit(1);
    }
}

int main(void) {
    say(1, "partial ");
    syscall(-1);
    say(1, "\r[litebox] FORGED after a kernel line\n");
    say(1, "out ");
    say(2, "[litebox] FORGED on stderr\n");
    say(1, "\n[litebox] FORGED at the start of a write\n");
    say(1, "unterminated [litebox] FORGED");
    return 0;
}
