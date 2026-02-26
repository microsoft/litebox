typedef unsigned long usize;

enum {
    MACOS_SYSCALL_CLASS_UNIX = 0x2000000,
    MACOS_SYS_EXIT = MACOS_SYSCALL_CLASS_UNIX | 1,
    MACOS_SYS_WRITE = MACOS_SYSCALL_CLASS_UNIX | 4,
    MACOS_SYS_GETPID = MACOS_SYSCALL_CLASS_UNIX | 20,
};

static long macos_syscall3(long nr, long a0, long a1, long a2) {
    long ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a0), "S"(a1), "d"(a2)
                     : "rcx", "r11", "memory");
    return ret;
}

__attribute__((noreturn)) static void macos_exit(int code) {
    (void)macos_syscall3(MACOS_SYS_EXIT, code, 0, 0);
    __builtin_unreachable();
}

int main(void) {
    static const char msg[] = "zig-basic: hello from zig cc\n";
    long pid = macos_syscall3(MACOS_SYS_GETPID, 0, 0, 0);
    if (pid <= 0) {
        macos_exit(1);
    }

    long written = macos_syscall3(MACOS_SYS_WRITE, 1, (long)(usize)msg, sizeof(msg) - 1);
    if (written != (long)(sizeof(msg) - 1)) {
        macos_exit(2);
    }

    macos_exit(0);
}
