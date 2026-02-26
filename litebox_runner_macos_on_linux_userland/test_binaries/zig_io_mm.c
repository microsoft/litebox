typedef unsigned long usize;
enum {
    MACOS_SYSCALL_CLASS_UNIX = 0x2000000,
    MACOS_SYS_EXIT = MACOS_SYSCALL_CLASS_UNIX | 1,
    MACOS_SYS_WRITE = MACOS_SYSCALL_CLASS_UNIX | 4,
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
    static const char payload[] = "zig-io-mm: zig toolchain smoke ok\n";
    long written = macos_syscall3(MACOS_SYS_WRITE, 1, (long)(usize)payload, sizeof(payload) - 1);
    if (written != (long)(sizeof(payload) - 1)) {
        macos_exit(12);
    }

    macos_exit(0);
}
