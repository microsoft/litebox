// probe.c: exercise libc wrappers that try a newer syscall first and fall back to an
// older one when the kernel returns ENOSYS (or EINVAL/EOPNOTSUPP in some cases).
//
// Usage:
//   ./probe            run every test, one line per test
//   ./probe NAME...    run only the named tests
//
// Pair with fault injection to see which wrappers survive a missing syscall:
//   strace -f -qq -o /dev/null -e inject=statx:error=ENOSYS ./probe
//
// SIM_FUTEX_ERRNO=<n> installs a seccomp filter that fails every futex op other than
// WAIT/WAKE/WAIT_BITSET/WAKE_BITSET with errno <n>, mimicking a futex implementation
// that only knows those four ops (LiteBox currently returns EINVAL=22; Linux returns
// ENOSYS=38 for ops it does not know).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1
#endif
#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 1
#endif

extern char **environ;
static const char *self_path;
static char dir[] = "/tmp/probeXXXXXX";
static char path_a[256], path_b[256], path_c[256];
static int fd_a;

static const char *errname(int e) {
    static char buf[16];
    switch (e) {
    case ENOSYS: return "ENOSYS";
    case EINVAL: return "EINVAL";
    case EPERM: return "EPERM";
    case ENOTSUP: return "ENOTSUP";
    case EBADF: return "EBADF";
    case ENOENT: return "ENOENT";
    case EEXIST: return "EEXIST";
    case ETIMEDOUT: return "ETIMEDOUT(hang)";
    case EACCES: return "EACCES";
    default: snprintf(buf, sizeof buf, "%d", e); return buf;
    }
}

static void install_futex_filter(int sim_errno) {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_futex, 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUTEX_WAIT, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUTEX_WAKE, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUTEX_WAIT_BITSET, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FUTEX_WAKE_BITSET, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (sim_errno & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {sizeof f / sizeof f[0], f};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("seccomp");
        exit(2);
    }
}

/* ---- tests: each returns nonzero on success, or 0 with errno set ---- */

static int t_stat(void) { struct stat st; return stat(path_a, &st) == 0; }
static int t_lstat(void) { struct stat st; return lstat(path_a, &st) == 0; }
static int t_fstat(void) { struct stat st; return fstat(fd_a, &st) == 0; }
static int t_fstatat_empty(void) {
    struct stat st;
    return fstatat(fd_a, "", &st, AT_EMPTY_PATH) == 0;
}
static int t_statx(void) {
    struct statx stx;
    return statx(AT_FDCWD, path_a, 0, STATX_BASIC_STATS, &stx) == 0;
}
static int t_access(void) { return access(path_a, R_OK) == 0; }
static int t_faccessat_eaccess(void) {
    return faccessat(AT_FDCWD, path_a, R_OK, AT_EACCESS) == 0;
}
static int t_fchmodat_nofollow(void) {
    return fchmodat(AT_FDCWD, path_a, 0600, AT_SYMLINK_NOFOLLOW) == 0;
}
static int t_utimensat(void) { return utimensat(AT_FDCWD, path_a, NULL, 0) == 0; }
static int t_rename(void) { return rename(path_a, path_b) == 0 && rename(path_b, path_a) == 0; }
static int t_renameat2_noreplace(void) {
    return renameat2(AT_FDCWD, path_a, AT_FDCWD, path_b, RENAME_NOREPLACE) == 0 &&
           rename(path_b, path_a) == 0;
}
static int t_pwrite(void) { return pwrite(fd_a, "hello", 5, 0) == 5; }
static int t_pwritev(void) {
    struct iovec iov = {"hello", 5};
    return pwritev(fd_a, &iov, 1, 0) == 5;
}
static int t_preadv2(void) {
    char b[5];
    struct iovec iov = {b, 5};
    (void)!pwrite(fd_a, "hello", 5, 0);
    return preadv2(fd_a, &iov, 1, 0, 0) == 5;
}
static int t_pwritev2(void) {
    struct iovec iov = {"hello", 5};
    return pwritev2(fd_a, &iov, 1, 0, 0) == 5;
}
static int t_posix_fallocate(void) {
    errno = posix_fallocate(fd_a, 0, 8192);
    return errno == 0;
}
static int t_copy_file_range(void) {
    int fd2 = open(path_c, O_CREAT | O_RDWR | O_TRUNC, 0644);
    loff_t off = 0;
    (void)!pwrite(fd_a, "hello", 5, 0);
    int ok = copy_file_range(fd_a, &off, fd2, NULL, 5, 0) == 5;
    close(fd2);
    return ok;
}
static int t_memfd_create(void) { return memfd_create("x", MFD_CLOEXEC) >= 0; }
static int t_tmpfile(void) {
    FILE *f = tmpfile();
    if (f) fclose(f);
    return f != NULL;
}
static int t_pipe(void) { int p[2]; return pipe(p) == 0; }
static int t_pipe2(void) { int p[2]; return pipe2(p, O_CLOEXEC) == 0; }
static int t_dup2(void) { return dup2(fd_a, 100) == 100; }
static int t_dup3(void) { return dup3(fd_a, 101, O_CLOEXEC) == 101; }
static int t_dupfd_cloexec(void) { return fcntl(fd_a, F_DUPFD_CLOEXEC, 200) >= 200; }
static int t_eventfd(void) { return eventfd(0, EFD_CLOEXEC) >= 0; }
static int t_epoll_create1(void) { return epoll_create1(EPOLL_CLOEXEC) >= 0; }
static int t_epoll_create(void) { return epoll_create(1) >= 0; }
static int t_epoll_wait(void) {
    int p[2], ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN};
    if (ep < 0 || pipe(p)) return 0;
    return epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) == 0 && epoll_wait(ep, &ev, 1, 0) == 0;
}
static int t_signalfd(void) {
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGUSR1);
    return signalfd(-1, &ss, SFD_CLOEXEC) >= 0;
}
static int t_inotify_init1(void) { return inotify_init1(IN_CLOEXEC) >= 0; }
static int t_socket_cloexec(void) {
    return socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) >= 0;
}
static int t_accept4(void) {
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sa = {.sun_family = AF_UNIX};
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s/sock", dir);
    unlink(sa.sun_path);
    if (bind(s, (void *)&sa, sizeof sa) || listen(s, 1)) return 0;
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(c, (void *)&sa, sizeof sa)) return 0;
    return accept4(s, 0, 0, SOCK_CLOEXEC) >= 0;
}
static int t_getrlimit(void) { struct rlimit rl; return getrlimit(RLIMIT_NOFILE, &rl) == 0; }
static int t_setrlimit(void) {
    struct rlimit rl;
    return getrlimit(RLIMIT_NOFILE, &rl) == 0 && setrlimit(RLIMIT_NOFILE, &rl) == 0;
}
static int t_clock_gettime(void) { struct timespec ts; return clock_gettime(CLOCK_MONOTONIC, &ts) == 0; }
static int t_sched_getcpu(void) { return sched_getcpu() >= 0; }
static int t_nprocs(void) { return sysconf(_SC_NPROCESSORS_ONLN) > 0; }
static int t_getrandom(void) { char b[16]; return getrandom(b, 16, 0) == 16; }
#ifdef __GLIBC__
static int t_arc4random(void) { char b[16]; arc4random_buf(b, 16); return 1; }
static int t_closefrom(void) {
    for (int i = 0; i < 5; i++) (void)!dup(0);
    closefrom(3);
    return fcntl(3, F_GETFD) == -1 && errno == EBADF;
}
#endif
static int t_mlock(void) {
    void *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return mlock(m, 4096) == 0;
}
static int t_mlock2(void) {
    void *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return mlock2(m, 4096, MLOCK_ONFAULT) == 0;
}

static void *thr(void *a) { return a; }
static int t_pthread_create(void) {
    pthread_t t;
    return pthread_create(&t, 0, thr, 0) == 0 && pthread_join(t, 0) == 0;
}

static pthread_mutex_t cm = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int go, woke;
static void *cond_waiter(void *a) {
    pthread_mutex_lock(&cm);
    while (!go) pthread_cond_wait(&cv, &cm);
    woke++;
    pthread_mutex_unlock(&cm);
    return a;
}
static int t_cond_broadcast(void) {
    enum { N = 4 };
    pthread_t t[N];
    go = woke = 0;
    for (int i = 0; i < N; i++) pthread_create(&t[i], 0, cond_waiter, 0);
    usleep(100000);
    pthread_mutex_lock(&cm);
    go = 1;
    pthread_cond_broadcast(&cv);
    pthread_mutex_unlock(&cm);
    for (int i = 0; i < 30 && woke < N; i++) usleep(100000);
    if (woke < N) {
        errno = ETIMEDOUT; /* the remaining waiters are stuck; exit() reaps them */
        return 0;
    }
    for (int i = 0; i < N; i++) pthread_join(t[i], 0);
    return 1;
}
static int t_pi_mutex(void) {
    pthread_mutexattr_t a;
    pthread_mutex_t m;
    pthread_mutexattr_init(&a);
    int r = pthread_mutexattr_setprotocol(&a, PTHREAD_PRIO_INHERIT);
    if (!r) r = pthread_mutex_init(&m, &a);
    if (!r) r = pthread_mutex_lock(&m);
    if (!r) r = pthread_mutex_unlock(&m);
    errno = r;
    return r == 0;
}
static pthread_mutex_t robust_m;
static void *lock_and_exit(void *a) { pthread_mutex_lock(&robust_m); return a; }
static int t_robust_mutex(void) {
    pthread_mutexattr_t a;
    pthread_t t;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(&robust_m, &a);
    pthread_create(&t, 0, lock_and_exit, 0); /* owner exits holding the lock */
    pthread_join(t, 0);
    errno = pthread_mutex_lock(&robust_m);
    return errno == EOWNERDEAD;
}
static int t_posix_spawn(void) {
    pid_t pid;
    int status;
    char *argv[] = {(char *)self_path, "--exit0", 0};
    errno = posix_spawn(&pid, self_path, 0, 0, argv, environ);
    return errno == 0 && waitpid(pid, &status, 0) == pid && status == 0;
}
static int t_fork(void) {
    int status;
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    return pid > 0 && waitpid(pid, &status, 0) == pid && status == 0;
}
static int t_fexecve(void) {
    int status;
    pid_t pid = fork();
    if (pid < 0) return 0;
    if (pid == 0) {
        int self = open(self_path, O_RDONLY | O_CLOEXEC);
        char *argv[] = {(char *)self_path, "--exit0", 0};
        fexecve(self, argv, environ);
        _exit(errno);
    }
    waitpid(pid, &status, 0);
    errno = WEXITSTATUS(status);
    return status == 0;
}

static const struct test {
    const char *name;
    int (*fn)(void);
} tests[] = {
    {"stat", t_stat},
    {"lstat", t_lstat},
    {"fstat", t_fstat},
    {"fstatat(AT_EMPTY_PATH)", t_fstatat_empty},
    {"statx()", t_statx},
    {"access", t_access},
    {"faccessat(AT_EACCESS)", t_faccessat_eaccess},
    {"fchmodat(NOFOLLOW)", t_fchmodat_nofollow},
    {"utimensat", t_utimensat},
    {"rename", t_rename},
    {"renameat2(NOREPLACE)", t_renameat2_noreplace},
    {"pwrite", t_pwrite},
    {"pwritev", t_pwritev},
    {"preadv2(flags=0)", t_preadv2},
    {"pwritev2(flags=0)", t_pwritev2},
    {"posix_fallocate", t_posix_fallocate},
    {"copy_file_range", t_copy_file_range},
    {"memfd_create", t_memfd_create},
    {"tmpfile", t_tmpfile},
    {"pipe", t_pipe},
    {"pipe2(O_CLOEXEC)", t_pipe2},
    {"dup2", t_dup2},
    {"dup3(O_CLOEXEC)", t_dup3},
    {"fcntl(F_DUPFD_CLOEXEC)", t_dupfd_cloexec},
    {"eventfd(EFD_CLOEXEC)", t_eventfd},
    {"epoll_create1", t_epoll_create1},
    {"epoll_create", t_epoll_create},
    {"epoll_wait", t_epoll_wait},
    {"signalfd(SFD_CLOEXEC)", t_signalfd},
    {"inotify_init1", t_inotify_init1},
    {"socket(SOCK_CLOEXEC)", t_socket_cloexec},
    {"accept4(SOCK_CLOEXEC)", t_accept4},
    {"getrlimit", t_getrlimit},
    {"setrlimit", t_setrlimit},
    {"clock_gettime", t_clock_gettime},
    {"sched_getcpu", t_sched_getcpu},
    {"sysconf(NPROCESSORS)", t_nprocs},
    {"getrandom", t_getrandom},
#ifdef __GLIBC__
    {"arc4random_buf", t_arc4random},
#endif
    {"mlock", t_mlock},
    {"mlock2(MLOCK_ONFAULT)", t_mlock2},
    {"pthread_create", t_pthread_create},
    {"pthread_cond_broadcast", t_cond_broadcast},
    {"PI mutex", t_pi_mutex},
    {"robust mutex owner death", t_robust_mutex},
    {"posix_spawn", t_posix_spawn},
    {"fork", t_fork},
    {"fexecve", t_fexecve},
#ifdef __GLIBC__
    {"closefrom", t_closefrom},
#endif
};

static void run(const struct test *t) {
    errno = 0;
    int ok = t->fn();
    int e = errno;
    printf("%-26s %s%s%s\n", t->name, ok ? "OK" : "FAIL", ok ? "" : " errno=",
           ok ? "" : errname(e));
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--exit0")) return 0;
    self_path = argv[0];
    setvbuf(stdout, 0, _IONBF, 0);
    const char *sim = getenv("SIM_FUTEX_ERRNO");
    if (sim) install_futex_filter(atoi(sim));

    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
    snprintf(path_a, sizeof path_a, "%s/a", dir);
    snprintf(path_b, sizeof path_b, "%s/b", dir);
    snprintf(path_c, sizeof path_c, "%s/c", dir);
    fd_a = open(path_a, O_CREAT | O_RDWR, 0644);

    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        int selected = argc == 1;
        for (int j = 1; j < argc && !selected; j++) selected = !strcmp(argv[j], tests[i].name);
        if (selected) run(&tests[i]);
    }
    exit(0);
}
