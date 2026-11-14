// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks creating UTS and IPC namespaces with `clone`, `clone3`, and `unshare`, and the host and
// NIS domain names a UTS namespace holds: setting and reading them, that the processes in a
// namespace share them, and that a new namespace starts with a copy. Runs as guest root, or, with
// the argument `unprivileged`, as another user, who can't create namespaces or set the names.
//
// LiteBox has no IPC objects, so nothing tells a new IPC namespace apart from its creator's. Those
// checks see only whether creating one succeeds.

#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

// The code each new child exits with.
#define CHILD_CODE 7

// Names that the program and its children set.
#define HOST "parent-host"
#define DOMAIN "parent.domain"
#define CHILD_HOST "child-host"
#define CHILD_DOMAIN "child.domain"
#define OTHER_HOST "other-host"
#define OTHER_DOMAIN "other.domain"

// The longest name, without a terminating NUL (Linux's `__NEW_UTS_LEN`).
#define NAME_MAX_LENGTH 64

extern char **environ;

static int failures;

// This program's path, which children exec.
static char *self_path;

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            printf("failed line=%d errno=%d\n", __LINE__, errno);                                  \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

// Creates a child like `fork`, with clone `flags` and `SIGCHLD` as its exit signal.
static pid_t clone_child(unsigned long flags) {
    return (pid_t)syscall(SYS_clone, flags | SIGCHLD, 0, 0, 0, 0);
}

// Creates a child like `fork` with `clone3`, with clone `flags` and `SIGCHLD` as its exit signal.
static pid_t clone3_child(uint64_t flags) {
    struct clone_args args = {.flags = flags, .exit_signal = SIGCHLD};
    return (pid_t)syscall(SYS_clone3, &args, sizeof args);
}

static char vfork_stack[64 * 1024] __attribute__((aligned(16)));

// Creates a vfork-style child, as `posix_spawn` does, with clone `flags`, which runs `function`
// with `argument`.
static pid_t vfork_child(int flags, int (*function)(void *), void *argument) {
    return clone(function, vfork_stack + sizeof vfork_stack,
                 CLONE_VM | CLONE_VFORK | flags | SIGCHLD, argument);
}

// Returns whether `pid` exited with `code`.
static int exited_with(pid_t pid, int code) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == code;
}

static int exit_now(void *unused) {
    (void)unused;
    _exit(CHILD_CODE);
}

// `clone`, `clone3`, and a vfork-style `clone` create children in new UTS and IPC namespaces.
static void clone_creates_namespaces(void) {
    pid_t child = clone_child(CLONE_NEWUTS | CLONE_NEWIPC);
    if (child == 0) {
        _exit(CHILD_CODE);
    }
    CHECK(child > 0 && exited_with(child, CHILD_CODE));
    child = clone3_child(CLONE_NEWUTS | CLONE_NEWIPC);
    if (child == 0) {
        _exit(CHILD_CODE);
    }
    CHECK(child > 0 && exited_with(child, CHILD_CODE));
    child = vfork_child(CLONE_NEWUTS | CLONE_NEWIPC, exit_now, NULL);
    CHECK(child > 0 && exited_with(child, CHILD_CODE));
}

// Runs `check` in a new child, which `check` may change, and returns whether it returned 0.
static int in_a_child(int (*check)(void)) {
    pid_t child = fork();
    if (child == 0) {
        _exit(check());
    }
    return child > 0 && exited_with(child, 0);
}

static int unshare_alone(void) {
    return unshare(CLONE_NEWUTS | CLONE_NEWIPC) == 0 ? 0 : 1;
}

static int unshare_with_a_pid_namespace(void) {
    return unshare(CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC) == 0 ? 0 : 1;
}

// Waits for a byte from the pipe whose read end `fd` points to.
static void *wait_for_byte(void *fd) {
    char byte;
    return read(*(int *)fd, &byte, 1) == 1 ? NULL : fd;
}

static int unshare_with_another_thread(void) {
    int release[2];
    pthread_t thread;
    if (pipe(release) != 0 || pthread_create(&thread, NULL, wait_for_byte, &release[0]) != 0) {
        return 1;
    }
    int code = unshare(CLONE_NEWUTS | CLONE_NEWIPC) == 0 ? 0 : 2;
    if (write(release[1], "x", 1) != 1 || pthread_join(thread, NULL) != 0) {
        return 3;
    }
    return code;
}

// An `unshare` a vfork child makes: its flags, and the error it got, or 0.
struct vfork_unshare {
    int flags;
    int error;
};

// Runs in a vfork child: makes the `unshare` that `request`, a `struct vfork_unshare`, describes.
static int unshare_and_exit(void *request) {
    struct vfork_unshare *unshare_request = request;
    unshare_request->error = unshare(unshare_request->flags) == -1 ? errno : 0;
    _exit(CHILD_CODE);
}

// Calls `unshare(flags)` in a vfork-style child, returning the error it got, 0 if it succeeded, or
// -1 if the child didn't run as expected.
static int unshare_in_a_vfork_child(int flags) {
    struct vfork_unshare request = {flags, -1};
    pid_t child = vfork_child(0, unshare_and_exit, &request);
    if (child <= 0 || !exited_with(child, CHILD_CODE)) {
        return -1;
    }
    return request.error;
}

// `unshare` creates UTS and IPC namespaces, alone, with a PID namespace, with another thread, and
// in a vfork child.
static void unshare_creates_namespaces(void) {
    CHECK(in_a_child(unshare_alone));
    CHECK(in_a_child(unshare_with_a_pid_namespace));
    CHECK(in_a_child(unshare_with_another_thread));
    CHECK(unshare_in_a_vfork_child(CLONE_NEWUTS | CLONE_NEWIPC) == 0);
}

// Returns whether the `uname` field `field` holds the `length` bytes at `name`, then only zeros.
static int holds(const char *field, const char *name, size_t length) {
    if (memcmp(field, name, length) != 0) {
        return 0;
    }
    for (size_t i = length; i < sizeof ((struct utsname *)0)->nodename; i++) {
        if (field[i] != 0) {
            return 0;
        }
    }
    return 1;
}

// Returns whether `uname` reports host name `host` and domain name `domain`.
static int has_names(const char *host, const char *domain) {
    struct utsname names;
    return uname(&names) == 0 && holds(names.nodename, host, strlen(host)) &&
           holds(names.domainname, domain, strlen(domain));
}

// Sets the host and domain names, returning whether both succeeded.
static int set_names(const char *host, const char *domain) {
    return sethostname(host, strlen(host)) == 0 && setdomainname(domain, strlen(domain)) == 0;
}

// Returns an address no mapping covers, right after a mapped page, or NULL.
static char *unmapped_address(void) {
    long size = sysconf(_SC_PAGESIZE);
    char *pages = mmap(NULL, 2 * size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pages == MAP_FAILED || munmap(pages + size, size) != 0) {
        return NULL;
    }
    return pages + size;
}

// The syscalls that set the host name and the domain name.
static const long setters[] = {SYS_sethostname, SYS_setdomainname};

// Returns whether the setter `number`, given `name` and `length`, fails with `error` and leaves the
// names `HOST` and `DOMAIN`.
static int fails_with(long number, const char *name, long length, int error) {
    int failed = syscall(number, name, length) == -1 && errno == error;
    return failed && has_names(HOST, DOMAIN);
}

// `sethostname` and `setdomainname` take up to 64 bytes, kept as given, and zero the rest of the
// name, as `uname`, `gethostname`, and `getdomainname` report. They check the length before the
// bytes, and a failed call changes nothing.
static void set_and_read_names(void) {
    char longest[NAME_MAX_LENGTH + 1];
    memset(longest, 'x', sizeof longest);
    CHECK(sethostname(longest, NAME_MAX_LENGTH) == 0);
    CHECK(setdomainname(longest, NAME_MAX_LENGTH) == 0);
    struct utsname names;
    CHECK(uname(&names) == 0 && holds(names.nodename, longest, NAME_MAX_LENGTH) &&
          holds(names.domainname, longest, NAME_MAX_LENGTH));
    char name[NAME_MAX_LENGTH + 1];
    CHECK(gethostname(name, sizeof name) == 0 && memcmp(name, longest, NAME_MAX_LENGTH) == 0 &&
          name[NAME_MAX_LENGTH] == 0);
    CHECK(getdomainname(name, sizeof name) == 0 && memcmp(name, longest, NAME_MAX_LENGTH) == 0 &&
          name[NAME_MAX_LENGTH] == 0);

    // A shorter name clears the rest of a longer one, and an empty one clears it all.
    CHECK(set_names(HOST, DOMAIN) && has_names(HOST, DOMAIN));
    CHECK(gethostname(name, sizeof name) == 0 && strcmp(name, HOST) == 0);
    CHECK(getdomainname(name, sizeof name) == 0 && strcmp(name, DOMAIN) == 0);
    CHECK(sethostname("", 0) == 0 && has_names("", DOMAIN));
    // The bytes are kept as given, zero bytes included.
    CHECK(sethostname("a\0b", 3) == 0 && uname(&names) == 0 && holds(names.nodename, "a\0b", 3));

    CHECK(set_names(HOST, DOMAIN));
    char *unmapped = unmapped_address();
    CHECK(unmapped != NULL);
    for (size_t i = 0; unmapped != NULL && i < sizeof setters / sizeof setters[0]; i++) {
        CHECK(fails_with(setters[i], longest, NAME_MAX_LENGTH + 1, EINVAL));
        CHECK(fails_with(setters[i], longest, -1, EINVAL));
        CHECK(fails_with(setters[i], unmapped, NAME_MAX_LENGTH + 1, EINVAL));
        CHECK(fails_with(setters[i], unmapped, 4, EFAULT));
        // A name that runs into the unmapped page.
        CHECK(fails_with(setters[i], unmapped - 2, 4, EFAULT));
    }
}

// The processes in a namespace share its names: a change by a child created by `fork`, by a
// vfork child, or by a program a child execs, reaches this program.
static void children_share_the_names(void) {
    CHECK(set_names(HOST, DOMAIN));
    pid_t child = fork();
    if (child == 0) {
        _exit(set_names(CHILD_HOST, CHILD_DOMAIN) ? 0 : 1);
    }
    CHECK(child > 0 && exited_with(child, 0));
    CHECK(has_names(CHILD_HOST, CHILD_DOMAIN));

    // What the vfork child read before and after setting the host name, in memory it shares with
    // this program.
    static int read_before, read_after;
    child = vfork();
    if (child == 0) {
        read_before = has_names(CHILD_HOST, CHILD_DOMAIN);
        read_after = sethostname(HOST, strlen(HOST)) == 0 && has_names(HOST, CHILD_DOMAIN);
        _exit(CHILD_CODE);
    }
    CHECK(child > 0 && exited_with(child, CHILD_CODE) && read_before && read_after);
    CHECK(has_names(HOST, CHILD_DOMAIN));

    child = fork();
    if (child == 0) {
        char *const argv[] = {self_path, "set", OTHER_HOST, NULL};
        execve(self_path, argv, environ);
        _exit(2);
    }
    CHECK(child > 0 && exited_with(child, 0));
    CHECK(has_names(OTHER_HOST, CHILD_DOMAIN));
}

// Runs in a child in a new UTS namespace: checks that it starts with its parent's names, then,
// once its parent changed its own, which it doesn't see, sets its own names.
static int keep_names_apart(int ready, int changed) {
    char byte;
    if (!has_names(HOST, DOMAIN) || write(ready, "x", 1) != 1 || read(changed, &byte, 1) != 1) {
        return 1;
    }
    return has_names(HOST, DOMAIN) && set_names(CHILD_HOST, CHILD_DOMAIN) &&
                   has_names(CHILD_HOST, CHILD_DOMAIN)
               ? 0
               : 2;
}

// A child in a new UTS namespace, from `clone` or `clone3`, starts with a copy of its parent's
// names, and a change on either side doesn't reach the other.
static void new_namespaces_are_separate(void) {
    for (int use_clone3 = 0; use_clone3 <= 1; use_clone3++) {
        CHECK(set_names(HOST, DOMAIN));
        int ready[2], changed[2];
        if (pipe(ready) != 0 || pipe(changed) != 0) {
            CHECK(0);
            return;
        }
        pid_t child = use_clone3 ? clone3_child(CLONE_NEWUTS) : clone_child(CLONE_NEWUTS);
        if (child == 0) {
            // Each side keeps only the ends it uses, so it sees a pipe close if the other fails.
            close(ready[0]);
            close(changed[1]);
            _exit(keep_names_apart(ready[1], changed[0]));
        }
        close(ready[1]);
        close(changed[0]);
        char byte;
        CHECK(child > 0 && read(ready[0], &byte, 1) == 1);
        CHECK(set_names(OTHER_HOST, OTHER_DOMAIN));
        CHECK(write(changed[1], "x", 1) == 1);
        close(changed[1]);
        CHECK(child > 0 && exited_with(child, 0));
        CHECK(has_names(OTHER_HOST, OTHER_DOMAIN));
        close(ready[0]);
    }
}

// Sets this process's names to `CHILD_HOST` and `CHILD_DOMAIN`, returning whether `uname` and
// `gethostname` then report them.
static int set_and_read_child_names(void) {
    char name[NAME_MAX_LENGTH + 1];
    return set_names(CHILD_HOST, CHILD_DOMAIN) && has_names(CHILD_HOST, CHILD_DOMAIN) &&
           gethostname(name, sizeof name) == 0 && strcmp(name, CHILD_HOST) == 0;
}

// Runs in a vfork child in a new UTS namespace: records at `read_back`, an `int`, whether it reads
// back the names it sets, then execs this program to check that it keeps them.
static int set_names_and_exec(void *read_back) {
    *(int *)read_back = set_and_read_child_names();
    char *const argv[] = {self_path, "check", CHILD_HOST, CHILD_DOMAIN, NULL};
    execve(self_path, argv, environ);
    _exit(2);
}

// Runs in a vfork child: moves to a new UTS namespace, then records at `read_back`, an `int`,
// whether it reads back the names it sets.
static int unshare_and_set_names(void *read_back) {
    *(int *)read_back = unshare(CLONE_NEWUTS) == 0 && set_and_read_child_names();
    _exit(CHILD_CODE);
}

// A vfork child in a new UTS namespace, from `clone` or its own `unshare`, has its own names while
// it shares its parent's memory, and keeps them in the program it execs. Its parent's don't change.
static void vfork_children_have_their_own_names(void) {
    CHECK(set_names(HOST, DOMAIN));
    int read_back = 0;
    pid_t child = vfork_child(CLONE_NEWUTS, set_names_and_exec, &read_back);
    CHECK(child > 0 && exited_with(child, 0) && read_back);
    CHECK(has_names(HOST, DOMAIN));
    read_back = 0;
    child = vfork_child(0, unshare_and_set_names, &read_back);
    CHECK(child > 0 && exited_with(child, CHILD_CODE) && read_back);
    CHECK(has_names(HOST, DOMAIN));
}

// Runs in a helper that has a child, `other`, waiting for a byte on `moved`: unshares a UTS
// namespace and sets its host name, which `other` doesn't see, then waits for `other` to set its
// own on `changed`, which the helper doesn't see. A child the helper creates afterwards shares the
// helper's names.
static int move_away_from_a_child(pid_t other, int moved, int changed) {
    int moved_away =
        unshare(CLONE_NEWUTS) == 0 && sethostname(CHILD_HOST, strlen(CHILD_HOST)) == 0;
    // Without the byte, `other` sees the pipe close and fails rather than waiting.
    int told = moved_away && write(moved, "x", 1) == 1;
    close(moved);
    char byte;
    int heard = read(changed, &byte, 1) == 1;
    if (!exited_with(other, 0) || !told || !heard) {
        return 1;
    }
    if (!has_names(CHILD_HOST, DOMAIN)) {
        return 2;
    }
    pid_t child = fork();
    if (child == 0) {
        _exit(has_names(CHILD_HOST, DOMAIN) &&
                      setdomainname(OTHER_DOMAIN, strlen(OTHER_DOMAIN)) == 0
                  ? 0
                  : 1);
    }
    return child > 0 && exited_with(child, 0) && has_names(CHILD_HOST, OTHER_DOMAIN) ? 0 : 3;
}

// Runs in a helper's child, which stays in the helper's first UTS namespace: once the helper moved
// away, it still has the old names, and sets its own.
static int stay_behind(int moved, int changed) {
    char byte;
    return read(moved, &byte, 1) == 1 && has_names(HOST, DOMAIN) &&
                   sethostname(OTHER_HOST, strlen(OTHER_HOST)) == 0 && write(changed, "x", 1) == 1
               ? 0
               : 1;
}

// `unshare` moves only the calling process to a new UTS namespace: a helper unshares while its
// child stays in this program's namespace.
static int unshare_moves_the_caller(void) {
    int moved[2], changed[2];
    if (pipe(moved) != 0 || pipe(changed) != 0) {
        return 1;
    }
    pid_t other = fork();
    if (other == 0) {
        // Each side keeps only the ends it uses, so it sees a pipe close if the other fails.
        close(moved[1]);
        close(changed[0]);
        _exit(stay_behind(moved[0], changed[1]));
    }
    close(moved[0]);
    close(changed[1]);
    return other > 0 ? move_away_from_a_child(other, moved[1], changed[0]) : 1;
}

// `unshare` creates a UTS namespace for the caller alone, with a copy of its names.
static void unshare_copies_the_names(void) {
    CHECK(set_names(HOST, DOMAIN));
    CHECK(in_a_child(unshare_moves_the_caller));
    // The helper's child stayed in this program's namespace.
    CHECK(has_names(OTHER_HOST, DOMAIN));
}

// Without root, the names can't be set, even with an invalid length or address. `uname` and
// `unshare` without namespaces still work.
static void unprivileged_changes_no_names(void) {
    char longest[NAME_MAX_LENGTH + 1];
    memset(longest, 'x', sizeof longest);
    char *unmapped = unmapped_address();
    CHECK(unmapped != NULL);
    for (size_t i = 0; unmapped != NULL && i < sizeof setters / sizeof setters[0]; i++) {
        CHECK(syscall(setters[i], longest, NAME_MAX_LENGTH + 1) == -1 && errno == EPERM);
        CHECK(syscall(setters[i], unmapped, 4) == -1 && errno == EPERM);
    }
    struct utsname names;
    CHECK(uname(&names) == 0);
    CHECK(unshare(0) == 0);
}

// Without root, neither `unshare` nor `clone`, also vfork-style, creates a UTS or IPC namespace.
static void unprivileged_creates_nothing(void) {
    const int flags[] = {CLONE_NEWUTS, CLONE_NEWIPC};
    for (size_t i = 0; i < sizeof flags / sizeof flags[0]; i++) {
        CHECK(unshare(flags[i]) == -1 && errno == EPERM);
        pid_t child = clone_child((unsigned long)flags[i]);
        if (child == 0) {
            _exit(CHILD_CODE);
        }
        CHECK(child == -1 && errno == EPERM);
        if (child > 0) {
            exited_with(child, CHILD_CODE);
        }
        child = vfork_child(flags[i], exit_now, NULL);
        CHECK(child == -1 && errno == EPERM);
        if (child > 0) {
            exited_with(child, CHILD_CODE);
        }
    }
    // LiteBox refuses `CLONE_NEWPID` in a vfork child, but only after the permission check.
    CHECK(unshare_in_a_vfork_child(CLONE_NEWPID | CLONE_NEWUTS) == EPERM);
}

int main(int argc, char **argv) {
    // A program a child execs checks that it has the given names, or sets the given host name.
    if (argc == 4 && strcmp(argv[1], "check") == 0) {
        return has_names(argv[2], argv[3]) ? 0 : 1;
    }
    if (argc == 3 && strcmp(argv[1], "set") == 0) {
        return sethostname(argv[2], strlen(argv[2])) == 0 ? 0 : 1;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 1 && strcmp(argv[1], "unprivileged") == 0) {
        unprivileged_creates_nothing();
        unprivileged_changes_no_names();
        printf("uts-ipc-namespace unprivileged failures=%d\n", failures);
        return failures != 0;
    }
    self_path = argv[0];
    // A write to a pipe whose reader failed and exited fails rather than ending this program.
    signal(SIGPIPE, SIG_IGN);
    clone_creates_namespaces();
    unshare_creates_namespaces();
    set_and_read_names();
    children_share_the_names();
    new_namespaces_are_separate();
    vfork_children_have_their_own_names();
    unshare_copies_the_names();
    printf("uts-ipc-namespace failures=%d\n", failures);
    return failures != 0;
}
