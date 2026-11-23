// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "line %d: %s (errno=%d)\n", __LINE__, #test, errno); \
    return 1; \
} } while (0)

static int split_attachment(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    int id = shmget(IPC_PRIVATE, 4 * page, 0600);
    CHECK(id >= 0);
    char *data = shmat(id, NULL, 0);
    CHECK(data != (void *)-1);
    struct shmid_ds ds;
    CHECK(munmap(data + page, page) == 0);
    // Linux counts both surviving VMAs, even though shmdt removes them as one attachment.
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 2);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 4);
        // Linux: splitting a VMA opens the new one as the splitting process (`shm_open`).
        CHECK(mprotect(data + 3 * page, page, PROT_READ) == 0);
        CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 5 && ds.shm_lpid == getpid());
        _exit(0);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 2);
    CHECK(shmdt(data) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 0);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    return 0;
}

// Checks the permission bits and ownership rules as the creator, without privilege.
static int permissions(void) {
    struct shmid_ds ds;
    int id = shmget(IPC_PRIVATE, 4096, 0400);
    CHECK(id >= 0);
    CHECK(shmat(id, NULL, 0) == (void *)-1 && errno == EACCES);
    char *ro = shmat(id, NULL, SHM_RDONLY);
    CHECK(ro != (void *)-1);
    CHECK(shmdt(ro) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0);
    ds.shm_perm.mode = 0;
    CHECK(shmctl(id, IPC_SET, &ds) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == -1 && errno == EACCES);
    // IPC_SET may give the segment away; its creator still controls it.
    ds.shm_perm.uid = geteuid() + 1;
    ds.shm_perm.mode = 0600;
    CHECK(shmctl(id, IPC_SET, &ds) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_perm.uid == geteuid() + 1);
    CHECK(ds.shm_perm.cuid == geteuid());
    ds.shm_perm.uid = geteuid();
    CHECK(shmctl(id, IPC_SET, &ds) == 0);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    return 0;
}

// Checks the IPC_INFO and SHM_INFO summaries, and SHM_STAT's enumeration by index, which `ipcs`
// uses. Other processes' segments may share the namespace.
static int listing(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    int id = shmget(IPC_PRIVATE, 3 * page, 0600);
    CHECK(id >= 0);
    struct shminfo limits;
    int highest = shmctl(0, IPC_INFO, (struct shmid_ds *)&limits);
    CHECK(highest >= 0 && limits.shmmin == 1 && limits.shmmax >= 3 * page);
    CHECK(limits.shmmni > 0 && limits.shmall >= 3);
    struct shm_info usage;
    CHECK(shmctl(0, SHM_INFO, (struct shmid_ds *)&usage) == highest);
    CHECK(usage.used_ids >= 1 && usage.shm_tot >= 3);
    // Indexes up to the highest one name the segments; SHM_STAT returns the segment's ID.
    struct shmid_ds ds;
    int index = -1;
    for (int i = 0; i <= highest && index < 0; i++) {
        if (shmctl(i, SHM_STAT, &ds) == id) {
            index = i;
        }
    }
    CHECK(index >= 0 && ds.shm_segsz == 3 * page);
    CHECK(shmctl(-1, SHM_STAT, &ds) == -1 && errno == EINVAL);
    // Linux: SHM_STAT needs read permission, unlike SHM_STAT_ANY.
    ds.shm_perm.mode = 0;
    CHECK(shmctl(id, IPC_SET, &ds) == 0);
    CHECK(shmctl(index, SHM_STAT, &ds) == -1 && errno == EACCES);
    CHECK(shmctl(index, SHM_STAT_ANY, &ds) == id && (ds.shm_perm.mode & 0777) == 0);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    CHECK(shmctl(index, SHM_STAT_ANY, &ds) == -1 && errno == EINVAL);
    return 0;
}

// Checks that SHM_EXEC needs the execute permission bit and maps executable pages, and that
// SHM_REMAP replaces what the range maps.
static int exec_and_remap(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    int id = shmget(IPC_PRIVATE, page, 0600);
    CHECK(id >= 0);
    CHECK(shmat(id, NULL, SHM_EXEC) == (void *)-1 && errno == EACCES);
    struct shmid_ds ds;
    CHECK(shmctl(id, IPC_STAT, &ds) == 0);
    ds.shm_perm.mode = 0700;
    CHECK(shmctl(id, IPC_SET, &ds) == 0);
    unsigned char *data = shmat(id, NULL, 0);
    unsigned char *code = shmat(id, NULL, SHM_EXEC | SHM_RDONLY);
    CHECK(data != (void *)-1 && code != (void *)-1);
#if defined(__x86_64__)
    static const unsigned char ret[] = {0xc3};
#elif defined(__aarch64__)
    static const unsigned char ret[] = {0xc0, 0x03, 0x5f, 0xd6};
#else
#error "unsupported architecture"
#endif
    memcpy(data, ret, sizeof(ret));
    __builtin___clear_cache((char *)code, (char *)code + sizeof(ret));
    ((void (*)(void))code)();

    unsigned char *area = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(area != MAP_FAILED);
    area[0] = 'a';
    area[2 * page] = 'c';
    CHECK(shmat(id, area + page, 0) == (void *)-1 && errno == EINVAL);
    CHECK(shmat(id, NULL, SHM_REMAP) == (void *)-1 && errno == EINVAL);
    CHECK(shmat(id, (void *)1, SHM_RND | SHM_REMAP) == (void *)-1 && errno == EINVAL);
    CHECK((unsigned char *)shmat(id, area + page, SHM_REMAP) == area + page);
    CHECK(area[page] == ret[0] && area[0] == 'a' && area[2 * page] == 'c');
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 3);
    // Replacing an attachment detaches it.
    CHECK((unsigned char *)shmat(id, data, SHM_REMAP | SHM_RDONLY) == data);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 3);
    CHECK(shmdt(area + page) == 0 && shmdt(data) == 0 && shmdt(code) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 0);
    CHECK(area[0] == 'a' && area[2 * page] == 'c');
    CHECK(munmap(area, 3 * page) == 0);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    return 0;
}

int main(int argc, char **argv) {
    // Fail rather than hang if a wait never ends.
    alarm(30);
    struct shmid_ds ds;
    if (argc == 3 && !strcmp(argv[1], "lookup")) {
        int id = shmget((key_t)atoi(argv[2]), 0, 0);
        CHECK(id >= 0);
        CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 2);
        char *data = shmat(id, NULL, 0);
        CHECK(data != (void *)-1 && data[0] == 'a');
        data[1] = 'b';
        return 0; // exit detaches
    }

    // The child reruns this program, from its own path, to look the segment up by key.
    const char *self = argv[0];
    CHECK(argc == 1 && self[0] == '/');
    CHECK(split_attachment() == 0);
    CHECK(permissions() == 0);
    CHECK(listing() == 0);
    CHECK(exec_and_remap() == 0);
    key_t key = getpid();
    int id = shmget(key, 123, IPC_CREAT | IPC_EXCL | 0600);
    CHECK(id >= 0);
    CHECK(shmget(key, 1, IPC_CREAT | IPC_EXCL) == -1 && errno == EEXIST);
    CHECK(shmget(key, 124, 0) == -1 && errno == EINVAL);
    CHECK(shmget(key, 0, 0) == id);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_segsz == 123 && ds.shm_nattch == 0);
    CHECK(ds.shm_cpid == getpid() && ds.shm_perm.uid == geteuid());
    ds.shm_perm.mode = 0640;
    CHECK(shmctl(id, IPC_SET, &ds) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && (ds.shm_perm.mode & 0777) == 0640);
    char *rw = shmat(id, NULL, 0);
    CHECK(rw != (void *)-1 && rw[0] == 0);
    char *ro = shmat(id, NULL, SHM_RDONLY);
    CHECK(ro != (void *)-1 && ro != rw);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        // In another process, so that recording a failed attach would change the last PID.
        struct shmid_ds before_failure;
        CHECK(shmctl(id, IPC_STAT, &before_failure) == 0);
        CHECK(shmat(id, rw, 0) == (void *)-1 && errno == EINVAL);
        CHECK(shmat(id, rw + 1, SHM_RND) == (void *)-1 && errno == EINVAL);
        CHECK(shmctl(id, IPC_STAT, &ds) == 0);
        CHECK(ds.shm_nattch == before_failure.shm_nattch &&
              ds.shm_atime == before_failure.shm_atime &&
              ds.shm_dtime == before_failure.shm_dtime &&
              ds.shm_lpid == before_failure.shm_lpid);
        _exit(0);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(mprotect(ro, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    rw[0] = 'a';
    CHECK(ro[0] == 'a');

    char key_string[32];
    snprintf(key_string, sizeof(key_string), "%d", key);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        // Linux credits fork's implicit attaches to the parent.
        CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 4 && ds.shm_lpid == getppid());
        CHECK(ro[0] == 'a');
        execl(self, self, "lookup", key_string, (char *)NULL);
        _exit(2);
    }
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(ro[1] == 'b');
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 2 && ds.shm_lpid == pid);
    // SHM_RND rounds a free address down to the page.
    CHECK(shmdt(rw) == 0);
    CHECK((char *)shmat(id, rw + 1, SHM_RND) == rw && rw[0] == 'a');
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    CHECK(shmget(key, 0, 0) == -1 && errno == ENOENT);
    // Linux: a removed segment stays attachable by ID until its last detach.
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && (ds.shm_perm.mode & SHM_DEST) &&
          ds.shm_perm.__key == IPC_PRIVATE);
    char *again = shmat(id, NULL, SHM_RDONLY);
    CHECK(again != (void *)-1 && again[0] == 'a');
    CHECK(shmdt(again) == 0);
    int replacement = shmget(key, 123, IPC_CREAT | IPC_EXCL | 0600);
    CHECK(replacement >= 0 && replacement != id);
    CHECK(shmctl(replacement, IPC_RMID, NULL) == 0);
    CHECK(shmdt(ro + 1) == -1 && errno == EINVAL);
    CHECK(shmdt(ro) == 0);
    CHECK(shmdt(ro) == -1 && errno == EINVAL);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1 && ds.shm_lpid == getpid());
    CHECK(shmdt(rw) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == -1 && errno == EINVAL);

    int first = shmget(IPC_PRIVATE, 4096, 0600);
    int second = shmget(IPC_PRIVATE, 4096, 0600);
    CHECK(first >= 0 && second >= 0 && first != second);
    CHECK(shmctl(first, IPC_RMID, NULL) == 0 && shmctl(second, IPC_RMID, NULL) == 0);
    return 0;
}
