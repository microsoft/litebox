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
