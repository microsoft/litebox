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

int main(int argc, char **argv) {
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
    CHECK(shmat(id, rw, 0) == (void *)-1 && errno == EINVAL);
    CHECK(shmat(id, rw + 1, SHM_RND) == (void *)-1 && errno == EINVAL);
    CHECK(mprotect(ro, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
    rw[0] = 'a';
    CHECK(ro[0] == 'a');

    char key_string[32];
    snprintf(key_string, sizeof(key_string), "%d", key);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 4);
        CHECK(ro[0] == 'a');
        execl(self, self, "lookup", key_string, (char *)NULL);
        _exit(2);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(ro[1] == 'b');
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    CHECK(shmget(key, 0, 0) == -1 && errno == ENOENT);
    int replacement = shmget(key, 123, IPC_CREAT | IPC_EXCL | 0600);
    CHECK(replacement >= 0 && replacement != id);
    CHECK(shmctl(replacement, IPC_RMID, NULL) == 0);
    CHECK(shmdt(ro + 1) == -1 && errno == EINVAL);
    CHECK(shmdt(ro) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1);
    CHECK(shmdt(rw) == 0);
    CHECK(shmctl(id, IPC_STAT, &ds) == -1 && errno == EINVAL);

    int first = shmget(IPC_PRIVATE, 4096, 0600);
    int second = shmget(IPC_PRIVATE, 4096, 0600);
    CHECK(first >= 0 && second >= 0 && first != second);
    CHECK(shmctl(first, IPC_RMID, NULL) == 0 && shmctl(second, IPC_RMID, NULL) == 0);
    return 0;
}
