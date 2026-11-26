// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Checks System V shared memory segments without attaching them: keys, metadata, removal, and the
// summaries and enumeration that `ipcs` uses.

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/shm.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { \
    fprintf(stderr, "line %d: %s (errno=%d)\n", __LINE__, #test, errno); \
    return 1; \
} } while (0)

// Checks the IPC_INFO and SHM_INFO summaries, and SHM_STAT's enumeration by index, which `ipcs`
// uses. Other processes' segments may share the namespace.
static int listing(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    int id = shmget(IPC_PRIVATE, 3 * page, 0600);
    CHECK(id >= 0);
    struct shminfo limits;
    int highest = shmctl(0, IPC_INFO, (struct shmid_ds *)&limits);
    CHECK(highest >= 0 && limits.shmmin == 1 && limits.shmmax >= 3 * page);
    CHECK(shmget(IPC_PRIVATE, limits.shmmax + 1, 0600) == -1 && errno == EINVAL);
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
    ds.shm_perm.mode = 0;
    CHECK(shmctl(id, IPC_SET, &ds) == 0);
    CHECK(shmctl(index, SHM_STAT_ANY, &ds) == id && (ds.shm_perm.mode & 0777) == 0);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    CHECK(shmctl(index, SHM_STAT_ANY, &ds) == -1 && errno == EINVAL);
    return 0;
}

int main(void) {
    CHECK(listing() == 0);
    struct shmid_ds ds;
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
    CHECK(shmctl(id, 99, &ds) == -1 && errno == EINVAL);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    CHECK(shmget(key, 0, 0) == -1 && errno == ENOENT);
    // Linux: an unattached segment is freed as it is removed.
    CHECK(shmctl(id, IPC_STAT, &ds) == -1 && errno == EINVAL);
    int replacement = shmget(key, 123, IPC_CREAT | IPC_EXCL | 0600);
    CHECK(replacement >= 0 && replacement != id);
    CHECK(shmctl(replacement, IPC_RMID, NULL) == 0);

    int first = shmget(IPC_PRIVATE, 4096, 0600);
    int second = shmget(IPC_PRIVATE, 4096, 0600);
    CHECK(first >= 0 && second >= 0 && first != second);
    CHECK(shmctl(first, IPC_RMID, NULL) == 0 && shmctl(second, IPC_RMID, NULL) == 0);
    return 0;
}
