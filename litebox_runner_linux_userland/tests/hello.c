#include <stdio.h>
#include <unistd.h>
#include <time.h>
 
void test_vdso_clock_gettime() {
    /// call clock_gettime
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    // Do some work
    for (int i = 0; i < 100000000; i++);
    clock_gettime(CLOCK_MONOTONIC, &end);
    // Calculate elapsed time
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Elapsed time: %f seconds\n", elapsed);
}

int main(int argc, char *argv[], char *envp[]) {
    int i;
    for (i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }

    for (i = 0; envp[i] != NULL; i++) {
        printf("envp[%d] = %s\n", i, envp[i]);
    }

    test_vdso_clock_gettime();

    return 0;
}