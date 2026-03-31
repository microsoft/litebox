#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    const char *mode = getenv("MODE");
    if (mode && strcmp(mode, "cat") == 0) {
        // Act as cat: read stdin, write to stdout
        char buf[4096];
        ssize_t n;
        while ((n = read(0, buf, sizeof(buf))) > 0) {
            write(1, buf, n);
        }
        return 0;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) { perror("pipe"); return 1; }
    
    fprintf(stderr, "pipe: read=%d write=%d\n", pipefd[0], pipefd[1]);

    // Fork right side first (cat - will exec)
    pid_t cat_pid = vfork();
    if (cat_pid < 0) { perror("vfork cat"); return 1; }
    if (cat_pid == 0) {
        dup2(pipefd[0], 0);
        close(pipefd[0]);
        close(pipefd[1]);
        char *argv[] = { "/proc/self/exe", NULL };
        char *envp[] = { "MODE=cat", NULL };
        execve("/proc/self/exe", argv, envp);
        _exit(99);
    }
    fprintf(stderr, "cat_pid=%d\n", cat_pid);

    // Fork left side (echo - no exec!)
    pid_t echo_pid = vfork();
    if (echo_pid < 0) { perror("vfork echo"); return 1; }
    if (echo_pid == 0) {
        dup2(pipefd[1], 1);
        close(pipefd[0]);
        close(pipefd[1]);
        write(1, "hello-from-vfork\n", 17);
        _exit(0);
    }
    fprintf(stderr, "echo_pid=%d\n", echo_pid);

    // Parent: close pipe ends
    close(pipefd[0]);
    close(pipefd[1]);
    fprintf(stderr, "parent: pipe closed, waiting...\n");

    int status;
    waitpid(echo_pid, &status, 0);
    fprintf(stderr, "echo exited: %d\n", WEXITSTATUS(status));
    waitpid(cat_pid, &status, 0);
    fprintf(stderr, "cat exited: %d\n", WEXITSTATUS(status));

    return 0;
}
