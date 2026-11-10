// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Linux always provides AT_EXECFN, the filename execve received: possibly
// relative, and naming a script rather than its interpreter. Some programs
// (e.g., uutils coreutils) pass it to strlen without a NULL check.
//
// Run with an absolute argv[0] and no other arguments. The program re-executes
// itself, with CHECK_ARGUMENT and the expected filename, through each kind of
// exec.

#include "helpers.h"
#include <sys/auxv.h>

#define CHECK_ARGUMENT "--check-execfn"
#define SCRIPT "tmp/auxv_execfn_script"

static void check_execfn(const char *expected) {
    const char *execfn = (const char *)getauxval(AT_EXECFN);
    TEST_ASSERT(execfn != NULL, "AT_EXECFN is missing");
    if (strcmp(execfn, expected) != 0) {
        fprintf(stderr, "FAIL: AT_EXECFN is \"%s\", expected \"%s\"\n", execfn, expected);
        exit(1);
    }
    printf("AT_EXECFN matches \"%s\"\n", expected);
    fflush(stdout);
}

static void vfork_exec(const char *path, char *const argv[]) {
    pid_t child = vfork();
    if (child == 0) {
        execv(path, argv);
        _exit(127);
    }
    TEST_ASSERT(child > 0, "vfork failed");
    int status = 0;
    TEST_ASSERT(waitpid(child, &status, 0) == child, "waitpid failed");
    TEST_ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0, "re-executed check failed");
}

int main(int argc, char *argv[]) {
    if (argc == 3 && strcmp(argv[1], CHECK_ARGUMENT) == 0) {
        check_execfn(argv[2]);
        return 0;
    }
    TEST_ASSERT(argc == 1 && argv[0][0] == '/', "expected only an absolute argv[0]");
    printf("auxv AT_EXECFN tests starting...\n");

    // The initial program.
    check_execfn(argv[0]);

    // Relative filenames, resolved against the root.
    TEST_ASSERT(chdir("/") == 0, "chdir failed");
    char *self = argv[0] + 1;
    FILE *script = fopen(SCRIPT, "w");
    TEST_ASSERT(script != NULL, "creating the script failed");
    // Linux runs the interpreter with argv: interpreter, argument, script filename.
    fprintf(script, "#!%s %s\n", argv[0], CHECK_ARGUMENT);
    TEST_ASSERT(fclose(script) == 0, "writing the script failed");
    TEST_ASSERT(chmod(SCRIPT, 0755) == 0, "chmod failed");

    vfork_exec(self, (char *[]){self, CHECK_ARGUMENT, self, NULL});
    vfork_exec(SCRIPT, (char *[]){SCRIPT, NULL});

    // Replace this process, which exits with the script's check.
    execv(SCRIPT, (char *[]){SCRIPT, NULL});
    TEST_ASSERT(0, "execv failed");
}
