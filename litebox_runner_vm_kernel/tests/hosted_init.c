// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// As litebox.init, which takes no arguments: executes the command line in `<own path>.args`, an
// argument a line, staying process 1.

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_ARGS 64

int main(int argc, char **argv) {
    (void)argc;
    char path[4096];
    snprintf(path, sizeof path, "%s.args", argv[0]);
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        perror(path);
        return 127;
    }
    static char lines[MAX_ARGS][1024];
    char *args[MAX_ARGS + 1];
    int count = 0;
    while (count < MAX_ARGS && fgets(lines[count], sizeof lines[count], file) != NULL) {
        lines[count][strcspn(lines[count], "\n")] = '\0';
        args[count] = lines[count];
        count++;
    }
    fclose(file);
    args[count] = NULL;
    if (count == 0) {
        fprintf(stderr, "%s: no command line\n", path);
        return 127;
    }
    execv(args[0], args);
    perror(args[0]);
    return 127;
}
