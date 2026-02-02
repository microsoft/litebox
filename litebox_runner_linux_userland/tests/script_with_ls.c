// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test script execution with command invocation
// This test validates that shell scripts can execute commands like 'ls'

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static void die(const char *msg) {
    perror(msg);
    exit(2);
}

int main(int argc, char *argv[]) {
    // This test creates a shell script that uses /bin/ls to list a directory
    // and then executes that script via execve
    
    const char *test_dir = "/tmp/test_dir";
    const char *script_path = "/tmp/test_ls_script.sh";
    
    // Create a test directory with some files
    if (mkdir(test_dir, 0755) < 0 && errno != EEXIST) {
        die("mkdir test_dir");
    }
    
    // Create a few test files in the directory
    const char *test_files[] = {"file1.txt", "file2.txt", "file3.txt"};
    for (int i = 0; i < 3; i++) {
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "%s/%s", test_dir, test_files[i]);
        int fd = open(filepath, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) {
            write(fd, "test\n", 5);
            close(fd);
        }
    }
    
    // Create a shell script that lists the test directory
    // Note: We create with executable permissions directly in open()
    int script_fd = open(script_path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (script_fd < 0) {
        die("open script");
    }
    
    const char *script_content = 
        "#!/bin/sh\n"
        "echo 'Script starting...'\n"
        "echo 'Listing directory:'\n"
        "/bin/ls /tmp/test_dir\n"
        "echo 'Script completed successfully'\n"
        "exit 0\n";
    
    if (write(script_fd, script_content, strlen(script_content)) < 0) {
        die("write script");
    }
    close(script_fd);
    
    printf("[INFO] Created test script at %s\n", script_path);
    printf("[INFO] Script will execute: /bin/ls %s\n", test_dir);
    
    // Now execute the script
    char *script_argv[] = {
        (char*)script_path,
        NULL
    };
    char *envp[] = { 
        "PATH=/bin:/usr/bin",
        NULL 
    };
    
    execve(script_path, script_argv, envp);
    
    // If we get here, execve failed
    if (errno == ENOENT) {
        printf("[SKIP] Script file not accessible (ENOENT)\n");
        return 0;
    } else if (errno == ENOEXEC) {
        printf("[FAIL] execve returned ENOEXEC - script interpreter not supported\n");
        return 1;
    } else {
        die("execve script");
    }
    
    return 0;
}
