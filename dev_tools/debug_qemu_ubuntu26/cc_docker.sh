#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# DEBUG (ubuntu-26.04 CI SIGILL): a C compiler for run_linux_on_vm_userland.sh's
# CC, from the Docker image $CC_DOCKER_IMAGE (another glibc); the host's for
# -print-file-name. Sources are under $GITHUB_WORKSPACE, outputs under
# $RUNNER_TEMP.

for arg in "$@"; do
    [[ $arg != -print-file-name=* ]] || exec cc "$@"
done
exec docker run --rm --user "$(id -u):$(id -g)" \
    -v "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE" -v "$RUNNER_TEMP:$RUNNER_TEMP" \
    -w "$PWD" "$CC_DOCKER_IMAGE" gcc "$@"
