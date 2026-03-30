#! /bin/sh

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Script intended to be sourced as a common helper for other scripts.

set -e

SCRIPT_DIR=$( cd "$( dirname "$0" )" && pwd -P )

RED=$(printf '\033[0;31m')
YELLOW=$(printf '\033[0;33m')
GREEN=$(printf '\033[0;32m')
BOLD=$(printf '\033[1m')
RESET=$(printf '\033[0m')

fatal() {
    printf "${RED}${BOLD}[!]${RESET} %s\n" "$1" 1>&2
    exit 1
}

warn() {
    printf "${YELLOW}${BOLD}[!]${RESET} %s\n" "$1" 1>&2
}

info() {
    printf "${BOLD}[i]${RESET} %s\n" "$1" 1>&2
}
info2() {
    printf "      %s\n" "$1" 1>&2
}

success() {
    printf "${GREEN}${BOLD}[+]${RESET} %s\n" "$1" 1>&2
}

check_for_tools() {
    missing_tools=0
    while [ $# -gt 0 ]; do
        if ! command -v "$1" > /dev/null 2>&1; then
            warn "Required tool ${BOLD}$1${RESET} not found"
            missing_tools=1
        fi
        shift
    done
    if [ "$missing_tools" -ne 0 ]; then
        fatal "Please install the missing tools and try again"
    fi
}
