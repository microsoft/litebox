#! /bin/bash

# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Script intended to be sourced as a common helper for other scripts.

set -eo pipefail

SCRIPT_DIR=$( cd "$( dirname "$0" )" && pwd -P )

RED="\033[0;31m"
YELLOW="\033[0;33m"
GREEN="\033[0;32m"
BOLD="\033[1m"
RESET="\033[0m"

fatal() {
    echo -e "${RED}${BOLD}[!]${RESET} $1" 1>&2
    exit 1
}

warn() {
    echo -e "${YELLOW}${BOLD}[!]${RESET} $1" 1>&2
}

info() {
    echo -e "${BOLD}[i]${RESET} $1" 1>&2
}
info2() {
    echo -e "      $1" 1>&2
}

success() {
    echo -e "${GREEN}${BOLD}[+]${RESET} $1" 1>&2
}

check_for_tools() {
    missing_tools=0
    while [ $# -gt 0 ]; do
        if ! command -v "$1" &> /dev/null; then
            warn "Required tool ${BOLD}$1${RESET} not found"
            missing_tools=1
        fi
        shift
    done
    if [ $missing_tools -ne 0 ]; then
        fatal "Please install the missing tools and try again"
    fi
}
