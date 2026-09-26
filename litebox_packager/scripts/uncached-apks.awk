# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

# Given two files: a plain listing of cached filenames (file 1) and a
# tab-separated name/version list of installed packages (file 2), prints
# the name of every installed package whose cache directory has no file
# starting with "<name>-<version>." -- i.e. every package `apk add
# --cache-dir` did not cache (see capture-alpine-apk-manifest.sh's
# comment on zero-content metapackages for why that set is nonempty).
NR == FNR {
    cached[$0] = 1
    next
}
{
    prefix = $1 "-" $2 "."
    found = 0
    for (f in cached) {
        if (index(f, prefix) == 1) {
            found = 1
            break
        }
    }
    if (!found) {
        printf "%s ", $1
    }
}
