// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include "helpers.h"

#include <sys/auxv.h>

int main(void) {
    // Linux always provides the clock rate, flags, and whether the program gained privileges.
    TEST_ASSERT(getauxval(AT_CLKTCK) == 100, "AT_CLKTCK should be USER_HZ");
    TEST_ASSERT(sysconf(_SC_CLK_TCK) == 100, "sysconf(_SC_CLK_TCK) should be USER_HZ");
    errno = 0;
    TEST_ASSERT(getauxval(AT_FLAGS) == 0 && errno == 0, "AT_FLAGS should be zero");
    errno = 0;
    TEST_ASSERT(getauxval(AT_SECURE) == 0 && errno == 0, "AT_SECURE should be zero");
    TEST_ASSERT(getauxval(AT_PAGESZ) == (unsigned long)sysconf(_SC_PAGESIZE),
                "AT_PAGESZ should be the page size");
    puts("All auxv tests passed.");
    return 0;
}
