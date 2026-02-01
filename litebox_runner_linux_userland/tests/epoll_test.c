// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Test EPOLL_CTL_MOD functionality

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <stdint.h>

#define TEST_PASS(name) printf("[PASS] %s\n", name)
#define TEST_FAIL(name, msg) do { printf("[FAIL] %s: %s\n", name, msg); exit(1); } while(0)

void test_epoll_ctl_mod_basic(void) {
    const char *test_name = "epoll_ctl_mod_basic";

    // Create epoll instance
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        TEST_FAIL(test_name, "epoll_create1 failed");
    }

    // Create eventfd
    int efd = eventfd(0, EFD_NONBLOCK);
    if (efd < 0) {
        close(epfd);
        TEST_FAIL(test_name, "eventfd failed");
    }

    // Add eventfd with EPOLLIN
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u64 = 42;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev) < 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "EPOLL_CTL_ADD failed");
    }

    // Modify to EPOLLOUT with different data
    ev.events = EPOLLOUT;
    ev.data.u64 = 99;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, efd, &ev) < 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "EPOLL_CTL_MOD failed");
    }

    // Wait for events - eventfd should be writable
    struct epoll_event events[1];
    int nfds = epoll_wait(epfd, events, 1, 100);
    if (nfds < 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "epoll_wait failed");
    }
    if (nfds == 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "epoll_wait timed out, expected EPOLLOUT event");
    }

    // Verify we got EPOLLOUT and the modified data
    if (!(events[0].events & EPOLLOUT)) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "expected EPOLLOUT event");
    }
    if (events[0].data.u64 != 99) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "expected modified data value 99");
    }

    close(efd);
    close(epfd);
    TEST_PASS(test_name);
}

void test_epoll_ctl_mod_not_found(void) {
    const char *test_name = "epoll_ctl_mod_not_found";

    // Create epoll instance
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        TEST_FAIL(test_name, "epoll_create1 failed");
    }

    // Create eventfd but don't add it
    int efd = eventfd(0, EFD_NONBLOCK);
    if (efd < 0) {
        close(epfd);
        TEST_FAIL(test_name, "eventfd failed");
    }

    // Try to modify without adding first - should fail with ENOENT
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.u64 = 42;
    int ret = epoll_ctl(epfd, EPOLL_CTL_MOD, efd, &ev);
    if (ret == 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "EPOLL_CTL_MOD should have failed");
    }
    if (errno != ENOENT) {
        close(efd);
        close(epfd);
        char msg[64];
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        snprintf(msg, sizeof(msg), "expected ENOENT, got errno=%d", errno);
        TEST_FAIL(test_name, msg);
    }

    close(efd);
    close(epfd);
    TEST_PASS(test_name);
}

void test_epoll_ctl_mod_update_data(void) {
    const char *test_name = "epoll_ctl_mod_update_data";

    // Create epoll instance
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        TEST_FAIL(test_name, "epoll_create1 failed");
    }

    // Create eventfd and write to make it readable
    int efd = eventfd(0, EFD_NONBLOCK);
    if (efd < 0) {
        close(epfd);
        TEST_FAIL(test_name, "eventfd failed");
    }

    // Write to eventfd to make it readable
    uint64_t val = 1;
    if (write(efd, &val, sizeof(val)) != sizeof(val)) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "write to eventfd failed");
    }

    // Add eventfd with EPOLLIN and data=100
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.u64 = 100;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev) < 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "EPOLL_CTL_ADD failed");
    }

    // Modify to keep EPOLLIN but change data to 200
    ev.events = EPOLLIN;
    ev.data.u64 = 200;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, efd, &ev) < 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "EPOLL_CTL_MOD failed");
    }

    // Wait for events
    struct epoll_event events[1];
    int nfds = epoll_wait(epfd, events, 1, 100);
    if (nfds != 1) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "expected 1 event from epoll_wait");
    }

    // Verify we got the updated data value
    if (events[0].data.u64 != 200) {
        close(efd);
        close(epfd);
        char msg[64];
        // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling)
        snprintf(msg, sizeof(msg), "expected data=200, got %lu", events[0].data.u64);
        TEST_FAIL(test_name, msg);
    }

    close(efd);
    close(epfd);
    TEST_PASS(test_name);
}

void test_epoll_ctl_mod_oneshot_rearm(void) {
    const char *test_name = "epoll_ctl_mod_oneshot_rearm";

    // Create epoll instance
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        TEST_FAIL(test_name, "epoll_create1 failed");
    }

    // Create eventfd (writable by default when counter < max)
    int efd = eventfd(0, EFD_NONBLOCK);
    if (efd < 0) {
        close(epfd);
        TEST_FAIL(test_name, "eventfd failed");
    }

    // Add eventfd with EPOLLOUT | EPOLLONESHOT
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLONESHOT;
    ev.data.u64 = 42;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev) < 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "EPOLL_CTL_ADD failed");
    }

    // First wait should return the event
    struct epoll_event events[1];
    int nfds = epoll_wait(epfd, events, 1, 100);
    if (nfds != 1) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "first epoll_wait should return 1 event");
    }
    if (events[0].data.u64 != 42) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "first event should have data=42");
    }

    // Second wait should timeout (ONESHOT disabled the entry)
    nfds = epoll_wait(epfd, events, 1, 50);
    if (nfds != 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "second epoll_wait should timeout (entry disabled)");
    }

    // Re-arm with EPOLL_CTL_MOD
    ev.events = EPOLLOUT | EPOLLONESHOT;
    ev.data.u64 = 99;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, efd, &ev) < 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "EPOLL_CTL_MOD to re-arm failed");
    }

    // Third wait should return the event (re-armed)
    nfds = epoll_wait(epfd, events, 1, 100);
    if (nfds != 1) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "third epoll_wait should return 1 event after re-arm");
    }
    if (events[0].data.u64 != 99) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "re-armed event should have data=99");
    }

    close(efd);
    close(epfd);
    TEST_PASS(test_name);
}

void test_epoll_ctl_mod_edge_triggered(void) {
    const char *test_name = "epoll_ctl_mod_edge_triggered";

    // Create epoll instance
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        TEST_FAIL(test_name, "epoll_create1 failed");
    }

    // Create eventfd
    int efd = eventfd(0, EFD_NONBLOCK);
    if (efd < 0) {
        close(epfd);
        TEST_FAIL(test_name, "eventfd failed");
    }

    // Add with level-triggered EPOLLOUT
    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.u64 = 42;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev) < 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "EPOLL_CTL_ADD failed");
    }

    // Modify to edge-triggered
    ev.events = EPOLLOUT | EPOLLET;
    ev.data.u64 = 99;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, efd, &ev) < 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "EPOLL_CTL_MOD to edge-triggered failed");
    }

    // First wait should return the event
    struct epoll_event events[1];
    int nfds = epoll_wait(epfd, events, 1, 100);
    if (nfds != 1) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "first epoll_wait should return 1 event");
    }
    if (events[0].data.u64 != 99) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "event should have updated data=99");
    }

    // Second wait should timeout (edge-triggered, no new edge)
    nfds = epoll_wait(epfd, events, 1, 50);
    if (nfds != 0) {
        close(efd);
        close(epfd);
        TEST_FAIL(test_name, "second epoll_wait should timeout (edge-triggered)");
    }

    close(efd);
    close(epfd);
    TEST_PASS(test_name);
}

int main(void) {
    printf("=== EPOLL_CTL_MOD Tests ===\n");

    test_epoll_ctl_mod_basic();
    test_epoll_ctl_mod_not_found();
    test_epoll_ctl_mod_update_data();
    test_epoll_ctl_mod_oneshot_rearm();
    test_epoll_ctl_mod_edge_triggered();

    printf("=== All EPOLL_CTL_MOD tests passed ===\n");
    return 0;
}
