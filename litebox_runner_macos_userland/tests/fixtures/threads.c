// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Guest thread scenarios for the runner's end-to-end tests, selected by argv[1].
// Until psynch is emulated, no pthread mutex is contended and only one thread
// at a time uses stdio (FILE locks are pthread mutexes). Delays use
// mach_wait_until: nanosleep's __semwait_signal is not emulated yet.

#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <os/lock.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// libsystem_kernel's raw calls, as libpthread and libplatform make them.
extern int __bsdthread_terminate(void *stackaddr, size_t freesize, mach_port_t thread,
                                 mach_port_t sem);
extern int __ulock_wait(uint32_t operation, void *address, uint64_t value, uint32_t timeout);
extern int __ulock_wake(uint32_t operation, void *address, uint64_t wake_value);
#define UL_COMPARE_AND_WAIT 1
#define ULF_WAKE_ALL 0x100
#define ULF_NO_ERRNO 0x1000000

static void sleep_ms(uint64_t milliseconds) {
  mach_timebase_info_data_t timebase;
  mach_timebase_info(&timebase);
  mach_wait_until(mach_absolute_time() + milliseconds * 1000000 * timebase.denom / timebase.numer);
}

#define WORKERS 16
#define DETACHED 4

static _Thread_local int tls_value;
static pthread_key_t key;
static atomic_int destructors;
static atomic_int detached_done;

struct report {
  uint64_t id;
  mach_port_t self_port;
  mach_port_t pthread_port;
  int errno_kept;
  int tls_kept;
};
static struct report reports[WORKERS];
static atomic_int started;
static _Atomic uint32_t release;

static void destructor(void *value) {
  atomic_fetch_add(&destructors, 1);
  free(value);
}

static void *worker(void *argument) {
  long index = (long)argument;
  tls_value = (int)index * 3;
  pthread_setspecific(key, malloc(16));
  errno = (int)index + 100;
  atomic_fetch_add(&started, 1);
  while (!atomic_load(&release)) {
    __ulock_wait(UL_COMPARE_AND_WAIT | ULF_NO_ERRNO, &release, 0, 0);
  }
  struct report *report = &reports[index];
  pthread_threadid_np(NULL, &report->id);
  report->self_port = mach_thread_self();
  report->pthread_port = pthread_mach_thread_np(pthread_self());
  mach_port_deallocate(mach_task_self(), report->self_port);
  report->errno_kept = errno == (int)index + 100;
  report->tls_kept = tls_value == (int)index * 3;
  return (void *)(index * 7);
}

static void *detached(void *argument) {
  (void)argument;
  pthread_setspecific(key, malloc(16));
  atomic_fetch_add(&detached_done, 1);
  return NULL;
}

// Create and join threads: return values, TSD destructors, _Thread_local,
// errno, thread IDs and ports, detached threads, a ulock gate and
// sched_yield.
static int join(void) {
  pthread_key_create(&key, destructor);
  tls_value = -1;
  pthread_t threads[WORKERS];
  for (long i = 0; i < WORKERS; i++) {
    if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) return 10;
  }
  pthread_attr_t attributes;
  pthread_attr_init(&attributes);
  pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
  for (int i = 0; i < DETACHED; i++) {
    pthread_t thread;
    if (pthread_create(&thread, &attributes, detached, NULL) != 0) return 11;
  }
  while (atomic_load(&started) < WORKERS) sched_yield();
  // Other threads' IDs, read while they run.
  uint64_t peer_ids[WORKERS];
  for (int i = 0; i < WORKERS; i++) {
    if (pthread_threadid_np(threads[i], &peer_ids[i]) != 0) return 12;
  }
  atomic_store(&release, 1);
  __ulock_wake(UL_COMPARE_AND_WAIT | ULF_WAKE_ALL | ULF_NO_ERRNO, &release, 0);
  int bad_results = 0;
  for (long i = 0; i < WORKERS; i++) {
    void *result;
    if (pthread_join(threads[i], &result) != 0 || (long)result != i * 7) bad_results++;
  }
  while (atomic_load(&detached_done) < DETACHED) sched_yield();
  uint64_t main_id;
  pthread_threadid_np(NULL, &main_id);
  mach_port_t main_port = mach_thread_self();
  int distinct = 1, consistent = 0;
  for (int i = 0; i < WORKERS; i++) {
    struct report *report = &reports[i];
    consistent += report->self_port == report->pthread_port && report->errno_kept &&
                  report->tls_kept && peer_ids[i] == report->id;
    if (report->id == main_id || report->self_port == main_port) distinct = 0;
    for (int j = 0; j < i; j++) {
      if (report->id == reports[j].id || report->self_port == reports[j].self_port) distinct = 0;
    }
  }
  // Detached threads may still run their destructors after their count.
  for (int tries = 0; atomic_load(&destructors) < WORKERS + DETACHED && tries < 5000; tries++) {
    sleep_ms(1);
  }
  printf("results %d distinct %d consistent %d destructors %d tls %d main %d\n", bad_results,
         distinct, consistent, atomic_load(&destructors), tls_value,
         main_port == pthread_mach_thread_np(pthread_self()));
  return 0;
}

static os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
static long counter;

static void *increment(void *argument) {
  (void)argument;
  for (int i = 0; i < 100000; i++) {
    os_unfair_lock_lock(&lock);
    counter++;
    os_unfair_lock_unlock(&lock);
  }
  return NULL;
}

// os_unfair_lock contention: 8 threads x 100k increments.
static int unfair(void) {
  pthread_t threads[8];
  for (int i = 0; i < 8; i++) pthread_create(&threads[i], NULL, increment, NULL);
  for (int i = 0; i < 8; i++) pthread_join(threads[i], NULL);
  printf("counter %ld\n", counter);
  return 0;
}

static atomic_int finished;

static void *late(void *argument) {
  sleep_ms(50 * (uint64_t)(long)argument);
  if (atomic_fetch_add(&finished, 1) + 1 == 4) {
    // The last thread: no other thread uses stdio any more.
    printf("finished %d\n", atomic_load(&finished));
    fflush(stdout);
  }
  return NULL;
}

// pthread_exit from main while workers run: the process ends with status 0
// once the last thread exits.
static int main_exit(void) {
  for (long i = 1; i <= 4; i++) {
    pthread_t thread;
    pthread_create(&thread, NULL, late, (void *)i);
  }
  pthread_exit(NULL);
}

static pthread_t chain[4];
static atomic_int blocking;

static void *lock_forever(void *argument) {
  (void)argument;
  atomic_fetch_add(&blocking, 1);
  os_unfair_lock_lock(&lock);
  return NULL;
}

static void *join_previous(void *argument) {
  atomic_fetch_add(&blocking, 1);
  pthread_join(*(pthread_t *)argument, NULL);
  return NULL;
}

static void *spin(void *argument) {
  (void)argument;
  atomic_fetch_add(&blocking, 1);
  for (volatile unsigned long i = 0;; i++) {
  }
  return NULL;
}

static void *sleep_forever(void *argument) {
  (void)argument;
  atomic_fetch_add(&blocking, 1);
  mach_wait_until(UINT64_MAX);
  return NULL;
}

static void *exit_soon(void *argument) {
  (void)argument;
  while (atomic_load(&blocking) < 8) sched_yield();
  // Let the others reach their waits.
  sleep_ms(100);
  exit(42);
}

// exit from a worker while the other threads run, sleep, block in joins, and
// block on an unfair lock.
static int exit_blocked(void) {
  os_unfair_lock_lock(&lock);
  pthread_t thread;
  pthread_create(&chain[0], NULL, spin, NULL);
  pthread_create(&thread, NULL, sleep_forever, NULL);
  for (int i = 0; i < 3; i++) pthread_create(&thread, NULL, lock_forever, NULL);
  for (int i = 1; i < 4; i++) pthread_create(&chain[i], NULL, join_previous, &chain[i - 1]);
  pthread_create(&thread, NULL, exit_soon, NULL);
  pthread_join(chain[3], NULL);
  return 1;
}

static void at_exit(void) { write(1, "atexit\n", 7); }

static void *terminate_later(void *argument) {
  (void)argument;
  sleep_ms(100);
  __bsdthread_terminate(NULL, 0, MACH_PORT_NULL, MACH_PORT_NULL);
  return NULL;
}

// Every thread terminates without exit: the kernel ends the process with
// status 0 when the last one goes, without running exit handlers.
static int last_terminate(void) {
  atexit(at_exit);
  pthread_t thread;
  pthread_create(&thread, NULL, terminate_later, NULL);
  __bsdthread_terminate(NULL, 0, MACH_PORT_NULL, MACH_PORT_NULL);
  return 1;
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  if (strcmp(argv[1], "join") == 0) return join();
  if (strcmp(argv[1], "unfair") == 0) return unfair();
  if (strcmp(argv[1], "main_exit") == 0) return main_exit();
  if (strcmp(argv[1], "exit_blocked") == 0) return exit_blocked();
  if (strcmp(argv[1], "last_terminate") == 0) return last_terminate();
  return 3;
}
