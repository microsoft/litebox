// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// pthread mutex, condition variable, rwlock and once scenarios for the
// runner's end-to-end tests, selected by argv[1]. They run on psynch by
// default and on ulock with PTHREAD_MUTEX_USE_ULOCK=1.

#include <errno.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

extern int __ulock_wait(uint32_t operation, void *address, uint64_t value, uint32_t timeout);
extern int __ulock_wake(uint32_t operation, void *address, uint64_t wake_value);
#define UL_COMPARE_AND_WAIT 1
#define ULF_WAKE_ALL 0x100
#define ULF_NO_ERRNO 0x1000000

#define THREADS 8
#define ITERATIONS 100000

// A start gate: every worker blocks until `open_gate`.
static _Atomic uint32_t gate;
static atomic_int at_gate;

static void wait_at_gate(void) {
  atomic_fetch_add(&at_gate, 1);
  while (!atomic_load(&gate)) __ulock_wait(UL_COMPARE_AND_WAIT | ULF_NO_ERRNO, &gate, 0, 0);
}

static void open_gate(int workers) {
  while (atomic_load(&at_gate) < workers) sched_yield();
  atomic_store(&gate, 1);
  __ulock_wake(UL_COMPARE_AND_WAIT | ULF_WAKE_ALL | ULF_NO_ERRNO, &gate, 0);
}

static void run(void *(*body)(void *), int count) {
  pthread_t threads[THREADS * 2];
  for (long i = 0; i < count; i++) pthread_create(&threads[i], NULL, body, (void *)i);
  open_gate(count);
  for (int i = 0; i < count; i++) pthread_join(threads[i], NULL);
}

// Whether `mutex` takes the ulock path: pthread_mutex_s's option word
// (after the signature and the internal lock) has its ulock bit set
// (types_internal.h pthread_mutex_options_s).
static int uses_ulock(pthread_mutex_t *mutex) {
  uint32_t options;
  memcpy(&options, (char *)mutex + 12, sizeof(options));
  return (options >> 14) & 1;
}

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static long counter;

static void *increment(void *argument) {
  (void)argument;
  wait_at_gate();
  for (int i = 0; i < ITERATIONS; i++) {
    pthread_mutex_lock(&mutex);
    counter++;
    pthread_mutex_unlock(&mutex);
  }
  return NULL;
}

// A contended pthread mutex, 8 threads x 100k, with the default (first-fit)
// policy and then fair share (which never takes the ulock path).
static int mutex_contention(void) {
  run(increment, THREADS);
  long first_fit = counter;
  int ulock = uses_ulock(&mutex);
  pthread_mutexattr_t attributes;
  pthread_mutexattr_init(&attributes);
  pthread_mutexattr_setpolicy_np(&attributes, PTHREAD_MUTEX_POLICY_FAIRSHARE_NP);
  pthread_mutex_destroy(&mutex);
  pthread_mutex_init(&mutex, &attributes);
  counter = 0;
  atomic_store(&gate, 0);
  atomic_store(&at_gate, 0);
  run(increment, THREADS);
  printf("firstfit %ld fairshare %ld ulock %d\n", first_fit, counter, ulock);
  return 0;
}

#define SLOTS 4
#define ITEMS 20000
static pthread_cond_t not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t not_full = PTHREAD_COND_INITIALIZER;
static int buffer[SLOTS];
static int head, count;
static long consumed_sum;
static int consumed;

static void *produce(void *argument) {
  long index = (long)argument;
  wait_at_gate();
  for (int i = 0; i < ITEMS; i++) {
    pthread_mutex_lock(&mutex);
    while (count == SLOTS) pthread_cond_wait(&not_full, &mutex);
    buffer[(head + count) % SLOTS] = (int)index * ITEMS + i;
    count++;
    pthread_cond_signal(&not_empty);
    pthread_mutex_unlock(&mutex);
  }
  return NULL;
}

static void *consume(void *argument) {
  (void)argument;
  wait_at_gate();
  for (;;) {
    pthread_mutex_lock(&mutex);
    while (count == 0 && consumed < 4 * ITEMS) pthread_cond_wait(&not_empty, &mutex);
    if (consumed == 4 * ITEMS) {
      pthread_mutex_unlock(&mutex);
      return NULL;
    }
    consumed_sum += buffer[head];
    head = (head + 1) % SLOTS;
    count--;
    if (++consumed == 4 * ITEMS) pthread_cond_broadcast(&not_empty);
    pthread_cond_signal(&not_full);
    pthread_mutex_unlock(&mutex);
  }
}

static void *produce_or_consume(void *argument) {
  return (long)argument < 4 ? produce(argument) : consume(argument);
}

// Condition variables: 4 producers and 4 consumers through a 4-slot
// buffer; then timed waits that time out (absolute and relative) and one a
// signal ends.
static pthread_cond_t timed = PTHREAD_COND_INITIALIZER;
static int timed_ready;

static void *signal_timed(void *argument) {
  (void)argument;
  pthread_mutex_lock(&mutex);
  timed_ready = 1;
  pthread_cond_signal(&timed);
  pthread_mutex_unlock(&mutex);
  return NULL;
}

static int condvar(void) {
  run(produce_or_consume, 8);
  long expected = 0;
  for (long i = 0; i < 4 * ITEMS; i++) expected += i;

  struct timeval now;
  gettimeofday(&now, NULL);
  struct timespec deadline = {now.tv_sec, now.tv_usec * 1000 + 50000000};
  if (deadline.tv_nsec >= 1000000000) {
    deadline.tv_sec++;
    deadline.tv_nsec -= 1000000000;
  }
  pthread_mutex_lock(&mutex);
  int absolute = pthread_cond_timedwait(&timed, &mutex, &deadline);
  struct timeval after;
  gettimeofday(&after, NULL);
  long waited_ms = (after.tv_sec - now.tv_sec) * 1000 + (after.tv_usec - now.tv_usec) / 1000;
  struct timespec relative_timeout = {0, 20000000};
  int relative = pthread_cond_timedwait_relative_np(&timed, &mutex, &relative_timeout);
  pthread_t thread;
  pthread_create(&thread, NULL, signal_timed, NULL);
  struct timespec long_timeout = {30, 0};
  int signaled = 0;
  while (!timed_ready && signaled == 0) {
    signaled = pthread_cond_timedwait_relative_np(&timed, &mutex, &long_timeout);
  }
  pthread_mutex_unlock(&mutex);
  pthread_join(thread, NULL);
  printf("consumed %d sum %d absolute %d waited %d relative %d signaled %d ulock %d\n", consumed,
         consumed_sum == expected, absolute == ETIMEDOUT, waited_ms >= 50,
         relative == ETIMEDOUT, signaled == 0 && timed_ready, uses_ulock(&mutex));
  return 0;
}

static pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
static long first_half, second_half;
static atomic_long reads, torn;

static void *read_or_write(void *argument) {
  long index = (long)argument;
  wait_at_gate();
  for (int i = 0; i < 2000; i++) {
    if (index < 2) {
      pthread_rwlock_wrlock(&rwlock);
      first_half++;
      sched_yield();
      second_half++;
      pthread_rwlock_unlock(&rwlock);
    } else {
      pthread_rwlock_rdlock(&rwlock);
      if (first_half != second_half) atomic_fetch_add(&torn, 1);
      atomic_fetch_add(&reads, 1);
      pthread_rwlock_unlock(&rwlock);
    }
  }
  return NULL;
}

// An rwlock with 2 writers and 6 readers: readers never see a writer's
// update half done.
static int rwlock_contention(void) {
  run(read_or_write, 8);
  printf("writes %ld reads %ld torn %ld\n", first_half, (long)atomic_load(&reads),
         (long)atomic_load(&torn));
  return first_half == second_half ? 0 : 1;
}

static pthread_once_t once = PTHREAD_ONCE_INIT;
static atomic_int initialized, saw_initialized;

// Holds the other callers in pthread_once's wait for a while.
static void initialize(void) {
  mach_timebase_info_data_t timebase;
  mach_timebase_info(&timebase);
  mach_wait_until(mach_absolute_time() + 5000000ull * timebase.denom / timebase.numer);
  atomic_fetch_add(&initialized, 1);
}

static void *call_once(void *argument) {
  (void)argument;
  wait_at_gate();
  pthread_once(&once, initialize);
  atomic_fetch_add(&saw_initialized, atomic_load(&initialized) == 1);
  return NULL;
}

// pthread_once from 16 threads at once: one initialization, which every
// caller sees done.
static int once_contention(void) {
  run(call_once, 16);
  printf("initialized %d saw %d\n", atomic_load(&initialized), atomic_load(&saw_initialized));
  return 0;
}

static void *print_lines(void *argument) {
  long index = (long)argument;
  wait_at_gate();
  for (int i = 0; i < 200; i++) printf("thread %02ld line %03d\n", index, i);
  return NULL;
}

// printf from 8 threads at once: stdout's FILE lock keeps every line whole.
static int printf_contention(void) {
  run(print_lines, THREADS);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  if (strcmp(argv[1], "mutex") == 0) return mutex_contention();
  if (strcmp(argv[1], "condvar") == 0) return condvar();
  if (strcmp(argv[1], "rwlock") == 0) return rwlock_contention();
  if (strcmp(argv[1], "once") == 0) return once_contention();
  if (strcmp(argv[1], "printf") == 0) return printf_contention();
  return 3;
}
