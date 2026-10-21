// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Mach semaphore, sleep, cancellation and Mach message scenarios for the
// runner's end-to-end tests, selected by argv[1]. "cancel_read" needs the
// runner's --test-open-stdin.

#include <dispatch/dispatch.h>
#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static double seconds_since(const struct timespec *start) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return (double)(now.tv_sec - start->tv_sec) + (double)(now.tv_nsec - start->tv_nsec) / 1e9;
}

// pthread_join of threads whose stacks the program allocated: the joiner
// also waits on a semaphore that bsdthread_terminate signals.
static void *custom_stack_worker(void *argument) {
  volatile char probe[256];
  probe[0] = 1;
  // Slow exits let some joins block in the kernel first.
  if ((uintptr_t)argument % 2) usleep(2000);
  return (void *)((uintptr_t)argument * 3 + probe[0]);
}

static int custom_stack(void) {
  enum { ROUNDS = 64, STACK = 256 * 1024 };
  int good = 0;
  for (uintptr_t round = 0; round < ROUNDS; round++) {
    void *stack = mmap(NULL, STACK, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (stack == MAP_FAILED) return 4;
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setstack(&attributes, stack, STACK);
    pthread_t thread;
    if (pthread_create(&thread, &attributes, custom_stack_worker, (void *)round) != 0) return 5;
    void *result;
    if (pthread_join(thread, &result) != 0) return 6;
    // The thread no longer runs on the stack the joiner frees.
    munmap(stack, STACK);
    if ((uintptr_t)result == round * 3 + 1) good++;
    pthread_attr_destroy(&attributes);
  }
  printf("joined %d\n", good);
  return 0;
}

// dispatch_semaphore ping-pong between two pthreads (no dispatch queues).
static dispatch_semaphore_t ping, pong;
enum { PINGS = 20000 };

static void *ponger(void *unused) {
  (void)unused;
  for (int i = 0; i < PINGS; i++) {
    dispatch_semaphore_wait(ping, DISPATCH_TIME_FOREVER);
    dispatch_semaphore_signal(pong);
  }
  return NULL;
}

static int dispatch_ping_pong(void) {
  ping = dispatch_semaphore_create(0);
  pong = dispatch_semaphore_create(0);
  pthread_t thread;
  pthread_create(&thread, NULL, ponger, NULL);
  int rounds = 0;
  for (int i = 0; i < PINGS; i++) {
    dispatch_semaphore_signal(ping);
    if (dispatch_semaphore_wait(pong, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC)) == 0) {
      rounds++;
    }
  }
  pthread_join(thread, NULL);
  // A timed wait that nobody signals times out.
  long timed_out = dispatch_semaphore_wait(pong, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_MSEC));
  printf("rounds %d timeout %d\n", rounds, timed_out != 0);
  return 0;
}

// pthread_cancel of threads blocked in pthread_cond_wait, sleep(), and a
// loop of write() calls.
static pthread_mutex_t cancel_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cancel_cond = PTHREAD_COND_INITIALIZER;
static int waiting;
static atomic_int cleanups;
static atomic_int writing;

static void unlock_cleanup(void *mutex) {
  atomic_fetch_add(&cleanups, 1);
  pthread_mutex_unlock(mutex);
}

static void *cond_waiter(void *unused) {
  (void)unused;
  pthread_mutex_lock(&cancel_mutex);
  pthread_cleanup_push(unlock_cleanup, &cancel_mutex);
  waiting = 1;
  for (;;) pthread_cond_wait(&cancel_cond, &cancel_mutex);
  pthread_cleanup_pop(1);
  return NULL;
}

static void *sleeper(void *unused) {
  (void)unused;
  sleep(1000);
  return NULL;
}

static void *writer(void *unused) {
  (void)unused;
  atomic_store(&writing, 1);
  for (;;) write(STDOUT_FILENO, "", 0);
  return NULL;
}

static int canceled(pthread_t thread) {
  void *result = NULL;
  if (pthread_cancel(thread) != 0 || pthread_join(thread, &result) != 0) return 0;
  return result == PTHREAD_CANCELED;
}

static int cancel(void) {
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  pthread_t thread;
  pthread_create(&thread, NULL, cond_waiter, NULL);
  // The waiter holds the mutex until pthread_cond_wait releases it.
  for (;;) {
    pthread_mutex_lock(&cancel_mutex);
    int ready = waiting;
    pthread_mutex_unlock(&cancel_mutex);
    if (ready) break;
    usleep(1000);
  }
  usleep(20000);
  int cond = canceled(thread);
  // The cleanup handler unlocked the mutex the canceled wait reacquired.
  int relocked = pthread_mutex_trylock(&cancel_mutex) == 0;
  if (relocked) pthread_mutex_unlock(&cancel_mutex);

  pthread_create(&thread, NULL, sleeper, NULL);
  usleep(20000);
  int slept = canceled(thread);

  pthread_create(&thread, NULL, writer, NULL);
  while (!atomic_load(&writing)) usleep(1000);
  usleep(20000);
  int wrote = canceled(thread);

  printf("cond %d cleanup %d relocked %d sleep %d write %d fast %d\n", cond,
         atomic_load(&cleanups), relocked, slept, wrote, seconds_since(&start) < 30);
  return 0;
}

// pthread_cancel of a thread blocked reading standard input that stays open
// and empty: the read ends with EINTR and the thread acts on the cancel.
static atomic_int reading;

static void *reader(void *unused) {
  (void)unused;
  char byte;
  atomic_store(&reading, 1);
  for (;;) read(STDIN_FILENO, &byte, 1);
  return NULL;
}

// Ends the process if the cancellation never takes effect, so a broken
// implementation fails within seconds instead of at the runner's bound.
static void *give_up(void *unused) {
  (void)unused;
  sleep(10);
  _exit(4);
}

static int cancel_read(void) {
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  pthread_t thread;
  pthread_create(&thread, NULL, give_up, NULL);
  pthread_detach(thread);
  pthread_create(&thread, NULL, reader, NULL);
  while (!atomic_load(&reading)) usleep(1000);
  // Long enough for the read to block.
  usleep(20000);
  int read_canceled = canceled(thread);
  printf("read %d fast %d\n", read_canceled, seconds_since(&start) < 30);
  return 0;
}

// nanosleep, usleep and sleep in threads sleep for their time.
static void *timed_sleeper(void *argument) {
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  for (int i = 0; i < 5; i++) usleep(10000);
  struct timespec request = {0, 20 * 1000 * 1000}, remaining = {0, 0};
  int result = nanosleep(&request, &remaining);
  if ((uintptr_t)argument == 0) result |= (int)sleep(1);
  double elapsed = seconds_since(&start);
  double expected = (uintptr_t)argument == 0 ? 1.069 : 0.069;
  return (void *)(uintptr_t)(result == 0 && elapsed >= expected);
}

static int sleeps(void) {
  pthread_t threads[4];
  for (uintptr_t i = 0; i < 4; i++) pthread_create(&threads[i], NULL, timed_sleeper, (void *)i);
  int good = 0;
  for (int i = 0; i < 4; i++) {
    void *result;
    pthread_join(threads[i], &result);
    good += (int)(uintptr_t)result;
  }
  printf("slept %d\n", good);
  return 0;
}

// Mach message ping-pong between two threads, each receiving on its own
// port and sending to the other's.
enum { MESSAGES = 5000 };
static mach_port_t ports[2];

typedef struct {
  mach_msg_header_t header;
  uint32_t value;
  mach_msg_max_trailer_t trailer;
} message_t;

static int send_value(int to, uint32_t value) {
  message_t message;
  memset(&message, 0, sizeof(message));
  message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  message.header.msgh_size = sizeof(mach_msg_header_t) + sizeof(uint32_t);
  message.header.msgh_remote_port = ports[to];
  message.value = value;
  return mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0, MACH_PORT_NULL,
                  MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == KERN_SUCCESS;
}

static uint32_t receive_value(int self) {
  message_t message;
  if (mach_msg(&message.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof(message), ports[self],
               10000, MACH_PORT_NULL) != KERN_SUCCESS) {
    return 0;
  }
  return message.value;
}

// The main thread sends first; each side answers what it received plus one.
static uint32_t bounce(int self) {
  uint32_t last = 0;
  for (int i = 0; i < MESSAGES; i++) {
    if (self == 0 && !send_value(1, last + 1)) return 0;
    last = receive_value(self);
    if (last == 0) return 0;
    if (self == 1 && !send_value(0, last + 1)) return 0;
  }
  return last;
}

static void *bouncer(void *unused) {
  (void)unused;
  return (void *)(uintptr_t)bounce(1);
}

static int mach_ping_pong(void) {
  for (int i = 0; i < 2; i++) {
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &ports[i]);
    mach_port_insert_right(mach_task_self(), ports[i], ports[i], MACH_MSG_TYPE_MAKE_SEND);
  }
  pthread_t thread;
  pthread_create(&thread, NULL, bouncer, NULL);
  uint32_t mine = bounce(0);
  void *theirs;
  pthread_join(thread, &theirs);
  printf("main %u peer %u\n", mine, (uint32_t)(uintptr_t)theirs);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  if (strcmp(argv[1], "custom_stack") == 0) return custom_stack();
  if (strcmp(argv[1], "dispatch") == 0) return dispatch_ping_pong();
  if (strcmp(argv[1], "cancel") == 0) return cancel();
  if (strcmp(argv[1], "cancel_read") == 0) return cancel_read();
  if (strcmp(argv[1], "sleep") == 0) return sleeps();
  if (strcmp(argv[1], "mach") == 0) return mach_ping_pong();
  return 3;
}
