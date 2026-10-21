// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// std::thread, std::mutex and std::condition_variable for the runner's
// end-to-end tests: libc++ on the guest's own libpthread. A C++ program,
// kept as .h for the repository's header check; the test compiles it as
// psynch.cpp.

#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

int main() {
  std::mutex mutex;
  long counter = 0;
  {
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; i++) {
      threads.emplace_back([&] {
        for (int j = 0; j < 20000; j++) {
          std::lock_guard<std::mutex> guard(mutex);
          counter++;
        }
      });
    }
    for (auto &thread : threads) thread.join();
  }

  // A producer and a consumer handing items through a bounded queue.
  std::condition_variable changed;
  std::deque<int> queue;
  long sum = 0;
  std::thread consumer([&] {
    for (int i = 0; i < 5000; i++) {
      std::unique_lock<std::mutex> lock(mutex);
      changed.wait(lock, [&] { return !queue.empty(); });
      sum += queue.front();
      queue.pop_front();
      changed.notify_all();
    }
  });
  for (int i = 0; i < 5000; i++) {
    std::unique_lock<std::mutex> lock(mutex);
    changed.wait(lock, [&] { return queue.size() < 4; });
    queue.push_back(i);
    changed.notify_all();
  }
  consumer.join();

  // A wait that times out.
  std::unique_lock<std::mutex> lock(mutex);
  auto start = std::chrono::steady_clock::now();
  bool timed_out = changed.wait_for(lock, std::chrono::milliseconds(50)) == std::cv_status::timeout;
  auto waited = std::chrono::steady_clock::now() - start;
  std::printf("counter %ld sum %ld timeout %d waited %d\n", counter, sum, timed_out,
              waited >= std::chrono::milliseconds(50));
  return 0;
}
