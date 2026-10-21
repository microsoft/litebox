// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// std::async(std::launch::async), std::promise and std::this_thread::sleep_for
// for the runner's end-to-end tests. A C++ program, kept as .h for the
// repository's header check; the test compiles it as sync.cpp.

#include <chrono>
#include <cstdio>
#include <future>
#include <thread>
#include <vector>

int main() {
  std::vector<std::future<long>> sums;
  for (long part = 0; part < 8; part++) {
    sums.push_back(std::async(std::launch::async, [part] {
      long sum = 0;
      for (long i = part * 1000; i < (part + 1) * 1000; i++) sum += i;
      return sum;
    }));
  }
  long total = 0;
  for (auto &sum : sums) total += sum.get();

  std::promise<int> promise;
  std::future<int> value = promise.get_future();
  auto start = std::chrono::steady_clock::now();
  std::thread setter([&promise] {
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    promise.set_value(42);
  });
  int received = value.get();
  setter.join();
  auto waited = std::chrono::steady_clock::now() - start;

  std::printf("total %ld promised %d waited %d\n", total, received,
              waited >= std::chrono::milliseconds(30));
  return 0;
}
