/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <unistd.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libdebuggerd/scudo.h"
#include "libdebuggerd/types.h"
#include "unwindstack/Memory.h"

#include "log_fake.h"

#include <inttypes.h>

// This needs to match the kExtraPages from ScudoCrashData::SetErrorInfo.
constexpr uint64_t kMaxPages = 16;

class MemoryAlwaysZero : public unwindstack::Memory {
 public:
  MemoryAlwaysZero() = default;
  virtual ~MemoryAlwaysZero() = default;

  size_t Read(uint64_t addr, void* buffer, size_t size) override {
    if (test_unreadable_addrs_.count(addr) != 0) {
      return 0;
    }
    test_read_addrs_.insert(addr);
    memset(buffer, 0, size);
    return size;
  }

  void TestAddUnreadableAddress(uint64_t addr) { test_unreadable_addrs_.insert(addr); }

  void TestClearAddresses() {
    test_read_addrs_.clear();
    test_unreadable_addrs_.clear();
  }

  std::set<uint64_t>& test_read_addrs() { return test_read_addrs_; }

 private:
  std::set<uint64_t> test_unreadable_addrs_;

  std::set<uint64_t> test_read_addrs_;
};

TEST(ScudoTest, no_fault_address) {
  MemoryAlwaysZero process_memory;
  ProcessInfo info;
  info.has_fault_address = false;
  info.untagged_fault_address = 0x5000;
  info.scudo_stack_depot = 0x1000;
  info.scudo_region_info = 0x2000;
  info.scudo_ring_buffer = 0x3000;

  ScudoCrashData crash;
  ASSERT_FALSE(crash.SetErrorInfo(&process_memory, info));

  info.has_fault_address = true;
  ASSERT_TRUE(crash.SetErrorInfo(&process_memory, info));
}

TEST(ScudoTest, scudo_data_read_check) {
  MemoryAlwaysZero process_memory;
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = 0x5000;
  info.scudo_stack_depot = 0x1000;
  info.scudo_region_info = 0x2000;
  info.scudo_ring_buffer = 0x3000;

  ScudoCrashData crash;
  ASSERT_TRUE(crash.SetErrorInfo(&process_memory, info));

  // Stack Depot unreadable
  process_memory.TestClearAddresses();
  process_memory.TestAddUnreadableAddress(0x1000);
  ASSERT_FALSE(crash.SetErrorInfo(&process_memory, info));

  // The Region Info doesn't exist for 32 bit.
#if defined(__LP64__)
  // Region Info unreadable
  process_memory.TestClearAddresses();
  process_memory.TestAddUnreadableAddress(0x2000);
  ASSERT_FALSE(crash.SetErrorInfo(&process_memory, info));
#endif

  // Ring Buffer unreadable
  process_memory.TestClearAddresses();
  process_memory.TestAddUnreadableAddress(0x3000);
  ASSERT_FALSE(crash.SetErrorInfo(&process_memory, info));

  // Verify that with all scudo data readable, the error info works.
  process_memory.TestClearAddresses();
  ASSERT_TRUE(crash.SetErrorInfo(&process_memory, info));
}

TEST(ScudoTest, fault_page_unreadable) {
  MemoryAlwaysZero process_memory;
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = 0x5124;
  info.scudo_stack_depot = 0x1000;
  info.scudo_region_info = 0x2000;
  info.scudo_ring_buffer = 0x3000;

  ScudoCrashData crash;
  ASSERT_TRUE(crash.SetErrorInfo(&process_memory, info));

  uint64_t fault_page = info.untagged_fault_address & ~(getpagesize() - 1);
  process_memory.TestAddUnreadableAddress(fault_page);
  ASSERT_FALSE(crash.SetErrorInfo(&process_memory, info));
}

TEST(ScudoTest, pages_before_fault_unreadable) {
  MemoryAlwaysZero process_memory;
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = 0x15124;
  info.scudo_stack_depot = 0x1000;
  info.scudo_region_info = 0x2000;
  info.scudo_ring_buffer = 0x3000;

  ScudoCrashData crash;
  ASSERT_TRUE(crash.SetErrorInfo(&process_memory, info));

  uint64_t page_size = getpagesize();
  uint64_t fault_page = info.untagged_fault_address & ~(page_size - 1);

  std::vector<uint64_t> expected_reads = {0x1000, 0x2000, 0x3000};
  for (size_t i = 0; i <= kMaxPages; i++) {
    expected_reads.emplace_back(fault_page + i * page_size);
  }

  // Loop through and make pages before the fault page unreadable.
  for (size_t i = 1; i <= kMaxPages + 1; i++) {
    process_memory.TestClearAddresses();
    uint64_t unreadable_addr = fault_page - i * page_size;
    SCOPED_TRACE(testing::Message()
                 << "Failed at unreadable address 0x" << std::hex << unreadable_addr);
    process_memory.TestAddUnreadableAddress(unreadable_addr);
    ASSERT_TRUE(crash.SetErrorInfo(&process_memory, info));
    ASSERT_THAT(process_memory.test_read_addrs(),
                testing::UnorderedElementsAreArray(expected_reads));
    // Need to add the previous unreadable_addr to the list of expected addresses.
    expected_reads.emplace_back(unreadable_addr);
  }
}

TEST(ScudoTest, pages_after_fault_unreadable) {
  MemoryAlwaysZero process_memory;
  ProcessInfo info;
  info.has_fault_address = true;
  info.untagged_fault_address = 0x15124;
  info.scudo_stack_depot = 0x1000;
  info.scudo_region_info = 0x2000;
  info.scudo_ring_buffer = 0x3000;

  ScudoCrashData crash;
  ASSERT_TRUE(crash.SetErrorInfo(&process_memory, info));

  uint64_t page_size = getpagesize();
  uint64_t fault_page = info.untagged_fault_address & ~(page_size - 1);

  std::vector<uint64_t> expected_reads = {0x1000, 0x2000, 0x3000};
  for (size_t i = 0; i <= kMaxPages; i++) {
    expected_reads.emplace_back(fault_page - i * page_size);
  }

  // Loop through and make pages after the fault page unreadable.
  for (size_t i = 1; i <= kMaxPages + 1; i++) {
    process_memory.TestClearAddresses();
    uint64_t unreadable_addr = fault_page + i * page_size;
    SCOPED_TRACE(testing::Message()
                 << "Failed at unreadable address 0x" << std::hex << unreadable_addr);
    process_memory.TestAddUnreadableAddress(unreadable_addr);
    ASSERT_TRUE(crash.SetErrorInfo(&process_memory, info));
    ASSERT_THAT(process_memory.test_read_addrs(),
                testing::UnorderedElementsAreArray(expected_reads));
    // Need to add the previous unreadable_addr to the list of expected addresses.
    expected_reads.emplace_back(unreadable_addr);
  }
}

// Make sure that if the fault address is low, you won't underflow.
TEST(ScudoTest, fault_address_low) {
  MemoryAlwaysZero process_memory;
  ProcessInfo info;
  info.has_fault_address = true;
  info.scudo_stack_depot = 0x21000;
  info.scudo_region_info = 0x22000;
  info.scudo_ring_buffer = 0x23000;

  ScudoCrashData crash;
  ASSERT_TRUE(crash.SetErrorInfo(&process_memory, info));

  uint64_t page_size = getpagesize();
  for (size_t i = 0; i < kMaxPages + 1; i++) {
    process_memory.TestClearAddresses();
    info.untagged_fault_address = 0x124 + i * getpagesize();
    SCOPED_TRACE(testing::Message()
                 << "Failed with fault address 0x" << std::hex << info.untagged_fault_address);
    ASSERT_TRUE(crash.SetErrorInfo(&process_memory, info));
    std::vector<uint64_t> expected_reads = {0x21000, 0x22000, 0x23000};
    uint64_t fault_page = info.untagged_fault_address & ~(page_size - 1);
    expected_reads.emplace_back(fault_page);
    for (size_t j = 1; j <= kMaxPages; j++) {
      expected_reads.emplace_back(fault_page + j * page_size);
    }
    while (fault_page != 0) {
      fault_page -= page_size;
      expected_reads.emplace_back(fault_page);
    }
    ASSERT_THAT(process_memory.test_read_addrs(),
                testing::UnorderedElementsAreArray(expected_reads));
  }
}
