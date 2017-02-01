/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <memory>

#include <android-base/unique_fd.h>

#include "Memory.h"

bool Memory::ReadString(uint64_t addr, std::string* string, uint64_t max_read) {
  string->clear();
  uint64_t bytes_read = 0;
  while (bytes_read < max_read) {
    uint8_t value;
    if (!Read(addr, &value, sizeof(value))) {
      return false;
    }
    if (value == '\0') {
      return true;
    }
    string->push_back(value);
    addr++;
    bytes_read++;
  }
  return false;
}

bool MemoryBuffer::Read(uint64_t addr, void* dst, size_t size) {
  uint64_t last_read_byte;
  if (__builtin_add_overflow(size, addr, &last_read_byte)) {
    return false;
  }
  if (last_read_byte > raw_.size()) {
    return false;
  }
  memcpy(dst, &raw_[addr], size);
  return true;
}

uint8_t* MemoryBuffer::GetPtr(size_t offset) {
  if (offset < raw_.size()) {
    return &raw_[offset];
  }
  return nullptr;
}

MemoryFileAtOffset::~MemoryFileAtOffset() {
  Clear();
}

void MemoryFileAtOffset::Clear() {
  if (data_) {
    munmap(&data_[-offset_], size_ + offset_);
    data_ = nullptr;
  }
}

bool MemoryFileAtOffset::Init(const std::string& file, uint64_t offset, uint64_t size) {
  // Clear out any previous data if it exists.
  Clear();

  android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(file.c_str(), O_RDONLY | O_CLOEXEC)));
  if (fd == -1) {
    return false;
  }
  struct stat buf;
  if (fstat(fd, &buf) == -1) {
    return false;
  }
  if (offset >= static_cast<uint64_t>(buf.st_size)) {
    return false;
  }

  offset_ = offset & (getpagesize() - 1);
  uint64_t aligned_offset = offset & ~(getpagesize() - 1);
  size_ = buf.st_size - aligned_offset;
  if (size < (UINT64_MAX - offset_) && size + offset_ < size_) {
    // Truncate the mapped size.
    size_ = size + offset_;
  }
  void* map = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd, aligned_offset);
  if (map == MAP_FAILED) {
    return false;
  }

  data_ = &reinterpret_cast<uint8_t*>(map)[offset_];
  size_ -= offset_;

  return true;
}

bool MemoryFileAtOffset::Read(uint64_t addr, void* dst, size_t size) {
  if (addr + size > size_) {
    return false;
  }
  memcpy(dst, &data_[addr], size);
  return true;
}

static bool PtraceRead(pid_t pid, uint64_t addr, long* value) {
#if !defined(__LP64__)
  // Cannot read an address greater than 32 bits.
  if (addr > UINT32_MAX) {
    return false;
  }
#endif
  // ptrace() returns -1 and sets errno when the operation fails.
  // To disambiguate -1 from a valid result, we clear errno beforehand.
  errno = 0;
  *value = ptrace(PTRACE_PEEKTEXT, pid, reinterpret_cast<void*>(addr), nullptr);
  if (*value == -1 && errno) {
    return false;
  }
  return true;
}

bool MemoryRemote::Read(uint64_t addr, void* dst, size_t bytes) {
  size_t bytes_read = 0;
  long data;
  size_t align_bytes = addr & (sizeof(long) - 1);
  if (align_bytes != 0) {
    if (!PtraceRead(pid_, addr & ~(sizeof(long) - 1), &data)) {
      return false;
    }
    size_t copy_bytes = std::min(sizeof(long) - align_bytes, bytes);
    memcpy(dst, reinterpret_cast<uint8_t*>(&data) + align_bytes, copy_bytes);
    addr += copy_bytes;
    dst = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(dst) + copy_bytes);
    bytes -= copy_bytes;
    bytes_read += copy_bytes;
  }

  for (size_t i = 0; i < bytes / sizeof(long); i++) {
    if (!PtraceRead(pid_, addr, &data)) {
      return false;
    }
    memcpy(dst, &data, sizeof(long));
    dst = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(dst) + sizeof(long));
    addr += sizeof(long);
    bytes_read += sizeof(long);
  }

  size_t left_over = bytes & (sizeof(long) - 1);
  if (left_over) {
    if (!PtraceRead(pid_, addr, &data)) {
      return false;
    }
    memcpy(dst, &data, left_over);
    bytes_read += left_over;
  }
  return true;
}

bool MemoryLocal::Read(uint64_t addr, void* dst, size_t size) {
  // The process_vm_readv call does will not always work on remote
  // processes, so only use it for reads from the current pid.
  // Use this method to avoid crashes if an address is invalid since
  // unwind data could try to access any part of the address space.
  struct iovec local_io;
  local_io.iov_base = dst;
  local_io.iov_len = size;

  struct iovec remote_io;
  remote_io.iov_base = reinterpret_cast<void*>(static_cast<uintptr_t>(addr));
  remote_io.iov_len = size;

  ssize_t bytes_read = process_vm_readv(getpid(), &local_io, 1, &remote_io, 1, 0);
  if (bytes_read == -1) {
    return false;
  }
  return static_cast<size_t>(bytes_read) == size;
}

bool MemoryOffline::Init(const std::string& file, uint64_t offset) {
  if (!MemoryFileAtOffset::Init(file, offset)) {
    return false;
  }
  // The first uint64_t value is the start of memory.
  if (!MemoryFileAtOffset::Read(0, &start_, sizeof(start_))) {
    return false;
  }
  // Subtract the first 64 bit value from the total size.
  size_ -= sizeof(start_);
  return true;
}

bool MemoryOffline::Read(uint64_t addr, void* dst, size_t size) {
  if (addr < start_ || addr + size > start_ + offset_ + size_) {
    return false;
  }
  memcpy(dst, &data_[addr + offset_ - start_ + sizeof(start_)], size);
  return true;
}
