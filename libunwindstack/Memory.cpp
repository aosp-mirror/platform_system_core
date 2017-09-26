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

#include <unwindstack/Memory.h>

#include "Check.h"

static size_t ProcessVmRead(pid_t pid, void* dst, uint64_t remote_src, size_t len) {
  struct iovec dst_iov = {
      .iov_base = dst,
      .iov_len = len,
  };

  // Split up the remote read across page boundaries.
  // From the manpage:
  //   A partial read/write may result if one of the remote_iov elements points to an invalid
  //   memory region in the remote process.
  //
  //   Partial transfers apply at the granularity of iovec elements.  These system calls won't
  //   perform a partial transfer that splits a single iovec element.
  constexpr size_t kMaxIovecs = 64;
  struct iovec src_iovs[kMaxIovecs];
  size_t iovecs_used = 0;

  uint64_t cur = remote_src;
  while (len > 0) {
    if (iovecs_used == kMaxIovecs) {
      errno = EINVAL;
      return 0;
    }

    // struct iovec uses void* for iov_base.
    if (cur >= UINTPTR_MAX) {
      errno = EFAULT;
      return 0;
    }

    src_iovs[iovecs_used].iov_base = reinterpret_cast<void*>(cur);

    uintptr_t misalignment = cur & (getpagesize() - 1);
    size_t iov_len = getpagesize() - misalignment;
    iov_len = std::min(iov_len, len);

    len -= iov_len;
    if (__builtin_add_overflow(cur, iov_len, &cur)) {
      errno = EFAULT;
      return 0;
    }

    src_iovs[iovecs_used].iov_len = iov_len;
    ++iovecs_used;
  }

  ssize_t rc = process_vm_readv(pid, &dst_iov, 1, src_iovs, iovecs_used, 0);
  return rc == -1 ? 0 : rc;
}

namespace unwindstack {

bool Memory::Read(uint64_t addr, void* dst, size_t size) {
  size_t rc = ReadPartially(addr, dst, size);
  return rc == size;
}

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

std::shared_ptr<Memory> Memory::CreateProcessMemory(pid_t pid) {
  if (pid == getpid()) {
    return std::shared_ptr<Memory>(new MemoryLocal());
  }
  return std::shared_ptr<Memory>(new MemoryRemote(pid));
}

size_t MemoryBuffer::ReadPartially(uint64_t addr, void* dst, size_t size) {
  if (addr >= raw_.size()) {
    return 0;
  }

  size_t bytes_left = raw_.size() - static_cast<size_t>(addr);
  const unsigned char* actual_base = static_cast<const unsigned char*>(raw_.data()) + addr;
  size_t actual_len = std::min(bytes_left, size);

  memcpy(dst, actual_base, actual_len);
  return actual_len;
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
  if (aligned_offset > static_cast<uint64_t>(buf.st_size) ||
      offset > static_cast<uint64_t>(buf.st_size)) {
    return false;
  }

  size_ = buf.st_size - aligned_offset;
  uint64_t max_size;
  if (!__builtin_add_overflow(size, offset_, &max_size) && max_size < size_) {
    // Truncate the mapped size.
    size_ = max_size;
  }
  void* map = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd, aligned_offset);
  if (map == MAP_FAILED) {
    return false;
  }

  data_ = &reinterpret_cast<uint8_t*>(map)[offset_];
  size_ -= offset_;

  return true;
}

size_t MemoryFileAtOffset::ReadPartially(uint64_t addr, void* dst, size_t size) {
  if (addr >= size_) {
    return 0;
  }

  size_t bytes_left = size_ - static_cast<size_t>(addr);
  const unsigned char* actual_base = static_cast<const unsigned char*>(data_) + addr;
  size_t actual_len = std::min(bytes_left, size);

  memcpy(dst, actual_base, actual_len);
  return actual_len;
}

size_t MemoryRemote::ReadPartially(uint64_t addr, void* dst, size_t size) {
  return ProcessVmRead(pid_, dst, addr, size);
}

size_t MemoryLocal::ReadPartially(uint64_t addr, void* dst, size_t size) {
  return ProcessVmRead(getpid(), dst, addr, size);
}

MemoryRange::MemoryRange(const std::shared_ptr<Memory>& memory, uint64_t begin, uint64_t length,
                         uint64_t offset)
    : memory_(memory), begin_(begin), length_(length), offset_(offset) {}

size_t MemoryRange::ReadPartially(uint64_t addr, void* dst, size_t size) {
  if (addr < offset_) {
    return 0;
  }

  uint64_t read_offset = addr - offset_;
  if (read_offset >= length_) {
    return 0;
  }

  uint64_t read_length = std::min(static_cast<uint64_t>(size), length_ - read_offset);
  uint64_t read_addr;
  if (__builtin_add_overflow(read_offset, begin_, &read_addr)) {
    return 0;
  }

  return memory_->ReadPartially(read_addr, dst, read_length);
}

bool MemoryOffline::Init(const std::string& file, uint64_t offset) {
  auto memory_file = std::make_shared<MemoryFileAtOffset>();
  if (!memory_file->Init(file, offset)) {
    return false;
  }

  // The first uint64_t value is the start of memory.
  uint64_t start;
  if (!memory_file->Read(0, &start, sizeof(start))) {
    return false;
  }

  uint64_t size = memory_file->Size();
  if (__builtin_sub_overflow(size, sizeof(start), &size)) {
    return false;
  }

  memory_ = std::make_unique<MemoryRange>(memory_file, sizeof(start), size, start);
  return true;
}

size_t MemoryOffline::ReadPartially(uint64_t addr, void* dst, size_t size) {
  if (!memory_) {
    return 0;
  }

  return memory_->ReadPartially(addr, dst, size);
}

}  // namespace unwindstack
