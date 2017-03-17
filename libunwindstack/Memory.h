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

#ifndef _LIBUNWINDSTACK_MEMORY_H
#define _LIBUNWINDSTACK_MEMORY_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <vector>

class Memory {
 public:
  Memory() = default;
  virtual ~Memory() = default;

  virtual bool ReadString(uint64_t addr, std::string* string, uint64_t max_read = UINT64_MAX);

  virtual bool Read(uint64_t addr, void* dst, size_t size) = 0;

  inline bool Read(uint64_t addr, void* start, void* field, size_t size) {
    return Read(addr + reinterpret_cast<uintptr_t>(field) - reinterpret_cast<uintptr_t>(start),
                field, size);
  }

  inline bool Read32(uint64_t addr, uint32_t* dst) {
    return Read(addr, dst, sizeof(uint32_t));
  }

  inline bool Read64(uint64_t addr, uint64_t* dst) {
    return Read(addr, dst, sizeof(uint64_t));
  }
};

class MemoryBuffer : public Memory {
 public:
  MemoryBuffer() = default;
  virtual ~MemoryBuffer() = default;

  bool Read(uint64_t addr, void* dst, size_t size) override;

  uint8_t* GetPtr(size_t offset);

  void Resize(size_t size) { raw_.resize(size); }

  uint64_t Size() { return raw_.size(); }

 private:
  std::vector<uint8_t> raw_;
};

class MemoryFileAtOffset : public Memory {
 public:
  MemoryFileAtOffset() = default;
  virtual ~MemoryFileAtOffset();

  bool Init(const std::string& file, uint64_t offset, uint64_t size = UINT64_MAX);

  bool Read(uint64_t addr, void* dst, size_t size) override;

  void Clear();

 protected:
  size_t size_ = 0;
  size_t offset_ = 0;
  uint8_t* data_ = nullptr;
};

class MemoryOffline : public MemoryFileAtOffset {
 public:
  MemoryOffline() = default;
  virtual ~MemoryOffline() = default;

  bool Init(const std::string& file, uint64_t offset);

  bool Read(uint64_t addr, void* dst, size_t size) override;

 private:
  uint64_t start_;
};

class MemoryRemote : public Memory {
 public:
  MemoryRemote(pid_t pid) : pid_(pid) {}
  virtual ~MemoryRemote() = default;

  bool Read(uint64_t addr, void* dst, size_t size) override;

  pid_t pid() { return pid_; }

 private:
  pid_t pid_;
};

class MemoryLocal : public Memory {
 public:
  MemoryLocal() = default;
  virtual ~MemoryLocal() = default;

  bool Read(uint64_t addr, void* dst, size_t size) override;
};

class MemoryRange : public Memory {
 public:
  MemoryRange(Memory* memory, uint64_t begin, uint64_t end)
      : memory_(memory), begin_(begin), length_(end - begin_) {}
  virtual ~MemoryRange() { delete memory_; }

  inline bool Read(uint64_t addr, void* dst, size_t size) override {
    if (addr + size <= length_) {
      return memory_->Read(addr + begin_, dst, size);
    }
    return false;
  }

 private:
  Memory* memory_;
  uint64_t begin_;
  uint64_t length_;
};

#endif  // _LIBUNWINDSTACK_MEMORY_H
