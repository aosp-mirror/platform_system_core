/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <stdint.h>
#include <sys/mman.h>
#include <cstddef>

#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <unordered_set>
#include <vector>

#include <unwindstack/Elf.h>
#include <unwindstack/JitDebug.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>

#if !defined(NO_LIBDEXFILE_SUPPORT)
#include <DexFile.h>
#endif

// This implements the JIT Compilation Interface.
// See https://sourceware.org/gdb/onlinedocs/gdb/JIT-Interface.html

namespace unwindstack {

// 32-bit platforms may differ in alignment of uint64_t.
struct Uint64_P {
  uint64_t value;
} __attribute__((packed));
struct Uint64_A {
  uint64_t value;
} __attribute__((aligned(8)));

// Wrapper around other memory object which protects us against data races.
// It will check seqlock after every read, and fail if the seqlock changed.
// This ensues that the read memory has not been partially modified.
struct JitMemory : public Memory {
  size_t Read(uint64_t addr, void* dst, size_t size) override;

  Memory* parent_ = nullptr;
  uint64_t seqlock_addr_ = 0;
  uint32_t expected_seqlock_ = 0;
  bool failed_due_to_race_ = false;
};

template <typename Symfile>
struct JitCacheEntry {
  // PC memory range described by this entry.
  uint64_t addr_ = 0;
  uint64_t size_ = 0;
  std::unique_ptr<Symfile> symfile_;

  bool Init(Maps* maps, JitMemory* memory, uint64_t addr, uint64_t size);
};

template <typename Symfile, typename PointerT, typename Uint64_T>
class JitDebugImpl : public JitDebug<Symfile>, public Global {
 public:
  static constexpr const char* kDescriptorExtMagic = "Android1";
  static constexpr int kMaxRaceRetries = 16;

  struct JITCodeEntry {
    PointerT next;
    PointerT prev;
    PointerT symfile_addr;
    Uint64_T symfile_size;
  };

  struct JITDescriptor {
    uint32_t version;
    uint32_t action_flag;
    PointerT relevant_entry;
    PointerT first_entry;
  };

  // Android-specific extensions.
  struct JITDescriptorExt {
    JITDescriptor desc;
    uint8_t magic[8];
    uint32_t flags;
    uint32_t sizeof_descriptor;
    uint32_t sizeof_entry;
    uint32_t action_seqlock;
    uint64_t action_timestamp;
  };

  JitDebugImpl(ArchEnum arch, std::shared_ptr<Memory>& memory,
               std::vector<std::string>& search_libs)
      : Global(memory, search_libs) {
    SetArch(arch);
  }

  Symfile* Get(Maps* maps, uint64_t pc) override;
  virtual bool ReadVariableData(uint64_t offset);
  virtual void ProcessArch() {}
  bool Update(Maps* maps);
  bool Read(Maps* maps, JitMemory* memory);

  bool initialized_ = false;
  uint64_t descriptor_addr_ = 0;  // Non-zero if we have found (non-empty) descriptor.
  uint64_t seqlock_addr_ = 0;     // Re-read entries if the value at this address changes.
  uint32_t last_seqlock_ = ~0u;   // The value of seqlock when we last read the entries.

  std::deque<JitCacheEntry<Symfile>> entries_;

  std::mutex lock_;
};

template <typename Symfile>
std::unique_ptr<JitDebug<Symfile>> JitDebug<Symfile>::Create(ArchEnum arch,
                                                             std::shared_ptr<Memory>& memory,
                                                             std::vector<std::string> search_libs) {
  typedef JitDebugImpl<Symfile, uint32_t, Uint64_P> JitDebugImpl32P;
  typedef JitDebugImpl<Symfile, uint32_t, Uint64_A> JitDebugImpl32A;
  typedef JitDebugImpl<Symfile, uint64_t, Uint64_A> JitDebugImpl64A;
  switch (arch) {
    case ARCH_X86:
      static_assert(sizeof(typename JitDebugImpl32P::JITCodeEntry) == 20, "layout");
      static_assert(sizeof(typename JitDebugImpl32P::JITDescriptor) == 16, "layout");
      static_assert(sizeof(typename JitDebugImpl32P::JITDescriptorExt) == 48, "layout");
      return std::unique_ptr<JitDebug>(new JitDebugImpl32P(arch, memory, search_libs));
      break;
    case ARCH_ARM:
    case ARCH_MIPS:
      static_assert(sizeof(typename JitDebugImpl32A::JITCodeEntry) == 24, "layout");
      static_assert(sizeof(typename JitDebugImpl32A::JITDescriptor) == 16, "layout");
      static_assert(sizeof(typename JitDebugImpl32A::JITDescriptorExt) == 48, "layout");
      return std::unique_ptr<JitDebug>(new JitDebugImpl32A(arch, memory, search_libs));
      break;
    case ARCH_ARM64:
    case ARCH_X86_64:
    case ARCH_MIPS64:
      static_assert(sizeof(typename JitDebugImpl64A::JITCodeEntry) == 32, "layout");
      static_assert(sizeof(typename JitDebugImpl64A::JITDescriptor) == 24, "layout");
      static_assert(sizeof(typename JitDebugImpl64A::JITDescriptorExt) == 56, "layout");
      return std::unique_ptr<JitDebug>(new JitDebugImpl64A(arch, memory, search_libs));
      break;
    default:
      abort();
  }
}

size_t JitMemory::Read(uint64_t addr, void* dst, size_t size) {
  if (!parent_->ReadFully(addr, dst, size)) {
    return 0;
  }
  // This is required for memory synchronization if the we are working with local memory.
  // For other types of memory (e.g. remote) this is no-op and has no significant effect.
  std::atomic_thread_fence(std::memory_order_acquire);
  uint32_t seen_seqlock;
  if (!parent_->Read32(seqlock_addr_, &seen_seqlock)) {
    return 0;
  }
  if (seen_seqlock != expected_seqlock_) {
    failed_due_to_race_ = true;
    return 0;
  }
  return size;
}

template <typename Symfile, typename PointerT, typename Uint64_T>
bool JitDebugImpl<Symfile, PointerT, Uint64_T>::ReadVariableData(uint64_t addr) {
  JITDescriptor desc;
  if (!this->memory_->ReadFully(addr, &desc, sizeof(desc))) {
    return false;
  }
  if (desc.version != 1) {
    return false;
  }
  if (desc.first_entry == 0) {
    return false;  // There could be multiple descriptors. Ignore empty ones.
  }
  descriptor_addr_ = addr;
  JITDescriptorExt desc_ext;
  if (this->memory_->ReadFully(addr, &desc_ext, sizeof(desc_ext)) &&
      memcmp(desc_ext.magic, kDescriptorExtMagic, 8) == 0) {
    seqlock_addr_ = descriptor_addr_ + offsetof(JITDescriptorExt, action_seqlock);
  } else {
    // In the absence of Android-specific fields, use the head pointer instead.
    seqlock_addr_ = descriptor_addr_ + offsetof(JITDescriptor, first_entry);
  }
  return true;
}

template <typename Symfile>
static const char* GetDescriptorName();

template <>
const char* GetDescriptorName<Elf>() {
  return "__jit_debug_descriptor";
}

template <typename Symfile, typename PointerT, typename Uint64_T>
Symfile* JitDebugImpl<Symfile, PointerT, Uint64_T>::Get(Maps* maps, uint64_t pc) {
  std::lock_guard<std::mutex> guard(lock_);
  if (!initialized_) {
    FindAndReadVariable(maps, GetDescriptorName<Symfile>());
    initialized_ = true;
  }

  if (descriptor_addr_ == 0) {
    return nullptr;
  }

  if (!Update(maps)) {
    return nullptr;
  }

  Symfile* fallback = nullptr;
  for (auto& entry : entries_) {
    // Skip entries which are obviously not relevant (if we know the PC range).
    if (entry.size_ == 0 || (entry.addr_ <= pc && (pc - entry.addr_) < entry.size_)) {
      // Double check the entry contains the PC in case there are overlapping entries.
      // This is might happen for native-code due to GC and for DEX due to data sharing.
      std::string method_name;
      uint64_t method_offset;
      if (entry.symfile_->GetFunctionName(pc, &method_name, &method_offset)) {
        return entry.symfile_.get();
      }
      fallback = entry.symfile_.get();  // Tests don't have any symbols.
    }
  }
  return fallback;  // Not found.
}

// Update JIT entries if needed.  It will retry if there are data races.
template <typename Symfile, typename PointerT, typename Uint64_T>
bool JitDebugImpl<Symfile, PointerT, Uint64_T>::Update(Maps* maps) {
  // We might need to retry the whole read in the presence of data races.
  for (int i = 0; i < kMaxRaceRetries; i++) {
    // Read the seqlock (counter which is incremented before and after any modification).
    uint32_t seqlock = 0;
    if (!this->memory_->Read32(seqlock_addr_, &seqlock)) {
      return false;  // Failed to read seqlock.
    }

    // Check if anything changed since the last time we checked.
    if (last_seqlock_ != seqlock) {
      // Create memory wrapper to allow us to read the entries safely even in a live process.
      JitMemory safe_memory;
      safe_memory.parent_ = this->memory_.get();
      safe_memory.seqlock_addr_ = seqlock_addr_;
      safe_memory.expected_seqlock_ = seqlock;
      std::atomic_thread_fence(std::memory_order_acquire);

      // Add all entries to our cache.
      if (!Read(maps, &safe_memory)) {
        if (safe_memory.failed_due_to_race_) {
          sleep(0);
          continue;  // Try again (there was a data race).
        } else {
          return false;  // Proper failure (we could not read the data).
        }
      }
      last_seqlock_ = seqlock;
    }
    return true;
  }
  return false;  // Too many retries.
}

// Read all JIT entries.  It might randomly fail due to data races.
template <typename Symfile, typename PointerT, typename Uint64_T>
bool JitDebugImpl<Symfile, PointerT, Uint64_T>::Read(Maps* maps, JitMemory* memory) {
  std::unordered_set<uint64_t> seen_entry_addr;

  // Read and verify the descriptor (must be after we have read the initial seqlock).
  JITDescriptor desc;
  if (!(memory->ReadFully(descriptor_addr_, &desc, sizeof(desc)))) {
    return false;
  }

  entries_.clear();
  JITCodeEntry entry;
  for (uint64_t entry_addr = desc.first_entry; entry_addr != 0; entry_addr = entry.next) {
    // Check for infinite loops in the lined list.
    if (!seen_entry_addr.emplace(entry_addr).second) {
      return true;  // TODO: Fail when seening infinite loop.
    }

    // Read the entry (while checking for data races).
    if (!memory->ReadFully(entry_addr, &entry, sizeof(entry))) {
      return false;
    }

    // Copy and load the symfile.
    entries_.emplace_back(JitCacheEntry<Symfile>());
    if (!entries_.back().Init(maps, memory, entry.symfile_addr, entry.symfile_size.value)) {
      return false;
    }
  }

  return true;
}

// Copy and load ELF file.
template <>
bool JitCacheEntry<Elf>::Init(Maps*, JitMemory* memory, uint64_t addr, uint64_t size) {
  // Make a copy of the in-memory symbol file (while checking for data races).
  std::unique_ptr<MemoryBuffer> buffer(new MemoryBuffer());
  buffer->Resize(size);
  if (!memory->ReadFully(addr, buffer->GetPtr(0), buffer->Size())) {
    return false;
  }

  // Load and validate the ELF file.
  symfile_.reset(new Elf(buffer.release()));
  symfile_->Init();
  if (!symfile_->valid()) {
    return false;
  }

  symfile_->GetTextRange(&addr_, &size_);
  return true;
}

template std::unique_ptr<JitDebug<Elf>> JitDebug<Elf>::Create(ArchEnum, std::shared_ptr<Memory>&,
                                                              std::vector<std::string>);

#if !defined(NO_LIBDEXFILE_SUPPORT)

template <>
const char* GetDescriptorName<DexFile>() {
  return "__dex_debug_descriptor";
}

// Copy and load DEX file.
template <>
bool JitCacheEntry<DexFile>::Init(Maps* maps, JitMemory* memory, uint64_t addr, uint64_t) {
  MapInfo* info = maps->Find(addr);
  if (info == nullptr) {
    return false;
  }
  symfile_ = DexFile::Create(addr, memory, info);
  if (symfile_ == nullptr) {
    return false;
  }
  return true;
}

template std::unique_ptr<JitDebug<DexFile>> JitDebug<DexFile>::Create(ArchEnum,
                                                                      std::shared_ptr<Memory>&,
                                                                      std::vector<std::string>);

#endif

}  // namespace unwindstack
