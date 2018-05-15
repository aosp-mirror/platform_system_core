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

#include <inttypes.h>
#include <string.h>

#include <functional>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>

#include <android-base/macros.h>
#include <backtrace.h>

#include "Allocator.h"
#include "Binder.h"
#include "HeapWalker.h"
#include "Leak.h"
#include "LeakFolding.h"
#include "LeakPipe.h"
#include "ProcessMappings.h"
#include "PtracerThread.h"
#include "ScopedDisableMalloc.h"
#include "Semaphore.h"
#include "ThreadCapture.h"

#include "bionic.h"
#include "log.h"
#include "memunreachable/memunreachable.h"

using namespace std::chrono_literals;

namespace android {

const size_t Leak::contents_length;

class MemUnreachable {
 public:
  MemUnreachable(pid_t pid, Allocator<void> allocator)
      : pid_(pid), allocator_(allocator), heap_walker_(allocator_) {}
  bool CollectAllocations(const allocator::vector<ThreadInfo>& threads,
                          const allocator::vector<Mapping>& mappings,
                          const allocator::vector<uintptr_t>& refs);
  bool GetUnreachableMemory(allocator::vector<Leak>& leaks, size_t limit, size_t* num_leaks,
                            size_t* leak_bytes);
  size_t Allocations() { return heap_walker_.Allocations(); }
  size_t AllocationBytes() { return heap_walker_.AllocationBytes(); }

 private:
  bool ClassifyMappings(const allocator::vector<Mapping>& mappings,
                        allocator::vector<Mapping>& heap_mappings,
                        allocator::vector<Mapping>& anon_mappings,
                        allocator::vector<Mapping>& globals_mappings,
                        allocator::vector<Mapping>& stack_mappings);
  DISALLOW_COPY_AND_ASSIGN(MemUnreachable);
  pid_t pid_;
  Allocator<void> allocator_;
  HeapWalker heap_walker_;
};

static void HeapIterate(const Mapping& heap_mapping,
                        const std::function<void(uintptr_t, size_t)>& func) {
  malloc_iterate(heap_mapping.begin, heap_mapping.end - heap_mapping.begin,
                 [](uintptr_t base, size_t size, void* arg) {
                   auto f = reinterpret_cast<const std::function<void(uintptr_t, size_t)>*>(arg);
                   (*f)(base, size);
                 },
                 const_cast<void*>(reinterpret_cast<const void*>(&func)));
}

bool MemUnreachable::CollectAllocations(const allocator::vector<ThreadInfo>& threads,
                                        const allocator::vector<Mapping>& mappings,
                                        const allocator::vector<uintptr_t>& refs) {
  MEM_ALOGI("searching process %d for allocations", pid_);
  allocator::vector<Mapping> heap_mappings{mappings};
  allocator::vector<Mapping> anon_mappings{mappings};
  allocator::vector<Mapping> globals_mappings{mappings};
  allocator::vector<Mapping> stack_mappings{mappings};
  if (!ClassifyMappings(mappings, heap_mappings, anon_mappings, globals_mappings, stack_mappings)) {
    return false;
  }

  for (auto it = heap_mappings.begin(); it != heap_mappings.end(); it++) {
    MEM_ALOGV("Heap mapping %" PRIxPTR "-%" PRIxPTR " %s", it->begin, it->end, it->name);
    HeapIterate(*it,
                [&](uintptr_t base, size_t size) { heap_walker_.Allocation(base, base + size); });
  }

  for (auto it = anon_mappings.begin(); it != anon_mappings.end(); it++) {
    MEM_ALOGV("Anon mapping %" PRIxPTR "-%" PRIxPTR " %s", it->begin, it->end, it->name);
    heap_walker_.Allocation(it->begin, it->end);
  }

  for (auto it = globals_mappings.begin(); it != globals_mappings.end(); it++) {
    MEM_ALOGV("Globals mapping %" PRIxPTR "-%" PRIxPTR " %s", it->begin, it->end, it->name);
    heap_walker_.Root(it->begin, it->end);
  }

  for (auto thread_it = threads.begin(); thread_it != threads.end(); thread_it++) {
    for (auto it = stack_mappings.begin(); it != stack_mappings.end(); it++) {
      if (thread_it->stack.first >= it->begin && thread_it->stack.first <= it->end) {
        MEM_ALOGV("Stack %" PRIxPTR "-%" PRIxPTR " %s", thread_it->stack.first, it->end, it->name);
        heap_walker_.Root(thread_it->stack.first, it->end);
      }
    }
    heap_walker_.Root(thread_it->regs);
  }

  heap_walker_.Root(refs);

  MEM_ALOGI("searching done");

  return true;
}

bool MemUnreachable::GetUnreachableMemory(allocator::vector<Leak>& leaks, size_t limit,
                                          size_t* num_leaks, size_t* leak_bytes) {
  MEM_ALOGI("sweeping process %d for unreachable memory", pid_);
  leaks.clear();

  if (!heap_walker_.DetectLeaks()) {
    return false;
  }

  allocator::vector<Range> leaked1{allocator_};
  heap_walker_.Leaked(leaked1, 0, num_leaks, leak_bytes);

  MEM_ALOGI("sweeping done");

  MEM_ALOGI("folding related leaks");

  LeakFolding folding(allocator_, heap_walker_);
  if (!folding.FoldLeaks()) {
    return false;
  }

  allocator::vector<LeakFolding::Leak> leaked{allocator_};

  if (!folding.Leaked(leaked, num_leaks, leak_bytes)) {
    return false;
  }

  allocator::unordered_map<Leak::Backtrace, Leak*> backtrace_map{allocator_};

  // Prevent reallocations of backing memory so we can store pointers into it
  // in backtrace_map.
  leaks.reserve(leaked.size());

  for (auto& it : leaked) {
    leaks.emplace_back();
    Leak* leak = &leaks.back();

    ssize_t num_backtrace_frames = malloc_backtrace(
        reinterpret_cast<void*>(it.range.begin), leak->backtrace.frames, leak->backtrace.max_frames);
    if (num_backtrace_frames > 0) {
      leak->backtrace.num_frames = num_backtrace_frames;

      auto inserted = backtrace_map.emplace(leak->backtrace, leak);
      if (!inserted.second) {
        // Leak with same backtrace already exists, drop this one and
        // increment similar counts on the existing one.
        leaks.pop_back();
        Leak* similar_leak = inserted.first->second;
        similar_leak->similar_count++;
        similar_leak->similar_size += it.range.size();
        similar_leak->similar_referenced_count += it.referenced_count;
        similar_leak->similar_referenced_size += it.referenced_size;
        similar_leak->total_size += it.range.size();
        similar_leak->total_size += it.referenced_size;
        continue;
      }
    }

    leak->begin = it.range.begin;
    leak->size = it.range.size();
    leak->referenced_count = it.referenced_count;
    leak->referenced_size = it.referenced_size;
    leak->total_size = leak->size + leak->referenced_size;
    memcpy(leak->contents, reinterpret_cast<void*>(it.range.begin),
           std::min(leak->size, Leak::contents_length));
  }

  MEM_ALOGI("folding done");

  std::sort(leaks.begin(), leaks.end(),
            [](const Leak& a, const Leak& b) { return a.total_size > b.total_size; });

  if (leaks.size() > limit) {
    leaks.resize(limit);
  }

  return true;
}

static bool has_prefix(const allocator::string& s, const char* prefix) {
  int ret = s.compare(0, strlen(prefix), prefix);
  return ret == 0;
}

bool MemUnreachable::ClassifyMappings(const allocator::vector<Mapping>& mappings,
                                      allocator::vector<Mapping>& heap_mappings,
                                      allocator::vector<Mapping>& anon_mappings,
                                      allocator::vector<Mapping>& globals_mappings,
                                      allocator::vector<Mapping>& stack_mappings) {
  heap_mappings.clear();
  anon_mappings.clear();
  globals_mappings.clear();
  stack_mappings.clear();

  allocator::string current_lib{allocator_};

  for (auto it = mappings.begin(); it != mappings.end(); it++) {
    if (it->execute) {
      current_lib = it->name;
      continue;
    }

    if (!it->read) {
      continue;
    }

    const allocator::string mapping_name{it->name, allocator_};
    if (mapping_name == "[anon:.bss]") {
      // named .bss section
      globals_mappings.emplace_back(*it);
    } else if (mapping_name == current_lib) {
      // .rodata or .data section
      globals_mappings.emplace_back(*it);
    } else if (mapping_name == "[anon:libc_malloc]") {
      // named malloc mapping
      heap_mappings.emplace_back(*it);
    } else if (has_prefix(mapping_name, "/dev/ashmem/dalvik")) {
      // named dalvik heap mapping
      globals_mappings.emplace_back(*it);
    } else if (has_prefix(mapping_name, "[stack")) {
      // named stack mapping
      stack_mappings.emplace_back(*it);
    } else if (mapping_name.size() == 0) {
      globals_mappings.emplace_back(*it);
    } else if (has_prefix(mapping_name, "[anon:") &&
               mapping_name != "[anon:leak_detector_malloc]") {
      // TODO(ccross): it would be nice to treat named anonymous mappings as
      // possible leaks, but naming something in a .bss or .data section makes
      // it impossible to distinguish them from mmaped and then named mappings.
      globals_mappings.emplace_back(*it);
    }
  }

  return true;
}

template <typename T>
static inline const char* plural(T val) {
  return (val == 1) ? "" : "s";
}

bool GetUnreachableMemory(UnreachableMemoryInfo& info, size_t limit) {
  int parent_pid = getpid();
  int parent_tid = gettid();

  Heap heap;

  Semaphore continue_parent_sem;
  LeakPipe pipe;

  PtracerThread thread{[&]() -> int {
    /////////////////////////////////////////////
    // Collection thread
    /////////////////////////////////////////////
    MEM_ALOGI("collecting thread info for process %d...", parent_pid);

    ThreadCapture thread_capture(parent_pid, heap);
    allocator::vector<ThreadInfo> thread_info(heap);
    allocator::vector<Mapping> mappings(heap);
    allocator::vector<uintptr_t> refs(heap);

    // ptrace all the threads
    if (!thread_capture.CaptureThreads()) {
      continue_parent_sem.Post();
      return 1;
    }

    // collect register contents and stacks
    if (!thread_capture.CapturedThreadInfo(thread_info)) {
      continue_parent_sem.Post();
      return 1;
    }

    // snapshot /proc/pid/maps
    if (!ProcessMappings(parent_pid, mappings)) {
      continue_parent_sem.Post();
      return 1;
    }

    if (!BinderReferences(refs)) {
      continue_parent_sem.Post();
      return 1;
    }

    // malloc must be enabled to call fork, at_fork handlers take the same
    // locks as ScopedDisableMalloc.  All threads are paused in ptrace, so
    // memory state is still consistent.  Unfreeze the original thread so it
    // can drop the malloc locks, it will block until the collection thread
    // exits.
    thread_capture.ReleaseThread(parent_tid);
    continue_parent_sem.Post();

    // fork a process to do the heap walking
    int ret = fork();
    if (ret < 0) {
      return 1;
    } else if (ret == 0) {
      /////////////////////////////////////////////
      // Heap walker process
      /////////////////////////////////////////////
      // Examine memory state in the child using the data collected above and
      // the CoW snapshot of the process memory contents.

      if (!pipe.OpenSender()) {
        _exit(1);
      }

      MemUnreachable unreachable{parent_pid, heap};

      if (!unreachable.CollectAllocations(thread_info, mappings, refs)) {
        _exit(2);
      }
      size_t num_allocations = unreachable.Allocations();
      size_t allocation_bytes = unreachable.AllocationBytes();

      allocator::vector<Leak> leaks{heap};

      size_t num_leaks = 0;
      size_t leak_bytes = 0;
      bool ok = unreachable.GetUnreachableMemory(leaks, limit, &num_leaks, &leak_bytes);

      ok = ok && pipe.Sender().Send(num_allocations);
      ok = ok && pipe.Sender().Send(allocation_bytes);
      ok = ok && pipe.Sender().Send(num_leaks);
      ok = ok && pipe.Sender().Send(leak_bytes);
      ok = ok && pipe.Sender().SendVector(leaks);

      if (!ok) {
        _exit(3);
      }

      _exit(0);
    } else {
      // Nothing left to do in the collection thread, return immediately,
      // releasing all the captured threads.
      MEM_ALOGI("collection thread done");
      return 0;
    }
  }};

  /////////////////////////////////////////////
  // Original thread
  /////////////////////////////////////////////

  {
    // Disable malloc to get a consistent view of memory
    ScopedDisableMalloc disable_malloc;

    // Start the collection thread
    thread.Start();

    // Wait for the collection thread to signal that it is ready to fork the
    // heap walker process.
    continue_parent_sem.Wait(30s);

    // Re-enable malloc so the collection thread can fork.
  }

  // Wait for the collection thread to exit
  int ret = thread.Join();
  if (ret != 0) {
    return false;
  }

  // Get a pipe from the heap walker process.  Transferring a new pipe fd
  // ensures no other forked processes can have it open, so when the heap
  // walker process dies the remote side of the pipe will close.
  if (!pipe.OpenReceiver()) {
    return false;
  }

  bool ok = true;
  ok = ok && pipe.Receiver().Receive(&info.num_allocations);
  ok = ok && pipe.Receiver().Receive(&info.allocation_bytes);
  ok = ok && pipe.Receiver().Receive(&info.num_leaks);
  ok = ok && pipe.Receiver().Receive(&info.leak_bytes);
  ok = ok && pipe.Receiver().ReceiveVector(info.leaks);
  if (!ok) {
    return false;
  }

  MEM_ALOGI("unreachable memory detection done");
  MEM_ALOGE("%zu bytes in %zu allocation%s unreachable out of %zu bytes in %zu allocation%s",
            info.leak_bytes, info.num_leaks, plural(info.num_leaks), info.allocation_bytes,
            info.num_allocations, plural(info.num_allocations));
  return true;
}

std::string Leak::ToString(bool log_contents) const {
  std::ostringstream oss;

  oss << "  " << std::dec << size;
  oss << " bytes unreachable at ";
  oss << std::hex << begin;
  oss << std::endl;
  if (referenced_count > 0) {
    oss << std::dec;
    oss << "   referencing " << referenced_size << " unreachable bytes";
    oss << " in " << referenced_count << " allocation" << plural(referenced_count);
    oss << std::endl;
  }
  if (similar_count > 0) {
    oss << std::dec;
    oss << "   and " << similar_size << " similar unreachable bytes";
    oss << " in " << similar_count << " allocation" << plural(similar_count);
    oss << std::endl;
    if (similar_referenced_count > 0) {
      oss << "   referencing " << similar_referenced_size << " unreachable bytes";
      oss << " in " << similar_referenced_count << " allocation" << plural(similar_referenced_count);
      oss << std::endl;
    }
  }

  if (log_contents) {
    const int bytes_per_line = 16;
    const size_t bytes = std::min(size, contents_length);

    if (bytes == size) {
      oss << "   contents:" << std::endl;
    } else {
      oss << "   first " << bytes << " bytes of contents:" << std::endl;
    }

    for (size_t i = 0; i < bytes; i += bytes_per_line) {
      oss << "   " << std::hex << begin + i << ": ";
      size_t j;
      oss << std::setfill('0');
      for (j = i; j < bytes && j < i + bytes_per_line; j++) {
        oss << std::setw(2) << static_cast<int>(contents[j]) << " ";
      }
      oss << std::setfill(' ');
      for (; j < i + bytes_per_line; j++) {
        oss << "   ";
      }
      for (j = i; j < bytes && j < i + bytes_per_line; j++) {
        char c = contents[j];
        if (c < ' ' || c >= 0x7f) {
          c = '.';
        }
        oss << c;
      }
      oss << std::endl;
    }
  }
  if (backtrace.num_frames > 0) {
    oss << backtrace_string(backtrace.frames, backtrace.num_frames);
  }

  return oss.str();
}

std::string UnreachableMemoryInfo::ToString(bool log_contents) const {
  std::ostringstream oss;
  oss << "  " << leak_bytes << " bytes in ";
  oss << num_leaks << " unreachable allocation" << plural(num_leaks);
  oss << std::endl;
  oss << "  ABI: '" ABI_STRING "'" << std::endl;
  oss << std::endl;

  for (auto it = leaks.begin(); it != leaks.end(); it++) {
    oss << it->ToString(log_contents);
    oss << std::endl;
  }

  return oss.str();
}

UnreachableMemoryInfo::~UnreachableMemoryInfo() {
  // Clear the memory that holds the leaks, otherwise the next attempt to
  // detect leaks may find the old data (for example in the jemalloc tcache)
  // and consider all the leaks to be referenced.
  memset(leaks.data(), 0, leaks.capacity() * sizeof(Leak));

  std::vector<Leak> tmp;
  leaks.swap(tmp);

  // Disable and re-enable malloc to flush the jemalloc tcache to make sure
  // there are no copies of the leaked pointer addresses there.
  malloc_disable();
  malloc_enable();
}

std::string GetUnreachableMemoryString(bool log_contents, size_t limit) {
  UnreachableMemoryInfo info;
  if (!GetUnreachableMemory(info, limit)) {
    return "Failed to get unreachable memory\n"
           "If you are trying to get unreachable memory from a system app\n"
           "(like com.android.systemui), disable selinux first using\n"
           "setenforce 0\n";
  }

  return info.ToString(log_contents);
}

}  // namespace android

bool LogUnreachableMemory(bool log_contents, size_t limit) {
  android::UnreachableMemoryInfo info;
  if (!android::GetUnreachableMemory(info, limit)) {
    return false;
  }

  for (auto it = info.leaks.begin(); it != info.leaks.end(); it++) {
    MEM_ALOGE("%s", it->ToString(log_contents).c_str());
  }
  return true;
}

bool NoLeaks() {
  android::UnreachableMemoryInfo info;
  if (!android::GetUnreachableMemory(info, 0)) {
    return false;
  }

  return info.num_leaks == 0;
}
