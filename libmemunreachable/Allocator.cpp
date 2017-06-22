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

// Header page:
//
// For minimum allocation size (8 bytes), bitmap can store used allocations for
// up to 4032*8*8=258048, which is 256KiB minus the header page

#include <assert.h>
#include <stdlib.h>

#include <sys/cdefs.h>
#include <sys/mman.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

#include "android-base/macros.h"

#include "Allocator.h"
#include "LinkedList.h"
#include "anon_vma_naming.h"

namespace android {

// runtime interfaces used:
// abort
// assert - fprintf + mmap
// mmap
// munmap
// prctl

constexpr size_t const_log2(size_t n, size_t p = 0) {
  return (n <= 1) ? p : const_log2(n / 2, p + 1);
}

constexpr unsigned int div_round_up(unsigned int x, unsigned int y) {
  return (x + y - 1) / y;
}

static constexpr size_t kPageSize = 4096;
static constexpr size_t kChunkSize = 256 * 1024;
static constexpr size_t kUsableChunkSize = kChunkSize - kPageSize;
static constexpr size_t kMaxBucketAllocationSize = kChunkSize / 4;
static constexpr size_t kMinBucketAllocationSize = 8;
static constexpr unsigned int kNumBuckets =
    const_log2(kMaxBucketAllocationSize) - const_log2(kMinBucketAllocationSize) + 1;
static constexpr unsigned int kUsablePagesPerChunk = kUsableChunkSize / kPageSize;

std::atomic<int> heap_count;

class Chunk;

class HeapImpl {
 public:
  HeapImpl();
  ~HeapImpl();
  void* operator new(std::size_t count) noexcept;
  void operator delete(void* ptr);

  void* Alloc(size_t size);
  void Free(void* ptr);
  bool Empty();

  void MoveToFullList(Chunk* chunk, int bucket_);
  void MoveToFreeList(Chunk* chunk, int bucket_);

 private:
  DISALLOW_COPY_AND_ASSIGN(HeapImpl);

  LinkedList<Chunk*> free_chunks_[kNumBuckets];
  LinkedList<Chunk*> full_chunks_[kNumBuckets];

  void MoveToList(Chunk* chunk, LinkedList<Chunk*>* head);
  void* MapAlloc(size_t size);
  void MapFree(void* ptr);
  void* AllocLocked(size_t size);
  void FreeLocked(void* ptr);

  struct MapAllocation {
    void* ptr;
    size_t size;
    MapAllocation* next;
  };
  MapAllocation* map_allocation_list_;
  std::mutex m_;
};

// Integer log 2, rounds down
static inline unsigned int log2(size_t n) {
  return 8 * sizeof(unsigned long long) - __builtin_clzll(n) - 1;
}

static inline unsigned int size_to_bucket(size_t size) {
  if (size < kMinBucketAllocationSize) return kMinBucketAllocationSize;
  return log2(size - 1) + 1 - const_log2(kMinBucketAllocationSize);
}

static inline size_t bucket_to_size(unsigned int bucket) {
  return kMinBucketAllocationSize << bucket;
}

static void* MapAligned(size_t size, size_t align) {
  const int prot = PROT_READ | PROT_WRITE;
  const int flags = MAP_ANONYMOUS | MAP_PRIVATE;

  size = (size + kPageSize - 1) & ~(kPageSize - 1);

  // Over-allocate enough to align
  size_t map_size = size + align - kPageSize;
  if (map_size < size) {
    return nullptr;
  }

  void* ptr = mmap(NULL, map_size, prot, flags, -1, 0);
  if (ptr == MAP_FAILED) {
    return nullptr;
  }

  size_t aligned_size = map_size;
  void* aligned_ptr = ptr;

  std::align(align, size, aligned_ptr, aligned_size);

  // Trim beginning
  if (aligned_ptr != ptr) {
    ptrdiff_t extra = reinterpret_cast<uintptr_t>(aligned_ptr) - reinterpret_cast<uintptr_t>(ptr);
    munmap(ptr, extra);
    map_size -= extra;
    ptr = aligned_ptr;
  }

  // Trim end
  if (map_size != size) {
    assert(map_size > size);
    assert(ptr != NULL);
    munmap(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(ptr) + size), map_size - size);
  }

#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, reinterpret_cast<uintptr_t>(ptr), size,
        "leak_detector_malloc");

  return ptr;
}

class Chunk {
 public:
  static void* operator new(std::size_t count) noexcept;
  static void operator delete(void* ptr);
  Chunk(HeapImpl* heap, int bucket);
  ~Chunk() {}

  void* Alloc();
  void Free(void* ptr);
  void Purge();
  bool Empty();

  static Chunk* ptr_to_chunk(void* ptr) {
    return reinterpret_cast<Chunk*>(reinterpret_cast<uintptr_t>(ptr) & ~(kChunkSize - 1));
  }
  static bool is_chunk(void* ptr) {
    return (reinterpret_cast<uintptr_t>(ptr) & (kChunkSize - 1)) != 0;
  }

  unsigned int free_count() { return free_count_; }
  HeapImpl* heap() { return heap_; }
  LinkedList<Chunk*> node_;  // linked list sorted by minimum free count

 private:
  DISALLOW_COPY_AND_ASSIGN(Chunk);
  HeapImpl* heap_;
  unsigned int bucket_;
  unsigned int allocation_size_;    // size of allocations in chunk, min 8 bytes
  unsigned int max_allocations_;    // maximum number of allocations in the chunk
  unsigned int first_free_bitmap_;  // index into bitmap for first non-full entry
  unsigned int free_count_;         // number of available allocations
  unsigned int frees_since_purge_;  // number of calls to Free since last Purge

  // bitmap of pages that have been dirtied
  uint32_t dirty_pages_[div_round_up(kUsablePagesPerChunk, 32)];

  // bitmap of free allocations.
  uint32_t free_bitmap_[kUsableChunkSize / kMinBucketAllocationSize / 32];

  char data_[0];

  unsigned int ptr_to_n(void* ptr) {
    ptrdiff_t offset = reinterpret_cast<uintptr_t>(ptr) - reinterpret_cast<uintptr_t>(data_);
    return offset / allocation_size_;
  }
  void* n_to_ptr(unsigned int n) { return data_ + n * allocation_size_; }
};
static_assert(sizeof(Chunk) <= kPageSize, "header must fit in page");

// Override new operator on chunk to use mmap to allocate kChunkSize
void* Chunk::operator new(std::size_t count __attribute__((unused))) noexcept {
  assert(count == sizeof(Chunk));
  void* mem = MapAligned(kChunkSize, kChunkSize);
  if (!mem) {
    abort();  // throw std::bad_alloc;
  }

  return mem;
}

// Override new operator on chunk to use mmap to allocate kChunkSize
void Chunk::operator delete(void* ptr) {
  assert(reinterpret_cast<Chunk*>(ptr) == ptr_to_chunk(ptr));
  munmap(ptr, kChunkSize);
}

Chunk::Chunk(HeapImpl* heap, int bucket)
    : node_(this),
      heap_(heap),
      bucket_(bucket),
      allocation_size_(bucket_to_size(bucket)),
      max_allocations_(kUsableChunkSize / allocation_size_),
      first_free_bitmap_(0),
      free_count_(max_allocations_),
      frees_since_purge_(0) {
  memset(dirty_pages_, 0, sizeof(dirty_pages_));
  memset(free_bitmap_, 0xff, sizeof(free_bitmap_));
}

bool Chunk::Empty() {
  return free_count_ == max_allocations_;
}

void* Chunk::Alloc() {
  assert(free_count_ > 0);

  unsigned int i = first_free_bitmap_;
  while (free_bitmap_[i] == 0) i++;
  assert(i < arraysize(free_bitmap_));
  unsigned int bit = __builtin_ffs(free_bitmap_[i]) - 1;
  assert(free_bitmap_[i] & (1U << bit));
  free_bitmap_[i] &= ~(1U << bit);
  unsigned int n = i * 32 + bit;
  assert(n < max_allocations_);

  unsigned int page = n * allocation_size_ / kPageSize;
  assert(page / 32 < arraysize(dirty_pages_));
  dirty_pages_[page / 32] |= 1U << (page % 32);

  free_count_--;
  if (free_count_ == 0) {
    heap_->MoveToFullList(this, bucket_);
  }

  return n_to_ptr(n);
}

void Chunk::Free(void* ptr) {
  assert(is_chunk(ptr));
  assert(ptr_to_chunk(ptr) == this);

  unsigned int n = ptr_to_n(ptr);
  unsigned int i = n / 32;
  unsigned int bit = n % 32;

  assert(i < arraysize(free_bitmap_));
  assert(!(free_bitmap_[i] & (1U << bit)));
  free_bitmap_[i] |= 1U << bit;
  free_count_++;

  if (i < first_free_bitmap_) {
    first_free_bitmap_ = i;
  }

  if (free_count_ == 1) {
    heap_->MoveToFreeList(this, bucket_);
  } else {
    // TODO(ccross): move down free list if necessary
  }

  if (frees_since_purge_++ * allocation_size_ > 16 * kPageSize) {
    Purge();
  }
}

void Chunk::Purge() {
  frees_since_purge_ = 0;

  // unsigned int allocsPerPage = kPageSize / allocation_size_;
}

// Override new operator on HeapImpl to use mmap to allocate a page
void* HeapImpl::operator new(std::size_t count __attribute__((unused))) noexcept {
  assert(count == sizeof(HeapImpl));
  void* mem = MapAligned(kPageSize, kPageSize);
  if (!mem) {
    abort();  // throw std::bad_alloc;
  }

  heap_count++;
  return mem;
}

void HeapImpl::operator delete(void* ptr) {
  munmap(ptr, kPageSize);
}

HeapImpl::HeapImpl() : free_chunks_(), full_chunks_(), map_allocation_list_(NULL) {}

bool HeapImpl::Empty() {
  for (unsigned int i = 0; i < kNumBuckets; i++) {
    for (LinkedList<Chunk*>* it = free_chunks_[i].next(); it->data() != NULL; it = it->next()) {
      if (!it->data()->Empty()) {
        return false;
      }
    }
    for (LinkedList<Chunk*>* it = full_chunks_[i].next(); it->data() != NULL; it = it->next()) {
      if (!it->data()->Empty()) {
        return false;
      }
    }
  }

  return true;
}

HeapImpl::~HeapImpl() {
  for (unsigned int i = 0; i < kNumBuckets; i++) {
    while (!free_chunks_[i].empty()) {
      Chunk* chunk = free_chunks_[i].next()->data();
      chunk->node_.remove();
      delete chunk;
    }
    while (!full_chunks_[i].empty()) {
      Chunk* chunk = full_chunks_[i].next()->data();
      chunk->node_.remove();
      delete chunk;
    }
  }
}

void* HeapImpl::Alloc(size_t size) {
  std::lock_guard<std::mutex> lk(m_);
  return AllocLocked(size);
}

void* HeapImpl::AllocLocked(size_t size) {
  if (size > kMaxBucketAllocationSize) {
    return MapAlloc(size);
  }
  int bucket = size_to_bucket(size);
  if (free_chunks_[bucket].empty()) {
    Chunk* chunk = new Chunk(this, bucket);
    free_chunks_[bucket].insert(chunk->node_);
  }
  return free_chunks_[bucket].next()->data()->Alloc();
}

void HeapImpl::Free(void* ptr) {
  std::lock_guard<std::mutex> lk(m_);
  FreeLocked(ptr);
}

void HeapImpl::FreeLocked(void* ptr) {
  if (!Chunk::is_chunk(ptr)) {
    HeapImpl::MapFree(ptr);
  } else {
    Chunk* chunk = Chunk::ptr_to_chunk(ptr);
    assert(chunk->heap() == this);
    chunk->Free(ptr);
  }
}

void* HeapImpl::MapAlloc(size_t size) {
  size = (size + kPageSize - 1) & ~(kPageSize - 1);

  MapAllocation* allocation = reinterpret_cast<MapAllocation*>(AllocLocked(sizeof(MapAllocation)));
  void* ptr = MapAligned(size, kChunkSize);
  if (!ptr) {
    FreeLocked(allocation);
    abort();  // throw std::bad_alloc;
  }
  allocation->ptr = ptr;
  allocation->size = size;
  allocation->next = map_allocation_list_;
  map_allocation_list_ = allocation;

  return ptr;
}

void HeapImpl::MapFree(void* ptr) {
  MapAllocation** allocation = &map_allocation_list_;
  while (*allocation && (*allocation)->ptr != ptr) allocation = &(*allocation)->next;

  assert(*allocation != nullptr);

  munmap((*allocation)->ptr, (*allocation)->size);
  FreeLocked(*allocation);

  *allocation = (*allocation)->next;
}

void HeapImpl::MoveToFreeList(Chunk* chunk, int bucket) {
  MoveToList(chunk, &free_chunks_[bucket]);
}

void HeapImpl::MoveToFullList(Chunk* chunk, int bucket) {
  MoveToList(chunk, &full_chunks_[bucket]);
}

void HeapImpl::MoveToList(Chunk* chunk, LinkedList<Chunk*>* head) {
  // Remove from old list
  chunk->node_.remove();

  LinkedList<Chunk*>* node = head;
  // Insert into new list, sorted by lowest free count
  while (node->next() != head && node->data() != nullptr &&
         node->data()->free_count() < chunk->free_count())
    node = node->next();

  node->insert(chunk->node_);
}

Heap::Heap() {
  // HeapImpl overloads the operator new in order to mmap itself instead of
  // allocating with new.
  // Can't use a shared_ptr to store the result because shared_ptr needs to
  // allocate, and Allocator<T> is still being constructed.
  impl_ = new HeapImpl();
  owns_impl_ = true;
}

Heap::~Heap() {
  if (owns_impl_) {
    delete impl_;
  }
}

void* Heap::allocate(size_t size) {
  return impl_->Alloc(size);
}

void Heap::deallocate(void* ptr) {
  impl_->Free(ptr);
}

void Heap::deallocate(HeapImpl* impl, void* ptr) {
  impl->Free(ptr);
}

bool Heap::empty() {
  return impl_->Empty();
}

}  // namespace android
