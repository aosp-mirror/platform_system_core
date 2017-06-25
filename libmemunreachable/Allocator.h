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

#ifndef LIBMEMUNREACHABLE_ALLOCATOR_H_
#define LIBMEMUNREACHABLE_ALLOCATOR_H_

#include <atomic>
#include <cstddef>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace android {

extern std::atomic<int> heap_count;

class HeapImpl;

template <typename T>
class Allocator;

// Non-templated class that implements wraps HeapImpl to keep
// implementation out of the header file
class Heap {
 public:
  Heap();
  ~Heap();

  // Copy constructor that does not take ownership of impl_
  Heap(const Heap& other) : impl_(other.impl_), owns_impl_(false) {}

  // Assignment disabled
  Heap& operator=(const Heap&) = delete;

  // Allocate size bytes
  void* allocate(size_t size);

  // Deallocate allocation returned by allocate
  void deallocate(void*);

  bool empty();

  static void deallocate(HeapImpl* impl, void* ptr);

  // Allocate a class of type T
  template <class T>
  T* allocate() {
    return reinterpret_cast<T*>(allocate(sizeof(T)));
  }

  // Comparators, copied objects will be equal
  bool operator==(const Heap& other) const { return impl_ == other.impl_; }
  bool operator!=(const Heap& other) const { return !(*this == other); }

  // std::unique_ptr wrapper that allocates using allocate and deletes using
  // deallocate
  template <class T>
  using unique_ptr = std::unique_ptr<T, std::function<void(void*)>>;

  template <class T, class... Args>
  unique_ptr<T> make_unique(Args&&... args) {
    HeapImpl* impl = impl_;
    return unique_ptr<T>(new (allocate<T>()) T(std::forward<Args>(args)...), [impl](void* ptr) {
      reinterpret_cast<T*>(ptr)->~T();
      deallocate(impl, ptr);
    });
  }

  // std::unique_ptr wrapper that allocates using allocate and deletes using
  // deallocate
  template <class T>
  using shared_ptr = std::shared_ptr<T>;

  template <class T, class... Args>
  shared_ptr<T> make_shared(Args&&... args);

 protected:
  HeapImpl* impl_;
  bool owns_impl_;
};

// STLAllocator implements the std allocator interface on top of a Heap
template <typename T>
class STLAllocator {
 public:
  using value_type = T;
  ~STLAllocator() {}

  // Construct an STLAllocator on top of a Heap
  STLAllocator(const Heap& heap)
      :  // NOLINT, implicit
        heap_(heap) {}

  // Rebind an STLAllocator from an another STLAllocator
  template <typename U>
  STLAllocator(const STLAllocator<U>& other)
      :  // NOLINT, implicit
        heap_(other.heap_) {}

  STLAllocator(const STLAllocator&) = default;
  STLAllocator<T>& operator=(const STLAllocator<T>&) = default;

  T* allocate(std::size_t n) { return reinterpret_cast<T*>(heap_.allocate(n * sizeof(T))); }

  void deallocate(T* ptr, std::size_t) { heap_.deallocate(ptr); }

  template <typename U>
  bool operator==(const STLAllocator<U>& other) const {
    return heap_ == other.heap_;
  }
  template <typename U>
  inline bool operator!=(const STLAllocator<U>& other) const {
    return !(this == other);
  }

  template <typename U>
  friend class STLAllocator;

 protected:
  Heap heap_;
};

// Allocator extends STLAllocator with some convenience methods for allocating
// a single object and for constructing unique_ptr and shared_ptr objects with
// appropriate deleters.
template <class T>
class Allocator : public STLAllocator<T> {
 public:
  ~Allocator() {}

  Allocator(const Heap& other)
      :  // NOLINT, implicit
        STLAllocator<T>(other) {}

  template <typename U>
  Allocator(const STLAllocator<U>& other)
      :  // NOLINT, implicit
        STLAllocator<T>(other) {}

  Allocator(const Allocator&) = default;
  Allocator<T>& operator=(const Allocator<T>&) = default;

  using STLAllocator<T>::allocate;
  using STLAllocator<T>::deallocate;
  using STLAllocator<T>::heap_;

  T* allocate() { return STLAllocator<T>::allocate(1); }
  void deallocate(void* ptr) { heap_.deallocate(ptr); }

  using shared_ptr = Heap::shared_ptr<T>;

  template <class... Args>
  shared_ptr make_shared(Args&&... args) {
    return heap_.template make_shared<T>(std::forward<Args>(args)...);
  }

  using unique_ptr = Heap::unique_ptr<T>;

  template <class... Args>
  unique_ptr make_unique(Args&&... args) {
    return heap_.template make_unique<T>(std::forward<Args>(args)...);
  }
};

// std::unique_ptr wrapper that allocates using allocate and deletes using
// deallocate.  Implemented outside class definition in order to pass
// Allocator<T> to shared_ptr.
template <class T, class... Args>
inline Heap::shared_ptr<T> Heap::make_shared(Args&&... args) {
  return std::allocate_shared<T, Allocator<T>, Args...>(Allocator<T>(*this),
                                                        std::forward<Args>(args)...);
}

namespace allocator {

template <class T>
using vector = std::vector<T, Allocator<T>>;

template <class T>
using list = std::list<T, Allocator<T>>;

template <class Key, class T, class Compare = std::less<Key>>
using map = std::map<Key, T, Compare, Allocator<std::pair<const Key, T>>>;

template <class Key, class T, class Hash = std::hash<Key>, class KeyEqual = std::equal_to<Key>>
using unordered_map =
    std::unordered_map<Key, T, Hash, KeyEqual, Allocator<std::pair<const Key, T>>>;

template <class Key, class Hash = std::hash<Key>, class KeyEqual = std::equal_to<Key>>
using unordered_set = std::unordered_set<Key, Hash, KeyEqual, Allocator<Key>>;

template <class Key, class Compare = std::less<Key>>
using set = std::set<Key, Compare, Allocator<Key>>;

using string = std::basic_string<char, std::char_traits<char>, Allocator<char>>;
}

}  // namespace android

#endif
