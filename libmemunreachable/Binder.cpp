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

#include <sys/cdefs.h>
#include <unistd.h>

#include <functional>

#include "Binder.h"
#include "log.h"

__BEGIN_DECLS

// Weak undefined references to the symbols in libbinder and libhwbinder
// so that libmemunreachable can call them in processes that have them
// loaded without requiring libmemunreachable to have dependencies on them.
ssize_t __attribute__((weak)) getBinderKernelReferences(size_t, uintptr_t*);
ssize_t __attribute__((weak)) getHWBinderKernelReferences(size_t, uintptr_t*);

__END_DECLS

namespace android {

static bool BinderReferencesToVector(allocator::vector<uintptr_t>& refs,
                                     std::function<ssize_t(size_t, uintptr_t*)> fn) {
  if (fn == nullptr) {
    return true;
  }

  size_t size = refs.size();

  do {
    refs.resize(size);

    ssize_t ret = fn(refs.size(), refs.data());
    if (ret < 0) {
      return false;
    }

    size = ret;
  } while (size > refs.size());

  refs.resize(size);
  return true;
}

bool BinderReferences(allocator::vector<uintptr_t>& refs) {
  refs.clear();

  allocator::vector<uintptr_t> binder_refs{refs.get_allocator()};
  if (BinderReferencesToVector(refs, getBinderKernelReferences)) {
    refs.insert(refs.end(), binder_refs.begin(), binder_refs.end());
  } else {
    MEM_ALOGE("getBinderKernelReferences failed");
  }

  allocator::vector<uintptr_t> hwbinder_refs{refs.get_allocator()};
  if (BinderReferencesToVector(hwbinder_refs, getHWBinderKernelReferences)) {
    refs.insert(refs.end(), hwbinder_refs.begin(), hwbinder_refs.end());
  } else {
    MEM_ALOGE("getHWBinderKernelReferences failed");
  }

  return true;
}

}  // namespace android
