/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <pthread.h>

#include <android-base/macros.h>
#include <android-base/thread_annotations.h>

// As of the end of May 2020, std::shared_mutex is *not* simply a pthread_rwlock, but rather a
// combination of std::mutex and std::condition variable, which is obviously less efficient.  This
// immitates what std::shared_mutex should be doing and is compatible with RAII thread wrappers.

class SHARED_CAPABILITY("mutex") RwLock {
  public:
    RwLock() {}
    ~RwLock() {}

    void lock() ACQUIRE() { pthread_rwlock_wrlock(&rwlock_); }
    void lock_shared() ACQUIRE_SHARED() { pthread_rwlock_rdlock(&rwlock_); }

    void unlock() RELEASE() { pthread_rwlock_unlock(&rwlock_); }

  private:
    pthread_rwlock_t rwlock_ = PTHREAD_RWLOCK_INITIALIZER;
};

// std::shared_lock does not have thread annotations, so we need our own.

class SCOPED_CAPABILITY SharedLock {
  public:
    SharedLock(RwLock& lock) ACQUIRE_SHARED(lock) : lock_(lock) { lock_.lock_shared(); }
    ~SharedLock() RELEASE() { lock_.unlock(); }

    void lock_shared() ACQUIRE_SHARED() { lock_.lock_shared(); }
    void unlock() RELEASE() { lock_.unlock(); }

    DISALLOW_IMPLICIT_CONSTRUCTORS(SharedLock);

  private:
    RwLock& lock_;
};
