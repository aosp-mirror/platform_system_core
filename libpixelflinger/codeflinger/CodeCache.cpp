/* libs/pixelflinger/codeflinger/CodeCache.cpp
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include <cutils/log.h>
#include <cutils/atomic.h>

#include "codeflinger/CodeCache.h"

namespace android {

// ----------------------------------------------------------------------------

#if defined(__arm__)
#include <unistd.h>
#include <errno.h>
#endif

// ----------------------------------------------------------------------------

Assembly::Assembly(size_t size)
    : mCount(1), mSize(0)
{
    mBase = (uint32_t*)mspace_malloc(getMspace(), size);
    mSize = size;
    ensureMbaseExecutable();
}

Assembly::~Assembly()
{
    mspace_free(getMspace(), mBase);
}

void Assembly::incStrong(const void*) const
{
    android_atomic_inc(&mCount);
}

void Assembly::decStrong(const void*) const
{
    if (android_atomic_dec(&mCount) == 1) {
        delete this;
    }
}

ssize_t Assembly::size() const
{
    if (!mBase) return NO_MEMORY;
    return mSize;
}

uint32_t* Assembly::base() const
{
    return mBase;
}

ssize_t Assembly::resize(size_t newSize)
{
    mBase = (uint32_t*)mspace_realloc(getMspace(), mBase, newSize);
    mSize = newSize;
    ensureMbaseExecutable();
    return size();
}

mspace Assembly::getMspace()
{
    static mspace msp = create_contiguous_mspace(2 * 1024, 1024 * 1024, /*locked=*/ false);
    return msp;
}

void Assembly::ensureMbaseExecutable()
{
    long pagesize = sysconf(_SC_PAGESIZE);
    long pagemask = ~(pagesize - 1);  // assumes pagesize is a power of 2

    uint32_t* pageStart = (uint32_t*) (((uintptr_t) mBase) & pagemask);
    size_t adjustedLength = mBase - pageStart + mSize;

    if (mBase && mprotect(pageStart, adjustedLength, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        mspace_free(getMspace(), mBase);
        mBase = NULL;
    }
}

// ----------------------------------------------------------------------------

CodeCache::CodeCache(size_t size)
    : mCacheSize(size), mCacheInUse(0)
{
    pthread_mutex_init(&mLock, 0);
}

CodeCache::~CodeCache()
{
    pthread_mutex_destroy(&mLock);
}

sp<Assembly> CodeCache::lookup(const AssemblyKeyBase& keyBase) const
{
    pthread_mutex_lock(&mLock);
    sp<Assembly> r;
    ssize_t index = mCacheData.indexOfKey(key_t(keyBase));
    if (index >= 0) {
        const cache_entry_t& e = mCacheData.valueAt(index);
        e.when = mWhen++;
        r = e.entry;
    }
    pthread_mutex_unlock(&mLock);
    return r;
}

int CodeCache::cache(  const AssemblyKeyBase& keyBase,
                            const sp<Assembly>& assembly)
{
    pthread_mutex_lock(&mLock);

    const ssize_t assemblySize = assembly->size();
    while (mCacheInUse + assemblySize > mCacheSize) {
        // evict the LRU
        size_t lru = 0;
        size_t count = mCacheData.size();
        for (size_t i=0 ; i<count ; i++) {
            const cache_entry_t& e = mCacheData.valueAt(i);
            if (e.when < mCacheData.valueAt(lru).when) {
                lru = i;
            }
        }
        const cache_entry_t& e = mCacheData.valueAt(lru);
        mCacheInUse -= e.entry->size();
        mCacheData.removeItemsAt(lru);
    }

    ssize_t err = mCacheData.add(key_t(keyBase), cache_entry_t(assembly, mWhen));
    if (err >= 0) {
        mCacheInUse += assemblySize;
        mWhen++;
        // synchronize caches...
#if defined(__arm__)
        const long base = long(assembly->base());
        const long curr = base + long(assembly->size());
        err = cacheflush(base, curr, 0);
        LOGE_IF(err, "__ARM_NR_cacheflush error %s\n",
                strerror(errno));
#endif
    }

    pthread_mutex_unlock(&mLock);
    return err;
}

// ----------------------------------------------------------------------------

}; // namespace android
