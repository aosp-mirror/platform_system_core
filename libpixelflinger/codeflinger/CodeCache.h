/* libs/pixelflinger/codeflinger/CodeCache.h
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


#ifndef ANDROID_CODECACHE_H
#define ANDROID_CODECACHE_H

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

#include "utils/KeyedVector.h"
#include "tinyutils/smartpointer.h"

namespace android {

using namespace tinyutils;

// ----------------------------------------------------------------------------

class AssemblyKeyBase {
public:
    virtual ~AssemblyKeyBase() { }
    virtual int compare_type(const AssemblyKeyBase& key) const = 0;
};

template  <typename T>
class AssemblyKey : public AssemblyKeyBase
{
public:
    AssemblyKey(const T& rhs) : mKey(rhs) { }
    virtual int compare_type(const AssemblyKeyBase& key) const {
        const T& rhs = static_cast<const AssemblyKey&>(key).mKey;
        return android::compare_type(mKey, rhs);
    }
private:
    T mKey;
};

// ----------------------------------------------------------------------------

class Assembly
{
public:
                Assembly(size_t size);
    virtual     ~Assembly();

    ssize_t     size() const;
    uint32_t*   base() const;
    ssize_t     resize(size_t size);

    // protocol for sp<>
            void    incStrong(const void* id) const;
            void    decStrong(const void* id) const;
    typedef void    weakref_type;

private:
    mutable int32_t     mCount;
            uint32_t*   mBase;
            size_t      mSize;
};

// ----------------------------------------------------------------------------

class CodeCache
{
public:
// pretty simple cache API...
                CodeCache(size_t size);
                ~CodeCache();
    
            sp<Assembly>        lookup(const AssemblyKeyBase& key) const;

            int                 cache(  const AssemblyKeyBase& key,
                                        const sp<Assembly>& assembly);

private:
    // nothing to see here...
    struct cache_entry_t {
        inline cache_entry_t() { }
        inline cache_entry_t(const sp<Assembly>& a, int64_t w)
                : entry(a), when(w) { }
        sp<Assembly>            entry;
        mutable int64_t         when;
    };

    class key_t {
        friend int compare_type(
            const key_value_pair_t<key_t, cache_entry_t>&,
            const key_value_pair_t<key_t, cache_entry_t>&);
        const AssemblyKeyBase* mKey;
    public:
        key_t() { };
        key_t(const AssemblyKeyBase& k) : mKey(&k)  { }
    };

    mutable pthread_mutex_t             mLock;
    mutable int64_t                     mWhen;
    size_t                              mCacheSize;
    size_t                              mCacheInUse;
    KeyedVector<key_t, cache_entry_t>   mCacheData;

    friend int compare_type(
        const key_value_pair_t<key_t, cache_entry_t>&,
        const key_value_pair_t<key_t, cache_entry_t>&);
};

// KeyedVector uses compare_type(), which is more efficient, than
// just using operator < ()
inline int compare_type(
    const key_value_pair_t<CodeCache::key_t, CodeCache::cache_entry_t>& lhs,
    const key_value_pair_t<CodeCache::key_t, CodeCache::cache_entry_t>& rhs)
{
    return lhs.key.mKey->compare_type(*(rhs.key.mKey));
}

// ----------------------------------------------------------------------------

}; // namespace android

#endif //ANDROID_CODECACHE_H
