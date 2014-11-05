/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <stdlib.h>
#include <utils/JenkinsHash.h>
#include <utils/LruCache.h>
#include <cutils/log.h>
#include <gtest/gtest.h>

namespace {

typedef int SimpleKey;
typedef const char* StringValue;

struct ComplexKey {
    int k;

    explicit ComplexKey(int k) : k(k) {
        instanceCount += 1;
    }

    ComplexKey(const ComplexKey& other) : k(other.k) {
        instanceCount += 1;
    }

    ~ComplexKey() {
        instanceCount -= 1;
    }

    bool operator ==(const ComplexKey& other) const {
        return k == other.k;
    }

    bool operator !=(const ComplexKey& other) const {
        return k != other.k;
    }

    static ssize_t instanceCount;
};

ssize_t ComplexKey::instanceCount = 0;

struct ComplexValue {
    int v;

    explicit ComplexValue(int v) : v(v) {
        instanceCount += 1;
    }

    ComplexValue(const ComplexValue& other) : v(other.v) {
        instanceCount += 1;
    }

    ~ComplexValue() {
        instanceCount -= 1;
    }

    static ssize_t instanceCount;
};

ssize_t ComplexValue::instanceCount = 0;

} // namespace


namespace android {

typedef LruCache<ComplexKey, ComplexValue> ComplexCache;

template<> inline android::hash_t hash_type(const ComplexKey& value) {
    return hash_type(value.k);
}

class EntryRemovedCallback : public OnEntryRemoved<SimpleKey, StringValue> {
public:
    EntryRemovedCallback() : callbackCount(0), lastKey(-1), lastValue(NULL) { }
    ~EntryRemovedCallback() {}
    void operator()(SimpleKey& k, StringValue& v) {
        callbackCount += 1;
        lastKey = k;
        lastValue = v;
    }
    ssize_t callbackCount;
    SimpleKey lastKey;
    StringValue lastValue;
};

class LruCacheTest : public testing::Test {
protected:
    virtual void SetUp() {
        ComplexKey::instanceCount = 0;
        ComplexValue::instanceCount = 0;
    }

    virtual void TearDown() {
        ASSERT_NO_FATAL_FAILURE(assertInstanceCount(0, 0));
    }

    void assertInstanceCount(ssize_t keys, ssize_t values) {
        if (keys != ComplexKey::instanceCount || values != ComplexValue::instanceCount) {
            FAIL() << "Expected " << keys << " keys and " << values << " values "
                    "but there were actually " << ComplexKey::instanceCount << " keys and "
                    << ComplexValue::instanceCount << " values";
        }
    }
};

TEST_F(LruCacheTest, Empty) {
    LruCache<SimpleKey, StringValue> cache(100);

    EXPECT_EQ(NULL, cache.get(0));
    EXPECT_EQ(0u, cache.size());
}

TEST_F(LruCacheTest, Simple) {
    LruCache<SimpleKey, StringValue> cache(100);

    cache.put(1, "one");
    cache.put(2, "two");
    cache.put(3, "three");
    EXPECT_STREQ("one", cache.get(1));
    EXPECT_STREQ("two", cache.get(2));
    EXPECT_STREQ("three", cache.get(3));
    EXPECT_EQ(3u, cache.size());
}

TEST_F(LruCacheTest, MaxCapacity) {
    LruCache<SimpleKey, StringValue> cache(2);

    cache.put(1, "one");
    cache.put(2, "two");
    cache.put(3, "three");
    EXPECT_EQ(NULL, cache.get(1));
    EXPECT_STREQ("two", cache.get(2));
    EXPECT_STREQ("three", cache.get(3));
    EXPECT_EQ(2u, cache.size());
}

TEST_F(LruCacheTest, RemoveLru) {
    LruCache<SimpleKey, StringValue> cache(100);

    cache.put(1, "one");
    cache.put(2, "two");
    cache.put(3, "three");
    cache.removeOldest();
    EXPECT_EQ(NULL, cache.get(1));
    EXPECT_STREQ("two", cache.get(2));
    EXPECT_STREQ("three", cache.get(3));
    EXPECT_EQ(2u, cache.size());
}

TEST_F(LruCacheTest, GetUpdatesLru) {
    LruCache<SimpleKey, StringValue> cache(100);

    cache.put(1, "one");
    cache.put(2, "two");
    cache.put(3, "three");
    EXPECT_STREQ("one", cache.get(1));
    cache.removeOldest();
    EXPECT_STREQ("one", cache.get(1));
    EXPECT_EQ(NULL, cache.get(2));
    EXPECT_STREQ("three", cache.get(3));
    EXPECT_EQ(2u, cache.size());
}

uint32_t hash_int(int x) {
    return JenkinsHashWhiten(JenkinsHashMix(0, x));
}

TEST_F(LruCacheTest, StressTest) {
    const size_t kCacheSize = 512;
    LruCache<SimpleKey, StringValue> cache(512);
    const size_t kNumKeys = 16 * 1024;
    const size_t kNumIters = 100000;
    char* strings[kNumKeys];

    for (size_t i = 0; i < kNumKeys; i++) {
        strings[i] = (char *)malloc(16);
        sprintf(strings[i], "%zu", i);
    }

    srandom(12345);
    int hitCount = 0;
    for (size_t i = 0; i < kNumIters; i++) {
        int index = random() % kNumKeys;
        uint32_t key = hash_int(index);
        const char *val = cache.get(key);
        if (val != NULL) {
            EXPECT_EQ(strings[index], val);
            hitCount++;
        } else {
            cache.put(key, strings[index]);
        }
    }
    size_t expectedHitCount = kNumIters * kCacheSize / kNumKeys;
    EXPECT_LT(int(expectedHitCount * 0.9), hitCount);
    EXPECT_GT(int(expectedHitCount * 1.1), hitCount);
    EXPECT_EQ(kCacheSize, cache.size());

    for (size_t i = 0; i < kNumKeys; i++) {
        free((void *)strings[i]);
    }
}

TEST_F(LruCacheTest, NoLeak) {
    ComplexCache cache(100);

    cache.put(ComplexKey(0), ComplexValue(0));
    cache.put(ComplexKey(1), ComplexValue(1));
    EXPECT_EQ(2, cache.size());
    assertInstanceCount(2, 3);  // the null value counts as an instance
}

TEST_F(LruCacheTest, Clear) {
    ComplexCache cache(100);

    cache.put(ComplexKey(0), ComplexValue(0));
    cache.put(ComplexKey(1), ComplexValue(1));
    EXPECT_EQ(2, cache.size());
    assertInstanceCount(2, 3);
    cache.clear();
    assertInstanceCount(0, 1);
}

TEST_F(LruCacheTest, ClearNoDoubleFree) {
    {
        ComplexCache cache(100);

        cache.put(ComplexKey(0), ComplexValue(0));
        cache.put(ComplexKey(1), ComplexValue(1));
        EXPECT_EQ(2, cache.size());
        assertInstanceCount(2, 3);
        cache.removeOldest();
        cache.clear();
        assertInstanceCount(0, 1);
    }
    assertInstanceCount(0, 0);
}

TEST_F(LruCacheTest, ClearReuseOk) {
    ComplexCache cache(100);

    cache.put(ComplexKey(0), ComplexValue(0));
    cache.put(ComplexKey(1), ComplexValue(1));
    EXPECT_EQ(2, cache.size());
    assertInstanceCount(2, 3);
    cache.clear();
    assertInstanceCount(0, 1);
    cache.put(ComplexKey(0), ComplexValue(0));
    cache.put(ComplexKey(1), ComplexValue(1));
    EXPECT_EQ(2, cache.size());
    assertInstanceCount(2, 3);
}

TEST_F(LruCacheTest, Callback) {
    LruCache<SimpleKey, StringValue> cache(100);
    EntryRemovedCallback callback;
    cache.setOnEntryRemovedListener(&callback);

    cache.put(1, "one");
    cache.put(2, "two");
    cache.put(3, "three");
    EXPECT_EQ(3, cache.size());
    cache.removeOldest();
    EXPECT_EQ(1, callback.callbackCount);
    EXPECT_EQ(1, callback.lastKey);
    EXPECT_STREQ("one", callback.lastValue);
}

TEST_F(LruCacheTest, CallbackOnClear) {
    LruCache<SimpleKey, StringValue> cache(100);
    EntryRemovedCallback callback;
    cache.setOnEntryRemovedListener(&callback);

    cache.put(1, "one");
    cache.put(2, "two");
    cache.put(3, "three");
    EXPECT_EQ(3, cache.size());
    cache.clear();
    EXPECT_EQ(3, callback.callbackCount);
}

}
