/*
 * Copyright 2020 The Android Open Source Project
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
#include <fuzzer/FuzzedDataProvider.h>
#include <log/log.h>
#include <utils/Vector.h>

#include <functional>

using android::Vector;

static constexpr uint16_t MAX_VEC_SIZE = 100;
static constexpr bool kLog = false;

struct NonTrivialDestructor {
    NonTrivialDestructor() : mInit(1) {}
    ~NonTrivialDestructor() {
        LOG_ALWAYS_FATAL_IF(mInit != 1, "mInit should be 1, but it's: %d", mInit);
        mInit--;
        LOG_ALWAYS_FATAL_IF(mInit != 0, "mInit should be 0, but it's: %d", mInit);
    }

  private:
    uint8_t mInit;
};

template <typename T>
struct VectorFuzzerData {
    Vector<T> vector;
    const std::vector<std::function<void(FuzzedDataProvider&, Vector<T>&)>> funcs = {
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                // operator= Vector<TYPE>, still needs for SortedVector
                if (kLog) ALOGI("operator=");
                vector = testVector(provider);
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (kLog) ALOGI("clear");
                vector.clear();
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (kLog) ALOGI("size");
                vector.size();
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (kLog) ALOGI("isEmpty");
                vector.isEmpty();
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (kLog) ALOGI("capacity");
                vector.capacity();
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                size_t vectorSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_VEC_SIZE);
                if (kLog) ALOGI("setCapacity");
                vector.setCapacity(vectorSize);
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                size_t vectorSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_VEC_SIZE);
                if (kLog) ALOGI("resize");
                vector.resize(vectorSize);
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (kLog) ALOGI("array");
                vector.array();
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (kLog) ALOGI("editArray");
                vector.editArray();
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                if (vector.size() == 0) return;
                size_t idx = provider.ConsumeIntegralInRange<size_t>(0, vector.size() - 1);
                if (kLog) ALOGI("operator[]");
                vector[idx];  // returns a const value for Vector
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                if (vector.size() == 0) return;
                size_t idx = provider.ConsumeIntegralInRange<size_t>(0, vector.size() - 1);
                if (kLog) ALOGI("itemAt");
                vector.itemAt(idx);
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (vector.size() == 0) return;
                if (kLog) ALOGI("top");
                vector.top();
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                if (vector.size() == 0) return;
                size_t idx = provider.ConsumeIntegralInRange<size_t>(0, vector.size() - 1);
                if (kLog) ALOGI("editItemAt");
                vector.editItemAt(idx);
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (vector.size() == 0) return;
                if (kLog) ALOGI("editTop");
                vector.editTop() = T{};
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                uint8_t idx = provider.ConsumeIntegralInRange<uint8_t>(0, vector.size());
                Vector vec2 = testVector(provider);
                if (vec2.size() == 0) return;  // TODO: maybe we should support this?
                if (kLog) ALOGI("insertVectorAt %d of size %zu", idx, vec2.size());
                vector.insertVectorAt(vec2, idx);
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                if (kLog) ALOGI("appendVector");
                vector.appendVector(testVector(provider));
            },
            // TODO: insertArrayAt
            // TODO: appendArray
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                uint8_t idx = provider.ConsumeIntegralInRange<uint8_t>(0, vector.size());
                uint8_t numItems = provider.ConsumeIntegralInRange<uint8_t>(1, 100);
                if (kLog) ALOGI("insertAt");
                vector.insertAt(idx, numItems);
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                uint8_t idx = provider.ConsumeIntegralInRange<uint8_t>(0, vector.size());
                uint8_t numItems = provider.ConsumeIntegralInRange<uint8_t>(1, 100);
                if (kLog) ALOGI("insertAt");
                vector.insertAt(T{}, idx, numItems);
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (vector.size() == 0) return;
                if (kLog) ALOGI("pop");
                vector.pop();
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (kLog) ALOGI("push");
                vector.push();
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (kLog) ALOGI("add");
                vector.add();
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (kLog) ALOGI("add");
                vector.add(T{});
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                uint8_t idx = provider.ConsumeIntegralInRange<uint8_t>(0, vector.size() - 1);
                if (kLog) ALOGI("replaceAt");
                vector.replaceAt(idx);
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                uint8_t idx = provider.ConsumeIntegralInRange<uint8_t>(0, vector.size() - 1);
                if (kLog) ALOGI("replaceAt");
                vector.replaceAt(T{}, idx);
            },
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                if (vector.size() == 0) return;
                uint8_t idx = provider.ConsumeIntegralInRange<uint8_t>(0, vector.size() - 1);
                if (kLog) ALOGI("remoteItemsAt");
                vector.removeItemsAt(idx);  // TODO: different count
            },
            // removeAt is alias for removeItemsAt
            // TODO: sort
            [&](FuzzedDataProvider& provider, Vector<T>& vector) {
                (void)provider;
                if (kLog) ALOGI("getItemSize");
                vector.getItemSize();
            },
            // TODO: iterators
    };

    Vector<T> testVector(FuzzedDataProvider& provider) {
        Vector<T> vec;
        size_t vectorSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_VEC_SIZE);
        return vec;
    }

    void fuzz(FuzzedDataProvider&& provider) {
        while (provider.remaining_bytes()) {
            size_t funcIdx = provider.ConsumeIntegralInRange<size_t>(0, funcs.size() - 1);
            funcs[funcIdx](provider, vector);
        }
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);

    provider.PickValueInArray<std::function<void()>>({
            [&]() { VectorFuzzerData<uint8_t>().fuzz(std::move(provider)); },
            [&]() { VectorFuzzerData<int32_t>().fuzz(std::move(provider)); },
            [&]() { VectorFuzzerData<NonTrivialDestructor>().fuzz(std::move(provider)); },
    })();

    return 0;
}
