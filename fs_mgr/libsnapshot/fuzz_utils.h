// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Generic classes for fuzzing a collection of APIs.

namespace android::fuzz {

// My custom boolean type -- to avoid conflict with (u)int8_t and char.
struct Bool {
    bool value;
    operator bool() const { return value; }
};

// Helper for FuzzData.
// A wrapper over an optional const object T. The buffer is maintained elsewhere.
template <typename T>
class Optional {
  public:
    Optional(const T* ptr) : ptr_(ptr) {}
    const T& operator*() const { return *ptr_; }
    const T& value() const { return *ptr_; }
    bool has_value() const { return ptr_; }

  private:
    const T* ptr_;
};

// Helper for FuzzData.
// A wrapper over an optional boolean. The boolean is owned by this object.
template <>
class Optional<Bool> {
  public:
    Optional(std::optional<Bool>&& val) : val_(std::move(val)) {}
    const Bool& operator*() const { return *val_; }
    const Bool& value() const { return val_.value(); }
    bool has_value() const { return val_.has_value(); }

  private:
    std::optional<Bool> val_;
};

// Helper for FuzzData.
// A view on a raw data buffer. Client is responsible for maintaining the lifetime of the data
// buffer.
class DataView {
  public:
    DataView(const uint8_t* data, uint64_t size) : data_(data), size_(size) {}
    DataView(const void* data, uint64_t size) : DataView(static_cast<const uint8_t*>(data), size) {}
    inline uint64_t size() const { return size_; }
    inline const uint8_t* data() const { return data_; }
    inline bool CanConsume(uint64_t size) { return size_ >= size; }
    // Consume the first |size| bytes from |this| and return a DataView object that represents
    // the consumed data. Data pointer in |this| is incremented by |size| bytes.
    // If not enough bytes, return nullopt.
    std::optional<DataView> Consume(uint64_t size) {
        if (!CanConsume(size)) return std::nullopt;
        DataView ret(data_, size);
        size_ -= size;
        data_ += size;
        return ret;
    }

  private:
    const uint8_t* data_;
    uint64_t size_;
};

// A view on the fuzz data. Provides APIs to consume typed objects.
class FuzzData : public DataView {
  public:
    // Inherit constructors.
    using DataView::DataView;
    // Consume a data object T and return the pointer (into the buffer). No copy is done.
    // If not enough bytes, return nullptr.
    template <typename T>
    inline Optional<T> Consume() {
        auto data_view = DataView::Consume(sizeof(T));
        if (!data_view.has_value()) return nullptr;
        return reinterpret_cast<const T*>(data_view->data());
    }
    // To provide enough entropy for booleans, they are consumed bit by bit.
    // Hence, the returned value is not indexed into the buffer. See Optional<Bool>.
    template <>
    Optional<Bool> Consume<Bool>() {
        if (!boolean_buffer_.has_value() || boolean_bit_offset_ >= sizeof(*boolean_buffer_)) {
            boolean_buffer_ = Consume<uint8_t>();
            boolean_bit_offset_ = 0;
        }
        if (!boolean_buffer_.has_value()) {
            return Optional<Bool>(std::nullopt);
        }
        const auto& byte = *boolean_buffer_;
        bool ret = (byte >> boolean_bit_offset_) & 0x1;
        boolean_bit_offset_++;
        return Optional<Bool>(Bool{ret});
    }

  private:
    // Separate buffer for booleans.
    Optional<uint8_t> boolean_buffer_ = nullptr;
    uint8_t boolean_bit_offset_ = 0;
};

enum class CallResult {
    SUCCESS,
    NOT_ENOUGH_DATA,
};

inline bool AllArgsHasValue() {
    return true;
}
template <typename T>
inline bool AllArgsHasValue(const Optional<T>& t) {
    return t.has_value();
}
template <typename First, typename... Remaining>
inline bool AllArgsHasValue(const Optional<First>& first, const Optional<Remaining>&... remaining) {
    return first.has_value() && AllArgsHasValue(remaining...);
}

// Base class of FuzzFunction.
class FuzzFunctionBase {
  public:
    virtual ~FuzzFunctionBase() = default;
    virtual CallResult Call(FuzzData* fuzz_data) const = 0;
};

template <typename T>
class FuzzFunction;  // undefined

// A wrapper over a fuzzed function.
template <typename R, typename... Args>
class FuzzFunction<R(Args...)> : public FuzzFunctionBase {
  public:
    using Function = std::function<R(Args...)>;
    FuzzFunction(Function&& function) : function_(std::move(function)) {}
    // Eat necessary data in |fuzz_data| and invoke the function.
    CallResult Call(FuzzData* fuzz_data) const override {
        return CallWithOptionalArgs(fuzz_data->Consume<std::remove_reference_t<Args>>()...);
    }

  private:
    Function function_;

    CallResult CallWithOptionalArgs(const Optional<std::remove_reference_t<Args>>&... args) const {
        if (!AllArgsHasValue(args...)) {
            return CallResult::NOT_ENOUGH_DATA;
        }
        (void)function_(args.value()...);  // ignore returned value
        return CallResult::SUCCESS;
    }
};

// CHECK(value) << msg
void CheckInternal(bool value, std::string_view msg);

// A collection of FuzzFunction's.
// FunctionsSizeType must be an integral type where
// functions_.size() <= std::numeric_limits<FunctionSizeType>::max().
template <typename FunctionsSizeType>
class FuzzFunctions {
  public:
    // Subclass should override this to register functions via AddFunction.
    FuzzFunctions() = default;
    virtual ~FuzzFunctions() = default;
    // Eat some amount of data in |fuzz_data| and call one of the |functions_|.
    CallResult CallOne(FuzzData* fuzz_data) const {
        auto opt_number = fuzz_data->Consume<FunctionsSizeType>();
        if (!opt_number.has_value()) {
            return CallResult::NOT_ENOUGH_DATA;
        }
        auto function_index = opt_number.value() % functions_.size();
        return functions_[function_index]->Call(fuzz_data);
    }

  private:
    template <typename R, typename... Args>
    struct FunctionTraits {
        using Function = std::function<R(Args...)>;
    };

  public:
    // There are no deduction guide from lambda to std::function, so the
    // signature of the lambda must be specified in the template argument.
    // FuzzFunctions provide the following 3 ways to specify the signature of
    // the lambda:

    // AddFunction<R(Args...)>, e.g. AddFunction<ReturnType(ArgType, ArgType)>
    template <typename T>
    void AddFunction(std::function<T>&& func) {
        functions_.push_back(std::make_unique<FuzzFunction<T>>(std::move(func)));
    }

    // AddFunction<R, Args...>, e.g. AddFunction<ReturnType, ArgType, ArgType>
    template <typename R, typename... Args>
    void AddFunction(typename FunctionTraits<R, Args...>::Function&& func) {
        functions_.push_back(std::make_unique<FuzzFunction<R(Args...)>>(std::move(func)));
    }

    // AddFunction<ArgType...>. Equivalent to AddFunction<void, Args...>
    template <typename... Args>
    void AddFunction(typename FunctionTraits<void, Args...>::Function&& func) {
        functions_.push_back(std::make_unique<FuzzFunction<void(Args...)>>(std::move(func)));
    }

    // Use |fuzz_data| as a guide to call |functions_| until |fuzz_data| is
    // depleted. Return
    void DepleteData(FuzzData* fuzz_data) const {
        CallResult result;
        while ((result = CallOne(fuzz_data)) == CallResult::SUCCESS)
            ;
        CheckInternal(result == CallResult::NOT_ENOUGH_DATA,
                      "result is " + std::to_string(static_cast<int>(result)));
    }

  protected:
    // Helper for subclass to check that size of |functions_| is actually within
    // SizeType. Should be called after all functions are registered.
    void CheckFunctionsSize() const {
        CheckInternal(functions_.size() <= std::numeric_limits<FunctionsSizeType>::max(),
                      "Need to extend number of bits for function count; there are " +
                              std::to_string(functions_.size()) + " functions now.");
    }

  private:
    std::vector<std::unique_ptr<FuzzFunctionBase>> functions_;
};

// An object whose APIs are being fuzzed.
template <typename T, typename FunctionsSizeType>
class FuzzObject : public FuzzFunctions<FunctionsSizeType> {
  public:
    // Not thread-safe; client is responsible for ensuring only one thread calls DepleteData.
    void DepleteData(T* obj, FuzzData* fuzz_data) {
        obj_ = obj;
        FuzzFunctions<FunctionsSizeType>::DepleteData(fuzz_data);
        obj_ = nullptr;
    }

  protected:
    // Helper for subclass to get the module under test in the added functions.
    T* get() const {
        CheckInternal(obj_ != nullptr, "No module under test is found.");
        return obj_;
    }

  private:
    T* obj_ = nullptr;
};

}  // namespace android::fuzz
