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

#pragma once

#include <map>
#include <string>
#include <string_view>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>

// Utilities for using a protobuf definition to fuzz APIs in a class.
// Terms:
// The "fuzzed class" is the C++ class definition whose functions are fuzzed.
// The "fuzzed object" is an instantiated object of the fuzzed class. It is
//   typically created and destroyed for each test run.
// An "action" is an operation on the fuzzed object that may mutate its state.
//   This typically involves one function call into the fuzzed object.

namespace android::fuzz {

// CHECK(value) << msg
void CheckInternal(bool value, std::string_view msg);

// Get the oneof descriptor inside Action
const google::protobuf::OneofDescriptor* GetProtoValueDescriptor(
        const google::protobuf::Descriptor* action_desc);

template <typename Class>
using FunctionMapImpl =
        std::map<int, std::function<void(Class*, const google::protobuf::Message& action_proto,
                                         const google::protobuf::FieldDescriptor* field_desc)>>;

template <typename Class>
class FunctionMap : public FunctionMapImpl<Class> {
  public:
    void CheckEmplace(typename FunctionMapImpl<Class>::key_type key,
                      typename FunctionMapImpl<Class>::mapped_type&& value) {
        auto [it, inserted] = this->emplace(key, std::move(value));
        CheckInternal(inserted,
                      "Multiple implementation registered for tag number " + std::to_string(key));
    }
};

template <typename Action>
int CheckConsistency() {
    const auto* function_map = Action::GetFunctionMap();
    const auto* action_value_desc = GetProtoValueDescriptor(Action::Proto::GetDescriptor());

    for (int field_index = 0; field_index < action_value_desc->field_count(); ++field_index) {
        const auto* field_desc = action_value_desc->field(field_index);
        CheckInternal(function_map->find(field_desc->number()) != function_map->end(),
                      "Missing impl for function " + field_desc->camelcase_name());
    }
    return 0;
}

// Get the field descriptor for the oneof field in the action message. If no oneof field is set,
// return nullptr.
template <typename Action>
const google::protobuf::FieldDescriptor* GetValueFieldDescriptor(
        const typename Action::Proto& action_proto) {
    static auto* action_value_desc = GetProtoValueDescriptor(Action::Proto::GetDescriptor());

    auto* action_refl = Action::Proto::GetReflection();
    if (!action_refl->HasOneof(action_proto, action_value_desc)) {
        return nullptr;
    }
    return action_refl->GetOneofFieldDescriptor(action_proto, action_value_desc);
}

template <typename Action>
void ExecuteActionProto(typename Action::ClassType* module,
                        const typename Action::Proto& action_proto) {
    const auto* field_desc = GetValueFieldDescriptor<Action>(action_proto);
    if (field_desc == nullptr) return;
    auto number = field_desc->number();
    const auto& map = *Action::GetFunctionMap();
    auto it = map.find(number);
    CheckInternal(it != map.end(), "Missing impl for function " + field_desc->camelcase_name());
    const auto& func = it->second;
    func(module, action_proto, field_desc);
}

template <typename Action>
void ExecuteAllActionProtos(
        typename Action::ClassType* module,
        const google::protobuf::RepeatedPtrField<typename Action::Proto>& action_protos) {
    for (const auto& proto : action_protos) {
        ExecuteActionProto<Action>(module, proto);
    }
}

// Safely cast message to T. Returns a pointer to message if cast successfully, otherwise nullptr.
template <typename T>
const T* SafeCast(const google::protobuf::Message& message) {
    if (message.GetDescriptor() != T::GetDescriptor()) {
        return nullptr;
    }
    return static_cast<const T*>(&message);
}

// Cast message to const T&. Abort if type mismatch.
template <typename T>
const T& CheckedCast(const google::protobuf::Message& message) {
    const auto* ptr = SafeCast<T>(message);
    CheckInternal(ptr, "Cannot cast " + message.GetDescriptor()->name() + " to " +
                               T::GetDescriptor()->name());
    return *ptr;
}

// A templated way to a primitive field from a message using reflection.
template <typename T>
struct PrimitiveGetter;
#define FUZZ_DEFINE_PRIMITIVE_GETTER(type, func_name)                              \
    template <>                                                                    \
    struct PrimitiveGetter<type> {                                                 \
        static constexpr const auto fp = &google::protobuf::Reflection::func_name; \
    }

FUZZ_DEFINE_PRIMITIVE_GETTER(bool, GetBool);
FUZZ_DEFINE_PRIMITIVE_GETTER(uint32_t, GetUInt32);
FUZZ_DEFINE_PRIMITIVE_GETTER(int32_t, GetInt32);
FUZZ_DEFINE_PRIMITIVE_GETTER(uint64_t, GetUInt64);
FUZZ_DEFINE_PRIMITIVE_GETTER(int64_t, GetInt64);
FUZZ_DEFINE_PRIMITIVE_GETTER(double, GetDouble);
FUZZ_DEFINE_PRIMITIVE_GETTER(float, GetFloat);

// ActionPerformer extracts arguments from the protobuf message, and then call FuzzFunction
// with these arguments.
template <typename FuzzFunction, typename Signature, typename Enabled = void>
struct ActionPerformerImpl;  // undefined

template <typename FuzzFunction, typename MessageProto>
struct ActionPerformerImpl<
        FuzzFunction, void(const MessageProto&),
        typename std::enable_if_t<std::is_base_of_v<google::protobuf::Message, MessageProto>>> {
    static typename FuzzFunction::ReturnType Invoke(
            typename FuzzFunction::ClassType* module, const google::protobuf::Message& action_proto,
            const google::protobuf::FieldDescriptor* field_desc) {
        const MessageProto& arg = CheckedCast<std::remove_reference_t<MessageProto>>(
                action_proto.GetReflection()->GetMessage(action_proto, field_desc));
        return FuzzFunction::ImplBody(module, arg);
    }
};

template <typename FuzzFunction, typename Primitive>
struct ActionPerformerImpl<FuzzFunction, void(Primitive),
                           typename std::enable_if_t<std::is_arithmetic_v<Primitive>>> {
    static typename FuzzFunction::ReturnType Invoke(
            typename FuzzFunction::ClassType* module, const google::protobuf::Message& action_proto,
            const google::protobuf::FieldDescriptor* field_desc) {
        Primitive arg = std::invoke(PrimitiveGetter<Primitive>::fp, action_proto.GetReflection(),
                                    action_proto, field_desc);
        return FuzzFunction::ImplBody(module, arg);
    }
};

template <typename FuzzFunction>
struct ActionPerformerImpl<FuzzFunction, void()> {
    static typename FuzzFunction::ReturnType Invoke(typename FuzzFunction::ClassType* module,
                                                    const google::protobuf::Message&,
                                                    const google::protobuf::FieldDescriptor*) {
        return FuzzFunction::ImplBody(module);
    }
};

template <typename FuzzFunction>
struct ActionPerformerImpl<FuzzFunction, void(const std::string&)> {
    static typename FuzzFunction::ReturnType Invoke(
            typename FuzzFunction::ClassType* module, const google::protobuf::Message& action_proto,
            const google::protobuf::FieldDescriptor* field_desc) {
        std::string scratch;
        const std::string& arg = action_proto.GetReflection()->GetStringReference(
                action_proto, field_desc, &scratch);
        return FuzzFunction::ImplBody(module, arg);
    }
};

template <typename FuzzFunction>
struct ActionPerformer : ActionPerformerImpl<FuzzFunction, typename FuzzFunction::Signature> {};

}  // namespace android::fuzz

// Fuzz existing C++ class, ClassType, with a collection of functions under the name Action.
//
// Prerequisite: ActionProto must be defined in Protobuf to describe possible actions:
// message FooActionProto {
//     message NoArgs {}
//     oneof value {
//         bool do_foo = 1;
//         NoArgs do_bar = 1;
//     }
// }
// Use it to fuzz a C++ class Foo by doing the following:
//   FUZZ_CLASS(Foo, FooAction)
// After linking functions of Foo to FooAction, execute all actions by:
//   FooAction::ExecuteAll(foo_object, action_protos)
#define FUZZ_CLASS(Class, Action)                                                                \
    class Action {                                                                               \
      public:                                                                                    \
        using Proto = Action##Proto;                                                             \
        using ClassType = Class;                                                                 \
        using FunctionMap = android::fuzz::FunctionMap<Class>;                                   \
        static FunctionMap* GetFunctionMap() {                                                   \
            static Action::FunctionMap map;                                                      \
            return &map;                                                                         \
        }                                                                                        \
        static void ExecuteAll(Class* module,                                                    \
                               const google::protobuf::RepeatedPtrField<Proto>& action_protos) { \
            [[maybe_unused]] static int consistent = android::fuzz::CheckConsistency<Action>();  \
            android::fuzz::ExecuteAllActionProtos<Action>(module, action_protos);                \
        }                                                                                        \
    }

#define FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName) Action##_##FunctionName
#define FUZZ_FUNCTION_TAG_NAME(FunctionName) k##FunctionName

// Implement an action defined in protobuf. Example:
// message FooActionProto {
//     oneof value {
//         bool do_foo = 1;
//     }
// }
// class Foo { public: void DoAwesomeFoo(bool arg); };
// FUZZ_OBJECT(FooAction, Foo);
// FUZZ_FUNCTION(FooAction, DoFoo, void, IFoo* module, bool arg) {
//   module->DoAwesomeFoo(arg);
// }
// The name DoFoo is the camel case name of the action in protobuf definition of FooActionProto.
#define FUZZ_FUNCTION(Action, FunctionName, Return, ModuleArg, ...)             \
    class FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName) {                      \
      public:                                                                   \
        using ActionType = Action;                                              \
        using ClassType = Action::ClassType;                                    \
        using ReturnType = Return;                                              \
        using Signature = void(__VA_ARGS__);                                    \
        static constexpr const char name[] = #FunctionName;                     \
        static constexpr const auto tag =                                       \
                Action::Proto::ValueCase::FUZZ_FUNCTION_TAG_NAME(FunctionName); \
        static ReturnType ImplBody(ModuleArg, ##__VA_ARGS__);                   \
                                                                                \
      private:                                                                  \
        static bool registered_;                                                \
    };                                                                          \
    auto FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName)::registered_ = ([] {    \
        auto tag = FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName)::tag;         \
        auto func = &::android::fuzz::ActionPerformer<FUZZ_FUNCTION_CLASS_NAME( \
                Action, FunctionName)>::Invoke;                                 \
        Action::GetFunctionMap()->CheckEmplace(tag, func);                      \
        return true;                                                            \
    })();                                                                       \
    Return FUZZ_FUNCTION_CLASS_NAME(Action, FunctionName)::ImplBody(ModuleArg, ##__VA_ARGS__)

// Implement a simple action by linking it to the function with the same name. Example:
// message FooActionProto {
//     message NoArgs {}
//     oneof value {
//         NoArgs do_bar = 1;
//     }
// }
// class Foo { public void DoBar(); };
// FUZZ_OBJECT(FooAction, Foo);
// FUZZ_FUNCTION(FooAction, DoBar);
// The name DoBar is the camel case name of the action in protobuf definition of FooActionProto, and
// also the name of the function of Foo.
#define FUZZ_SIMPLE_FUNCTION(Action, FunctionName)                            \
    FUZZ_FUNCTION(Action, FunctionName,                                       \
                  decltype(std::declval<Action::ClassType>().FunctionName()), \
                  Action::ClassType* module) {                                \
        return module->FunctionName();                                        \
    }
