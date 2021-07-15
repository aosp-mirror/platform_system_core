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

#include "fuzz_utils.h"

#include <android-base/logging.h>

namespace android::fuzz {

void CheckInternal(bool value, std::string_view msg) {
    CHECK(value) << msg;
}

const google::protobuf::OneofDescriptor* GetProtoValueDescriptor(
        const google::protobuf::Descriptor* action_desc) {
    CHECK(action_desc);
    CHECK(action_desc->oneof_decl_count() == 1)
            << action_desc->oneof_decl_count() << " oneof fields found in " << action_desc->name()
            << "; only one is expected.";
    auto* oneof_value_desc = action_desc->oneof_decl(0);
    CHECK(oneof_value_desc);
    CHECK(oneof_value_desc->name() == "value")
            << "oneof field has name " << oneof_value_desc->name();
    return oneof_value_desc;
}

}  // namespace android::fuzz
