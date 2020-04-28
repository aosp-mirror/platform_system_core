/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef _LIBDM_TEST_UTILS_H_
#define _LIBDM_TEST_UTILS_H_

#include <android-base/unique_fd.h>
#include <stddef.h>

#include <string>

namespace android {
namespace dm {

// Create a temporary in-memory file. If size is non-zero, the file will be
// created with a fixed size.
android::base::unique_fd CreateTempFile(const std::string& name, size_t size);

}  // namespace dm
}  // namespace android

#endif  // _LIBDM_TEST_UTILS_H_
