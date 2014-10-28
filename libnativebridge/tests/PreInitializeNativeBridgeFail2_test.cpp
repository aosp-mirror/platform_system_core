/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "NativeBridgeTest.h"

#include <cstdio>
#include <cstring>
#include <cutils/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>

namespace android {

TEST_F(NativeBridgeTest, PreInitializeNativeBridgeFail2) {
  // Needs LoadNativeBridge() first
  ASSERT_FALSE(PreInitializeNativeBridge(nullptr, "isa"));
  ASSERT_TRUE(NativeBridgeError());
}

}  // namespace android
