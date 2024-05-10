/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <android-base/logging.h>

#define FSTAB_TAG "[libfstab] "

/* The CHECK() in logging.h will use program invocation name as the tag.
 * Thus, the log will have prefix "init: " when libfs_mgr is statically
 * linked in the init process. This might be opaque when debugging.
 * Append a library name tag at the end of the abort message to aid debugging.
 */
#define FSTAB_CHECK(x) CHECK(x) << "in " << FSTAB_TAG

// Logs a message to kernel
#define LINFO LOG(INFO) << FSTAB_TAG
#define LWARNING LOG(WARNING) << FSTAB_TAG
#define LERROR LOG(ERROR) << FSTAB_TAG
#define LFATAL LOG(FATAL) << FSTAB_TAG

// Logs a message with strerror(errno) at the end
#define PINFO PLOG(INFO) << FSTAB_TAG
#define PWARNING PLOG(WARNING) << FSTAB_TAG
#define PERROR PLOG(ERROR) << FSTAB_TAG
#define PFATAL PLOG(FATAL) << FSTAB_TAG
