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

#ifndef _LLKD_H_
#define _LLKD_H_

#ifndef LOG_TAG
#define LOG_TAG "livelock"
#endif

#include <stdbool.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

bool llkInit(const char* threadname); /* threadname NULL, not spawned */
unsigned llkCheckMilliseconds(void);

/* clang-format off */
#define LLK_ENABLE_PROPERTY            "ro.llk.enable"
#define LLK_ENABLE_DEFAULT             false
#define KHT_ENABLE_PROPERTY            "ro.khungtask.enable"
#define LLK_MLOCKALL_PROPERTY          "ro.llk.mlockall"
#define LLK_MLOCKALL_DEFAULT           true
#define LLK_TIMEOUT_MS_PROPERTY        "ro.llk.timeout_ms"
#define KHT_TIMEOUT_PROPERTY           "ro.khungtask.timeout"
#define LLK_D_TIMEOUT_MS_PROPERTY      "ro.llk.D.timeout_ms"
#define LLK_Z_TIMEOUT_MS_PROPERTY      "ro.llk.Z.timeout_ms"
#define LLK_CHECK_MS_PROPERTY          "ro.llk.check_ms"
/* LLK_CHECK_MS_DEFAULT = actual timeout_ms / LLK_CHECKS_PER_TIMEOUT_DEFAULT */
#define LLK_CHECKS_PER_TIMEOUT_DEFAULT 5
#define LLK_BLACKLIST_PROCESS_PROPERTY "ro.llk.blacklist.process"
#define LLK_BLACKLIST_PROCESS_DEFAULT  \
    "0,1,2,init,[kthreadd],[khungtaskd],lmkd,lmkd.llkd,llkd,watchdogd,[watchdogd],[watchdogd/0]"
#define LLK_BLACKLIST_PARENT_PROPERTY  "ro.llk.blacklist.parent"
#define LLK_BLACKLIST_PARENT_DEFAULT   "0,2,[kthreadd]"
#define LLK_BLACKLIST_UID_PROPERTY     "ro.llk.blacklist.uid"
#define LLK_BLACKLIST_UID_DEFAULT      ""
/* clang-format on */

__END_DECLS

#ifdef __cplusplus
extern "C++" { /* In case this included wrapped with __BEGIN_DECLS */

#include <chrono>

__BEGIN_DECLS
/* C++ code allowed to not specify threadname argument for this C linkage */
bool llkInit(const char* threadname = nullptr);
__END_DECLS
std::chrono::milliseconds llkCheck(bool checkRunning = false);

/* clang-format off */
#define LLK_TIMEOUT_MS_DEFAULT  std::chrono::duration_cast<milliseconds>(std::chrono::minutes(10))
#define LLK_TIMEOUT_MS_MINIMUM  std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(10))
#define LLK_CHECK_MS_MINIMUM    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(1))
/* clang-format on */

} /* extern "C++" */
#endif /* __cplusplus */

#endif /* _LLKD_H_ */
