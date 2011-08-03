/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef __CUTILS_QTAGUID_H
#define __CUTILS_QTAGUID_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Set tags (and owning UIDs) for network sockets.
*/
extern int qtaguid_tagSocket(int sockfd, int tag, uid_t uid);

/*
 * Untag a network socket before closing.
*/
extern int qtaguid_untagSocket(int sockfd);

#ifdef __cplusplus
}
#endif

#endif /* __CUTILS_QTAG_UID_H */
