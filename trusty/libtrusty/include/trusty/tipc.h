/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef _LIB_TIPC_H
#define _LIB_TIPC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/uio.h>
#include <trusty/ipc.h>

int tipc_connect(const char *dev_name, const char *srv_name);
ssize_t tipc_send(int fd, const struct iovec* iov, int iovcnt, struct trusty_shm* shm, int shmcnt);
int tipc_close(int fd);

#ifdef __cplusplus
}
#endif

#endif
