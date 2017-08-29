/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _ASYNCIO_H
#define _ASYNCIO_H

#include <cstring>
#include <cstdint>
#include <linux/aio_abi.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Provides kernel aio operations.
 */

int io_setup(unsigned nr, aio_context_t* ctxp);
int io_destroy(aio_context_t ctx);
int io_submit(aio_context_t ctx, long nr, iocb** iocbpp);
int io_getevents(aio_context_t ctx, long min_nr, long max_nr, io_event* events, timespec* timeout);
int io_cancel(aio_context_t ctx, iocb*, io_event* result);
void io_prep(iocb* iocb, int fd, const void* buf, uint64_t count, int64_t offset, bool read);

#ifdef __cplusplus
};
#endif

#endif  // ASYNCIO_H
