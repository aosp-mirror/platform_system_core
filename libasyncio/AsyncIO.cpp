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

#include <asyncio/AsyncIO.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>

int io_setup(unsigned nr, aio_context_t* ctxp) {
    return syscall(__NR_io_setup, nr, ctxp);
}

int io_destroy(aio_context_t ctx) {
    return syscall(__NR_io_destroy, ctx);
}

int io_submit(aio_context_t ctx, long nr, iocb** iocbpp) {
    return syscall(__NR_io_submit, ctx, nr, iocbpp);
}

int io_getevents(aio_context_t ctx, long min_nr, long max_nr, io_event* events, timespec* timeout) {
    return syscall(__NR_io_getevents, ctx, min_nr, max_nr, events, timeout);
}

int io_cancel(aio_context_t ctx, iocb* iocbp, io_event* result) {
    return syscall(__NR_io_cancel, ctx, iocbp, result);
}

void io_prep(iocb* iocb, int fd, const void* buf, uint64_t count, int64_t offset, bool read) {
    memset(iocb, 0, sizeof(*iocb));
    iocb->aio_fildes = fd;
    iocb->aio_lio_opcode = read ? IOCB_CMD_PREAD : IOCB_CMD_PWRITE;
    iocb->aio_reqprio = 0;
    iocb->aio_buf = reinterpret_cast<uint64_t>(buf);
    iocb->aio_nbytes = count;
    iocb->aio_offset = offset;
}

void io_prep_pread(struct iocb* iocb, int fd, void* buf, size_t count, long long offset) {
    io_prep(iocb, fd, buf, count, offset, true);
}

void io_prep_pwrite(struct iocb* iocb, int fd, void* buf, size_t count, long long offset) {
    io_prep(iocb, fd, buf, count, offset, false);
}
