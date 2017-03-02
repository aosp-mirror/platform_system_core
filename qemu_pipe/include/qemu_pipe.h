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
#ifndef ANDROID_CORE_INCLUDE_QEMU_PIPE_H
#define ANDROID_CORE_INCLUDE_QEMU_PIPE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
// Try to open a new Qemu fast-pipe. This function returns a file descriptor
// that can be used to communicate with a named service managed by the
// emulator.
//
// This file descriptor can be used as a standard pipe/socket descriptor.
//
// 'pipeName' is the name of the emulator service you want to connect to,
// and must begin with 'pipe:' (e.g. 'pipe:camera' or 'pipe:opengles').
//
// On success, return a valid file descriptor, or -1/errno on failure. E.g.:
//
// EINVAL  -> unknown/unsupported pipeName
// ENOSYS  -> fast pipes not available in this system.
//
// ENOSYS should never happen, except if you're trying to run within a
// misconfigured emulator.
//
// You should be able to open several pipes to the same pipe service,
// except for a few special cases (e.g. GSM modem), where EBUSY will be
// returned if more than one client tries to connect to it.
int qemu_pipe_open(const char* pipeName);

// Send a framed message |buff| of |len| bytes through the |fd| descriptor.
// This really adds a 4-hexchar prefix describing the payload size.
// Returns 0 on success, and -1 on error.
int qemu_pipe_frame_send(int fd, const void* buff, size_t len);

// Read a frame message from |fd|, and store it into |buff| of |len| bytes.
// If the framed message is larger than |len|, then this returns -1 and the
// content is lost. Otherwise, this returns the size of the message. NOTE:
// empty messages are possible in a framed wire protocol and do not mean
// end-of-stream.
int qemu_pipe_frame_recv(int fd, void* buff, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ANDROID_CORE_INCLUDE_QEMU_PIPE_H */
