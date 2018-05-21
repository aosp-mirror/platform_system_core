/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <string>

#include <sys/cdefs.h>
#include <sys/types.h>

#include <android-base/unique_fd.h>

// *** WARNING ***
// tombstoned's sockets are SOCK_SEQPACKET sockets.
// Short reads are treated as errors and short writes are assumed to not happen.

// Sends a packet with an attached fd.
ssize_t send_fd(int sockfd, const void* _Nonnull data, size_t len, android::base::unique_fd fd);

// Receives a packet and optionally, its attached fd.
// If out_fd is non-null, packets can optionally have an attached fd.
// If out_fd is null, received packets must not have an attached fd.
//
// Errors:
//   EOVERFLOW: sockfd is SOCK_DGRAM or SOCK_SEQPACKET and buffer is too small.
//              The first len bytes of the packet are stored in data, but the
//              rest of the packet is dropped.
//   ERANGE:    too many file descriptors were attached to the packet.
//   ENOMSG:    not enough file descriptors were attached to the packet.
//
//   plus any errors returned by the underlying recvmsg.
ssize_t recv_fd(int sockfd, void* _Nonnull data, size_t len,
                android::base::unique_fd* _Nullable out_fd);

std::string get_process_name(pid_t pid);
std::string get_thread_name(pid_t tid);
