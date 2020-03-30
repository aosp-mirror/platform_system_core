/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define MKID(a, b, c, d) ((a) | ((b) << 8) | ((c) << 16) | ((d) << 24))

#define ID_LSTAT_V1 MKID('S', 'T', 'A', 'T')
#define ID_STAT_V2 MKID('S', 'T', 'A', '2')
#define ID_LSTAT_V2 MKID('L', 'S', 'T', '2')

#define ID_LIST_V1 MKID('L', 'I', 'S', 'T')
#define ID_LIST_V2 MKID('L', 'I', 'S', '2')
#define ID_DENT_V1 MKID('D', 'E', 'N', 'T')
#define ID_DENT_V2 MKID('D', 'N', 'T', '2')

#define ID_SEND_V1 MKID('S', 'E', 'N', 'D')
#define ID_SEND_V2 MKID('S', 'N', 'D', '2')
#define ID_RECV_V1 MKID('R', 'E', 'C', 'V')
#define ID_RECV_V2 MKID('R', 'C', 'V', '2')
#define ID_DONE MKID('D', 'O', 'N', 'E')
#define ID_DATA MKID('D', 'A', 'T', 'A')
#define ID_OKAY MKID('O', 'K', 'A', 'Y')
#define ID_FAIL MKID('F', 'A', 'I', 'L')
#define ID_QUIT MKID('Q', 'U', 'I', 'T')

struct SyncRequest {
    uint32_t id;           // ID_STAT, et cetera.
    uint32_t path_length;  // <= 1024
    // Followed by 'path_length' bytes of path (not NUL-terminated).
} __attribute__((packed));

struct __attribute__((packed)) sync_stat_v1 {
    uint32_t id;
    uint32_t mode;
    uint32_t size;
    uint32_t mtime;
};

struct __attribute__((packed)) sync_stat_v2 {
    uint32_t id;
    uint32_t error;
    uint64_t dev;
    uint64_t ino;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    int64_t atime;
    int64_t mtime;
    int64_t ctime;
};

struct __attribute__((packed)) sync_dent_v1 {
    uint32_t id;
    uint32_t mode;
    uint32_t size;
    uint32_t mtime;
    uint32_t namelen;
};  // followed by `namelen` bytes of the name.

struct __attribute__((packed)) sync_dent_v2 {
    uint32_t id;
    uint32_t error;
    uint64_t dev;
    uint64_t ino;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    int64_t atime;
    int64_t mtime;
    int64_t ctime;
    uint32_t namelen;
};  // followed by `namelen` bytes of the name.

enum SyncFlag : uint32_t {
    kSyncFlagNone = 0,
    kSyncFlagBrotli = 1,
};

// send_v1 sent the path in a buffer, followed by a comma and the mode as a string.
// send_v2 sends just the path in the first request, and then sends another syncmsg (with the
// same ID!) with details.
struct __attribute__((packed)) sync_send_v2 {
    uint32_t id;
    uint32_t mode;
    uint32_t flags;
};

// Likewise, recv_v1 just sent the path without any accompanying data.
struct __attribute__((packed)) sync_recv_v2 {
    uint32_t id;
    uint32_t flags;
};

struct __attribute__((packed)) sync_data {
    uint32_t id;
    uint32_t size;
};  // followed by `size` bytes of data.

struct __attribute__((packed)) sync_status {
    uint32_t id;
    uint32_t msglen;
};  // followed by `msglen` bytes of error message, if id == ID_FAIL.

union syncmsg {
    sync_stat_v1 stat_v1;
    sync_stat_v2 stat_v2;
    sync_dent_v1 dent_v1;
    sync_dent_v2 dent_v2;
    sync_data data;
    sync_status status;
    sync_send_v2 send_v2_setup;
    sync_recv_v2 recv_v2_setup;
};

#define SYNC_DATA_MAX (64 * 1024)
