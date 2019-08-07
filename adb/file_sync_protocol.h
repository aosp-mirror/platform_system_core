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

#define ID_SEND MKID('S', 'E', 'N', 'D')
#define ID_RECV MKID('R', 'E', 'C', 'V')
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

union syncmsg {
    struct __attribute__((packed)) {
        uint32_t id;
        uint32_t mode;
        uint32_t size;
        uint32_t mtime;
    } stat_v1;
    struct __attribute__((packed)) {
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
    } stat_v2;
    struct __attribute__((packed)) {
        uint32_t id;
        uint32_t mode;
        uint32_t size;
        uint32_t mtime;
        uint32_t namelen;
    } dent_v1; // followed by `namelen` bytes of the name.
    struct __attribute__((packed)) {
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
    } dent_v2; // followed by `namelen` bytes of the name.
    struct __attribute__((packed)) {
        uint32_t id;
        uint32_t size;
    } data; // followed by `size` bytes of data.
    struct __attribute__((packed)) {
        uint32_t id;
        uint32_t msglen;
    } status; // followed by `msglen` bytes of error message, if id == ID_FAIL.
};

#define SYNC_DATA_MAX (64 * 1024)
