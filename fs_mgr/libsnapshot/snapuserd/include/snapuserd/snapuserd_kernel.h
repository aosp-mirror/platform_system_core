// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <linux/types.h>

namespace android {
namespace snapshot {

#define DM_USER_REQ_MAP_READ 0
#define DM_USER_REQ_MAP_WRITE 1

#define DM_USER_RESP_SUCCESS 0
#define DM_USER_RESP_ERROR 1
#define DM_USER_RESP_UNSUPPORTED 2

// Kernel COW header fields
static constexpr uint32_t SNAP_MAGIC = 0x70416e53;

static constexpr uint32_t SNAPSHOT_DISK_VERSION = 1;

static constexpr uint32_t NUM_SNAPSHOT_HDR_CHUNKS = 1;

static constexpr uint32_t SNAPSHOT_VALID = 1;

/*
 * The basic unit of block I/O is a sector. It is used in a number of contexts
 * in Linux (blk, bio, genhd). The size of one sector is 512 = 2**9
 * bytes. Variables of type sector_t represent an offset or size that is a
 * multiple of 512 bytes. Hence these two constants.
 */
static constexpr uint32_t SECTOR_SHIFT = 9;
static constexpr uint64_t SECTOR_SIZE = (1ULL << SECTOR_SHIFT);

static constexpr size_t BLOCK_SZ = 4096;
static constexpr size_t BLOCK_SHIFT = (__builtin_ffs(BLOCK_SZ) - 1);

typedef __u64 sector_t;
typedef sector_t chunk_t;

static constexpr uint32_t CHUNK_SIZE = 8;
static constexpr uint32_t CHUNK_SHIFT = (__builtin_ffs(CHUNK_SIZE) - 1);

// This structure represents the kernel COW header.
// All the below fields should be in Little Endian format.
struct disk_header {
    uint32_t magic;

    /*
     * Is this snapshot valid.  There is no way of recovering
     * an invalid snapshot.
     */
    uint32_t valid;

    /*
     * Simple, incrementing version. no backward
     * compatibility.
     */
    uint32_t version;

    /* In sectors */
    uint32_t chunk_size;
} __attribute__((packed));

// A disk exception is a mapping of old_chunk to new_chunk
// old_chunk is the chunk ID of a dm-snapshot device.
// new_chunk is the chunk ID of the COW device.
struct disk_exception {
    uint64_t old_chunk;
    uint64_t new_chunk;
} __attribute__((packed));

// Control structures to communicate with dm-user
// It comprises of header and a payload
struct dm_user_header {
    __u64 seq;
    __u64 type;
    __u64 flags;
    __u64 sector;
    __u64 len;
} __attribute__((packed));

struct dm_user_payload {
    __u8 buf[];
};

// Message comprising both header and payload
struct dm_user_message {
    struct dm_user_header header;
    struct dm_user_payload payload;
};

}  // namespace snapshot
}  // namespace android
