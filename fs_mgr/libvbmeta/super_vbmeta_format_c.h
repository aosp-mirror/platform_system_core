/*
 * Copyright (C) 2019 The Android Open Source Project
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

/* This .h file is intended for C clients (usually bootloader).  */

#pragma once

#include <stdint.h>

/* Magic signature for super vbmeta. */
#define SUPER_VBMETA_MAGIC 0x5356424d

/* Current super vbmeta version. */
#define SUPER_VBMETA_MAJOR_VERSION 1
#define SUPER_VBMETA_MINOR_VERSION 0

/* super vbmeta size. */
#define SUPER_VBMETA_HEADER_SIZE sizeof(SuperVBMetaHeader)
#define SUPER_VBMETA_DESCRIPTOR_SIZE sizeof(VBMetaDescriptor)
#define SUPER_VBMETA_TABLE_MAX_SIZE 2048

/* super vbmeta offset. */
#define PRIMARY_SUPER_VBMETA_TABLE_OFFSET 0
#define BACKUP_SUPER_VBMETA_TABLE_OFFSET SUPER_VBMETA_TABLE_MAX_SIZE

/* restriction of vbmeta image */
#define VBMETA_IMAGE_MAX_NUM 32
#define VBMETA_IMAGE_MAX_SIZE 64 * 1024

/* Binary format of the super vbmeta image.
 *
 * The super vbmeta image consists of two blocks:
 *
 *  +------------------------------------------+
 *  | Super VBMeta Table - fixed size          |
 *  +------------------------------------------+
 *  | Backup Super VBMeta Table - fixed size   |
 *  +------------------------------------------+
 *  | VBMeta Images - fixed size               |
 *  +------------------------------------------+
 *
 *  The "Super VBMeta Table" records the offset
 *  and the size of each vbmeta_partition within
 *  /super_vbmeta.
 *
 *  The "VBMeta Image" is copied from each vbmeta_partition
 *  and filled with 0 until 64K bytes.
 *
 * The super vbmeta table consists of two blocks:
 *
 *  +-----------------------------------------+
 *  | Header data - fixed size                |
 *  +-----------------------------------------+
 *  | VBMeta descriptors - variable size      |
 *  +-----------------------------------------+
 *
 * The "Header data" block is described by the following struct and
 * is always 128 bytes long.
 *
 * The "VBMeta descriptor" is |descriptors_size| + |vbmeta_name_length|
 * bytes long. It contains the offset and size for each vbmeta image
 * and is followed by |vbmeta_name_length| bytes of the partition name
 * (UTF-8 encoded).
 */

typedef struct SuperVBMetaHeader {
    /*  0: Magic signature (SUPER_VBMETA_MAGIC). */
    uint32_t magic;

    /*  4: Major version. Version number required to read this super vbmeta. If the version is not
     * equal to the library version, the super vbmeta should be considered incompatible.
     */
    uint16_t major_version;

    /*  6: Minor version. A library supporting newer features should be able to
     * read super vbmeta with an older minor version. However, an older library
     * should not support reading super vbmeta if its minor version is higher.
     */
    uint16_t minor_version;

    /*  8: The size of this header struct. */
    uint32_t header_size;

    /*  12: The size of this super vbmeta table. */
    uint32_t total_size;

    /*  16: SHA256 checksum of this super vbmeta table, with this field set to 0. */
    uint8_t checksum[32];

    /*  48: The size of the vbmeta table descriptors. */
    uint32_t descriptors_size;

    /*  52: mark which slot is in use. */
    uint32_t in_use = 0;

    /*  56: reserved for other usage, filled with 0. */
    uint8_t reserved[72];
} __attribute__((packed)) SuperVBMetaHeader;

typedef struct VBMetaDescriptor {
    /*  0: The slot number of the vbmeta image. */
    uint8_t vbmeta_index;

    /*  12: The length of the vbmeta image name. */
    uint32_t vbmeta_name_length;

    /*  16: Space reserved for other usage, filled with 0. */
    uint8_t reserved[48];
} __attribute__((packed)) VBMetaDescriptor;