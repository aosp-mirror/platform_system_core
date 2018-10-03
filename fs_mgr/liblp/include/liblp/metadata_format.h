/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef LOGICAL_PARTITION_METADATA_FORMAT_H_
#define LOGICAL_PARTITION_METADATA_FORMAT_H_

#ifdef __cplusplus
#include <string>
#include <vector>
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic signature for LpMetadataGeometry. */
#define LP_METADATA_GEOMETRY_MAGIC 0x616c4467

/* Space reserved for geometry information. */
#define LP_METADATA_GEOMETRY_SIZE 4096

/* Magic signature for LpMetadataHeader. */
#define LP_METADATA_HEADER_MAGIC 0x414C5030

/* Current metadata version. */
#define LP_METADATA_MAJOR_VERSION 2
#define LP_METADATA_MINOR_VERSION 0

/* Attributes for the LpMetadataPartition::attributes field.
 *
 * READONLY - The partition should not be considered writable. When used with
 * device mapper, the block device will be created as read-only.
 */
#define LP_PARTITION_ATTR_NONE 0x0
#define LP_PARTITION_ATTR_READONLY 0x1

/* Mask that defines all valid attributes. */
#define LP_PARTITION_ATTRIBUTE_MASK (LP_PARTITION_ATTR_READONLY)

/* Default name of the physical partition that holds logical partition entries.
 * The layout of this partition will look like:
 *
 *     +--------------------+
 *     | Disk Geometry      |
 *     +--------------------+
 *     | Metadata           |
 *     +--------------------+
 *     | Logical Partitions |
 *     +--------------------+
 *     | Backup Metadata    |
 *     +--------------------+
 *     | Geometry Backup    |
 *     +--------------------+
 */
#define LP_METADATA_PARTITION_NAME "super"

/* Size of a sector is always 512 bytes for compatibility with the Linux kernel. */
#define LP_SECTOR_SIZE 512

/* This structure is stored at sector 0 in the first 4096 bytes of the
 * partition, and again in the very last 4096 bytes. It is never modified and
 * describes how logical partition information can be located.
 */
typedef struct LpMetadataGeometry {
    /*  0: Magic signature (LP_METADATA_GEOMETRY_MAGIC). */
    uint32_t magic;

    /*  4: Size of the LpMetadataGeometry struct. */
    uint32_t struct_size;

    /*  8: SHA256 checksum of this struct, with this field set to 0. */
    uint8_t checksum[32];

    /* 40: Maximum amount of space a single copy of the metadata can use. This
     * must be a multiple of LP_SECTOR_SIZE.
     */
    uint32_t metadata_max_size;

    /* 44: Number of copies of the metadata to keep. For A/B devices, this
     * will be 2. For an A/B/C device, it would be 3, et cetera. For Non-A/B
     * it will be 1. A backup copy of each slot is kept, so if this is "2",
     * there will be four copies total.
     */
    uint32_t metadata_slot_count;

    /* 48: First usable sector for allocating logical partitions. this will be
     * the first sector after the initial 4096 geometry block, followed by the
     * space consumed by metadata_max_size*metadata_slot_count.
     */
    uint64_t first_logical_sector;

    /* 56: Last usable sector, inclusive, for allocating logical partitions.
     * At the end of this sector will follow backup metadata slots and the
     * backup geometry block at the very end.
     */
    uint64_t last_logical_sector;

    /* 64: Alignment for defining partitions or partition extents. For example,
     * an alignment of 1MiB will require that all partitions have a size evenly
     * divisible by 1MiB, and that the smallest unit the partition can grow by
     * is 1MiB.
     *
     * Alignment is normally determined at runtime when growing or adding
     * partitions. If for some reason the alignment cannot be determined, then
     * this predefined alignment in the geometry is used instead. By default
     * it is set to 1MiB.
     */
    uint32_t alignment;

    /* 68: Alignment offset for "stacked" devices. For example, if the "super"
     * partition itself is not aligned within the parent block device's
     * partition table, then we adjust for this in deciding where to place
     * |first_logical_sector|.
     *
     * Similar to |alignment|, this will be derived from the operating system.
     * If it cannot be determined, it is assumed to be 0.
     */
    uint32_t alignment_offset;

    /* 72: Block device size, as specified when the metadata was created. This
     * can be used to verify the geometry against a target device.
     */
    uint64_t block_device_size;

    /* 76: Logical block size of the super partition block device. This is the
     * minimal alignment for partition and extent sizes, and it must be a
     * multiple of LP_SECTOR_SIZE.
     */
    uint32_t logical_block_size;
} __attribute__((packed)) LpMetadataGeometry;

/* The logical partition metadata has a number of tables; they are described
 * in the header via the following structure.
 *
 * The size of the table can be computed by multiplying entry_size by
 * num_entries, and the result must not overflow a 32-bit signed integer.
 */
typedef struct LpMetadataTableDescriptor {
    /*  0: Location of the table, relative to the metadata header. */
    uint32_t offset;
    /*  4: Number of entries in the table. */
    uint32_t num_entries;
    /*  8: Size of each entry in the table, in bytes. */
    uint32_t entry_size;
} __attribute__((packed)) LpMetadataTableDescriptor;

/* Binary format for the header of the logical partition metadata format.
 *
 * The format has three sections. The header must occur first, and the
 * proceeding tables may be placed in any order after.
 *
 *  +-----------------------------------------+
 *  | Header data - fixed size                |
 *  +-----------------------------------------+
 *  | Partition table - variable size         |
 *  +-----------------------------------------+
 *  | Partition table extents - variable size |
 *  +-----------------------------------------+
 *
 * The "Header" portion is described by LpMetadataHeader. It will always
 * precede the other three blocks.
 *
 * All fields are stored in little-endian byte order when serialized.
 *
 * This struct is versioned; see the |major_version| and |minor_version|
 * fields.
 */
typedef struct LpMetadataHeader {
    /*  0: Four bytes equal to LP_METADATA_HEADER_MAGIC. */
    uint32_t magic;

    /*  4: Version number required to read this metadata. If the version is not
     * equal to the library version, the metadata should be considered
     * incompatible.
     */
    uint16_t major_version;

    /*  6: Minor version. A library supporting newer features should be able to
     * read metadata with an older minor version. However, an older library
     * should not support reading metadata if its minor version is higher.
     */
    uint16_t minor_version;

    /*  8: The size of this header struct. */
    uint32_t header_size;

    /* 12: SHA256 checksum of the header, up to |header_size| bytes, computed as
     * if this field were set to 0.
     */
    uint8_t header_checksum[32];

    /* 44: The total size of all tables. This size is contiguous; tables may not
     * have gaps in between, and they immediately follow the header.
     */
    uint32_t tables_size;

    /* 48: SHA256 checksum of all table contents. */
    uint8_t tables_checksum[32];

    /* 80: Partition table descriptor. */
    LpMetadataTableDescriptor partitions;
    /* 92: Extent table descriptor. */
    LpMetadataTableDescriptor extents;
    /* 104: Updateable group descriptor. */
    LpMetadataTableDescriptor groups;
} __attribute__((packed)) LpMetadataHeader;

/* This struct defines a logical partition entry, similar to what would be
 * present in a GUID Partition Table.
 */
typedef struct LpMetadataPartition {
    /*  0: Name of this partition in ASCII characters. Any unused characters in
     * the buffer must be set to 0. Characters may only be alphanumeric or _.
     * The name must include at least one ASCII character, and it must be unique
     * across all partition names. The length (36) is the same as the maximum
     * length of a GPT partition name.
     */
    char name[36];

    /* 36: Globally unique identifier (GUID) of this partition. */
    uint8_t guid[16];

    /* 52: Attributes for the partition (see LP_PARTITION_ATTR_* flags above). */
    uint32_t attributes;

    /* 56: Index of the first extent owned by this partition. The extent will
     * start at logical sector 0. Gaps between extents are not allowed.
     */
    uint32_t first_extent_index;

    /* 60: Number of extents in the partition. Every partition must have at
     * least one extent.
     */
    uint32_t num_extents;

    /* 64: Group this partition belongs to. */
    uint32_t group_index;
} __attribute__((packed)) LpMetadataPartition;

/* This extent is a dm-linear target, and the index is an index into the
 * LinearExtent table.
 */
#define LP_TARGET_TYPE_LINEAR 0

/* This extent is a dm-zero target. The index is ignored and must be 0. */
#define LP_TARGET_TYPE_ZERO 1

/* This struct defines an extent entry in the extent table block. */
typedef struct LpMetadataExtent {
    /*  0: Length of this extent, in 512-byte sectors. */
    uint64_t num_sectors;

    /*  8: Target type for device-mapper (see LP_TARGET_TYPE_* values). */
    uint32_t target_type;

    /* 12: Contents depends on target_type.
     *
     * LINEAR: The sector on the physical partition that this extent maps onto.
     * ZERO: This field must be 0.
     */
    uint64_t target_data;
} __attribute__((packed)) LpMetadataExtent;

/* This struct defines an entry in the groups table. Each group has a maximum
 * size, and partitions in a group must not exceed that size. There is always
 * a "default" group of unlimited size, which is used when not using update
 * groups or when using overlayfs or fastbootd.
 */
typedef struct LpMetadataPartitionGroup {
    /*  0: Name of this group. Any unused characters must be 0. */
    char name[36];

    /* 36: Maximum size in bytes. If 0, the group has no maximum size. */
    uint64_t maximum_size;
} LpMetadataPartitionGroup;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LOGICAL_PARTITION_METADATA_FORMAT_H_ */
