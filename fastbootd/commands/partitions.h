/*
 * Copyright (c) 2009-2013, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of Google, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#ifndef __FASTBOOTD_PATITIONS_
#define __FASTBOOTD_PATITIONS_

#include <stdint.h>

#define GPT_ENTRIES 128
#define GPT_NAMELEN 36

#define GPT_FLAG_SYSTEM (1ULL << 0)
#define GPT_FLAG_BOOTABLE (1ULL << 2)
#define GPT_FLAG_READONLY (1ULL << 60)
#define GPT_FLAG_DOAUTOMOUNT (1ULL << 63)

// it should be passed in little endian order
struct GPT_entry_raw {
    uint8_t type_guid[16];
    uint8_t partition_guid[16];
    uint64_t first_lba; // little endian
    uint64_t last_lba;
    uint64_t flags;
    uint16_t name[GPT_NAMELEN]; // UTF-16 LE
};

struct GPT_mapping {
    void *map_ptr;
    void *ptr;
    unsigned size;
};

struct GPT_entry_table {
    int fd;

    struct GPT_mapping header_map;
    struct GPT_mapping entries_map;
    struct GPT_mapping sec_header_map;
    struct GPT_mapping sec_entries_map;

    struct GPT_header *header;
    struct GPT_entry_raw *entries;
    struct GPT_header *second_header;
    struct GPT_entry_raw *second_entries;

    unsigned sector_size;
    unsigned partition_table_size;
    int second_valid;
};

struct GPT_header {
    uint8_t signature[8];
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_checksum;
    uint32_t reserved_zeros;
    uint64_t current_lba;
    uint64_t backup_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t disk_guid[16];
    uint64_t entries_lba;
    uint32_t entries_count;
    uint32_t entry_size;
    uint32_t partition_array_checksum;
    // the rest should be filled with zeros
} __attribute__((packed));

struct GPT_content {
    struct GPT_header header;
    struct GPT_entry_raw *entries;
};


struct GPT_entry_table* GPT_get_device(const char *, unsigned lba);

void GPT_release_device(struct GPT_entry_table *);

void GPT_edit_entry(struct GPT_entry_table *table,
                    struct GPT_entry_raw *old_entry,
                    struct GPT_entry_raw *new_entry);

int GPT_delete_entry(struct GPT_entry_table *table, struct GPT_entry_raw *entry);

void GPT_add_entry(struct GPT_entry_table *table, struct GPT_entry_raw *entry);

struct GPT_entry_raw *GPT_get_pointer(struct GPT_entry_table *table, struct GPT_entry_raw *entry);
struct GPT_entry_raw *GPT_get_pointer_by_guid(struct GPT_entry_table *, const char *);
struct GPT_entry_raw *GPT_get_pointer_by_name(struct GPT_entry_table *, const char *);

//Use after every edit operation
void GPT_sync();

void GPT_to_UTF16(uint16_t *, const char *, int );
void GPT_from_UTF16(char *, const uint16_t *, int);

int GPT_parse_entry(char *string, struct GPT_entry_raw *entry);

void GPT_default_content(struct GPT_content *content, struct GPT_entry_table *table);

void GPT_release_content(struct GPT_content *content);

int GPT_parse_file(int fd, struct GPT_content *content);

int GPT_write_content(const char *device, struct GPT_content *content);

int gpt_mmap(struct GPT_mapping *mapping, uint64_t location, int size, int fd);

void gpt_unmap(struct GPT_mapping *mapping);

#endif
