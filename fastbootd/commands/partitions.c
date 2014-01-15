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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <endian.h>
#include <zlib.h>
#include <linux/hdreg.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <cutils/config_utils.h>
#include <inttypes.h>

#include "partitions.h"
#include "debug.h"
#include "utils.h"
#include "protocol.h"

#define BLKRRPART  _IO(0x12,95) /* re-read partition table */
#define BLKSSZGET  _IO(0x12,104)

#define DIV_ROUND_UP(x, y) (((x) + (y) - 1)/(y))
#define ALIGN(x, y) ((y) * DIV_ROUND_UP((x), (y)))
#define ALIGN_DOWN(x, y) ((y) * ((x) / (y)))


const uint8_t partition_type_uuid[16] = {
    0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44,
    0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
};

//TODO: There is assumption that we are using little endian

static void GPT_entry_clear(struct GPT_entry_raw *entry)
{
    memset(entry, 0, sizeof(*entry));
}

/*
 * returns mapped location to choosen area
 * mapped_ptr is pointer to whole area mapped (it can be bigger then requested)
 */
int gpt_mmap(struct GPT_mapping *mapping, uint64_t location, int size, int fd)
{
    unsigned int location_diff = location & ~PAGE_MASK;

    mapping->size = ALIGN(size + location_diff, PAGE_SIZE);

    uint64_t sz = get_file_size64(fd);
    if (sz < size + location) {
        D(ERR, "the location of mapping area is outside of the device size %" PRId64, sz);
        return 1;
    }
    location = ALIGN_DOWN(location, PAGE_SIZE);

    mapping->map_ptr = mmap64(NULL, mapping->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, location);

    if (mapping->map_ptr == MAP_FAILED) {
        mapping->ptr = MAP_FAILED;
        D(ERR, "map failed: %s", strerror(errno));
        return 1;
    }

    mapping->ptr = (void *)((char *) mapping->map_ptr + location_diff);
    return 0;
}

void gpt_unmap(struct GPT_mapping *mapping) {
    munmap(mapping->map_ptr, mapping->size);
}


#define LBA_ADDR(table, value)   ((uint64_t) (table)->sector_size * (value))

int GPT_map_from_content(struct GPT_entry_table *table, const struct GPT_content *content)
{

    // Mapping header
    if (gpt_mmap(&table->header_map, LBA_ADDR(table, content->header.current_lba),
                 table->sector_size, table->fd)) {
        D(ERR, "unable to map header:%s\n", strerror(errno));
        goto error_header;
    }

    table->header = (struct GPT_header *) table->header_map.ptr;

    table->partition_table_size = ROUND_UP(content->header.entries_count * sizeof(*table->entries),
                                           table->sector_size);

    // Mapping entry table
    if (gpt_mmap(&table->entries_map, LBA_ADDR(table, content->header.entries_lba),
                 table->partition_table_size, table->fd)) {
        D(ERR, "unable to map entries");
        goto error_signature;
    }

    table->entries = (struct GPT_entry_raw *) table->entries_map.ptr;

    // Mapping secondary header
    if (gpt_mmap(&table->sec_header_map, LBA_ADDR(table, content->header.backup_lba),
                 table->sector_size, table->fd)) {
        D(ERR, "unable to map backup gpt header");
        goto error_sec_header;
    }

    // Mapping secondary entries table
    if (gpt_mmap(&table->sec_entries_map,
                 LBA_ADDR(table, content->header.backup_lba) - table->partition_table_size,
                 table->partition_table_size, table->fd)) {
        D(ERR, "unable to map secondary gpt table");
        goto error_sec_entries;
    }

    table->second_header = (struct GPT_header *) table->sec_header_map.ptr;
    table->second_entries = (struct GPT_entry_raw *) table->sec_entries_map.ptr;
    table->second_valid = strcmp("EFI PART", (char *) table->second_header->signature) == 0;

    return 0;

error_sec_entries:
    gpt_unmap(&table->sec_header_map);
error_sec_header:
    gpt_unmap(&table->entries_map);
error_signature:
    gpt_unmap(&table->header_map);
error_header:
    return 1;
}

int GPT_map(struct GPT_entry_table *table, unsigned header_lba)
{
    struct GPT_content content;
    struct GPT_mapping mapping;
    struct GPT_header *header;

    if (gpt_mmap(&mapping, LBA_ADDR(table, header_lba), table->sector_size, table->fd)) {
        D(ERR, "unable to map header: %s", strerror(errno));
        goto error_header;
    }

    header = (struct GPT_header *) mapping.ptr;

    if (strcmp("EFI PART", (char *) header->signature)) {
        D(ERR, "GPT entry not valid");
        goto error_signature;
    }

    content.header = *header;

    gpt_unmap(&mapping);

    return GPT_map_from_content(table, &content);

error_signature:
    gpt_unmap(&table->header_map);
error_header:
    return 1;
}

struct GPT_entry_table* GPT_get_device(const char *path, unsigned header_lba)
{
    struct GPT_entry_table *table;
    size_t sector_bytes;

    table = (struct GPT_entry_table *) malloc(sizeof(*table));
    table->fd = open(path, O_RDWR);

    if (table->fd < 0) {
        D(ERR, "unable to open file %s:%s\n", path, strerror(errno));
        return NULL;
    }

    if (!ioctl(table->fd, BLKSSZGET, &sector_bytes)) {
        table->sector_size = (unsigned) sector_bytes;
        D(INFO, "Got sector size %d", table->sector_size);
    } else {
        D(WARN, "unable to get sector size, assuming 512");
        table->sector_size = 512;
    }

    if (GPT_map(table, header_lba)) {
        D(ERR, "Could not map gpt");
        return NULL;
    }

    return table;
}

static struct GPT_entry_table* GPT_get_from_content(const char *path, const struct GPT_content *content)
{
    struct GPT_entry_table *table;
    size_t sector_bytes;

    table = (struct GPT_entry_table *) malloc(sizeof(*table));
    table->fd = open(path, O_RDWR);

    if (table->fd < 0) {
        D(ERR, "unable to open file %s:%s\n", path, strerror(errno));
        return NULL;
    }

    if (!ioctl(table->fd, BLKSSZGET, &sector_bytes)) {
        table->sector_size = (unsigned) sector_bytes;
        D(INFO, "Got sector size %d", table->sector_size);
    } else {
        D(WARN, "unable to get sector size %s, assuming 512", strerror(errno));
        table->sector_size = 512;
    }

    if (GPT_map_from_content(table, content)) {
        D(ERR, "Could not map gpt");
        return NULL;
    }

    return table;
}


void GPT_release_device(struct GPT_entry_table *table)
{
    gpt_unmap(&table->header_map);
    gpt_unmap(&table->entries_map);
    gpt_unmap(&table->sec_header_map);
    gpt_unmap(&table->sec_entries_map);
    close(table->fd);
    free(table);
}

static int GPT_check_overlap(struct GPT_entry_table *table, struct GPT_entry_raw *entry);
static int GPT_check_overlap_except(struct GPT_entry_table *table,
                                    struct GPT_entry_raw *entry,
                                    struct GPT_entry_raw *exclude);

void GPT_edit_entry(struct GPT_entry_table *table,
                    struct GPT_entry_raw *old_entry,
                    struct GPT_entry_raw *new_entry)
{
    struct GPT_entry_raw *current_entry = GPT_get_pointer(table, old_entry);

    if (GPT_check_overlap_except(table, new_entry, current_entry)) {
        D(ERR, "Couldn't add overlaping partition");
        return;
    }

    if (current_entry == NULL) {
        D(ERR, "Couldn't find entry");
        return;
    }

    *current_entry = *new_entry;
}

int GPT_delete_entry(struct GPT_entry_table *table, struct GPT_entry_raw *entry)
{
    struct GPT_entry_raw *raw = GPT_get_pointer(table, entry);

    if (raw == NULL) {
        D(ERR, "could not find entry");
        return 1;
    }
    D(DEBUG, "Deleting gpt entry '%s'\n", raw->partition_guid);

    // Entry in the middle of table may become empty
    GPT_entry_clear(raw);

    return 0;
}

void GPT_add_entry(struct GPT_entry_table *table, struct GPT_entry_raw *entry)
{
    unsigned i;
    int inserted = 0;
    if (GPT_check_overlap(table, entry)) {
        D(ERR, "Couldn't add overlaping partition");
        return;
    }

    if (GPT_get_pointer(table, entry) != NULL) {
        D(WARN, "Add entry fault, this entry already exists");
        return;
    }

    struct GPT_entry_raw *entries = table->entries;

    for (i = 0; i < table->header->entries_count; ++i) {
        if (!entries[i].type_guid[0]) {
            inserted = 1;
            D(DEBUG, "inserting");
            memcpy(&entries[i], entry, sizeof(entries[i]));
            break;
        }
    }

    if (!inserted) {
        D(ERR, "Unable to find empty partion entry");
    }
}

struct GPT_entry_raw *GPT_get_pointer_by_UTFname(struct GPT_entry_table *table, const uint16_t *name);

struct GPT_entry_raw *GPT_get_pointer(struct GPT_entry_table *table, struct GPT_entry_raw *entry)
{
    if (entry->partition_guid[0] != 0)
        return GPT_get_pointer_by_guid(table, (const char *) entry->partition_guid);
    else if (entry->name[0] != 0)
        return GPT_get_pointer_by_UTFname(table, entry->name);

    D(WARN, "Name or guid needed to find entry");
    return NULL;
}

struct GPT_entry_raw *GPT_get_pointer_by_guid(struct GPT_entry_table *table, const char *name)
{
    int current = (int) table->header->entries_count;

    for (current = current - 1; current >= 0; --current) {
        if (strncmp((char *) name,
                    (char *) table->entries[current].partition_guid, 16) == 0) {
                return &table->entries[current];
        }
    }

    return NULL;
}

int strncmp_UTF16_char(const uint16_t *s1, const char *s2, size_t n)
{
    if (n == 0)
        return (0);
    do {
        if (((*s1) & 127) != *s2++)
            return (((unsigned char) ((*s1) & 127)) - *(unsigned char *)--s2);
        if (*s1++ == 0)
            break;
    } while (--n != 0);
    return (0);
}

int strncmp_UTF16(const uint16_t *s1, const uint16_t *s2, size_t n)
{
    if (n == 0)
        return (0);
    do {
        if ((*s1) != *s2++)
            return (*s1 - *--s2);
        if (*s1++ == 0)
            break;
    } while (--n != 0);
    return (0);
}

struct GPT_entry_raw *GPT_get_pointer_by_name(struct GPT_entry_table *table, const char *name)
{
    int count = (int) table->header->entries_count;
    int current;

    for (current = 0; current < count; ++current) {
        if (strncmp_UTF16_char(table->entries[current].name,
                         (char *) name, 16) == 0) {
                    return &table->entries[current];
        }
    }

    return NULL;
}

struct GPT_entry_raw *GPT_get_pointer_by_UTFname(struct GPT_entry_table *table, const uint16_t *name)
{
    int count = (int) table->header->entries_count;
    int current;

    for (current = 0; current < count; ++current) {
        if (strncmp_UTF16(table->entries[current].name,
                          name, GPT_NAMELEN) == 0) {
                return &table->entries[current];
        }
    }

    return NULL;
}

void GPT_sync(struct GPT_entry_table *table)
{
    uint32_t crc;

    //calculate crc32
    crc = crc32(0, Z_NULL, 0);
    crc = crc32(crc, (void*) table->entries, table->header->entries_count * sizeof(*table->entries));
    table->header->partition_array_checksum = crc;

    table->header->header_checksum = 0;
    crc = crc32(0, Z_NULL, 0);
    crc = crc32(crc, (void*) table->header, table->header->header_size);
    table->header->header_checksum = crc;

    //sync secondary partion
    if (table->second_valid) {
        memcpy((void *)table->second_entries, (void *) table->entries, table->partition_table_size);
        memcpy((void *)table->second_header, (void *)table->header, sizeof(*table->header));
    }

    if(!ioctl(table->fd, BLKRRPART, NULL)) {
        D(WARN, "Unable to force kernel to refresh partition table");
    }
}

void GPT_to_UTF16(uint16_t *to, const char *from, int n)
{
    int i;
    for (i = 0; i < (n - 1) && (to[i] = from[i]) != '\0'; ++i);
    to[i] = '\0';
}

void GPT_from_UTF16(char *to, const uint16_t *from, int n)
{
    int i;
    for (i = 0; i < (n - 1) && (to[i] = from[i] & 127) != '\0'; ++i);
    to[i] = '\0';
}

static int GPT_check_overlap_except(struct GPT_entry_table *table,
                                    struct GPT_entry_raw *entry,
                                    struct GPT_entry_raw *exclude) {
    int current = (int) table->header->entries_count;
    int dontcheck;
    struct GPT_entry_raw *current_entry;
    if (entry->last_lba < entry->first_lba) {
        D(WARN, "Start address have to be less than end address");
        return 1;
    }

    for (current = current - 1; current >= 0; --current) {
        current_entry = &table->entries[current];
        dontcheck = strncmp((char *) entry->partition_guid,
                           (char *) current_entry->partition_guid , 16) == 0;
        dontcheck |= current_entry->type_guid[0] == 0;
        dontcheck |= current_entry == exclude;

        if (!dontcheck && ((entry->last_lba >= current_entry->first_lba &&
                            entry->first_lba < current_entry->last_lba ))) {
            return 1;
        }
    }

    return 0;
}

static int GPT_check_overlap(struct GPT_entry_table *table, struct GPT_entry_raw *entry)
{
    return GPT_check_overlap_except(table, entry, NULL);
}

static char *get_key_value(char *ptr, char **key, char **value)
{
    *key = ptr;
    ptr = strchr(ptr, '=');

    if (ptr == NULL)
        return NULL;

    *ptr++ = '\0';
    *value = ptr;
    ptr = strchr(ptr, ';');

    if (ptr == NULL)
        ptr = *value + strlen(*value);
    else
        *ptr = '\0';

    *key = strip(*key);
    *value = strip(*value);

    return ptr;
}

//TODO: little endian?
static int add_key_value(const char *key, const char *value, struct GPT_entry_raw *entry)
{
    char *endptr;
    if (!strcmp(key, "type")) {
        strncpy((char *) entry->type_guid, value, 16);
        entry->type_guid[15] = 0;
    }
    else if (!strcmp(key, "guid")) {
        strncpy((char *) entry->partition_guid, value, 16);
        entry->type_guid[15] = 0;
    }
    else if (!strcmp(key, "firstlba")) {
        entry->first_lba = strtoul(value, &endptr, 10);
        if (*endptr != '\0') goto error;
    }
    else if (!strcmp(key, "lastlba")) {
        entry->last_lba = strtoul(value, &endptr, 10);
        if (*endptr != '\0') goto error;
    }
    else if (!strcmp(key, "flags")) {
        entry->flags = strtoul(value, &endptr, 16);
        if (*endptr != '\0') goto error;
    }
    else if (!strcmp(key, "name")) {
        GPT_to_UTF16(entry->name, value, GPT_NAMELEN);
    }
    else {
        goto error;
    }

    return 0;

error:
    D(ERR, "Could not find key or parse value: %s,%s", key, value);
    return 1;
}

int GPT_parse_entry(char *string, struct GPT_entry_raw *entry)
{
    char *ptr = string;
    char *key, *value;

    while ((ptr = get_key_value(ptr, &key, &value)) != NULL) {
        if (add_key_value(key, value, entry)) {
            D(WARN, "key or value not valid: %s %s", key, value);
            return 1;
        }
    }

    return 0;
}

void entry_set_guid(int n, uint8_t *guid)
{
    int fd;
    fd = open("/dev/urandom", O_RDONLY);
    read(fd, guid, 16);
    close(fd);

    //rfc4122
    guid[8] = (guid[8] & 0x3F) | 0x80;
    guid[7] = (guid[7] & 0x0F) | 0x40;
}

void GPT_default_content(struct GPT_content *content, struct GPT_entry_table *table)
{
    if (table != NULL) {
        memcpy(&content->header, table->header, sizeof(content->header));
        content->header.header_size = sizeof(content->header);
        content->header.entry_size = sizeof(struct GPT_entry_raw);
    }
    else {
        D(WARN, "Could not locate old gpt table, using default values");
        memset(&content->header, 0, sizeof(content->header) / sizeof(int));
        content->header = (struct GPT_header) {
            .revision = 0x10000,
            .header_size = sizeof(content->header),
            .header_checksum = 0,
            .reserved_zeros = 0,
            .current_lba = 1,
            .backup_lba = 1,
            .entry_size = sizeof(struct GPT_entry_raw),
            .partition_array_checksum = 0
        };
        strncpy((char *)content->header.signature, "EFI PART", 8);
        strncpy((char *)content->header.disk_guid, "ANDROID MMC DISK", 16);
    }
}

static int get_config_uint64(cnode *node, uint64_t *ptr, const char *name)
{
    const char *tmp;
    uint64_t val;
    char *endptr;
    if ((tmp = config_str(node, name, NULL))) {
        val = strtoull(tmp, &endptr, 10);
        if (*endptr != '\0') {
            D(WARN, "Value for %s is not a number: %s", name, tmp);
            return 1;
        }
        *ptr = val;
        return 0;
    }
    return 1;
}

static int get_config_string(cnode *node, char *ptr, int max_len, const char *name)
{
    size_t begin, end;
    const char *value = config_str(node, name, NULL);
    if (!value)
        return -1;

    begin = strcspn(value, "\"") + 1;
    end = strcspn(&value[begin], "\"");

    if ((int) end > max_len) {
        D(WARN, "Identifier \"%s\" too long", value);
        return -1;
    }

    strncpy(ptr, &value[begin], end);
    if((int) end < max_len)
        ptr[end] = 0;
    return 0;
}

static void GPT_parse_header(cnode *node, struct GPT_content *content)
{
    get_config_uint64(node, &content->header.current_lba, "header_lba");
    get_config_uint64(node, &content->header.backup_lba, "backup_lba");
    get_config_uint64(node, &content->header.first_usable_lba, "first_lba");
    get_config_uint64(node, &content->header.last_usable_lba, "last_lba");
    get_config_uint64(node, &content->header.entries_lba, "entries_lba");
    get_config_string(node, (char *) content->header.disk_guid, 16, "guid");
}

static int GPT_parse_partitions(cnode *node, struct GPT_content *content)
{
    cnode *current;
    int i;
    uint64_t partition_size;
    struct GPT_entry_raw *entry;
    for (i = 0, current = node->first_child; current; current = current->next, ++i) {
        entry = &content->entries[i];
        entry_set_guid(i, content->entries[i].partition_guid);
        memcpy(&content->entries[i].type_guid, partition_type_uuid, 16);
        if (get_config_uint64(current, &entry->first_lba, "first_lba")) {
            D(ERR, "first_lba not specified");
            return 1;
        }
        if (get_config_uint64(current, &partition_size, "partition_size")) {
            D(ERR, "partition_size not specified");
            return 1;
        }
        if (config_str(current, "system", NULL)) {
            entry->flags |= GPT_FLAG_SYSTEM;
        }
        if (config_str(current, "bootable", NULL)) {
            entry->flags |= GPT_FLAG_BOOTABLE;
        }
        if (config_str(current, "readonly", NULL)) {
            entry->flags |= GPT_FLAG_READONLY;
        }
        if (config_str(current, "automount", NULL)) {
            entry->flags |= GPT_FLAG_DOAUTOMOUNT;
        }

        get_config_uint64(current, &content->entries[i].flags, "flags");
        content->entries[i].last_lba = content->entries[i].first_lba + partition_size - 1;
        GPT_to_UTF16(content->entries[i].name, current->name, 16);
    }
    return 0;
}

static inline int cnode_count(cnode *node)
{
    int i;
    cnode *current;
    for (i = 0, current = node->first_child; current; current = current->next, ++i)
        ;
    return i;
}


static int GPT_parse_cnode(cnode *root, struct GPT_content *content)
{
    cnode *partnode;

    if (!(partnode = config_find(root, "partitions"))) {
        D(ERR, "Could not find partition table");
        return 0;
    }

    GPT_parse_header(root, content);

    content->header.entries_count = cnode_count(partnode);
    content->entries = malloc(content->header.entries_count * sizeof(struct GPT_entry_raw));

    if (GPT_parse_partitions(partnode, content)) {
        D(ERR, "Could not parse partitions");
        return 0;
    }

    return 1;
}

int GPT_parse_file(int fd, struct GPT_content *content)
{
    char *data;
    int size;
    int ret;
    cnode *root = config_node("", "");

    size = get_file_size(fd);
    data = (char *) mmap(NULL, size + 1, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (data == NULL) {
        if (size == 0)
            D(ERR, "config file empty");
        else
            D(ERR, "Out of memory");
        return 0;
    }

    data[size - 1] = 0;
    config_load(root, data);

    if (root->first_child == NULL) {
        D(ERR, "Could not read config file");
        return 0;
    }

    ret = GPT_parse_cnode(root, content);
    munmap(data, size);
    return ret;
}

void GPT_release_content(struct GPT_content *content)
{
    free(content->entries);
}

int GPT_write_content(const char *device, struct GPT_content *content)
{
    struct GPT_entry_table *maptable;

    maptable = GPT_get_from_content(device, content);
    if (maptable == NULL) {
        D(ERR, "could not map device");
        return 0;
    }

    memcpy(maptable->header, &content->header, sizeof(*maptable->header));
    memcpy(maptable->entries, content->entries,
           content->header.entries_count * sizeof(*maptable->entries));

    GPT_sync(maptable);
    GPT_release_device(maptable);

    return 1;
}

