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

#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cutils/klog.h>

#include "commands/partitions.h"
#include "debug.h"

unsigned int debug_level = DEBUG;
//TODO: add tool to generate config file

void usage() {
    fprintf(stderr,
            "usage: test_gpt [ <option> ] <file>\n"
            "\n"
            "options:\n"
            "  -p                                       print partitions\n"
            "  -c                                       print config file\n"
            "  -a                                       adds new partition\n"
            "  -d                                       deletes partition (-o needed)\n"
            "\n"
            "  -n name@startlba,endlba                  new partition detail\n"
            "  -o                                       old partition name\n"
            "  -t                                       type guid\n"
            "  -g                                       partition guid\n"
            "  -l gpt_location                          specyfies gpt secto\n"
    );

}

void printGPT(struct GPT_entry_table *table);
void addGPT(struct GPT_entry_table *table, const char *arg, const char *guid, const char *tguid);
void deleteGPT(struct GPT_entry_table *table, const char *name);
void configPrintGPT(struct GPT_entry_table *table);

int main(int argc, char *argv[]) {
    int print_cmd = 0;
    int config_cmd = 0;
    int add_cmd = 0;
    int del_cmd = 0;
    int sync_cmd = 0;
    int c;
    const char *new_partition = NULL;
    const char *old_partition = NULL;
    const char *type_guid = NULL;
    const char *partition_guid = NULL;
    unsigned gpt_location = 1;

    klog_init();
    klog_set_level(6);

    const struct option longopts[] = {
        {"print", no_argument, 0, 'p'},
        {"config-print", no_argument, 0, 'c'},
        {"add", no_argument, 0, 'a'},
        {"del", no_argument, 0, 'd'},
        {"new", required_argument, 0, 'n'},
        {"old", required_argument, 0, 'o'},
        {"type", required_argument, 0, 't'},
        {"sync", required_argument, 0, 's'},
        {"guid", required_argument, 0, 'g'},
        {"location", required_argument, 0, 'l'},
        {0, 0, 0, 0}
    };

    while (1) {
        c = getopt_long(argc, argv, "pcadt:g:n:o:sl:", longopts, NULL);
        /* Alphabetical cases */
        if (c < 0)
            break;
        switch (c) {
        case 'p':
            print_cmd = 1;
            break;
        case 'c':
            config_cmd = 1;
            break;
        case 'a':
            add_cmd = 1;
            break;
        case 'd':
            del_cmd = 1;
            break;
        case 'n':
            new_partition = optarg;
            break;
        case 'o':
            old_partition = optarg;
            break;
        case 't':
            type_guid = optarg;
        case 'g':
            partition_guid = optarg;
            break;
        case 's':
            sync_cmd = 1;
            break;
        case 'l':
            gpt_location = strtoul(optarg, NULL, 10);
            fprintf(stderr, "Got offset as %d", gpt_location);
            break;
        case '?':
            return 1;
        default:
            abort();
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 1) {
        usage();
        return 1;
    }

    const char *path = argv[0];
    struct GPT_entry_table *table = GPT_get_device(path, gpt_location);
    if (table == NULL) {
        fprintf(stderr, "unable to get GPT table from %s\n", path);
        return 1;
    }

    if (add_cmd)
        addGPT(table, new_partition, partition_guid, type_guid);
    if (del_cmd)
        deleteGPT(table, old_partition);
    if (print_cmd)
        printGPT(table);
    if (config_cmd)
        configPrintGPT(table);
    if (sync_cmd)
        GPT_sync(table);

    GPT_release_device(table);

    return 0;
}

void printGPT(struct GPT_entry_table *table) {
    struct GPT_entry_raw *entry = table->entries;
    unsigned n, m;
    char name[GPT_NAMELEN + 1];

    printf("ptn  start block   end block     name\n");
    printf("---- ------------- -------------\n");

    for (n = 0; n < table->header->entries_count; n++, entry++) {
        if (entry->type_guid[0] == 0)
            continue;
        for (m = 0; m < GPT_NAMELEN; m++) {
            name[m] = entry->name[m] & 127;
        }
        name[m] = 0;
        printf("#%03d %13"PRId64" %13"PRId64" %s\n",
            n + 1, entry->first_lba, entry->last_lba, name);
    }
}

void configPrintGPT(struct GPT_entry_table *table) {
    struct GPT_entry_raw *entry = table->entries;
    unsigned n, m;
    char name[GPT_NAMELEN + 1];
    char temp_guid[17];
    temp_guid[16] = 0;

    printf("header_lba %"PRId64"\n", table->header->current_lba);
    printf("backup_lba %"PRId64"\n", table->header->backup_lba);
    printf("first_lba %"PRId64"\n", table->header->first_usable_lba);
    printf("last_lba %"PRId64"\n", table->header->last_usable_lba);
    printf("entries_lba %"PRId64"\n", table->header->entries_lba);
    snprintf(temp_guid, 17, "%s", table->header->disk_guid);
    printf("guid \"%s\"", temp_guid);

    printf("\npartitions {\n");

    for (n = 0; n < table->header->entries_count; n++, entry++) {
        uint64_t size = entry->last_lba - entry->first_lba + 1;

        if (entry->type_guid[0] == 0)
            continue;
        for (m = 0; m < GPT_NAMELEN; m++) {
            name[m] = entry->name[m] & 127;
        }
        name[m] = 0;

        printf("    %s {\n", name);
        snprintf(temp_guid, 17, "%s", entry->partition_guid);
        printf("        guid \"%s\"\n", temp_guid);
        printf("        first_lba %"PRId64"\n", entry->first_lba);
        printf("        partition_size %"PRId64"\n", size);
        if (entry->flags & GPT_FLAG_SYSTEM)
            printf("        system\n");
        if (entry->flags & GPT_FLAG_BOOTABLE)
            printf("        bootable\n");
        if (entry->flags & GPT_FLAG_READONLY)
            printf("        readonly\n");
        if (entry->flags & GPT_FLAG_DOAUTOMOUNT)
            printf("        automount\n");
        printf("    }\n\n");
    }
    printf("}\n");
}

void addGPT(struct GPT_entry_table *table, const char *str  , const char *guid, const char *tguid) {
    char *c, *c2;
    char *arg = malloc(strlen(str));
    char *name = arg;
    unsigned start, end;
    strcpy(arg, str);
    if (guid == NULL || tguid == NULL) {
        fprintf(stderr, "Type guid and partion guid needed");
        free(arg);
        return;
    }

    c = strchr(arg, '@');

    if (c == NULL) {
        fprintf(stderr, "Wrong entry format");
        free(arg);
        return;
    }

    *c++ = '\0';

    c2 = strchr(c, ',');

    if (c2 == NULL) {
        fprintf(stderr, "Wrong entry format");
        free(arg);
        return;
    }

    start = strtoul(c, NULL, 10);
    *c2++ = '\0';
    end = strtoul(c2, NULL, 10);

    struct GPT_entry_raw data;
    strncpy((char *)data.partition_guid, guid, 15);
    data.partition_guid[15] = '\0';
    strncpy((char *)data.type_guid, tguid, 15);
    data.type_guid[15] = '\0';
    GPT_to_UTF16(data.name, name, GPT_NAMELEN);
    data.first_lba = start;
    data.last_lba = end;

    fprintf(stderr, "Adding (%d,%d) %s as, [%s, %s]", start, end, name, (char *) data.type_guid, (char *) data.partition_guid);
    GPT_add_entry(table, &data);
    free(arg);
}

void deleteGPT(struct GPT_entry_table *table, const char *name) {
    struct GPT_entry_raw *entry;

    if (name == NULL) {
        fprintf(stderr, "Need partition name");
        return;
    }

    entry = GPT_get_pointer_by_name(table, name);

    if (!entry) {
        fprintf(stderr, "Unable to find partition: %s", name);
        return;
    }
    GPT_delete_entry(table, entry);
}

