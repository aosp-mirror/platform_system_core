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

#define LOG_TAG "Corkscrew"
//#define LOG_NDEBUG 0

#include "ptrace-arch.h"
#include <corkscrew/ptrace.h>

#include <errno.h>
#include <sys/ptrace.h>
#include <cutils/log.h>

static const uint32_t ELF_MAGIC = 0x464C457f; // "ELF\0177"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifndef PAGE_MASK
#define PAGE_MASK (~(PAGE_SIZE - 1))
#endif

bool try_get_word(pid_t tid, uintptr_t ptr, uint32_t* out_value) {
    if (ptr & 3) {
        ALOGV("try_get_word: invalid pointer 0x%08x", ptr);
        *out_value = 0;
        return false;
    }
    if (tid < 0) {
#if 0 /*unreliable, unclear whether this is safe from a signal handler context*/
        // Determine whether the pointer is likely to be valid before dereferencing it.
        unsigned char vec[1];
        while (mincore((void*)(ptr & PAGE_MASK), sizeof(uint32_t), vec)) {
            if (errno != EAGAIN && errno != EINTR) {
                ALOGV("try_get_word: invalid pointer 0x%08x, mincore() errno=%d", ptr, errno);
                *out_value = 0;
                return false;
            }
        }
#endif
        *out_value = *(uint32_t*)ptr;
        return true;
    } else {
        // ptrace() returns -1 and sets errno when the operation fails.
        // To disambiguate -1 from a valid result, we clear errno beforehand.
        errno = 0;
        *out_value = ptrace(PTRACE_PEEKTEXT, tid, (void*)ptr, NULL);
        if (*out_value == 0xffffffffL && errno) {
            ALOGV("try_get_word: invalid pointer 0x%08x, ptrace() errno=%d", ptr, errno);
            *out_value = 0;
            return false;
        }
        return true;
    }
}

static void load_ptrace_map_info_data(pid_t pid, map_info_t* mi) {
    if (mi->is_executable) {
        uint32_t elf_magic;
        if (try_get_word(pid, mi->start, &elf_magic) && elf_magic == ELF_MAGIC) {
            map_info_data_t* data = (map_info_data_t*)calloc(1, sizeof(map_info_data_t));
            if (data) {
                mi->data = data;
                if (mi->name[0]) {
                    data->symbol_table = load_symbol_table(mi->name);
                }
#ifdef CORKSCREW_HAVE_ARCH
                load_ptrace_map_info_data_arch(pid, mi, data);
#endif
            }
        }
    }
}

ptrace_context_t* load_ptrace_context(pid_t pid) {
    ptrace_context_t* context =
            (ptrace_context_t*)calloc(1, sizeof(ptrace_context_t));
    if (context) {
        context->map_info_list = load_map_info_list(pid);
        for (map_info_t* mi = context->map_info_list; mi; mi = mi->next) {
            load_ptrace_map_info_data(pid, mi);
        }
    }
    return context;
}

static void free_ptrace_map_info_data(map_info_t* mi) {
    map_info_data_t* data = (map_info_data_t*)mi->data;
    if (data) {
        if (data->symbol_table) {
            free_symbol_table(data->symbol_table);
        }
#ifdef CORKSCREW_HAVE_ARCH
        free_ptrace_map_info_data_arch(mi, data);
#endif
        free(data);
        mi->data = NULL;
    }
}

void free_ptrace_context(ptrace_context_t* context) {
    for (map_info_t* mi = context->map_info_list; mi; mi = mi->next) {
        free_ptrace_map_info_data(mi);
    }
    free_map_info_list(context->map_info_list);
}

void find_symbol_ptrace(const ptrace_context_t* context,
        uintptr_t addr, const map_info_t** out_map_info, const symbol_t** out_symbol) {
    const map_info_t* mi = find_map_info(context->map_info_list, addr);
    const symbol_t* symbol = NULL;
    if (mi) {
        const map_info_data_t* data = (const map_info_data_t*)mi->data;
        if (data && data->symbol_table) {
            symbol = find_symbol(data->symbol_table, addr - mi->start);
        }
    }
    *out_map_info = mi;
    *out_symbol = symbol;
}
