/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <memtrack/memtrack.h>

#define LOG_TAG "memtrack"

#include <log/log.h>

#include <hardware/memtrack.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

static const memtrack_module_t *module;

struct memtrack_proc {
    pid_t pid;
    struct memtrack_proc_type {
        enum memtrack_type type;
        size_t num_records;
        size_t allocated_records;
        struct memtrack_record *records;
    } types[MEMTRACK_NUM_TYPES];
};

int memtrack_init(void)
{
    int err;

    if (module) {
        return 0;
    }

    err = hw_get_module(MEMTRACK_HARDWARE_MODULE_ID,
            (hw_module_t const**)&module);
    if (err) {
        ALOGE("Couldn't load %s module (%s)", MEMTRACK_HARDWARE_MODULE_ID,
                strerror(-err));
        return err;
    }

    return module->init(module);
}

struct memtrack_proc *memtrack_proc_new(void)
{
    if (!module) {
        return NULL;
    }

    return calloc(sizeof(struct memtrack_proc), 1);
}

void memtrack_proc_destroy(struct memtrack_proc *p)
{
    enum memtrack_type i;

    if (p) {
        for (i = 0; i < MEMTRACK_NUM_TYPES; i++) {
            free(p->types[i].records);
        }
    }
    free(p);
}

static int memtrack_proc_get_type(struct memtrack_proc_type *t,
            pid_t pid, enum memtrack_type type)
{
    size_t num_records = t->num_records;
    int ret;

retry:
    ret = module->getMemory(module, pid, type, t->records, &num_records);
    if (ret) {
        t->num_records = 0;
        return ret;
    }
    if (num_records > t->allocated_records) {
        /* Need more records than allocated */
        free(t->records);
        t->records = calloc(sizeof(*t->records), num_records);
        if (!t->records) {
            return -ENOMEM;
        }
        t->allocated_records = num_records;
        goto retry;
    }
    t->num_records = num_records;

    return 0;
}

/* TODO: sanity checks on return values from HALs:
 *   make sure no records have invalid flags set
 *    - unknown flags
 *    - too many flags of a single category
 *    - missing ACCOUNTED/UNACCOUNTED
 *   make sure there are not overlapping SHARED and SHARED_PSS records
 */
static int memtrack_proc_sanity_check(struct memtrack_proc *p)
{
    (void)p;
    return 0;
}

int memtrack_proc_get(struct memtrack_proc *p, pid_t pid)
{
    enum memtrack_type i;

    if (!module) {
        return -EINVAL;
    }

    if (!p) {
        return -EINVAL;
    }

    p->pid = pid;
    for (i = 0; i < MEMTRACK_NUM_TYPES; i++) {
        memtrack_proc_get_type(&p->types[i], pid, i);
    }

    return memtrack_proc_sanity_check(p);
}

static ssize_t memtrack_proc_sum(struct memtrack_proc *p,
            enum memtrack_type types[], size_t num_types,
            unsigned int flags)
{
    ssize_t sum = 0;
    size_t i;
    size_t j;

    for (i = 0; i < num_types; i++) {
        enum memtrack_type type = types[i];
        for (j = 0; j < p->types[type].num_records; j++) {
            if ((p->types[type].records[j].flags & flags) == flags) {
                sum += p->types[type].records[j].size_in_bytes;
            }
        }
    }

    return sum;
}

ssize_t memtrack_proc_graphics_total(struct memtrack_proc *p)
{
    enum memtrack_type types[] = { MEMTRACK_TYPE_GRAPHICS };
    return memtrack_proc_sum(p, types, ARRAY_SIZE(types), 0);
}

ssize_t memtrack_proc_graphics_pss(struct memtrack_proc *p)
{
    enum memtrack_type types[] = { MEMTRACK_TYPE_GRAPHICS };
    return memtrack_proc_sum(p, types, ARRAY_SIZE(types),
                MEMTRACK_FLAG_SMAPS_UNACCOUNTED);
}

ssize_t memtrack_proc_gl_total(struct memtrack_proc *p)
{
    enum memtrack_type types[] = { MEMTRACK_TYPE_GL };
    return memtrack_proc_sum(p, types, ARRAY_SIZE(types), 0);
}

ssize_t memtrack_proc_gl_pss(struct memtrack_proc *p)
{
    enum memtrack_type types[] = { MEMTRACK_TYPE_GL };
    return memtrack_proc_sum(p, types, ARRAY_SIZE(types),
                MEMTRACK_FLAG_SMAPS_UNACCOUNTED);
}

ssize_t memtrack_proc_other_total(struct memtrack_proc *p)
{
    enum memtrack_type types[] = { MEMTRACK_TYPE_MULTIMEDIA,
                                        MEMTRACK_TYPE_CAMERA,
                                        MEMTRACK_TYPE_OTHER };
    return memtrack_proc_sum(p, types, ARRAY_SIZE(types), 0);
}

ssize_t memtrack_proc_other_pss(struct memtrack_proc *p)
{
    enum memtrack_type types[] = { MEMTRACK_TYPE_MULTIMEDIA,
                                        MEMTRACK_TYPE_CAMERA,
                                        MEMTRACK_TYPE_OTHER };
    return memtrack_proc_sum(p, types, ARRAY_SIZE(types),
                MEMTRACK_FLAG_SMAPS_UNACCOUNTED);
}
