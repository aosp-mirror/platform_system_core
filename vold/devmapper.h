
/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _DEVMAPPER_H
#define _DEVMAPPER_H

#include <pthread.h>

#include "vold.h"
#include "blkdev.h"
#include "media.h"

#define MAX_LOOP 8

enum dm_src_type {
    dmsrc_unknown,
    dmsrc_loopback,
    dmsrc_partition,
};

struct loop_data {
    char *loop_src;

    char *loop_dev;
    int  loop_no;
};

struct part_data {
    char part_type;
    
    char *part_dev;
};

struct devmapping {
        enum dm_src_type src_type;
        union {
            struct loop_data loop;
            struct part_data part;
        } type_data;
        
        uint32_t         size_mb;
	char             *target;
        char             *params;
        char             *tgt_fs;

        unsigned char key[16];
        int           dm_no;

        media_t *media;
};

struct devmapping *devmapper_init(char *, char *, unsigned int, char *, char *, char *, char *);
int devmapper_start(struct devmapping *);
int devmapper_stop(struct devmapping *);
int devmapper_genesis(struct devmapping *);
#endif
