
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

#ifndef _VOLMGR_H
#define _VOLMGR_H

#include <pthread.h>

#include "vold.h"
#include "blkdev.h"
#include "media.h"
#include "devmapper.h"

#define PROP_EXTERNAL_STORAGE_STATE "EXTERNAL_STORAGE_STATE"

// these must match the corresponding states in the MediaState enum.
// A path to the volume mount point follows the colon
typedef enum volume_state {
    volstate_unknown,

    volstate_nomedia,
#define VOLD_EVT_NOMEDIA       "volume_nomedia:"
#define VOLD_ES_PVAL_NOMEDIA   "removed"

    volstate_unmounted,
#define VOLD_EVT_UNMOUNTED     "volume_unmounted:"
#define VOLD_ES_PVAL_UNMOUNTED "unmounted"

    volstate_checking,
#define VOLD_EVT_CHECKING      "volume_checking:"
#define VOLD_ES_PVAL_CHECKING  "checking"

    volstate_mounted,
#define VOLD_EVT_MOUNTED       "volume_mounted:"
#define VOLD_ES_PVAL_MOUNTED   "mounted"

    volstate_mounted_ro,
#define VOLD_EVT_MOUNTED_RO     "volume_mounted_ro:"
#define VOLD_ES_PVAL_MOUNTED_RO "mounted_ro"

    volstate_badremoval,
#define VOLD_EVT_BADREMOVAL     "volume_badremoval:"
#define VOLD_ES_PVAL_BADREMOVAL "bad_removal"

    volstate_damaged,
#define VOLD_EVT_DAMAGED         "volume_damaged:"
#define VOLD_ES_PVAL_DAMAGED     "unmountable"

    volstate_nofs,
#define VOLD_EVT_NOFS            "volume_nofs:"
#define VOLD_ES_PVAL_NOFS        "nofs"

    volstate_ums,
#define VOLD_EVT_UMS             "volume_ums:"
#define VOLD_ES_PVAL_UMS         "shared"

    volstate_ejecting,
#define VOLD_EVT_EJECTING        "volume_ejecting:"
#define VOLD_ES_PVAL_EJECTING    "ejecting"

    volstate_formatting,
} volume_state_t;

struct volume;

struct volmgr_fstable_entry {
    char *name;
    int     (*identify_fn) (blkdev_t *dev);
    int     (*check_fn) (blkdev_t *dev);
    int     (*mount_fn) (blkdev_t *dev, struct volume *vol, boolean safe_mode);
    boolean case_sensitive_paths;
};

struct volmgr_start_args {
    struct volmgr_fstable_entry *fs;
    blkdev_t                    *dev;
};

struct volmgr_reaper_args {
    void (*cb) (struct volume *, void *);
    void *cb_arg;
};

#define VOLMGR_MAX_MEDIAPATHS_PER_VOLUME 8

typedef struct volume {
    char            *media_paths[VOLMGR_MAX_MEDIAPATHS_PER_VOLUME];

    media_type_t      media_type;
    char              *mount_point;
    char              *ums_path;
    struct devmapping *dm;

    pthread_mutex_t          lock;
    volume_state_t           state;
    blkdev_t                 *dev;
    pid_t                    worker_pid;
    pthread_t                worker_thread;
    union {
        struct volmgr_start_args  start_args;
        struct volmgr_reaper_args reaper_args;
    } worker_args;
    boolean                  worker_running;
    pthread_mutex_t          worker_sem;

    struct volmgr_fstable_entry *fs;

    struct volume            *next;
} volume_t;

int volmgr_consider_disk(blkdev_t *dev);
int volmgr_notify_eject(blkdev_t *dev, void (* cb) (blkdev_t *));
int volmgr_send_states(void);
int volmgr_enable_ums(boolean enable);
int volmgr_stop_volume_by_mountpoint(char *mount_point);
int volmgr_start_volume_by_mountpoint(char *mount_point);
int volmgr_safe_mode(boolean enable);
int volmgr_format_volume(char *mount_point);
int volmgr_set_volume_key(char *mount_point, unsigned char *key);
void KillProcessesWithOpenFiles(const char* mountPoint, boolean sigkill, int *excluded, int num_excluded);
#endif
