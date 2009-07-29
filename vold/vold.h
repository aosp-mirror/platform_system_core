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

#ifndef VOLD_H__
#define VOLD_H__

#define LOG_TAG "vold"
#include "cutils/log.h"

typedef int boolean;
enum {
    false = 0,
    true = 1
};

#define DEVPATH "/dev/block/"
#define DEVPATHLENGTH 11

#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)

// Set this for logging error messages
#define ENABLE_LOG_ERROR

// set this to log vold events
#define ENABLE_LOG_VOL

#ifdef ENABLE_LOG_ERROR
#define LOG_ERROR(fmt, args...) \
    { LOGE(fmt , ## args); }
#else
#define LOG_ERROR(fmt, args...) \
    do { } while (0)
#endif /* ENABLE_LOG_ERROR */

#ifdef ENABLE_LOG_VOL
#define LOG_VOL(fmt, args...) \
    { LOGD(fmt , ## args); }
#else
#define LOG_VOL(fmt, args...) \
    do { } while (0)
#endif /* ENABLE_LOG_VOL */

#ifdef ENABLE_LOG_SERVER
#define LOG_SERVER(fmt, args...) \
    { LOGD(fmt , ## args); }
#else
#define LOG_SERVER(fmt, args...) \
    do { } while (0)
#endif /* ENABLE_LOG_SERVER */

#ifdef ENABLE_LOG_ASEC
#define LOG_ASEC(fmt, args...) \
    { LOGD(fmt , ## args); }
#else
#define LOG_ASEC(fmt, args...) \
    do { } while (0)
#endif /* ENABLE_LOG_ASEC */

/*
 * Prototypes
 */

int process_framework_command(int socket);

int process_inotify_event(int fd);
int inotify_bootstrap(void);

int process_uevent_message(int socket);
int simulate_uevent(char *subsystem, char *path, char *action, char **params);

int mmc_bootstrap(void);
int ums_bootstrap(void);

int volmgr_bootstrap(void);

int switch_bootstrap(void);

void *read_file(char *filename, ssize_t *_size);
char *truncate_sysfs_path(char *path, int num_elements_to_remove, char *buffer, int buffer_size);
char *read_sysfs_var(char *buffer, size_t maxlen, char *devpath, char *var);

void ums_hostconnected_set(boolean connected);
boolean ums_hostconnected_get(void);

int send_msg(char *msg);
int send_msg_with_data(char *msg, char *data);
extern int bootstrap;
#endif
