/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _INIT_INIT_H
#define _INIT_INIT_H

#include <cutils/list.h>

#include <sys/stat.h>

void handle_control_message(const char *msg, const char *arg);

struct command
{
        /* list of commands in an action */
    struct listnode clist;

    int (*func)(int nargs, char **args);
    int nargs;
    char *args[1];
};
    
struct action {
        /* node in list of all actions */
    struct listnode alist;
        /* node in the queue of pending actions */
    struct listnode qlist;
        /* node in list of actions for a trigger */
    struct listnode tlist;

    unsigned hash;
    const char *name;
    
    struct listnode commands;
    struct command *current;
};

struct socketinfo {
    struct socketinfo *next;
    const char *name;
    const char *type;
    uid_t uid;
    gid_t gid;
    int perm;
};

struct svcenvinfo {
    struct svcenvinfo *next;
    const char *name;
    const char *value;
};

#define SVC_DISABLED    0x01  /* do not autostart with class */
#define SVC_ONESHOT     0x02  /* do not restart on exit */
#define SVC_RUNNING     0x04  /* currently active */
#define SVC_RESTARTING  0x08  /* waiting to restart */
#define SVC_CONSOLE     0x10  /* requires console */
#define SVC_CRITICAL    0x20  /* will reboot into recovery if keeps crashing */
#define SVC_RESET       0x40  /* Use when stopping a process, but not disabling
                                 so it can be restarted with its class */
#define SVC_RC_DISABLED 0x80  /* Remember if the disabled flag was set in the rc script */

#define NR_SVC_SUPP_GIDS 12    /* twelve supplementary groups */

#define COMMAND_RETRY_TIMEOUT 5

struct service {
        /* list of all services */
    struct listnode slist;

    const char *name;
    const char *classname;

    unsigned flags;
    pid_t pid;
    time_t time_started;    /* time of last start */
    time_t time_crashed;    /* first crash within inspection window */
    int nr_crashed;         /* number of times crashed within window */
    
    uid_t uid;
    gid_t gid;
    gid_t supp_gids[NR_SVC_SUPP_GIDS];
    size_t nr_supp_gids;

    struct socketinfo *sockets;
    struct svcenvinfo *envvars;

    struct action onrestart;  /* Actions to execute on restart. */
    
    /* keycodes for triggering this service via /dev/keychord */
    int *keycodes;
    int nkeycodes;
    int keychord_id;

    int ioprio_class;
    int ioprio_pri;

    int nargs;
    /* "MUST BE AT THE END OF THE STRUCT" */
    char *args[1];
}; /*     ^-------'args' MUST be at the end of this struct! */

void notify_service_state(const char *name, const char *state);

struct service *service_find_by_name(const char *name);
struct service *service_find_by_pid(pid_t pid);
struct service *service_find_by_keychord(int keychord_id);
void service_for_each(void (*func)(struct service *svc));
void service_for_each_class(const char *classname,
                            void (*func)(struct service *svc));
void service_for_each_flags(unsigned matchflags,
                            void (*func)(struct service *svc));
void service_stop(struct service *svc);
void service_reset(struct service *svc);
void service_start(struct service *svc, const char *dynamic_args);
void property_changed(const char *name, const char *value);

#define INIT_IMAGE_FILE	"/initlogo.rle"

int load_565rle_image( char *file_name );

#endif	/* _INIT_INIT_H */
