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

int mtd_name_to_number(const char *name);

void handle_control_message(const char *msg, const char *arg);

int create_socket(const char *name, int type, mode_t perm,
                  uid_t uid, gid_t gid);

void *read_file(const char *fn, unsigned *_sz);

void log_init(void);
void log_set_level(int level);
void log_close(void);
void log_write(int level, const char *fmt, ...)
    __attribute__ ((format(printf, 2, 3)));

#define ERROR(x...)   log_write(3, "<3>init: " x)
#define NOTICE(x...)  log_write(5, "<5>init: " x)
#define INFO(x...)    log_write(6, "<6>init: " x)

#define LOG_DEFAULT_LEVEL  3  /* messages <= this level are logged */
#define LOG_UEVENTS        0  /* log uevent messages if 1. verbose */

unsigned int decode_uid(const char *s);

struct listnode
{
    struct listnode *next;
    struct listnode *prev;
};

#define node_to_item(node, container, member) \
    (container *) (((char*) (node)) - offsetof(container, member))

#define list_declare(name) \
    struct listnode name = { \
        .next = &name, \
        .prev = &name, \
    }

#define list_for_each(node, list) \
    for (node = (list)->next; node != (list); node = node->next)

void list_init(struct listnode *list);
void list_add_tail(struct listnode *list, struct listnode *item);
void list_remove(struct listnode *item);

#define list_empty(list) ((list) == (list)->next)
#define list_head(list) ((list)->next)
#define list_tail(list) ((list)->prev)

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

#define NR_SVC_SUPP_GIDS 6    /* six supplementary groups */

#define SVC_MAXARGS 64

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

    int nargs;
    /* "MUST BE AT THE END OF THE STRUCT" */
    char *args[1];
}; /*     ^-------'args' MUST be at the end of this struct! */

int parse_config_file(const char *fn);

struct service *service_find_by_name(const char *name);
struct service *service_find_by_pid(pid_t pid);
struct service *service_find_by_keychord(int keychord_id);
void service_for_each(void (*func)(struct service *svc));
void service_for_each_class(const char *classname,
                            void (*func)(struct service *svc));
void service_for_each_flags(unsigned matchflags,
                            void (*func)(struct service *svc));
void service_stop(struct service *svc);
void service_start(struct service *svc, const char *dynamic_args);
void property_changed(const char *name, const char *value);

struct action *action_remove_queue_head(void);
void action_add_queue_tail(struct action *act);
void action_for_each_trigger(const char *trigger,
                             void (*func)(struct action *act));
void queue_property_triggers(const char *name, const char *value);
void queue_all_property_triggers();

#define INIT_IMAGE_FILE	"/initlogo.rle"

int load_565rle_image( char *file_name );

#endif	/* _INIT_INIT_H */
