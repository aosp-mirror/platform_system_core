/*
** Copyright 2013-2014, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define _GNU_SOURCE /* asprintf for x86 host */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/cdefs.h>
#include <sys/ioctl.h>

#include <cutils/list.h>
#include <log/log.h>
#include <log/logger.h>

#define __LOGGERIO     0xAE

#define LOGGER_GET_LOG_BUF_SIZE    _IO(__LOGGERIO, 1) /* size of log */
#define LOGGER_GET_LOG_LEN         _IO(__LOGGERIO, 2) /* used log len */
#define LOGGER_GET_NEXT_ENTRY_LEN  _IO(__LOGGERIO, 3) /* next entry len */
#define LOGGER_FLUSH_LOG           _IO(__LOGGERIO, 4) /* flush log */
#define LOGGER_GET_VERSION         _IO(__LOGGERIO, 5) /* abi version */
#define LOGGER_SET_VERSION         _IO(__LOGGERIO, 6) /* abi version */

typedef char bool;
#define false (const bool)0
#define true (const bool)1

#define LOG_FILE_DIR "/dev/log/"

/* timeout in milliseconds */
#define LOG_TIMEOUT_FLUSH 5
#define LOG_TIMEOUT_NEVER -1

#define logger_for_each(logger, logger_list) \
    for (logger = node_to_item((logger_list)->node.next, struct logger, node); \
         logger != node_to_item(&(logger_list)->node, struct logger, node); \
         logger = node_to_item((logger)->node.next, struct logger, node))

#ifndef __unused
#define __unused __attribute__((unused))
#endif

/* In the future, we would like to make this list extensible */
static const char *LOG_NAME[LOG_ID_MAX] = {
    [LOG_ID_MAIN] = "main",
    [LOG_ID_RADIO] = "radio",
    [LOG_ID_EVENTS] = "events",
    [LOG_ID_SYSTEM] = "system",
    [LOG_ID_CRASH] = "crash",
    [LOG_ID_KERNEL] = "kernel",
};

const char *android_log_id_to_name(log_id_t log_id)
{
    if (log_id >= LOG_ID_MAX) {
        log_id = LOG_ID_MAIN;
    }
    return LOG_NAME[log_id];
}

static int accessmode(int mode)
{
    if ((mode & ANDROID_LOG_ACCMODE) == ANDROID_LOG_WRONLY) {
        return W_OK;
    }
    if ((mode & ANDROID_LOG_ACCMODE) == ANDROID_LOG_RDWR) {
        return R_OK | W_OK;
    }
    return R_OK;
}

/* repeated fragment */
static int check_allocate_accessible(char **n, const char *b, int mode)
{
    *n = NULL;

    if (!b) {
        return -EINVAL;
    }

    asprintf(n, LOG_FILE_DIR "%s", b);
    if (!*n) {
        return -1;
    }

    return access(*n, accessmode(mode));
}

log_id_t android_name_to_log_id(const char *logName)
{
    const char *b;
    char *n;
    int ret;

    if (!logName) {
        return -1; /* NB: log_id_t is unsigned */
    }
    b = strrchr(logName, '/');
    if (!b) {
        b = logName;
    } else {
        ++b;
    }

    ret = check_allocate_accessible(&n, b, ANDROID_LOG_RDONLY);
    free(n);
    if (ret) {
        return ret;
    }

    for(ret = LOG_ID_MIN; ret < LOG_ID_MAX; ++ret) {
        const char *l = LOG_NAME[ret];
        if (l && !strcmp(b, l)) {
            return ret;
        }
    }
    return -1;   /* should never happen */
}

struct logger_list {
    struct listnode node;
    int mode;
    unsigned int tail;
    pid_t pid;
    unsigned int queued_lines;
    int timeout_ms;
    int error;
    bool flush;
    bool valid_entry; /* valiant(?) effort to deal with memory starvation */
    struct log_msg entry;
};

struct log_list {
    struct listnode node;
    struct log_msg entry; /* Truncated to event->len() + 1 to save space */
};

struct logger {
    struct listnode node;
    struct logger_list *top;
    int fd;
    log_id_t id;
    short *revents;
    struct listnode log_list;
};

/* android_logger_alloc unimplemented, no use case */
/* android_logger_free not exported */
static void android_logger_free(struct logger *logger)
{
    if (!logger) {
        return;
    }

    while (!list_empty(&logger->log_list)) {
        struct log_list *entry = node_to_item(
            list_head(&logger->log_list), struct log_list, node);
        list_remove(&entry->node);
        free(entry);
        if (logger->top->queued_lines) {
            logger->top->queued_lines--;
        }
    }

    if (logger->fd >= 0) {
        close(logger->fd);
    }

    list_remove(&logger->node);

    free(logger);
}

log_id_t android_logger_get_id(struct logger *logger)
{
    return logger->id;
}

/* worker for sending the command to the logger */
static int logger_ioctl(struct logger *logger, int cmd, int mode)
{
    char *n;
    int  f, ret;

    if (!logger || !logger->top) {
        return -EFAULT;
    }

    if (((mode & ANDROID_LOG_ACCMODE) == ANDROID_LOG_RDWR)
            || (((mode ^ logger->top->mode) & ANDROID_LOG_ACCMODE) == 0)) {
        return ioctl(logger->fd, cmd);
    }

    /* We go here if android_logger_list_open got mode wrong for this ioctl */
    ret = check_allocate_accessible(&n, android_log_id_to_name(logger->id), mode);
    if (ret) {
        free(n);
        return ret;
    }

    f = open(n, mode);
    free(n);
    if (f < 0) {
        return f;
    }

    ret = ioctl(f, cmd);
    close (f);

    return ret;
}

int android_logger_clear(struct logger *logger)
{
    return logger_ioctl(logger, LOGGER_FLUSH_LOG, ANDROID_LOG_WRONLY);
}

/* returns the total size of the log's ring buffer */
long android_logger_get_log_size(struct logger *logger)
{
    return logger_ioctl(logger, LOGGER_GET_LOG_BUF_SIZE, ANDROID_LOG_RDWR);
}

int android_logger_set_log_size(struct logger *logger __unused,
                                unsigned long size __unused)
{
    return -ENOTSUP;
}

/*
 * returns the readable size of the log's ring buffer (that is, amount of the
 * log consumed)
 */
long android_logger_get_log_readable_size(struct logger *logger)
{
    return logger_ioctl(logger, LOGGER_GET_LOG_LEN, ANDROID_LOG_RDONLY);
}

/*
 * returns the logger version
 */
int android_logger_get_log_version(struct logger *logger)
{
    int ret = logger_ioctl(logger, LOGGER_GET_VERSION, ANDROID_LOG_RDWR);
    return (ret < 0) ? 1 : ret;
}

/*
 * returns statistics
 */
static const char unsupported[] = "18\nNot Supported\n\f";

ssize_t android_logger_get_statistics(struct logger_list *logger_list __unused,
                                      char *buf, size_t len)
{
    strncpy(buf, unsupported, len);
    return -ENOTSUP;
}

ssize_t android_logger_get_prune_list(struct logger_list *logger_list __unused,
                                      char *buf, size_t len)
{
    strncpy(buf, unsupported, len);
    return -ENOTSUP;
}

int android_logger_set_prune_list(struct logger_list *logger_list __unused,
                                  char *buf, size_t len)
{
    static const char unsupported_error[] = "Unsupported";
    strncpy(buf, unsupported, len);
    return -ENOTSUP;
}

struct logger_list *android_logger_list_alloc(int mode,
                                              unsigned int tail,
                                              pid_t pid)
{
    struct logger_list *logger_list;

    logger_list = calloc(1, sizeof(*logger_list));
    if (!logger_list) {
        return NULL;
    }
    list_init(&logger_list->node);
    logger_list->mode = mode;
    logger_list->tail = tail;
    logger_list->pid = pid;
    return logger_list;
}

struct logger_list *android_logger_list_alloc_time(int mode,
                                                   log_time start __unused,
                                                   pid_t pid)
{
    return android_logger_list_alloc(mode, 0, pid);
}

/* android_logger_list_register unimplemented, no use case */
/* android_logger_list_unregister unimplemented, no use case */

/* Open the named log and add it to the logger list */
struct logger *android_logger_open(struct logger_list *logger_list,
                                   log_id_t id)
{
    struct listnode *node;
    struct logger *logger;
    char *n;

    if (!logger_list || (id >= LOG_ID_MAX)) {
        goto err;
    }

    logger_for_each(logger, logger_list) {
        if (logger->id == id) {
            goto ok;
        }
    }

    logger = calloc(1, sizeof(*logger));
    if (!logger) {
        goto err;
    }

    if (check_allocate_accessible(&n, android_log_id_to_name(id),
                                  logger_list->mode)) {
        goto err_name;
    }

    logger->fd = open(n, logger_list->mode & (ANDROID_LOG_ACCMODE | ANDROID_LOG_NONBLOCK));
    if (logger->fd < 0) {
        goto err_name;
    }

    free(n);
    logger->id = id;
    list_init(&logger->log_list);
    list_add_tail(&logger_list->node, &logger->node);
    logger->top = logger_list;
    logger_list->timeout_ms = LOG_TIMEOUT_FLUSH;
    goto ok;

err_name:
    free(n);
err_logger:
    free(logger);
err:
    logger = NULL;
ok:
    return logger;
}

/* Open the single named log and make it part of a new logger list */
struct logger_list *android_logger_list_open(log_id_t id,
                                             int mode,
                                             unsigned int tail,
                                             pid_t pid)
{
    struct logger_list *logger_list = android_logger_list_alloc(mode, tail, pid);
    if (!logger_list) {
        return NULL;
    }

    if (!android_logger_open(logger_list, id)) {
        android_logger_list_free(logger_list);
        return NULL;
    }

    return logger_list;
}

/* prevent memory starvation when backfilling */
static unsigned int queue_threshold(struct logger_list *logger_list)
{
    return (logger_list->tail < 64) ? 64 : logger_list->tail;
}

static bool low_queue(struct listnode *node)
{
    /* low is considered less than 2 */
    return list_head(node) == list_tail(node);
}

/* Flush queues in sequential order, one at a time */
static int android_logger_list_flush(struct logger_list *logger_list,
                                     struct log_msg *log_msg)
{
    int ret = 0;
    struct log_list *firstentry = NULL;

    while ((ret == 0)
            && (logger_list->flush
                || (logger_list->queued_lines > logger_list->tail))) {
        struct logger *logger;

        /* Merge sort */
        bool at_least_one_is_low = false;
        struct logger *firstlogger = NULL;
        firstentry = NULL;

        logger_for_each(logger, logger_list) {
            struct listnode *node;
            struct log_list *oldest = NULL;

            /* kernel logger channels not necessarily time-sort order */
            list_for_each(node, &logger->log_list) {
                struct log_list *entry = node_to_item(node,
                                                      struct log_list, node);
                if (!oldest
                        || (entry->entry.entry.sec < oldest->entry.entry.sec)
                        || ((entry->entry.entry.sec == oldest->entry.entry.sec)
                            && (entry->entry.entry.nsec < oldest->entry.entry.nsec))) {
                    oldest = entry;
                }
            }

            if (!oldest) {
                at_least_one_is_low = true;
                continue;
            } else if (low_queue(&logger->log_list)) {
                at_least_one_is_low = true;
            }

            if (!firstentry
                    || (oldest->entry.entry.sec < firstentry->entry.entry.sec)
                    || ((oldest->entry.entry.sec == firstentry->entry.entry.sec)
                        && (oldest->entry.entry.nsec < firstentry->entry.entry.nsec))) {
                firstentry = oldest;
                firstlogger = logger;
            }
        }

        if (!firstentry) {
            break;
        }

        /* when trimming list, tries to keep one entry behind in each bucket */
        if (!logger_list->flush
                && at_least_one_is_low
                && (logger_list->queued_lines < queue_threshold(logger_list))) {
            break;
        }

        /* within tail?, send! */
        if ((logger_list->tail == 0)
                || (logger_list->queued_lines <= logger_list->tail)) {
            int diff;
            ret = firstentry->entry.entry.hdr_size;
            if (!ret) {
                ret = sizeof(firstentry->entry.entry_v1);
            }

            /* Promote entry to v3 format */
            memcpy(log_msg->buf, firstentry->entry.buf, ret);
            diff = sizeof(firstentry->entry.entry_v3) - ret;
            if (diff < 0) {
                diff = 0;
            } else if (diff > 0) {
                memset(log_msg->buf + ret, 0, diff);
            }
            memcpy(log_msg->buf + ret + diff, firstentry->entry.buf + ret,
                   firstentry->entry.entry.len + 1);
            ret += diff;
            log_msg->entry.hdr_size = ret;
            log_msg->entry.lid = firstlogger->id;

            ret += firstentry->entry.entry.len;
        }

        /* next entry */
        list_remove(&firstentry->node);
        free(firstentry);
        if (logger_list->queued_lines) {
            logger_list->queued_lines--;
        }
    }

    /* Flushed the list, no longer in tail mode for continuing content */
    if (logger_list->flush && !firstentry) {
        logger_list->tail = 0;
    }
    return ret;
}

/* Read from the selected logs */
int android_logger_list_read(struct logger_list *logger_list,
                             struct log_msg *log_msg)
{
    struct logger *logger;
    nfds_t nfds;
    struct pollfd *p, *pollfds = NULL;
    int error = 0, ret = 0;

    memset(log_msg, 0, sizeof(struct log_msg));

    if (!logger_list) {
        return -ENODEV;
    }

    if (!(accessmode(logger_list->mode) & R_OK)) {
        logger_list->error = EPERM;
        goto done;
    }

    nfds = 0;
    logger_for_each(logger, logger_list) {
        ++nfds;
    }
    if (nfds <= 0) {
        error = ENODEV;
        goto done;
    }

    /* Do we have anything to offer from the buffer or state? */
    if (logger_list->valid_entry) { /* implies we are also in a flush state */
        goto flush;
    }

    ret = android_logger_list_flush(logger_list, log_msg);
    if (ret) {
        goto done;
    }

    if (logger_list->error) { /* implies we are also in a flush state */
        goto done;
    }

    /* Lets start grinding on metal */
    pollfds = calloc(nfds, sizeof(struct pollfd));
    if (!pollfds) {
        error = ENOMEM;
        goto flush;
    }

    p = pollfds;
    logger_for_each(logger, logger_list) {
        p->fd = logger->fd;
        p->events = POLLIN;
        logger->revents = &p->revents;
        ++p;
    }

    while (!ret && !error) {
        int result;

        /* If we oversleep it's ok, i.e. ignore EINTR. */
        result = TEMP_FAILURE_RETRY(
                    poll(pollfds, nfds, logger_list->timeout_ms));

        if (result <= 0) {
            if (result) {
                error = errno;
            } else if (logger_list->mode & ANDROID_LOG_NONBLOCK) {
                error = EAGAIN;
            } else {
                logger_list->timeout_ms = LOG_TIMEOUT_NEVER;
            }

            logger_list->flush = true;
            goto try_flush;
        }

        logger_list->timeout_ms = LOG_TIMEOUT_FLUSH;

        /* Anti starvation */
        if (!logger_list->flush
                && (logger_list->queued_lines > (queue_threshold(logger_list) / 2))) {
            /* Any queues with input pending that is low? */
            bool starving = false;
            logger_for_each(logger, logger_list) {
                if ((*(logger->revents) & POLLIN)
                        && low_queue(&logger->log_list)) {
                    starving = true;
                    break;
                }
            }

            /* pushback on any queues that are not low */
            if (starving) {
                logger_for_each(logger, logger_list) {
                    if ((*(logger->revents) & POLLIN)
                            && !low_queue(&logger->log_list)) {
                        *(logger->revents) &= ~POLLIN;
                    }
                }
            }
        }

        logger_for_each(logger, logger_list) {
            unsigned int hdr_size;
            struct log_list *entry;
            int diff;

            if (!(*(logger->revents) & POLLIN)) {
                continue;
            }

            memset(logger_list->entry.buf, 0, sizeof(struct log_msg));
            /* NOTE: driver guarantees we read exactly one full entry */
            result = read(logger->fd, logger_list->entry.buf,
                          LOGGER_ENTRY_MAX_LEN);
            if (result <= 0) {
                if (!result) {
                    error = EIO;
                } else if (errno != EINTR) {
                    error = errno;
                }
                continue;
            }

            if (logger_list->pid
                    && (logger_list->pid != logger_list->entry.entry.pid)) {
                continue;
            }

            hdr_size = logger_list->entry.entry.hdr_size;
            if (!hdr_size) {
                hdr_size = sizeof(logger_list->entry.entry_v1);
            }

            if ((hdr_size > sizeof(struct log_msg))
                    || (logger_list->entry.entry.len
                        > sizeof(logger_list->entry.buf) - hdr_size)
                    || (logger_list->entry.entry.len != result - hdr_size)) {
                error = EINVAL;
                continue;
            }

            /* Promote entry to v3 format */
            diff = sizeof(logger_list->entry.entry_v3) - hdr_size;
            if (diff > 0) {
                if (logger_list->entry.entry.len
                        > sizeof(logger_list->entry.buf) - hdr_size - diff) {
                    error = EINVAL;
                    continue;
                }
                result += diff;
                memmove(logger_list->entry.buf + hdr_size + diff,
                        logger_list->entry.buf + hdr_size,
                        logger_list->entry.entry.len + 1);
                memset(logger_list->entry.buf + hdr_size, 0, diff);
                logger_list->entry.entry.hdr_size = hdr_size + diff;
            }
            logger_list->entry.entry.lid = logger->id;

            /* speedup: If not tail, and only one list, send directly */
            if (!logger_list->tail
                    && (list_head(&logger_list->node)
                        == list_tail(&logger_list->node))) {
                ret = result;
                memcpy(log_msg->buf, logger_list->entry.buf, result + 1);
                break;
            }

            entry = malloc(sizeof(*entry) - sizeof(entry->entry) + result + 1);

            if (!entry) {
                logger_list->valid_entry = true;
                error = ENOMEM;
                break;
            }

            logger_list->queued_lines++;

            memcpy(entry->entry.buf, logger_list->entry.buf, result);
            entry->entry.buf[result] = '\0';
            list_add_tail(&logger->log_list, &entry->node);
        }

        if (ret <= 0) {
try_flush:
            ret = android_logger_list_flush(logger_list, log_msg);
        }
    }

    free(pollfds);

flush:
    if (error) {
        logger_list->flush = true;
    }

    if (ret <= 0) {
        ret = android_logger_list_flush(logger_list, log_msg);

        if (!ret && logger_list->valid_entry) {
            ret = logger_list->entry.entry.hdr_size;
            if (!ret) {
                ret = sizeof(logger_list->entry.entry_v1);
            }
            ret += logger_list->entry.entry.len;

            memcpy(log_msg->buf, logger_list->entry.buf,
                   sizeof(struct log_msg));
            logger_list->valid_entry = false;
        }
    }

done:
    if (logger_list->error) {
        error = logger_list->error;
    }
    if (error) {
        logger_list->error = error;
        if (!ret) {
            ret = -error;
        }
    }
    return ret;
}

/* Close all the logs */
void android_logger_list_free(struct logger_list *logger_list)
{
    if (logger_list == NULL) {
        return;
    }

    while (!list_empty(&logger_list->node)) {
        struct listnode *node = list_head(&logger_list->node);
        struct logger *logger = node_to_item(node, struct logger, node);
        android_logger_free(logger);
    }

    free(logger_list);
}
