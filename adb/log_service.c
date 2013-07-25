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


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <log/logger.h>
#include "sysdeps.h"
#include "adb.h"

#define LOG_FILE_DIR    "/dev/log/"

void write_log_entry(int fd, struct logger_entry *buf);

void log_service(int fd, void *cookie)
{
    /* get the name of the log filepath to read */
    char * log_filepath = cookie;

    /* open the log file. */
    int logfd = unix_open(log_filepath, O_RDONLY);
    if (logfd < 0) {
        goto done;
    }

    // temp buffer to read the entries
    unsigned char buf[LOGGER_ENTRY_MAX_LEN + 1] __attribute__((aligned(4)));
    struct logger_entry *entry = (struct logger_entry *) buf;

    while (1) {
        int ret;

        ret = unix_read(logfd, entry, LOGGER_ENTRY_MAX_LEN);
        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            // perror("logcat read");
            goto done;
        }
        else if (!ret) {
            // fprintf(stderr, "read: Unexpected EOF!\n");
            goto done;
        }

        /* NOTE: driver guarantees we read exactly one full entry */

        entry->msg[entry->len] = '\0';

        write_log_entry(fd, entry);
    }

done:
    unix_close(fd);
    free(log_filepath);
}

/* returns the full path to the log file in a newly allocated string */
char * get_log_file_path(const char * log_name) {
    char *log_device = malloc(strlen(LOG_FILE_DIR) + strlen(log_name) + 1);

    strcpy(log_device, LOG_FILE_DIR);
    strcat(log_device, log_name);

    return log_device;
}


/* prints one log entry into the file descriptor fd */
void write_log_entry(int fd, struct logger_entry *buf)
{
    size_t size = sizeof(struct logger_entry) + buf->len;

    writex(fd, buf, size);
}
