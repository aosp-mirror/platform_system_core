/*
 * Copyright (c) 2013, Google Inc.
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

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "protocol.h"

#include "debug.h"

// TODO: change config path
#define CONFIG_PATH "/data/fastboot.cfg"

static char *strip(char *str)
{
    int n;

    n = strspn(str, " \t");
    str += n;

    for (n = strlen(str) - 1; n >= 0; n--) {
        if (str[n] == ' ' || str[n] == '\t')
            str[n] = '\0';
        else
            break;
    }

    return str;
}

static int config_parse_line(char *line)
{
    char *c;
    char *key;
    char *value;

    c = strchr(line, '#');
    if (c)
        *c = '\0';

    if (strspn(line, " \t") == strlen(line))
        return 0;

    c = strchr(line, '=');
    if (c == NULL)
        return -1;

    key = line;
    *c = '\0';
    value = c + 1;

    key = strip(key);
    value = strip(value);

    key = strdup(key);
    value = strdup(value);

    fastboot_publish(key, value);

    return 0;
}

static void config_parse(char *buffer)
{
    char *saveptr;
    char *str = buffer;
    char *line = buffer;
    int c;
    int ret;

    for (c = 1; line != NULL; c++) {
        line = strtok_r(str, "\r\n", &saveptr);
        if (line != NULL) {
            D(VERBOSE, "'%s'", line);
            ret = config_parse_line(line);
            if (ret < 0) {
                D(WARN, "error parsing " CONFIG_PATH " line %d", c);
            }
        }
        str = NULL;
    }
}

void config_init()
{
    int fd;
    off_t len;
    ssize_t ret;
    size_t count = 0;
    char *buffer;

    fd = open(CONFIG_PATH, O_RDONLY);
    if (fd < 0) {
        D(ERR, "failed to open " CONFIG_PATH);
        return;
    }

    len = lseek(fd, 0, SEEK_END);
    if (len < 0) {
        D(ERR, "failed to seek to end of " CONFIG_PATH);
        return;
    }

    lseek(fd, 0, SEEK_SET);

    buffer = malloc(len + 1);
    if (buffer == NULL) {
        D(ERR, "failed to allocate %ld bytes", len);
        return;
    }

    while (count < (size_t)len) {
        ret = read(fd, buffer + count, len - count);
        if (ret < 0 && errno != EINTR) {
            D(ERR, "failed to read " CONFIG_PATH ": %d %s", errno, strerror(errno));
            return;
        }
        if (ret == 0) {
            D(ERR, "early EOF reading " CONFIG_PATH);
            return;
        }

        count += ret;
    }

    buffer[len] = '\0';

    config_parse(buffer);

    free(buffer);
}
