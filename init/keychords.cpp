/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/keychord.h>
#include <unistd.h>

#include "init.h"
#include "log.h"
#include "property_service.h"

static struct input_keychord *keychords = 0;
static int keychords_count = 0;
static int keychords_length = 0;
static int keychord_fd = -1;

void add_service_keycodes(struct service *svc)
{
    struct input_keychord *keychord;
    int i, size;

    if (svc->keycodes) {
        /* add a new keychord to the list */
        size = sizeof(*keychord) + svc->nkeycodes * sizeof(keychord->keycodes[0]);
        keychords = (input_keychord*) realloc(keychords, keychords_length + size);
        if (!keychords) {
            ERROR("could not allocate keychords\n");
            keychords_length = 0;
            keychords_count = 0;
            return;
        }

        keychord = (struct input_keychord *)((char *)keychords + keychords_length);
        keychord->version = KEYCHORD_VERSION;
        keychord->id = keychords_count + 1;
        keychord->count = svc->nkeycodes;
        svc->keychord_id = keychord->id;

        for (i = 0; i < svc->nkeycodes; i++) {
            keychord->keycodes[i] = svc->keycodes[i];
        }
        keychords_count++;
        keychords_length += size;
    }
}

static void handle_keychord() {
    struct service *svc;
    char adb_enabled[PROP_VALUE_MAX];
    int ret;
    __u16 id;

    // Only handle keychords if adb is enabled.
    property_get("init.svc.adbd", adb_enabled);
    ret = read(keychord_fd, &id, sizeof(id));
    if (ret != sizeof(id)) {
        ERROR("could not read keychord id\n");
        return;
    }

    if (!strcmp(adb_enabled, "running")) {
        svc = service_find_by_keychord(id);
        if (svc) {
            INFO("Starting service %s from keychord\n", svc->name);
            service_start(svc, NULL);
        } else {
            ERROR("service for keychord %d not found\n", id);
        }
    }
}

void keychord_init() {
    service_for_each(add_service_keycodes);

    // Nothing to do if no services require keychords.
    if (!keychords) {
        return;
    }

    keychord_fd = TEMP_FAILURE_RETRY(open("/dev/keychord", O_RDWR | O_CLOEXEC));
    if (keychord_fd == -1) {
        ERROR("could not open /dev/keychord: %s\n", strerror(errno));
        return;
    }

    int ret = write(keychord_fd, keychords, keychords_length);
    if (ret != keychords_length) {
        ERROR("could not configure /dev/keychord %d: %s\n", ret, strerror(errno));
        close(keychord_fd);
    }

    free(keychords);
    keychords = nullptr;

    register_epoll_handler(keychord_fd, handle_keychord);
}
