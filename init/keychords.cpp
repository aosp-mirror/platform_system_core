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

#include "keychords.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/keychord.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/properties.h>

#include "init.h"

namespace android {
namespace init {

static struct input_keychord *keychords = 0;
static int keychords_count = 0;
static int keychords_length = 0;
static int keychord_fd = -1;

void add_service_keycodes(Service* svc)
{
    struct input_keychord *keychord;
    size_t i, size;

    if (!svc->keycodes().empty()) {
        /* add a new keychord to the list */
        size = sizeof(*keychord) + svc->keycodes().size() * sizeof(keychord->keycodes[0]);
        keychords = (input_keychord*) realloc(keychords, keychords_length + size);
        if (!keychords) {
            PLOG(ERROR) << "could not allocate keychords";
            keychords_length = 0;
            keychords_count = 0;
            return;
        }

        keychord = (struct input_keychord *)((char *)keychords + keychords_length);
        keychord->version = KEYCHORD_VERSION;
        keychord->id = keychords_count + 1;
        keychord->count = svc->keycodes().size();
        svc->set_keychord_id(keychord->id);

        for (i = 0; i < svc->keycodes().size(); i++) {
            keychord->keycodes[i] = svc->keycodes()[i];
        }
        keychords_count++;
        keychords_length += size;
    }
}

static void handle_keychord() {
    int ret;
    __u16 id;

    ret = read(keychord_fd, &id, sizeof(id));
    if (ret != sizeof(id)) {
        PLOG(ERROR) << "could not read keychord id";
        return;
    }

    // Only handle keychords if adb is enabled.
    std::string adb_enabled = android::base::GetProperty("init.svc.adbd", "");
    if (adb_enabled == "running") {
        Service* svc = ServiceList::GetInstance().FindService(id, &Service::keychord_id);
        if (svc) {
            LOG(INFO) << "Starting service '" << svc->name() << "' from keychord " << id;
            if (auto result = svc->Start(); !result) {
                LOG(ERROR) << "Could not start service '" << svc->name() << "' from keychord " << id
                           << ": " << result.error();
            }
        } else {
            LOG(ERROR) << "Service for keychord " << id << " not found";
        }
    } else {
        LOG(WARNING) << "Not starting service for keychord " << id << " because ADB is disabled";
    }
}

void keychord_init() {
    for (const auto& service : ServiceList::GetInstance()) {
        add_service_keycodes(service.get());
    }

    // Nothing to do if no services require keychords.
    if (!keychords) {
        return;
    }

    keychord_fd = TEMP_FAILURE_RETRY(open("/dev/keychord", O_RDWR | O_CLOEXEC));
    if (keychord_fd == -1) {
        PLOG(ERROR) << "could not open /dev/keychord";
        return;
    }

    int ret = write(keychord_fd, keychords, keychords_length);
    if (ret != keychords_length) {
        PLOG(ERROR) << "could not configure /dev/keychord " << ret;
        close(keychord_fd);
    }

    free(keychords);
    keychords = nullptr;

    register_epoll_handler(keychord_fd, handle_keychord);
}

}  // namespace init
}  // namespace android
