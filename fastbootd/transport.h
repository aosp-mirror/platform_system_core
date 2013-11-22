/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef _FASTBOOTD_TRANSPORT_H_
#define _FASTBOOTD_TRANSPORT_H_

#include <stdbool.h>

struct transport_handle {
    struct transport *transport;

    bool stopped;
};

struct transport {
    void (*init)();
    void (*close)(struct transport_handle *thandle);
    ssize_t (*read)(struct transport_handle *thandle, void *data, size_t len);
    ssize_t (*write)(struct transport_handle *thandle, const void *data, size_t len);
    struct transport_handle *(*connect)(struct transport *transport);
    bool stopped;
};

void transport_register(struct transport *transport);
ssize_t transport_handle_write(struct transport_handle *handle, char *buffer, size_t len);
int transport_handle_download(struct transport_handle *handle, size_t len);

#endif
