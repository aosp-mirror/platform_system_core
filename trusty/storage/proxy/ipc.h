/*
 * Copyright (C) 2016 The Android Open Source Project
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
#pragma once

#include <stdint.h>
#include <trusty/interface/storage.h>

int ipc_connect(const char *device, const char *service_name);
void ipc_disconnect(void);
ssize_t ipc_get_msg(struct storage_msg *msg, void *req_buf, size_t req_buf_len);
int ipc_respond(struct storage_msg *msg, void *out, size_t out_size);
