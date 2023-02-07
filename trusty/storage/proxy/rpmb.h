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

#include "watchdog.h"

enum dev_type { UNKNOWN_RPMB, MMC_RPMB, VIRT_RPMB, UFS_RPMB, SOCK_RPMB };

int rpmb_open(const char* rpmb_devname, enum dev_type dev_type);
int rpmb_send(struct storage_msg* msg, const void* r, size_t req_len, struct watcher* watcher);
void rpmb_close(void);
