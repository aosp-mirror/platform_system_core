/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "storage.h"

#ifdef __cplusplus
extern "C" {
#endif

struct watcher;

/**
 * watch_start() - Create a watcher for a storage request
 * @id:        Identifier string to distinguish watchers
 * @request:   Incoming request from Trusty storage service
 *
 * Create a watcher that will start logging if not finished before a timeout.
 * Only one watcher may be active at a time, and this function may only be
 * called from a single thread.
 */
struct watcher* watch_start(const char* id, const struct storage_msg* request);

/**
 * watch_progress() - Note progress on servicing the current request
 * @watcher:   Current watcher, created by watch()
 *
 * Sets the current progress state of the watcher, to allow for more granular
 * reporting of what exactly is stuck if the timeout is reached.
 */
void watch_progress(struct watcher* watcher, const char* state);

/**
 * watch_finish() - Finish watching and unregister the watch
 * @watcher:   Current watcher, created by watch(). Takes ownership of this pointer.
 *
 * Finish the current watch task. This function takes ownership of the watcher
 * and destroys it, so @watcher must not be used again after calling this
 * function.
 */
void watch_finish(struct watcher* watcher);

#ifdef __cplusplus
}
#endif
