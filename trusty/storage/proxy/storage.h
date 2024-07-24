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

/* Defined in watchdog.h */
struct watcher;

/* Is used for managing alternate backing storage, generally will be a block device. */
struct storage_mapping_node {
    struct storage_mapping_node* next;
    const char* file_name;
    const char* backing_storage;
    int fd;
};

int storage_file_delete(struct storage_msg* msg, const void* req, size_t req_len,
                        struct watcher* watcher);

int storage_file_open(struct storage_msg* msg, const void* req, size_t req_len,
                      struct watcher* watcher);

int storage_file_close(struct storage_msg* msg, const void* req, size_t req_len,
                       struct watcher* watcher);

int storage_file_write(struct storage_msg* msg, const void* req, size_t req_len,
                       struct watcher* watcher);

int storage_file_read(struct storage_msg* msg, const void* req, size_t req_len,
                      struct watcher* watcher);

int storage_file_get_size(struct storage_msg* msg, const void* req, size_t req_len,
                          struct watcher* watcher);

int storage_file_set_size(struct storage_msg* msg, const void* req, size_t req_len,
                          struct watcher* watcher);

int storage_file_get_max_size(struct storage_msg* msg, const void* req, size_t req_len,
                              struct watcher* watcher);

int storage_init(const char* dirname, struct storage_mapping_node* head,
                 const char* max_file_size_from);

int storage_sync_checkpoint(struct watcher* watcher);
