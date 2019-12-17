/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef __RPMB_H__
#define __RPMB_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct rpmb_key {
    uint8_t byte[32];
};

struct rpmb_state;

#define RPMB_BUF_SIZE 256

/* provides */
int rpmb_init(struct rpmb_state** statep,
              void* mmc_handle,
              const struct rpmb_key* key);
void rpmb_uninit(struct rpmb_state* statep);
int rpmb_read(struct rpmb_state* state,
              void* buf,
              uint16_t addr,
              uint16_t count);
/* count must be 1 or 2, addr must be aligned */
int rpmb_write(struct rpmb_state* state,
               const void* buf,
               uint16_t addr,
               uint16_t count,
               bool sync);

/* needs */
int rpmb_send(void* mmc_handle,
              void* reliable_write_buf,
              size_t reliable_write_size,
              void* write_buf,
              size_t write_buf_size,
              void* read_buf,
              size_t read_buf_size,
              bool sync);

#endif
