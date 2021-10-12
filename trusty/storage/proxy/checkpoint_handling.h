/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * is_data_checkpoint_active() - Check for an active, uncommitted checkpoint of
 * /data. If a checkpoint is active, storage should not commit any
 * rollback-protected writes to /data.
 * @active: Out parameter that will be set to the result of the check.
 *
 * Return: 0 if active was set and is valid, non-zero otherwise.
 */
int is_data_checkpoint_active(bool* active);

#ifdef __cplusplus
}
#endif
