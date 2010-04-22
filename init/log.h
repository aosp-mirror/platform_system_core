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

#ifndef _INIT_LOG_H_
#define _INIT_LOG_H_

void log_init(void);
void log_set_level(int level);
void log_close(void);
void log_write(int level, const char *fmt, ...)
    __attribute__ ((format(printf, 2, 3)));

#define ERROR(x...)   log_write(3, "<3>init: " x)
#define NOTICE(x...)  log_write(5, "<5>init: " x)
#define INFO(x...)    log_write(6, "<6>init: " x)

#define LOG_DEFAULT_LEVEL  3  /* messages <= this level are logged */
#define LOG_UEVENTS        0  /* log uevent messages if 1. verbose */

#endif
