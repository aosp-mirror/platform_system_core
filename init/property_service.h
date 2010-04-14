/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _INIT_PROPERTY_H
#define _INIT_PROPERTY_H

extern void handle_property_set_fd(void);
extern void property_init(void);
extern void start_property_service(void);
void get_property_workspace(int *fd, int *sz);
extern const char* property_get(const char *name);
extern int property_set(const char *name, const char *value);
int get_property_set_fd(void);

#endif	/* _INIT_PROPERTY_H */
