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

#ifndef _DAEMON_MDNS_H_
#define _DAEMON_MDNS_H_

void setup_mdns(int port);

void register_adb_secure_connect_service(int port);
void unregister_adb_secure_connect_service();
bool is_adb_secure_connect_service_registered();

void start_mdnsd();
#endif  // _DAEMON_MDNS_H_
