/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _DHCP_EVENT_H
#define _DHCP_EVENT_H

class DhcpEvent {
public:
    static const int UNKNOWN = 0;
    static const int STOP    = 1;
    static const int RENEW   = 2;
    static const int RELEASE = 3;
    static const int TIMEOUT = 4;

    static char *toString(int val, char *buffer, int max);

    static int parseString(const char *buffer);
};

#endif
