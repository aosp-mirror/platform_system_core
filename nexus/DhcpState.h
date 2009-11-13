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

#ifndef _DHCP_STATE_H
#define _DHCP_STATE_H

class DhcpState {
public:
    static const int INIT            = 0;
    static const int DISCOVERING     = 1;
    static const int REQUESTING      = 2;
    static const int BOUND           = 3;
    static const int RENEWING        = 4;
    static const int REBINDING       = 5;
    static const int REBOOT          = 6;
    static const int RENEW_REQUESTED = 7;
    static const int INIT_IPV4LL     = 8;
    static const int PROBING         = 9;
    static const int ANNOUNCING      = 10;

    static char *toString(int val, char *buffer, int max);

    static int parseString(const char *buffer);
};

#endif
