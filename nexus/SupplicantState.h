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

#ifndef _SUPPLICANT_STATE_H
#define _SUPPLICANT_STATE_H

class SupplicantState {
public:
    static const int UNKNOWN           = -1;
    static const int DISCONNECTED      = 0;
    static const int INACTIVE          = 1;
    static const int SCANNING          = 2;
    static const int ASSOCIATING       = 3;
    static const int ASSOCIATED        = 4;
    static const int FOURWAY_HANDSHAKE = 5;
    static const int GROUP_HANDSHAKE   = 6;
    static const int COMPLETED         = 7;
    static const int IDLE              = 8;

    static char *toString(int val, char *buffer, int max);
};

#endif
