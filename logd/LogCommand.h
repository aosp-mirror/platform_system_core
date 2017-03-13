/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#ifndef _LOGD_COMMAND_H
#define _LOGD_COMMAND_H

#include <sysutils/FrameworkCommand.h>
#include <sysutils/SocketClient.h>

class LogCommand : public FrameworkCommand {
   public:
    explicit LogCommand(const char* cmd);
    virtual ~LogCommand() {
    }
};

#endif
