/*
 * Copyright (C) 2012-2013 The Android Open Source Project
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

#ifndef _LOGD_LOG_LISTENER_H__
#define _LOGD_LOG_LISTENER_H__

#include <sysutils/SocketListener.h>
#include "LogReader.h"

class LogListener : public SocketListener {
    LogBuffer* logbuf;
    LogReader* reader;

   public:
     LogListener(LogBuffer* buf, LogReader* reader);

   protected:
    virtual bool onDataAvailable(SocketClient* cli);

   private:
    static int getLogSocket();
};

#endif
