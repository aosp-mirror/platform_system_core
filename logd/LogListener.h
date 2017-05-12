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

// DEFAULT_OVERFLOWUID is defined in linux/highuid.h, which is not part of
// the uapi headers for userspace to use.  This value is filled in on the
// out-of-band socket credentials if the OS fails to find one available.
// One of the causes of this is if SO_PASSCRED is set, all the packets before
// that point will have this value.  We also use it in a fake credential if
// no socket credentials are supplied.
#ifndef DEFAULT_OVERFLOWUID
#define DEFAULT_OVERFLOWUID 65534
#endif

class LogListener : public SocketListener {
    LogBufferInterface* logbuf;
    LogReader* reader;

   public:
    LogListener(LogBufferInterface* buf, LogReader* reader /* nullable */);

   protected:
    virtual bool onDataAvailable(SocketClient* cli);

   private:
    static int getLogSocket();
};

#endif
