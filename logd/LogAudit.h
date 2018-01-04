/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef _LOGD_LOG_AUDIT_H__
#define _LOGD_LOG_AUDIT_H__

#include <map>

#include <sysutils/SocketListener.h>

#include "LogBuffer.h"

class LogReader;

class LogAudit : public SocketListener {
    LogBuffer* logbuf;
    LogReader* reader;
    int fdDmesg;  // fdDmesg >= 0 is functionally bool dmesg
    bool main;
    bool events;
    bool initialized;

   public:
    LogAudit(LogBuffer* buf, LogReader* reader, int fdDmesg);
    int log(char* buf, size_t len);
    bool isMonotonic() {
        return logbuf->isMonotonic();
    }

   protected:
    virtual bool onDataAvailable(SocketClient* cli);

   private:
    static int getLogSocket();
    std::map<std::string, std::string> populateDenialMap();
    std::string denialParse(const std::string& denial, char terminator,
                            const std::string& search_term);
    void logParse(const std::string& string, std::string* bug_num);
    int logPrint(const char* fmt, ...)
        __attribute__((__format__(__printf__, 2, 3)));
};

#endif
