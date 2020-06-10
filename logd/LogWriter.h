/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <string>

#include <log/log_read.h>

// An interface for writing logs to a reader.
class LogWriter {
  public:
    LogWriter(uid_t uid, bool privileged) : uid_(uid), privileged_(privileged) {}
    virtual ~LogWriter() {}

    virtual bool Write(const logger_entry& entry, const char* msg) = 0;
    virtual void Shutdown() {}
    virtual void Release() {}

    virtual std::string name() const = 0;
    uid_t uid() const { return uid_; }

    bool privileged() const { return privileged_; }

  private:
    uid_t uid_;

    // If this writer sees logs from all UIDs or only its own UID.  See clientHasLogCredentials().
    bool privileged_;
};