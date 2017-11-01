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

#ifndef BUGREPORT_H
#define BUGREPORT_H

#include <vector>

#include "adb.h"
#include "commandline.h"
#include "line_printer.h"

class Bugreport {
    friend class BugreportStandardStreamsCallback;

  public:
    Bugreport() : line_printer_() {
    }
    int DoIt(int argc, const char** argv);

  protected:
    // Functions below are abstractions of external functions so they can be
    // mocked on tests.
    virtual int SendShellCommand(
        const std::string& command, bool disable_shell_protocol,
        StandardStreamsCallbackInterface* callback = &DEFAULT_STANDARD_STREAMS_CALLBACK);

    virtual bool DoSyncPull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                            const char* name);

  private:
    virtual void UpdateProgress(const std::string& file_name, int progress_percentage);
    LinePrinter line_printer_;
    DISALLOW_COPY_AND_ASSIGN(Bugreport);
};

#endif  // BUGREPORT_H
