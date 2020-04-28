/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <vector>
#include "commandline.h"

class DeployAgentFileCallback : public StandardStreamsCallbackInterface {
  public:
    DeployAgentFileCallback(FILE* outputFile, std::vector<char>* errBuffer);

    virtual void OnStdout(const char* buffer, int length);
    virtual void OnStderr(const char* buffer, int length);
    virtual int Done(int status);

    int getBytesWritten();

  private:
    FILE* mpOutFile;
    std::vector<char>* mpErrBuffer;
    int mBytesWritten;
};

int capture_shell_command(const char* command, std::vector<char>* outBuffer,
                          std::vector<char>* errBuffer);
