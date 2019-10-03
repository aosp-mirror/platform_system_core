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

#define TRACE_TAG ADB

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "client/file_sync_client.h"
#include "commandline.h"
#include "sysdeps.h"

#include "fastdeploycallbacks.h"

static void appendBuffer(std::vector<char>* buffer, const char* input, int length) {
    if (buffer != NULL) {
        buffer->insert(buffer->end(), input, input + length);
    }
}

class DeployAgentBufferCallback : public StandardStreamsCallbackInterface {
  public:
    DeployAgentBufferCallback(std::vector<char>* outBuffer, std::vector<char>* errBuffer);

    virtual void OnStdout(const char* buffer, int length);
    virtual void OnStderr(const char* buffer, int length);
    virtual int Done(int status);

  private:
    std::vector<char>* mpOutBuffer;
    std::vector<char>* mpErrBuffer;
};

int capture_shell_command(const char* command, std::vector<char>* outBuffer,
                          std::vector<char>* errBuffer) {
    DeployAgentBufferCallback cb(outBuffer, errBuffer);
    return send_shell_command(command, /*disable_shell_protocol=*/false, &cb);
}

DeployAgentBufferCallback::DeployAgentBufferCallback(std::vector<char>* outBuffer,
                                                     std::vector<char>* errBuffer) {
    mpOutBuffer = outBuffer;
    mpErrBuffer = errBuffer;
}

void DeployAgentBufferCallback::OnStdout(const char* buffer, int length) {
    appendBuffer(mpOutBuffer, buffer, length);
}

void DeployAgentBufferCallback::OnStderr(const char* buffer, int length) {
    appendBuffer(mpErrBuffer, buffer, length);
}

int DeployAgentBufferCallback::Done(int status) {
    return status;
}
