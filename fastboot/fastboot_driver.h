/*
 * Copyright (C) 2018 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#pragma once
#include <cstdlib>
#include <deque>
#include <limits>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <bootimg.h>
#include <inttypes.h>
#include <sparse/sparse.h>
#include "transport.h"

class Transport;

namespace fastboot {

static constexpr int FB_COMMAND_SZ = 64;
static constexpr int FB_RESPONSE_SZ = 64;

enum RetCode : int {
    SUCCESS = 0,
    BAD_ARG,
    IO_ERROR,
    BAD_DEV_RESP,
    DEVICE_FAIL,
    TIMEOUT,
};

class FastBootDriver {
  public:
    static constexpr int RESP_TIMEOUT = 10;  // 10 seconds
    static constexpr uint32_t MAX_DOWNLOAD_SIZE = std::numeric_limits<uint32_t>::max();
    static constexpr size_t TRANSPORT_CHUNK_SIZE = 1024;

    FastBootDriver(Transport* transport,
                   std::function<void(std::string&)> info = [](std::string&) {},
                   bool no_checks = false);

    RetCode Boot(std::string* response = nullptr, std::vector<std::string>* info = nullptr);
    RetCode Continue(std::string* response = nullptr, std::vector<std::string>* info = nullptr);
    RetCode Download(int fd, size_t size, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr);
    RetCode Download(const std::vector<char>& buf, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr);
    // This will be removed after fastboot is modified to use a vector
    RetCode Download(const char* buf, uint32_t size, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr);
    RetCode Download(sparse_file* s, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr);
    RetCode Erase(const std::string& part, std::string* response = nullptr,
                  std::vector<std::string>* info = nullptr);
    RetCode Flash(const std::string& part, std::string* response = nullptr,
                  std::vector<std::string>* info = nullptr);
    RetCode GetVar(const std::string& key, std::string* val,
                   std::vector<std::string>* info = nullptr);
    RetCode GetVarAll(std::vector<std::string>* response);
    RetCode Powerdown(std::string* response = nullptr, std::vector<std::string>* info = nullptr);
    RetCode Reboot(std::string* response = nullptr, std::vector<std::string>* info = nullptr);
    RetCode SetActive(const std::string& part, std::string* response = nullptr,
                      std::vector<std::string>* info = nullptr);
    RetCode Upload(const std::string& outfile, std::string* response = nullptr,
                   std::vector<std::string>* info = nullptr);
    RetCode Verify(uint32_t num, std::string* response = nullptr,
                   std::vector<std::string>* info = nullptr);

    /* HIGHER LEVEL COMMANDS -- Composed of the commands above */
    RetCode FlashPartition(const std::string& part, const std::vector<char>& data);
    RetCode FlashPartition(const std::string& part, int fd, uint32_t sz);
    RetCode FlashPartition(const std::string& part, sparse_file* s);

    RetCode Partitions(std::vector<std::tuple<std::string, uint32_t>>* parts);
    RetCode Require(const std::string& var, const std::vector<std::string>& allowed, bool* reqmet,
                    bool invert = false);

    /* HELPERS */
    void SetInfoCallback(std::function<void(std::string&)> info);
    static const std::string RCString(RetCode rc);
    std::string Error();
    RetCode WaitForDisconnect();

    // This is temporarily public for engine.cpp
    RetCode RawCommand(const std::string& cmd, std::string* response = nullptr,
                       std::vector<std::string>* info = nullptr, int* dsize = nullptr);

  protected:
    RetCode DownloadCommand(uint32_t size, std::string* response = nullptr,
                            std::vector<std::string>* info = nullptr);
    RetCode HandleResponse(std::string* response = nullptr,
                           std::vector<std::string>* info = nullptr, int* dsize = nullptr);

    std::string ErrnoStr(const std::string& msg);

    // More like a namespace...
    struct Commands {
        static const std::string BOOT;
        static const std::string CONTINUE;
        static const std::string DOWNLOAD;
        static const std::string ERASE;
        static const std::string FLASH;
        static const std::string GET_VAR;
        static const std::string POWERDOWN;
        static const std::string REBOOT;
        static const std::string SET_ACTIVE;
        static const std::string UPLOAD;
        static const std::string VERIFY;
    };

    Transport* const transport;

  private:
    RetCode SendBuffer(int fd, size_t size);
    RetCode SendBuffer(const std::vector<char>& buf);
    RetCode SendBuffer(const void* buf, size_t size);

    RetCode ReadBuffer(std::vector<char>& buf);
    RetCode ReadBuffer(void* buf, size_t size);

    int SparseWriteCallback(std::vector<char>& tpbuf, const char* data, size_t len);

    std::string error_;
    std::function<void(std::string&)> info_cb_;
    bool disable_checks_;
};

}  // namespace fastboot
