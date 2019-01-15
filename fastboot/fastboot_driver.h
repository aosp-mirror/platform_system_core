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

#include "constants.h"
#include "transport.h"

class Transport;

namespace fastboot {

enum RetCode : int {
    SUCCESS = 0,
    BAD_ARG,
    IO_ERROR,
    BAD_DEV_RESP,
    DEVICE_FAIL,
    TIMEOUT,
};

struct DriverCallbacks {
    std::function<void(const std::string&)> prolog = [](const std::string&) {};
    std::function<void(int)> epilog = [](int) {};
    std::function<void(const std::string&)> info = [](const std::string&) {};
};

class FastBootDriver {
    friend class FastBootTest;

  public:
    static constexpr int RESP_TIMEOUT = 30;  // 30 seconds
    static constexpr uint32_t MAX_DOWNLOAD_SIZE = std::numeric_limits<uint32_t>::max();
    static constexpr size_t TRANSPORT_CHUNK_SIZE = 1024;

    FastBootDriver(Transport* transport, DriverCallbacks driver_callbacks = {},
                   bool no_checks = false);
    ~FastBootDriver();

    RetCode Boot(std::string* response = nullptr, std::vector<std::string>* info = nullptr);
    RetCode Continue(std::string* response = nullptr, std::vector<std::string>* info = nullptr);
    RetCode CreatePartition(const std::string& partition, const std::string& size);
    RetCode DeletePartition(const std::string& partition);
    RetCode Download(const std::string& name, int fd, size_t size, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr);
    RetCode Download(int fd, size_t size, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr);
    RetCode Download(const std::string& name, const std::vector<char>& buf,
                     std::string* response = nullptr, std::vector<std::string>* info = nullptr);
    RetCode Download(const std::vector<char>& buf, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr);
    RetCode Download(const std::string& partition, struct sparse_file* s, uint32_t sz,
                     size_t current, size_t total, bool use_crc, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr);
    RetCode Download(sparse_file* s, bool use_crc = false, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr);
    RetCode Erase(const std::string& partition, std::string* response = nullptr,
                  std::vector<std::string>* info = nullptr);
    RetCode Flash(const std::string& partition, std::string* response = nullptr,
                  std::vector<std::string>* info = nullptr);
    RetCode GetVar(const std::string& key, std::string* val,
                   std::vector<std::string>* info = nullptr);
    RetCode GetVarAll(std::vector<std::string>* response);
    RetCode Reboot(std::string* response = nullptr, std::vector<std::string>* info = nullptr);
    RetCode RebootTo(std::string target, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr);
    RetCode ResizePartition(const std::string& partition, const std::string& size);
    RetCode SetActive(const std::string& slot, std::string* response = nullptr,
                      std::vector<std::string>* info = nullptr);
    RetCode Upload(const std::string& outfile, std::string* response = nullptr,
                   std::vector<std::string>* info = nullptr);

    /* HIGHER LEVEL COMMANDS -- Composed of the commands above */
    RetCode FlashPartition(const std::string& partition, const std::vector<char>& data);
    RetCode FlashPartition(const std::string& partition, int fd, uint32_t sz);
    RetCode FlashPartition(const std::string& partition, sparse_file* s, uint32_t sz,
                           size_t current, size_t total);

    RetCode Partitions(std::vector<std::tuple<std::string, uint64_t>>* partitions);
    RetCode Require(const std::string& var, const std::vector<std::string>& allowed, bool* reqmet,
                    bool invert = false);

    /* HELPERS */
    void SetInfoCallback(std::function<void(const std::string&)> info);
    static const std::string RCString(RetCode rc);
    std::string Error();
    RetCode WaitForDisconnect();

    // Note: set_transport will return the previous transport.
    Transport* set_transport(Transport* transport);
    Transport* transport() const { return transport_; }

    RetCode RawCommand(const std::string& cmd, const std::string& message,
                       std::string* response = nullptr, std::vector<std::string>* info = nullptr,
                       int* dsize = nullptr);

    RetCode RawCommand(const std::string& cmd, std::string* response = nullptr,
                       std::vector<std::string>* info = nullptr, int* dsize = nullptr);

  protected:
    RetCode DownloadCommand(uint32_t size, std::string* response = nullptr,
                            std::vector<std::string>* info = nullptr);
    RetCode HandleResponse(std::string* response = nullptr,
                           std::vector<std::string>* info = nullptr, int* dsize = nullptr);

    std::string ErrnoStr(const std::string& msg);

    Transport* transport_;

  private:
    RetCode SendBuffer(int fd, size_t size);
    RetCode SendBuffer(const std::vector<char>& buf);
    RetCode SendBuffer(const void* buf, size_t size);

    RetCode ReadBuffer(std::vector<char>& buf);
    RetCode ReadBuffer(void* buf, size_t size);

    RetCode UploadInner(const std::string& outfile, std::string* response = nullptr,
                        std::vector<std::string>* info = nullptr);

    int SparseWriteCallback(std::vector<char>& tpbuf, const char* data, size_t len);

    std::string error_;
    std::function<void(const std::string&)> prolog_;
    std::function<void(int)> epilog_;
    std::function<void(const std::string&)> info_;
    bool disable_checks_;
};

}  // namespace fastboot
