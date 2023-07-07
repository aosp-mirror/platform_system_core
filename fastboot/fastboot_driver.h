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

#include <android-base/endian.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <bootimg.h>
#include <inttypes.h>
#include <sparse/sparse.h>

#include "constants.h"
#include "fastboot_driver_interface.h"
#include "transport.h"

class Transport;

namespace fastboot {

struct DriverCallbacks {
    std::function<void(const std::string&)> prolog = [](const std::string&) {};
    std::function<void(int)> epilog = [](int) {};
    std::function<void(const std::string&)> info = [](const std::string&) {};
    std::function<void(const std::string&)> text = [](const std::string&) {};
};

class FastBootDriver : public IFastBootDriver {
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
    RetCode DeletePartition(const std::string& partition) override;
    RetCode Download(const std::string& name, android::base::borrowed_fd fd, size_t size,
                     std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr) override;
    RetCode Download(android::base::borrowed_fd fd, size_t size, std::string* response = nullptr,
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
                  std::vector<std::string>* info = nullptr) override;
    RetCode Flash(const std::string& partition, std::string* response = nullptr,
                  std::vector<std::string>* info = nullptr);
    RetCode GetVar(const std::string& key, std::string* val,
                   std::vector<std::string>* info = nullptr) override;
    RetCode GetVarAll(std::vector<std::string>* response);
    RetCode Reboot(std::string* response = nullptr,
                   std::vector<std::string>* info = nullptr) override;
    RetCode RebootTo(std::string target, std::string* response = nullptr,
                     std::vector<std::string>* info = nullptr) override;
    RetCode ResizePartition(const std::string& partition, const std::string& size) override;
    RetCode SetActive(const std::string& slot, std::string* response = nullptr,
                      std::vector<std::string>* info = nullptr);
    RetCode Upload(const std::string& outfile, std::string* response = nullptr,
                   std::vector<std::string>* info = nullptr);
    RetCode SnapshotUpdateCommand(const std::string& command, std::string* response = nullptr,
                                  std::vector<std::string>* info = nullptr);
    RetCode FetchToFd(const std::string& partition, android::base::borrowed_fd fd,
                      int64_t offset = -1, int64_t size = -1, std::string* response = nullptr,
                      std::vector<std::string>* info = nullptr);

    /* HIGHER LEVEL COMMANDS -- Composed of the commands above */
    RetCode FlashPartition(const std::string& partition, const std::vector<char>& data);
    RetCode FlashPartition(const std::string& partition, android::base::borrowed_fd fd,
                           uint32_t sz) override;
    RetCode FlashPartition(const std::string& partition, sparse_file* s, uint32_t sz,
                           size_t current, size_t total);

    RetCode Partitions(std::vector<std::tuple<std::string, uint64_t>>* partitions);
    RetCode Require(const std::string& var, const std::vector<std::string>& allowed, bool* reqmet,
                    bool invert = false);

    /* HELPERS */
    void SetInfoCallback(std::function<void(const std::string&)> info);
    static const std::string RCString(RetCode rc);
    std::string Error();
    RetCode WaitForDisconnect() override;

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
    RetCode SendBuffer(android::base::borrowed_fd fd, size_t size);
    RetCode SendBuffer(const std::vector<char>& buf);
    RetCode SendBuffer(const void* buf, size_t size);

    RetCode ReadBuffer(void* buf, size_t size);

    RetCode UploadInner(const std::string& outfile, std::string* response = nullptr,
                        std::vector<std::string>* info = nullptr);
    RetCode RunAndReadBuffer(const std::string& cmd, std::string* response,
                             std::vector<std::string>* info,
                             const std::function<RetCode(const char*, uint64_t)>& write_fn);

    int SparseWriteCallback(std::vector<char>& tpbuf, const char* data, size_t len);

    std::string error_;
    std::function<void(const std::string&)> prolog_;
    std::function<void(int)> epilog_;
    std::function<void(const std::string&)> info_;
    std::function<void(const std::string&)> text_;
    bool disable_checks_;
};

}  // namespace fastboot
