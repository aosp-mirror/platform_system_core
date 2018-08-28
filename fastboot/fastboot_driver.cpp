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
#include "fastboot_driver.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <chrono>
#include <fstream>
#include <memory>
#include <regex>
#include <vector>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <utils/FileMap.h>
#include "fastboot_driver.h"
#include "transport.h"

namespace fastboot {

/*************************** PUBLIC *******************************/
FastBootDriver::FastBootDriver(Transport* transport, std::function<void(std::string&)> info,
                               bool no_checks)
    : transport_(transport) {
    info_cb_ = info;
    disable_checks_ = no_checks;
}

FastBootDriver::~FastBootDriver() {
    set_transport(nullptr);
}

RetCode FastBootDriver::Boot(std::string* response, std::vector<std::string>* info) {
    return RawCommand(Commands::BOOT, response, info);
}

RetCode FastBootDriver::Continue(std::string* response, std::vector<std::string>* info) {
    return RawCommand(Commands::CONTINUE, response, info);
}

RetCode FastBootDriver::Erase(const std::string& part, std::string* response,
                              std::vector<std::string>* info) {
    return RawCommand(Commands::ERASE + part, response, info);
}

RetCode FastBootDriver::Flash(const std::string& part, std::string* response,
                              std::vector<std::string>* info) {
    return RawCommand(Commands::FLASH + part, response, info);
}

RetCode FastBootDriver::GetVar(const std::string& key, std::string* val,
                               std::vector<std::string>* info) {
    return RawCommand(Commands::GET_VAR + key, val, info);
}

RetCode FastBootDriver::GetVarAll(std::vector<std::string>* response) {
    std::string tmp;
    return GetVar("all", &tmp, response);
}

RetCode FastBootDriver::Powerdown(std::string* response, std::vector<std::string>* info) {
    return RawCommand(Commands::POWERDOWN, response, info);
}

RetCode FastBootDriver::Reboot(std::string* response, std::vector<std::string>* info) {
    return RawCommand(Commands::REBOOT, response, info);
}

RetCode FastBootDriver::RebootTo(std::string target, std::string* response,
                                 std::vector<std::string>* info) {
    return RawCommand("reboot-" + target, response, info);
}

RetCode FastBootDriver::SetActive(const std::string& part, std::string* response,
                                  std::vector<std::string>* info) {
    return RawCommand(Commands::SET_ACTIVE + part, response, info);
}

RetCode FastBootDriver::Verify(uint32_t num, std::string* response, std::vector<std::string>* info) {
    std::string cmd = android::base::StringPrintf("%s%08" PRIx32, Commands::VERIFY.c_str(), num);
    return RawCommand(cmd, response, info);
}

RetCode FastBootDriver::FlashPartition(const std::string& part, const std::vector<char>& data) {
    RetCode ret;
    if ((ret = Download(data))) {
        return ret;
    }
    return RawCommand(Commands::FLASH + part);
}

RetCode FastBootDriver::FlashPartition(const std::string& part, int fd, uint32_t sz) {
    RetCode ret;
    if ((ret = Download(fd, sz))) {
        return ret;
    }
    return RawCommand(Commands::FLASH + part);
}

RetCode FastBootDriver::FlashPartition(const std::string& part, sparse_file* s) {
    RetCode ret;
    if ((ret = Download(s))) {
        return ret;
    }
    return RawCommand(Commands::FLASH + part);
}

RetCode FastBootDriver::Partitions(std::vector<std::tuple<std::string, uint32_t>>* parts) {
    std::vector<std::string> all;
    RetCode ret;
    if ((ret = GetVarAll(&all))) {
        return ret;
    }

    std::regex reg("partition-size[[:s:]]*:[[:s:]]*([[:w:]]+)[[:s:]]*:[[:s:]]*0x([[:xdigit:]]+)");
    std::smatch sm;

    for (auto& s : all) {
        if (std::regex_match(s, sm, reg)) {
            std::string m1(sm[1]);
            std::string m2(sm[2]);
            uint32_t tmp = strtol(m2.c_str(), 0, 16);
            parts->push_back(std::make_tuple(m1, tmp));
        }
    }
    return SUCCESS;
}

RetCode FastBootDriver::Require(const std::string& var, const std::vector<std::string>& allowed,
                                bool* reqmet, bool invert) {
    *reqmet = invert;
    RetCode ret;
    std::string response;
    if ((ret = GetVar(var, &response))) {
        return ret;
    }

    // Now check if we have a match
    for (const auto s : allowed) {
        // If it ends in *, and starting substring match
        if (response == s || (s.length() && s.back() == '*' &&
                              !response.compare(0, s.length() - 1, s, 0, s.length() - 1))) {
            *reqmet = !invert;
            break;
        }
    }

    return SUCCESS;
}

RetCode FastBootDriver::Download(int fd, size_t size, std::string* response,
                                 std::vector<std::string>* info) {
    RetCode ret;

    if ((size <= 0 || size > MAX_DOWNLOAD_SIZE) && !disable_checks_) {
        error_ = "File is too large to download";
        return BAD_ARG;
    }

    uint32_t u32size = static_cast<uint32_t>(size);
    if ((ret = DownloadCommand(u32size, response, info))) {
        return ret;
    }

    // Write the buffer
    if ((ret = SendBuffer(fd, size))) {
        return ret;
    }

    // Wait for response
    return HandleResponse(response, info);
}

RetCode FastBootDriver::Download(const std::vector<char>& buf, std::string* response,
                                 std::vector<std::string>* info) {
    return Download(buf.data(), buf.size(), response, info);
}

RetCode FastBootDriver::Download(const char* buf, uint32_t size, std::string* response,
                                 std::vector<std::string>* info) {
    RetCode ret;
    error_ = "";
    if ((size == 0 || size > MAX_DOWNLOAD_SIZE) && !disable_checks_) {
        error_ = "Buffer is too large or 0 bytes";
        return BAD_ARG;
    }

    if ((ret = DownloadCommand(size, response, info))) {
        return ret;
    }

    // Write the buffer
    if ((ret = SendBuffer(buf, size))) {
        return ret;
    }

    // Wait for response
    return HandleResponse(response, info);
}

RetCode FastBootDriver::Download(sparse_file* s, bool use_crc, std::string* response,
                                 std::vector<std::string>* info) {
    error_ = "";
    int64_t size = sparse_file_len(s, true, use_crc);
    if (size <= 0 || size > MAX_DOWNLOAD_SIZE) {
        error_ = "Sparse file is too large or invalid";
        return BAD_ARG;
    }

    RetCode ret;
    uint32_t u32size = static_cast<uint32_t>(size);
    if ((ret = DownloadCommand(u32size, response, info))) {
        return ret;
    }

    struct SparseCBPrivate {
        FastBootDriver* self;
        std::vector<char> tpbuf;
    } cb_priv;
    cb_priv.self = this;

    auto cb = [](void* priv, const void* buf, size_t len) -> int {
        SparseCBPrivate* data = static_cast<SparseCBPrivate*>(priv);
        const char* cbuf = static_cast<const char*>(buf);
        return data->self->SparseWriteCallback(data->tpbuf, cbuf, len);
    };

    if (sparse_file_callback(s, true, use_crc, cb, &cb_priv) < 0) {
        error_ = "Error reading sparse file";
        return IO_ERROR;
    }

    // Now flush
    if (cb_priv.tpbuf.size() && (ret = SendBuffer(cb_priv.tpbuf))) {
        return ret;
    }

    return HandleResponse(response, info);
}

RetCode FastBootDriver::Upload(const std::string& outfile, std::string* response,
                               std::vector<std::string>* info) {
    RetCode ret;
    int dsize;
    if ((ret = RawCommand(Commands::UPLOAD, response, info, &dsize))) {
        error_ = "Upload request failed: " + error_;
        return ret;
    }

    if (!dsize) {
        error_ = "Upload request failed, device reports 0 bytes available";
        return BAD_DEV_RESP;
    }

    std::vector<char> data;
    data.resize(dsize);

    if ((ret = ReadBuffer(data))) {
        return ret;
    }

    std::ofstream ofs;
    ofs.open(outfile, std::ofstream::out | std::ofstream::binary);
    if (ofs.fail()) {
        error_ = android::base::StringPrintf("Failed to open '%s'", outfile.c_str());
        return IO_ERROR;
    }
    ofs.write(data.data(), data.size());
    if (ofs.fail() || ofs.bad()) {
        error_ = android::base::StringPrintf("Writing to '%s' failed", outfile.c_str());
        return IO_ERROR;
    }
    ofs.close();

    return HandleResponse(response, info);
}

// Helpers
void FastBootDriver::SetInfoCallback(std::function<void(std::string&)> info) {
    info_cb_ = info;
}

const std::string FastBootDriver::RCString(RetCode rc) {
    switch (rc) {
        case SUCCESS:
            return std::string("Success");

        case BAD_ARG:
            return std::string("Invalid Argument");

        case IO_ERROR:
            return std::string("I/O Error");

        case BAD_DEV_RESP:
            return std::string("Invalid Device Response");

        case DEVICE_FAIL:
            return std::string("Device Error");

        case TIMEOUT:
            return std::string("Timeout");

        default:
            return std::string("Unknown Error");
    }
}

std::string FastBootDriver::Error() {
    return error_;
}

RetCode FastBootDriver::WaitForDisconnect() {
    return transport_->WaitForDisconnect() ? IO_ERROR : SUCCESS;
}

/****************************** PROTECTED *************************************/
RetCode FastBootDriver::RawCommand(const std::string& cmd, std::string* response,
                                   std::vector<std::string>* info, int* dsize) {
    error_ = "";  // Clear any pending error
    if (cmd.size() > FB_COMMAND_SZ && !disable_checks_) {
        error_ = "Command length to RawCommand() is too long";
        return BAD_ARG;
    }

    if (transport_->Write(cmd.c_str(), cmd.size()) != static_cast<int>(cmd.size())) {
        error_ = ErrnoStr("Write to device failed");
        return IO_ERROR;
    }

    // Read the response
    return HandleResponse(response, info, dsize);
}

RetCode FastBootDriver::DownloadCommand(uint32_t size, std::string* response,
                                        std::vector<std::string>* info) {
    std::string cmd(android::base::StringPrintf("%s%08" PRIx32, Commands::DOWNLOAD.c_str(), size));
    RetCode ret;
    if ((ret = RawCommand(cmd, response, info))) {
        return ret;
    }
    return SUCCESS;
}

RetCode FastBootDriver::HandleResponse(std::string* response, std::vector<std::string>* info,
                                       int* dsize) {
    char status[FB_RESPONSE_SZ + 1];
    auto start = std::chrono::system_clock::now();

    auto set_response = [response](std::string s) {
        if (response) *response = std::move(s);
    };
    auto add_info = [info](std::string s) {
        if (info) info->push_back(std::move(s));
    };

    // erase response
    set_response("");
    while ((std::chrono::system_clock::now() - start) < std::chrono::seconds(RESP_TIMEOUT)) {
        int r = transport_->Read(status, FB_RESPONSE_SZ);
        if (r < 0) {
            error_ = ErrnoStr("Status read failed");
            return IO_ERROR;
        }

        status[r] = '\0';  // Need the null terminator
        std::string input(status);
        if (android::base::StartsWith(input, "INFO")) {
            std::string tmp = input.substr(strlen("INFO"));
            info_cb_(tmp);
            add_info(std::move(tmp));
        } else if (android::base::StartsWith(input, "OKAY")) {
            set_response(input.substr(strlen("OKAY")));
            return SUCCESS;
        } else if (android::base::StartsWith(input, "FAIL")) {
            error_ = android::base::StringPrintf("remote: '%s'", status + strlen("FAIL"));
            set_response(input.substr(strlen("FAIL")));
            return DEVICE_FAIL;
        } else if (android::base::StartsWith(input, "DATA")) {
            std::string tmp = input.substr(strlen("DATA"));
            uint32_t num = strtol(tmp.c_str(), 0, 16);
            if (num > MAX_DOWNLOAD_SIZE) {
                error_ = android::base::StringPrintf("Data size too large (%d)", num);
                return BAD_DEV_RESP;
            }
            if (dsize) *dsize = num;
            set_response(std::move(tmp));
            return SUCCESS;
        } else {
            error_ = android::base::StringPrintf("Device sent unknown status code: %s", status);
            return BAD_DEV_RESP;
        }

    }  // End of while loop

    return TIMEOUT;
}

std::string FastBootDriver::ErrnoStr(const std::string& msg) {
    return android::base::StringPrintf("%s (%s)", msg.c_str(), strerror(errno));
}

const std::string FastBootDriver::Commands::BOOT = "boot";
const std::string FastBootDriver::Commands::CONTINUE = "continue";
const std::string FastBootDriver::Commands::DOWNLOAD = "download:";
const std::string FastBootDriver::Commands::ERASE = "erase:";
const std::string FastBootDriver::Commands::FLASH = "flash:";
const std::string FastBootDriver::Commands::GET_VAR = "getvar:";
const std::string FastBootDriver::Commands::POWERDOWN = "powerdown";
const std::string FastBootDriver::Commands::REBOOT = "reboot";
const std::string FastBootDriver::Commands::SET_ACTIVE = "set_active:";
const std::string FastBootDriver::Commands::UPLOAD = "upload";
const std::string FastBootDriver::Commands::VERIFY = "verify:";

/******************************* PRIVATE **************************************/
RetCode FastBootDriver::SendBuffer(int fd, size_t size) {
    static constexpr uint32_t MAX_MAP_SIZE = 512 * 1024 * 1024;
    off64_t offset = 0;
    uint32_t remaining = size;
    RetCode ret;

    while (remaining) {
        // Memory map the file
        android::FileMap filemap;
        size_t len = std::min(remaining, MAX_MAP_SIZE);

        if (!filemap.create(NULL, fd, offset, len, true)) {
            error_ = "Creating filemap failed";
            return IO_ERROR;
        }

        if ((ret = SendBuffer(filemap.getDataPtr(), len))) {
            return ret;
        }

        remaining -= len;
        offset += len;
    }

    return SUCCESS;
}

RetCode FastBootDriver::SendBuffer(const std::vector<char>& buf) {
    // Write the buffer
    return SendBuffer(buf.data(), buf.size());
}

RetCode FastBootDriver::SendBuffer(const void* buf, size_t size) {
    // ioctl on 0-length buffer causes freezing
    if (!size) {
        return BAD_ARG;
    }
    // Write the buffer
    ssize_t tmp = transport_->Write(buf, size);

    if (tmp < 0) {
        error_ = ErrnoStr("Write to device failed in SendBuffer()");
        return IO_ERROR;
    } else if (static_cast<size_t>(tmp) != size) {
        error_ = android::base::StringPrintf("Failed to write all %zu bytes", size);

        return IO_ERROR;
    }

    return SUCCESS;
}

RetCode FastBootDriver::ReadBuffer(std::vector<char>& buf) {
    // Read the buffer
    return ReadBuffer(buf.data(), buf.size());
}

RetCode FastBootDriver::ReadBuffer(void* buf, size_t size) {
    // Read the buffer
    ssize_t tmp = transport_->Read(buf, size);

    if (tmp < 0) {
        error_ = ErrnoStr("Read from device failed in ReadBuffer()");
        return IO_ERROR;
    } else if (static_cast<size_t>(tmp) != size) {
        error_ = android::base::StringPrintf("Failed to read all %zu bytes", size);
        return IO_ERROR;
    }

    return SUCCESS;
}

int FastBootDriver::SparseWriteCallback(std::vector<char>& tpbuf, const char* data, size_t len) {
    size_t total = 0;
    size_t to_write = std::min(TRANSPORT_CHUNK_SIZE - tpbuf.size(), len);

    // Handle the residual
    tpbuf.insert(tpbuf.end(), data, data + to_write);
    if (tpbuf.size() < TRANSPORT_CHUNK_SIZE) {  // Nothing enough to send rn
        return 0;
    }

    if (SendBuffer(tpbuf)) {
        error_ = ErrnoStr("Send failed in SparseWriteCallback()");
        return -1;
    }
    tpbuf.clear();
    total += to_write;

    // Now we need to send a multiple of chunk size
    size_t nchunks = (len - total) / TRANSPORT_CHUNK_SIZE;
    size_t nbytes = TRANSPORT_CHUNK_SIZE * nchunks;
    if (nbytes && SendBuffer(data + total, nbytes)) {  // Don't send a ZLP
        error_ = ErrnoStr("Send failed in SparseWriteCallback()");
        return -1;
    }
    total += nbytes;

    if (len - total > 0) {  // We have residual data to save for next time
        tpbuf.assign(data + total, data + len);
    }

    return 0;
}

void FastBootDriver::set_transport(Transport* transport) {
    if (transport_) {
        transport_->Close();
        delete transport_;
    }
    transport_ = transport;
}

}  // End namespace fastboot
