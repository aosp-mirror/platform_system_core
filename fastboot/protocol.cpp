/*
 * Copyright (C) 2008 The Android Open Source Project
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

#define round_down(a, b) \
    ({ typeof(a) _a = (a); typeof(b) _b = (b); _a - (_a % _b); })

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <algorithm>
#include <vector>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <sparse/sparse.h>
#include <utils/FileMap.h>

#include "fastboot.h"
#include "transport.h"

static std::string g_error;

using android::base::unique_fd;
using android::base::WriteStringToFile;

const std::string fb_get_error() {
    return g_error;
}

static int64_t check_response(Transport* transport, uint32_t size, char* response) {
    char status[FB_RESPONSE_SZ + 1];

    while (true) {
        int r = transport->Read(status, FB_RESPONSE_SZ);
        if (r < 0) {
            g_error = android::base::StringPrintf("status read failed (%s)", strerror(errno));
            transport->Close();
            return -1;
        }
        status[r] = 0;

        if (r < 4) {
            g_error = android::base::StringPrintf("status malformed (%d bytes)", r);
            transport->Close();
            return -1;
        }

        if (!memcmp(status, "INFO", 4)) {
            verbose("received INFO \"%s\"", status + 4);
            fprintf(stderr, "(bootloader) %s\n", status + 4);
            continue;
        }

        if (!memcmp(status, "OKAY", 4)) {
            verbose("received OKAY \"%s\"", status + 4);
            if (response) {
                strcpy(response, status + 4);
            }
            return 0;
        }

        if (!memcmp(status, "FAIL", 4)) {
            verbose("received FAIL \"%s\"", status + 4);
            if (r > 4) {
                g_error = android::base::StringPrintf("remote: %s", status + 4);
            } else {
                g_error = "remote failure";
            }
            return -1;
        }

        if (!memcmp(status, "DATA", 4) && size > 0){
            verbose("received DATA %s", status + 4);
            uint32_t dsize = strtol(status + 4, 0, 16);
            if (dsize > size) {
                g_error = android::base::StringPrintf("data size too large (%d)", dsize);
                transport->Close();
                return -1;
            }
            return dsize;
        }

        verbose("received unknown status code \"%4.4s\"", status);
        g_error = "unknown status code";
        transport->Close();
        break;
    }

    return -1;
}

static int64_t _command_start(Transport* transport, const std::string& cmd, uint32_t size,
                              char* response) {
    if (cmd.size() > FB_COMMAND_SZ) {
        g_error = android::base::StringPrintf("command too large (%zu)", cmd.size());
        return -1;
    }

    if (response) {
        response[0] = 0;
    }

    verbose("sending command \"%s\"", cmd.c_str());

    if (transport->Write(cmd.c_str(), cmd.size()) != static_cast<int>(cmd.size())) {
        g_error = android::base::StringPrintf("command write failed (%s)", strerror(errno));
        transport->Close();
        return -1;
    }

    return check_response(transport, size, response);
}

static int64_t _command_write_data(Transport* transport, const void* data, uint32_t size) {
    verbose("sending data (%" PRIu32 " bytes)", size);

    int64_t r = transport->Write(data, size);
    if (r < 0) {
        g_error = android::base::StringPrintf("data write failure (%s)", strerror(errno));
        transport->Close();
        return -1;
    }
    if (r != static_cast<int64_t>(size)) {
        g_error = "data write failure (short transfer)";
        transport->Close();
        return -1;
    }
    return r;
}

static int64_t _command_read_data(Transport* transport, void* data, uint32_t size) {
    verbose("reading data (%" PRIu32 " bytes)", size);

    int64_t r = transport->Read(data, size);
    if (r < 0) {
        g_error = android::base::StringPrintf("data read failure (%s)", strerror(errno));
        transport->Close();
        return -1;
    }
    if (r != (static_cast<int64_t>(size))) {
        g_error = "data read failure (short transfer)";
        transport->Close();
        return -1;
    }
    return r;
}

static int64_t _command_end(Transport* transport) {
    return check_response(transport, 0, 0) < 0 ? -1 : 0;
}

static int64_t _command_send(Transport* transport, const std::string& cmd, const void* data,
                             uint32_t size, char* response) {
    if (size == 0) {
        return -1;
    }

    int64_t r = _command_start(transport, cmd, size, response);
    if (r < 0) {
        return -1;
    }
    r = _command_write_data(transport, data, size);
    if (r < 0) {
        return -1;
    }

    r = _command_end(transport);
    if (r < 0) {
        return -1;
    }

    return size;
}

static int64_t _command_send_fd(Transport* transport, const std::string& cmd, int fd, uint32_t size,
                                char* response) {
    static constexpr uint32_t MAX_MAP_SIZE = 512 * 1024 * 1024;
    off64_t offset = 0;
    uint32_t remaining = size;

    if (_command_start(transport, cmd, size, response) < 0) {
        return -1;
    }

    while (remaining) {
        android::FileMap filemap;
        size_t len = std::min(remaining, MAX_MAP_SIZE);

        if (!filemap.create(NULL, fd, offset, len, true)) {
            return -1;
        }

        if (_command_write_data(transport, filemap.getDataPtr(), len) < 0) {
            return -1;
        }

        remaining -= len;
        offset += len;
    }

    if (_command_end(transport) < 0) {
        return -1;
    }

    return size;
}

static int _command_send_no_data(Transport* transport, const std::string& cmd, char* response) {
    return _command_start(transport, cmd, 0, response);
}

int fb_command(Transport* transport, const std::string& cmd) {
    return _command_send_no_data(transport, cmd, 0);
}

int fb_command_response(Transport* transport, const std::string& cmd, char* response) {
    return _command_send_no_data(transport, cmd, response);
}

int64_t fb_download_data(Transport* transport, const void* data, uint32_t size) {
    std::string cmd(android::base::StringPrintf("download:%08x", size));
    return _command_send(transport, cmd.c_str(), data, size, 0) < 0 ? -1 : 0;
}

int64_t fb_download_data_fd(Transport* transport, int fd, uint32_t size) {
    std::string cmd(android::base::StringPrintf("download:%08x", size));
    return _command_send_fd(transport, cmd.c_str(), fd, size, 0) < 0 ? -1 : 0;
}

int64_t fb_upload_data(Transport* transport, const char* outfile) {
    // positive return value is the upload size sent by the device
    int64_t r = _command_start(transport, "upload", std::numeric_limits<int32_t>::max(), nullptr);
    if (r <= 0) {
        g_error = android::base::StringPrintf("command start failed (%s)", strerror(errno));
        return r;
    }

    std::string data;
    data.resize(r);
    if ((r = _command_read_data(transport, &data[0], data.size())) == -1) {
        return r;
    }

    if (!WriteStringToFile(data, outfile, true)) {
        g_error = android::base::StringPrintf("write to '%s' failed", outfile);
        return -1;
    }

    return _command_end(transport);
}

static constexpr size_t TRANSPORT_BUF_SIZE = 1024;
static char transport_buf[TRANSPORT_BUF_SIZE];
static size_t transport_buf_len;

static int fb_download_data_sparse_write(void* priv, const void* data, size_t len) {
    const char* ptr = static_cast<const char*>(data);
    if (transport_buf_len) {
        size_t to_write = std::min(TRANSPORT_BUF_SIZE - transport_buf_len, len);

        memcpy(transport_buf + transport_buf_len, ptr, to_write);
        transport_buf_len += to_write;
        ptr += to_write;
        len -= to_write;
    }

    Transport* transport = static_cast<Transport*>(priv);
    if (transport_buf_len == TRANSPORT_BUF_SIZE) {
        int64_t r = _command_write_data(transport, transport_buf, TRANSPORT_BUF_SIZE);
        if (r != static_cast<int64_t>(TRANSPORT_BUF_SIZE)) {
            return -1;
        }
        transport_buf_len = 0;
    }

    if (len > TRANSPORT_BUF_SIZE) {
        if (transport_buf_len > 0) {
            g_error = "internal error: transport_buf not empty";
            return -1;
        }
        size_t to_write = round_down(len, TRANSPORT_BUF_SIZE);
        int64_t r = _command_write_data(transport, ptr, to_write);
        if (r != static_cast<int64_t>(to_write)) {
            return -1;
        }
        ptr += to_write;
        len -= to_write;
    }

    if (len > 0) {
        if (len > TRANSPORT_BUF_SIZE) {
            g_error = "internal error: too much left for transport_buf";
            return -1;
        }
        memcpy(transport_buf, ptr, len);
        transport_buf_len = len;
    }

    return 0;
}

static int fb_download_data_sparse_flush(Transport* transport) {
    if (transport_buf_len > 0) {
        int64_t r = _command_write_data(transport, transport_buf, transport_buf_len);
        if (r != static_cast<int64_t>(transport_buf_len)) {
            return -1;
        }
        transport_buf_len = 0;
    }
    return 0;
}

int fb_download_data_sparse(Transport* transport, struct sparse_file* s) {
    int64_t size = sparse_file_len(s, true, false);
    if (size <= 0 || size > std::numeric_limits<uint32_t>::max()) {
        return -1;
    }

    std::string cmd(android::base::StringPrintf("download:%08" PRIx64, size));
    int r = _command_start(transport, cmd, size, 0);
    if (r < 0) {
        return -1;
    }

    r = sparse_file_callback(s, true, false, fb_download_data_sparse_write, transport);
    if (r < 0) {
        return -1;
    }

    r = fb_download_data_sparse_flush(transport);
    if (r < 0) {
        return -1;
    }

    return _command_end(transport);
}
