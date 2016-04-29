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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <algorithm>

#include <android-base/stringprintf.h>
#include <sparse/sparse.h>

#include "fastboot.h"
#include "transport.h"

static std::string g_error;

const std::string fb_get_error() {
    return g_error;
}

static int check_response(Transport* transport, uint32_t size, char* response) {
    char status[65];

    while (true) {
        int r = transport->Read(status, 64);
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
            fprintf(stderr,"(bootloader) %s\n", status + 4);
            continue;
        }

        if (!memcmp(status, "OKAY", 4)) {
            if (response) {
                strcpy(response, (char*) status + 4);
            }
            return 0;
        }

        if (!memcmp(status, "FAIL", 4)) {
            if (r > 4) {
                g_error = android::base::StringPrintf("remote: %s", status + 4);
            } else {
                g_error = "remote failure";
            }
            return -1;
        }

        if (!memcmp(status, "DATA", 4) && size > 0){
            uint32_t dsize = strtol(status + 4, 0, 16);
            if (dsize > size) {
                g_error = android::base::StringPrintf("data size too large (%d)", dsize);
                transport->Close();
                return -1;
            }
            return dsize;
        }

        g_error = "unknown status code";
        transport->Close();
        break;
    }

    return -1;
}

static int _command_start(Transport* transport, const char* cmd, uint32_t size, char* response) {
    size_t cmdsize = strlen(cmd);
    if (cmdsize > 64) {
        g_error = android::base::StringPrintf("command too large (%zu)", cmdsize);
        return -1;
    }

    if (response) {
        response[0] = 0;
    }

    if (transport->Write(cmd, cmdsize) != static_cast<int>(cmdsize)) {
        g_error = android::base::StringPrintf("command write failed (%s)", strerror(errno));
        transport->Close();
        return -1;
    }

    return check_response(transport, size, response);
}

static int _command_data(Transport* transport, const void* data, uint32_t size) {
    int r = transport->Write(data, size);
    if (r < 0) {
        g_error = android::base::StringPrintf("data transfer failure (%s)", strerror(errno));
        transport->Close();
        return -1;
    }
    if (r != ((int) size)) {
        g_error = "data transfer failure (short transfer)";
        transport->Close();
        return -1;
    }
    return r;
}

static int _command_end(Transport* transport) {
    return check_response(transport, 0, 0) < 0 ? -1 : 0;
}

static int _command_send(Transport* transport, const char* cmd, const void* data, uint32_t size,
                         char* response) {
    if (size == 0) {
        return -1;
    }

    int r = _command_start(transport, cmd, size, response);
    if (r < 0) {
        return -1;
    }

    r = _command_data(transport, data, size);
    if (r < 0) {
        return -1;
    }

    r = _command_end(transport);
    if (r < 0) {
        return -1;
    }

    return size;
}

static int _command_send_no_data(Transport* transport, const char* cmd, char* response) {
    return _command_start(transport, cmd, 0, response);
}

int fb_command(Transport* transport, const char* cmd) {
    return _command_send_no_data(transport, cmd, 0);
}

int fb_command_response(Transport* transport, const char* cmd, char* response) {
    return _command_send_no_data(transport, cmd, response);
}

int fb_download_data(Transport* transport, const void* data, uint32_t size) {
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "download:%08x", size);
    return _command_send(transport, cmd, data, size, 0) < 0 ? -1 : 0;
}

#define TRANSPORT_BUF_SIZE 1024
static char transport_buf[TRANSPORT_BUF_SIZE];
static int transport_buf_len;

static int fb_download_data_sparse_write(void *priv, const void *data, int len)
{
    int r;
    Transport* transport = reinterpret_cast<Transport*>(priv);
    int to_write;
    const char* ptr = reinterpret_cast<const char*>(data);

    if (transport_buf_len) {
        to_write = std::min(TRANSPORT_BUF_SIZE - transport_buf_len, len);

        memcpy(transport_buf + transport_buf_len, ptr, to_write);
        transport_buf_len += to_write;
        ptr += to_write;
        len -= to_write;
    }

    if (transport_buf_len == TRANSPORT_BUF_SIZE) {
        r = _command_data(transport, transport_buf, TRANSPORT_BUF_SIZE);
        if (r != TRANSPORT_BUF_SIZE) {
            return -1;
        }
        transport_buf_len = 0;
    }

    if (len > TRANSPORT_BUF_SIZE) {
        if (transport_buf_len > 0) {
            g_error = "internal error: transport_buf not empty";
            return -1;
        }
        to_write = round_down(len, TRANSPORT_BUF_SIZE);
        r = _command_data(transport, ptr, to_write);
        if (r != to_write) {
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
        if (_command_data(transport, transport_buf, transport_buf_len) != transport_buf_len) {
            return -1;
        }
        transport_buf_len = 0;
    }
    return 0;
}

int fb_download_data_sparse(Transport* transport, struct sparse_file* s) {
    int size = sparse_file_len(s, true, false);
    if (size <= 0) {
        return -1;
    }

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "download:%08x", size);
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
