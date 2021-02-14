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

#define LOG_TAG "TrustyAppLoader"

#include <BufferAllocator/BufferAllocator.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <trusty/tipc.h>
#include <unistd.h>
#include <algorithm>
#include <string>

#include "apploader_ipc.h"

using android::base::unique_fd;
using std::string;

constexpr const char kTrustyDefaultDeviceName[] = "/dev/trusty-ipc-dev0";

static const char* dev_name = kTrustyDefaultDeviceName;

static const char* _sopts = "hs";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"dev", required_argument, 0, 'D'},
        {0, 0, 0, 0},
};

static const char* usage =
        "Usage: %s [options] package-file\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -D, --dev name        Trusty device name\n"
        "\n";

static void print_usage_and_exit(const char* prog, int code) {
    fprintf(stderr, usage, prog);
    exit(code);
}

static void parse_options(int argc, char** argv) {
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) {
            break; /* done */
        }

        switch (c) {
            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS);
                break;

            case 'D':
                dev_name = strdup(optarg);
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
    }
}

static unique_fd read_file(const char* file_name, off64_t* out_file_size) {
    int rc;
    long page_size = sysconf(_SC_PAGESIZE);
    off64_t file_size, file_page_offset, file_page_size;
    struct stat64 st;

    unique_fd file_fd(TEMP_FAILURE_RETRY(open(file_name, O_RDONLY)));
    if (!file_fd.ok()) {
        fprintf(stderr, "Error opening file '%s': %s\n", file_name, strerror(errno));
        return {};
    }

    rc = fstat64(file_fd, &st);
    if (rc < 0) {
        fprintf(stderr, "Error calling stat on file '%s': %s\n", file_name, strerror(errno));
        return {};
    }

    assert(st.st_size >= 0);
    file_size = st.st_size;

    /* The dmabuf size needs to be a multiple of the page size */
    file_page_offset = file_size & (page_size - 1);
    if (file_page_offset) {
        file_page_offset = page_size - file_page_offset;
    }
    if (__builtin_add_overflow(file_size, file_page_offset, &file_page_size)) {
        fprintf(stderr, "Failed to page-align file size\n");
        return {};
    }

    BufferAllocator alloc;
    unique_fd dmabuf_fd(alloc.Alloc(kDmabufSystemHeapName, file_page_size));
    if (!dmabuf_fd.ok()) {
        fprintf(stderr, "Error creating dmabuf: %d\n", dmabuf_fd.get());
        return dmabuf_fd;
    }

    void* shm = mmap(0, file_page_size, PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf_fd, 0);
    if (shm == MAP_FAILED) {
        return {};
    }

    off64_t file_offset = 0;
    while (file_offset < file_size) {
        ssize_t num_read = TEMP_FAILURE_RETRY(
                pread(file_fd, (char*)shm + file_offset, file_size - file_offset, file_offset));

        if (num_read < 0) {
            fprintf(stderr, "Error reading package file '%s': %s\n", file_name, strerror(errno));
            break;
        }

        if (num_read == 0) {
            fprintf(stderr, "Unexpected end of file '%s'\n", file_name);
            break;
        }

        file_offset += (off64_t)num_read;
    }

    munmap(shm, file_page_size);

    if (file_offset < file_size) {
        return {};
    }

    assert(file_offset == file_size);
    if (out_file_size) {
        *out_file_size = file_size;
    }

    return dmabuf_fd;
}

static ssize_t send_load_message(int tipc_fd, int package_fd, off64_t package_size) {
    struct apploader_header hdr = {
            .cmd = APPLOADER_CMD_LOAD_APPLICATION,
    };
    struct apploader_load_app_req req = {
            .package_size = static_cast<uint64_t>(package_size),
    };
    struct iovec tx[2] = {{&hdr, sizeof(hdr)}, {&req, sizeof(req)}};
    struct trusty_shm shm = {
            .fd = package_fd,
            .transfer = TRUSTY_SHARE,
    };
    return tipc_send(tipc_fd, tx, 2, &shm, 1);
}

static ssize_t read_response(int tipc_fd) {
    struct apploader_resp resp;
    ssize_t rc = read(tipc_fd, &resp, sizeof(resp));
    if (rc < 0) {
        fprintf(stderr, "Failed to read response: %zd\n", rc);
        return rc;
    }

    if (rc < sizeof(resp)) {
        fprintf(stderr, "Not enough data in response: %zd\n", rc);
        return -EIO;
    }

    if (resp.hdr.cmd != (APPLOADER_CMD_LOAD_APPLICATION | APPLOADER_RESP_BIT)) {
        fprintf(stderr, "Invalid command in response: %u\n", resp.hdr.cmd);
        return -EINVAL;
    }

    switch (resp.error) {
        case APPLOADER_NO_ERROR:
            break;
        case APPLOADER_ERR_UNKNOWN_CMD:
            fprintf(stderr, "Error: unknown command\n");
            break;
        case APPLOADER_ERR_INVALID_CMD:
            fprintf(stderr, "Error: invalid command arguments\n");
            break;
        case APPLOADER_ERR_NO_MEMORY:
            fprintf(stderr, "Error: out of Trusty memory\n");
            break;
        case APPLOADER_ERR_VERIFICATION_FAILED:
            fprintf(stderr, "Error: failed to verify the package\n");
            break;
        case APPLOADER_ERR_LOADING_FAILED:
            fprintf(stderr, "Error: failed to load the package\n");
            break;
        case APPLOADER_ERR_ALREADY_EXISTS:
            fprintf(stderr, "Error: application already exists\n");
            break;
        case APPLOADER_ERR_INTERNAL:
            fprintf(stderr, "Error: internal apploader error\n");
            break;
        default:
            fprintf(stderr, "Unrecognized error: %u\n", resp.error);
            break;
    }

    return static_cast<ssize_t>(resp.error);
}

static ssize_t send_app_package(const char* package_file_name) {
    ssize_t rc = 0;
    int tipc_fd = -1;
    off64_t package_size;

    unique_fd package_fd = read_file(package_file_name, &package_size);
    if (!package_fd.ok()) {
        rc = -1;
        goto err_read_file;
    }

    tipc_fd = tipc_connect(dev_name, APPLOADER_PORT);
    if (tipc_fd < 0) {
        fprintf(stderr, "Failed to connect to Trusty app loader: %s\n", strerror(-tipc_fd));
        rc = tipc_fd;
        goto err_tipc_connect;
    }

    rc = send_load_message(tipc_fd, package_fd, package_size);
    if (rc < 0) {
        fprintf(stderr, "Failed to send package: %zd\n", rc);
        goto err_send;
    }

    rc = read_response(tipc_fd);

err_send:
    tipc_close(tipc_fd);
err_tipc_connect:
err_read_file:
    return rc;
}

int main(int argc, char** argv) {
    parse_options(argc, argv);
    if (optind + 1 != argc) {
        print_usage_and_exit(argv[0], EXIT_FAILURE);
    }

    int rc = send_app_package(argv[optind]);
    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
