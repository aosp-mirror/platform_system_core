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

#define LOG_TAG "spiproxyd"

#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <log/log.h>
#include <stdlib.h>
#include <string.h>
#include <trusty/tipc.h>
#include <unistd.h>

int handle_msg(int trusty_dev_fd, int spi_dev_fd) {
    int rc;
    uint8_t msg_buf[4096];
    size_t msg_len;

    /* read request from SPI Trusty app */
    rc = read(trusty_dev_fd, &msg_buf, sizeof(msg_buf));
    if (rc < 0) {
        ALOGE("failed (%d) to read request from TA\n", rc);
        return rc;
    }
    msg_len = rc;

    /* forward request to SPI host device */
    rc = write(spi_dev_fd, &msg_buf, msg_len);
    if (rc < 0 || (size_t)rc != msg_len) {
        ALOGE("failed (%d) to forward request to host\n", rc);
        return rc < 0 ? rc : -1;
    }

    /* read response from SPI host device */
    rc = read(spi_dev_fd, &msg_buf, sizeof(msg_buf));
    if (rc < 0) {
        ALOGE("failed (%d) to read response from host\n", rc);
        return rc;
    }
    msg_len = rc;

    /* forward response to SPI Trusty app */
    rc = write(trusty_dev_fd, &msg_buf, msg_len);
    if (rc < 0 || (size_t)rc != msg_len) {
        ALOGE("failed (%d) to forward response to TA\n", rc);
        return rc < 0 ? rc : -1;
    }

    return 0;
}

int event_loop(int trusty_dev_fd, int spi_dev_fd) {
    while (true) {
        int rc = handle_msg(trusty_dev_fd, spi_dev_fd);
        if (rc < 0) {
            ALOGE("exiting event loop\n");
            return EXIT_FAILURE;
        }
    }
}

static void show_usage() {
    ALOGE("usage: spiproxyd -t TRUSTY_DEVICE -s SPI_DEVICE -p SPI_PROXY_PORT\n");
}

static void parse_args(int argc, char* argv[], const char** trusty_dev_name,
                       const char** spi_dev_name, const char** spi_proxy_port) {
    int opt;
    while ((opt = getopt(argc, argv, "ht:s:p:")) != -1) {
        switch (opt) {
            case 'h':
                show_usage();
                exit(EXIT_SUCCESS);
                break;
            case 't':
                *trusty_dev_name = strdup(optarg);
                break;
            case 's':
                *spi_dev_name = strdup(optarg);
                break;
            case 'p':
                *spi_proxy_port = strdup(optarg);
                break;
            default:
                show_usage();
                exit(EXIT_FAILURE);
                break;
        }
    }

    if (!*trusty_dev_name || !*spi_dev_name || !*spi_proxy_port) {
        show_usage();
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {
    int rc;
    const char* trusty_dev_name = NULL;
    const char* spi_dev_name = NULL;
    const char* spi_proxy_port = NULL;
    int trusty_dev_fd;
    int spi_dev_fd;

    parse_args(argc, argv, &trusty_dev_name, &spi_dev_name, &spi_proxy_port);

    rc = tipc_connect(trusty_dev_name, spi_proxy_port);
    if (rc < 0) {
        ALOGE("failed (%d) to connect to SPI proxy port\n", rc);
        return rc;
    }
    trusty_dev_fd = rc;

    rc = open(spi_dev_name, O_RDWR, 0);
    if (rc < 0) {
        ALOGE("failed (%d) to open SPI device\n", rc);
        return rc;
    }
    spi_dev_fd = rc;

    return event_loop(trusty_dev_fd, spi_dev_fd);
}
