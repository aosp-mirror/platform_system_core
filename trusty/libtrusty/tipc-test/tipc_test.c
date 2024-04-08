/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#define __USE_GNU
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <time.h>

#include <BufferAllocator/BufferAllocatorWrapper.h>

#include <trusty/tipc.h>

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"

/* clang-format off */
#define BENCH_RESULT_TPL                                    \
"{"                                                         \
"    \"schema_version\": 3,"                                \
"    \"suite_name\": \"tipc\","                           \
"    \"bench_name\": \"%s\","                               \
"    \"results\": ["                                        \
"        {"                                                 \
"            \"metric_name\": \"time_micro_sec\","          \
"            \"min\": \"%" PRId64 "\","                     \
"            \"max\": \"%" PRId64 "\","                     \
"            \"avg\": \"%" PRId64 "\","                     \
"            \"cold\": \"%" PRId64 "\","                    \
"            \"raw_min\": %" PRId64 ","                     \
"            \"raw_max\": %" PRId64 ","                     \
"            \"raw_avg\": %" PRId64 ","                     \
"            \"raw_cold\": %" PRId64 ""                     \
"        },"                                                \
"    ]"                                                     \
"}"
/* clang-format on */

static const char *uuid_name = "com.android.ipc-unittest.srv.uuid";
static const char *echo_name = "com.android.ipc-unittest.srv.echo";
static const char *ta_only_name = "com.android.ipc-unittest.srv.ta_only";
static const char *ns_only_name = "com.android.ipc-unittest.srv.ns_only";
static const char *datasink_name = "com.android.ipc-unittest.srv.datasink";
static const char *closer1_name = "com.android.ipc-unittest.srv.closer1";
static const char *closer2_name = "com.android.ipc-unittest.srv.closer2";
static const char *closer3_name = "com.android.ipc-unittest.srv.closer3";
static const char *main_ctrl_name = "com.android.ipc-unittest.ctrl";
static const char* receiver_name = "com.android.trusty.memref.receiver";
static const size_t memref_chunk_size = 4096;

static const char* _sopts = "hsvDS:t:r:m:b:B:";
/* clang-format off */
static const struct option _lopts[] =  {
    {"help",    no_argument,       0, 'h'},
    {"silent",  no_argument,       0, 's'},
    {"variable",no_argument,       0, 'v'},
    {"dev",     required_argument, 0, 'D'},
    {"srv",     required_argument, 0, 'S'},
    {"repeat",  required_argument, 0, 'r'},
    {"burst",   required_argument, 0, 'b'},
    {"msgsize", required_argument, 0, 'm'},
    {"test",    required_argument, 0, 't'},
    {"bench",   required_argument, 0, 'B'},
    {0, 0, 0, 0}
};
/* clang-format on */

static const char* usage =
        "Usage: %s [options]\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -D, --dev name        device name\n"
        "  -S, --srv name        service name\n"
        "  -t, --test name       test to run\n"
        "  -r, --repeat cnt      repeat count\n"
        "  -b, --burst cnt       burst count\n"
        "  -m, --msgsize size    max message size\n"
        "  -v, --variable        variable message size\n"
        "  -s, --silent          silent\n"
        "  -B, --bench           Run as Benchmark N times\n"
        "\n";

static const char* usage_long =
        "\n"
        "The following tests are available:\n"
        "   connect      - connect to specified service, defaults to echo+datasink\n"
        "   connect_foo  - connect to non existing service\n"
        "   burst_write  - send messages to datasink service\n"
        "   echo         - send/receive messages to echo service\n"
        "   select       - test select call\n"
        "   blocked_read - test blocked read\n"
        "   closer1      - connection closed by remote (test1)\n"
        "   closer2      - connection closed by remote (test2)\n"
        "   closer3      - connection closed by remote (test3)\n"
        "   ta2ta-ipc    - execute TA to TA unittest\n"
        "   dev-uuid     - print device uuid\n"
        "   ta-access    - test ta-access flags\n"
        "   writev       - writev test\n"
        "   readv        - readv test\n"
        "   send-fd      - transmit dma_buf to trusty, use as shm\n"
        "\n";

struct tipc_test_params {
    uint repeat;
    uint msgsize;
    uint msgburst;
    bool variable;
    bool silent;
    uint bench;
    char* srv_name;
    char* dev_name;
    char* test_name;
};
typedef int (*tipc_test_func_t)(const struct tipc_test_params*);

struct tipc_test_def {
    char* test_name;
    tipc_test_func_t func;
};

static void init_params(struct tipc_test_params* params) {
    params->repeat = 1;
    params->msgsize = 32;
    params->msgburst = 32;
    params->variable = false;
    params->silent = false;
    params->bench = 0;
    params->srv_name = NULL;
    params->test_name = NULL;
}

static void print_usage_and_exit(const char *prog, int code, bool verbose)
{
    fprintf(stderr, usage, prog);
    if (verbose) fprintf(stderr, "%s", usage_long);
    exit(code);
}

static void parse_options(int argc, char** argv, struct tipc_test_params* params) {
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) break; /* done */

        switch (c) {
            case 'D':
                params->dev_name = strdup(optarg);
                break;

            case 'S':
                params->srv_name = strdup(optarg);
                break;

            case 't':
                params->test_name = strdup(optarg);
                break;

            case 'v':
                params->variable = true;
                break;

            case 'r':
                params->repeat = atoi(optarg);
                break;

            case 'm':
                params->msgsize = atoi(optarg);
                break;

            case 'b':
                params->msgburst = atoi(optarg);
                break;

            case 's':
                params->silent = true;
                break;

            case 'B':
                params->bench = atoi(optarg);
                break;

            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS, true);
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE, false);
        }
    }
}

static int connect_test(const struct tipc_test_params* params) {
    uint i;
    int echo_fd;
    int dsink_fd;
    int custom_fd;

    if (!params->silent) {
        printf("%s: repeat = %u\n", __func__, params->repeat);
    }

    for (i = 0; i < params->repeat; i++) {
        if (params->srv_name) {
            custom_fd = tipc_connect(params->dev_name, params->srv_name);
            if (custom_fd < 0) {
                fprintf(stderr, "Failed to connect to '%s' service\n", params->srv_name);
            }
            if (custom_fd >= 0) {
                tipc_close(custom_fd);
            }
        } else {
            echo_fd = tipc_connect(params->dev_name, echo_name);
            if (echo_fd < 0) {
                fprintf(stderr, "Failed to connect to '%s' service\n", "echo");
            }
            dsink_fd = tipc_connect(params->dev_name, datasink_name);
            if (dsink_fd < 0) {
                fprintf(stderr, "Failed to connect to '%s' service\n", "datasink");
            }

            if (echo_fd >= 0) {
                tipc_close(echo_fd);
            }
            if (dsink_fd >= 0) {
                tipc_close(dsink_fd);
            }
        }
    }

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int connect_foo(const struct tipc_test_params* params) {
    uint i;
    int fd;

    if (!params->silent) {
        printf("%s: repeat = %u\n", __func__, params->repeat);
    }

    for (i = 0; i < params->repeat; i++) {
        fd = tipc_connect(params->dev_name, "foo");
        if (fd >= 0) {
            fprintf(stderr, "succeeded to connect to '%s' service\n", "foo");
            tipc_close(fd);
        }
    }

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int closer1_test(const struct tipc_test_params* params) {
    uint i;
    int fd;

    if (!params->silent) {
        printf("%s: repeat = %u\n", __func__, params->repeat);
    }

    for (i = 0; i < params->repeat; i++) {
        fd = tipc_connect(params->dev_name, closer1_name);
        if (fd < 0) {
            fprintf(stderr, "Failed to connect to '%s' service\n", "closer1");
            continue;
        }
        if (!params->silent) {
            printf("%s: connected\n", __func__);
        }
        tipc_close(fd);
    }

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int closer2_test(const struct tipc_test_params* params) {
    uint i;
    int fd;

    if (!params->silent) {
        printf("%s: repeat = %u\n", __func__, params->repeat);
    }

    for (i = 0; i < params->repeat; i++) {
        fd = tipc_connect(params->dev_name, closer2_name);
        if (fd < 0) {
            if (!params->silent) {
                printf("failed to connect to '%s' service\n", "closer2");
            }
        } else {
            /* this should always fail */
            fprintf(stderr, "connected to '%s' service\n", "closer2");
            tipc_close(fd);
        }
    }

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int closer3_test(const struct tipc_test_params* params) {
    uint i, j;
    ssize_t rc;
    int fd[4];
    char buf[64];

    if (!params->silent) {
        printf("%s: repeat = %u\n", __func__, params->repeat);
    }

    for (i = 0; i < params->repeat; i++) {
        /* open 4 connections to closer3 service */
        for (j = 0; j < 4; j++) {
            fd[j] = tipc_connect(params->dev_name, closer3_name);
            if (fd[j] < 0) {
                fprintf(stderr, "fd[%d]: failed to connect to '%s' service\n", j, "closer3");
            } else {
                if (!params->silent) {
                    printf("%s: fd[%d]=%d: connected\n", __func__, j, fd[j]);
                }
                memset(buf, i + j, sizeof(buf));
                rc = write(fd[j], buf, sizeof(buf));
                if (rc != sizeof(buf)) {
                    if (!params->silent) {
                        printf("%s: fd[%d]=%d: write returned  = %zd\n", __func__, j, fd[j], rc);
                    }
                    perror("closer3_test: write");
                }
            }
        }

        /* sleep a bit */
        sleep(1);

        /* It is expected that they will be closed by remote */
        for (j = 0; j < 4; j++) {
            if (fd[j] < 0) continue;
            rc = write(fd[j], buf, sizeof(buf));
            if (rc != sizeof(buf)) {
                if (!params->silent) {
                    printf("%s: fd[%d]=%d: write returned = %zd\n", __func__, j, fd[j], rc);
                }
                perror("closer3_test: write");
            }
        }

        /* then they have to be closed by remote */
        for (j = 0; j < 4; j++) {
            if (fd[j] >= 0) {
                tipc_close(fd[j]);
            }
        }
    }

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int echo_test(const struct tipc_test_params* params) {
    uint i;
    ssize_t rc;
    size_t msg_len;
    int echo_fd = -1;
    char tx_buf[params->msgsize];
    char rx_buf[params->msgsize];

    if (!params->silent) {
        printf("%s: repeat %u: params->msgsize %u: variable %s\n", __func__, params->repeat,
               params->msgsize, params->variable ? "true" : "false");
    }

    echo_fd = tipc_connect(params->dev_name, echo_name);
    if (echo_fd < 0) {
        fprintf(stderr, "Failed to connect to service\n");
        return echo_fd;
    }

    for (i = 0; i < params->repeat; i++) {
        msg_len = params->msgsize;
        if (params->variable && params->msgsize) {
            msg_len = rand() % params->msgsize;
        }

        memset(tx_buf, i + 1, msg_len);

        rc = write(echo_fd, tx_buf, msg_len);
        if ((size_t)rc != msg_len) {
            perror("echo_test: write");
            break;
        }

        rc = read(echo_fd, rx_buf, msg_len);
        if (rc < 0) {
            perror("echo_test: read");
            break;
        }

        if ((size_t)rc != msg_len) {
            fprintf(stderr, "data truncated (%zu vs. %zu)\n", rc, msg_len);
            continue;
        }

        if (memcmp(tx_buf, rx_buf, (size_t)rc)) {
            fprintf(stderr, "data mismatch\n");
            continue;
        }
    }

    tipc_close(echo_fd);

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int burst_write_test(const struct tipc_test_params* params) {
    int fd;
    uint i, j;
    ssize_t rc;
    size_t msg_len;
    char tx_buf[params->msgsize];

    if (!params->silent) {
        printf("%s: repeat %u: burst %u: params->msgsize %u: variable %s\n", __func__,
               params->repeat, params->msgburst, params->msgsize,
               params->variable ? "true" : "false");
    }

    for (i = 0; i < params->repeat; i++) {
        fd = tipc_connect(params->dev_name, datasink_name);
        if (fd < 0) {
            fprintf(stderr, "Failed to connect to '%s' service\n", "datasink");
            break;
        }

        for (j = 0; j < params->msgburst; j++) {
            msg_len = params->msgsize;
            if (params->variable && params->msgsize) {
                msg_len = rand() % params->msgsize;
            }

            memset(tx_buf, i + 1, msg_len);
            rc = write(fd, tx_buf, msg_len);
            if ((size_t)rc != msg_len) {
                perror("burst_test: write");
                break;
            }
        }

        tipc_close(fd);
    }

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int _wait_for_msg(int fd, int timeout, const struct tipc_test_params* params) {
    int rc;
    fd_set rfds;
    uint msgcnt = 0;
    char rx_buf[params->msgsize];
    struct timeval tv;

    if (!params->silent) {
        printf("waiting (%d) for msg\n", timeout);
    }

    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);

    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    for (;;) {
        rc = select(fd + 1, &rfds, NULL, NULL, &tv);

        if (rc == 0) {
            if (!params->silent) {
                printf("select timedout\n");
            }
            break;
        }

        if (rc == -1) {
            perror("select_test: select");
            return rc;
        }

        rc = read(fd, rx_buf, sizeof(rx_buf));
        if (rc < 0) {
            perror("select_test: read");
            return rc;
        } else {
            if (rc > 0) {
                msgcnt++;
            }
        }
    }

    if (!params->silent) {
        printf("got %u messages\n", msgcnt);
    }

    return 0;
}

static int select_test(const struct tipc_test_params* params) {
    int fd;
    uint i, j;
    ssize_t rc;
    char tx_buf[params->msgsize];

    if (!params->silent) {
        printf("%s: repeat %u\n", __func__, params->repeat);
    }

    fd = tipc_connect(params->dev_name, echo_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to '%s' service\n", "echo");
        return fd;
    }

    for (i = 0; i < params->repeat; i++) {
        _wait_for_msg(fd, 1, params);

        if (!params->silent) {
            printf("sending burst: %u msg\n", params->msgburst);
        }

        for (j = 0; j < params->msgburst; j++) {
            memset(tx_buf, i + j, params->msgsize);
            rc = write(fd, tx_buf, params->msgsize);
            if ((size_t)rc != params->msgsize) {
                perror("burst_test: write");
                break;
            }
        }
    }

    tipc_close(fd);

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int blocked_read_test(const struct tipc_test_params* params) {
    int fd;
    uint i;
    ssize_t rc;
    char rx_buf[512];

    if (!params->silent) {
        printf("%s: repeat %u\n", __func__, params->repeat);
    }

    fd = tipc_connect(params->dev_name, echo_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to '%s' service\n", "echo");
        return fd;
    }

    for (i = 0; i < params->repeat; i++) {
        rc = read(fd, rx_buf, sizeof(rx_buf));
        if (rc < 0) {
            perror("select_test: read");
            break;
        } else {
            if (!params->silent) {
                printf("got %zd bytes\n", rc);
            }
        }
    }

    tipc_close(fd);

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int ta2ta_ipc_test(const struct tipc_test_params* params) {
    enum test_message_header {
        TEST_PASSED = 0,
        TEST_FAILED = 1,
        TEST_MESSAGE = 2,
        TEST_TEXT = 3,
    };

    int fd;
    int ret;
    unsigned char rx_buf[256];

    if (!params->silent) {
        printf("%s:\n", __func__);
    }

    fd = tipc_connect(params->dev_name, main_ctrl_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to '%s' service\n", "main_ctrl");
        return fd;
    }

    /* Wait for tests to complete and read status */
    while (true) {
        ret = read(fd, rx_buf, sizeof(rx_buf));
        if (ret <= 0 || ret >= (int)sizeof(rx_buf)) {
            fprintf(stderr, "%s: Read failed: %d\n", __func__, ret);
            tipc_close(fd);
            return -1;
        }

        if (rx_buf[0] == TEST_PASSED) {
            break;
        } else if (rx_buf[0] == TEST_FAILED) {
            break;
        } else if (rx_buf[0] == TEST_MESSAGE || rx_buf[0] == TEST_TEXT) {
            write(STDOUT_FILENO, rx_buf + 1, ret - 1);
        } else {
            fprintf(stderr, "%s: Bad message header: %d\n", __func__, rx_buf[0]);
            break;
        }
    }

    tipc_close(fd);

    return rx_buf[0] == TEST_PASSED ? 0 : -1;
}

typedef struct uuid
{
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq_and_node[8];
} uuid_t;

static void print_uuid(const char *dev, uuid_t *uuid)
{
    printf("%s:", dev);
    printf("uuid: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", uuid->time_low,
           uuid->time_mid, uuid->time_hi_and_version, uuid->clock_seq_and_node[0],
           uuid->clock_seq_and_node[1], uuid->clock_seq_and_node[2], uuid->clock_seq_and_node[3],
           uuid->clock_seq_and_node[4], uuid->clock_seq_and_node[5], uuid->clock_seq_and_node[6],
           uuid->clock_seq_and_node[7]);
}

static int dev_uuid_test(const struct tipc_test_params* params) {
    int fd;
    ssize_t rc;
    uuid_t uuid;

    fd = tipc_connect(params->dev_name, uuid_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to '%s' service\n", "uuid");
        return fd;
    }

    /* wait for test to complete */
    rc = read(fd, &uuid, sizeof(uuid));
    if (rc < 0) {
        perror("dev_uuid_test: read");
    } else if (rc != sizeof(uuid)) {
        fprintf(stderr, "unexpected uuid size (%d vs. %d)\n", (int)rc, (int)sizeof(uuid));
    } else {
        print_uuid(params->dev_name, &uuid);
    }

    tipc_close(fd);

    return 0;
}

static int ta_access_test(const struct tipc_test_params* params) {
    int fd;

    if (!params->silent) {
        printf("%s:\n", __func__);
    }

    fd = tipc_connect(params->dev_name, ta_only_name);
    if (fd >= 0) {
        fprintf(stderr, "Succeed to connect to '%s' service\n", "ta_only");
        tipc_close(fd);
    }

    fd = tipc_connect(params->dev_name, ns_only_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to '%s' service\n", "ns_only");
        return fd;
    }
    tipc_close(fd);

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int writev_test(const struct tipc_test_params* params) {
    uint i;
    ssize_t rc;
    size_t msg_len;
    int echo_fd = -1;
    char tx0_buf[params->msgsize];
    char tx1_buf[params->msgsize];
    char rx_buf[params->msgsize];
    struct iovec iovs[2] = {{tx0_buf, 0}, {tx1_buf, 0}};

    if (!params->silent) {
        printf("%s: repeat %u: params->msgsize %u: variable %s\n", __func__, params->repeat,
               params->msgsize, params->variable ? "true" : "false");
    }

    echo_fd = tipc_connect(params->dev_name, echo_name);
    if (echo_fd < 0) {
        fprintf(stderr, "Failed to connect to service\n");
        return echo_fd;
    }

    for (i = 0; i < params->repeat; i++) {
        msg_len = params->msgsize;
        if (params->variable && params->msgsize) {
            msg_len = rand() % params->msgsize;
        }

        iovs[0].iov_len = msg_len / 3;
        iovs[1].iov_len = msg_len - iovs[0].iov_len;

        memset(tx0_buf, i + 1, iovs[0].iov_len);
        memset(tx1_buf, i + 2, iovs[1].iov_len);
        memset(rx_buf, i + 3, sizeof(rx_buf));

        rc = writev(echo_fd, iovs, 2);
        if (rc < 0) {
            perror("writev_test: writev");
            break;
        }

        if ((size_t)rc != msg_len) {
            fprintf(stderr, "%s: %s: data size mismatch (%zd vs. %zd)\n", __func__, "writev",
                    (size_t)rc, msg_len);
            break;
        }

        rc = read(echo_fd, rx_buf, sizeof(rx_buf));
        if (rc < 0) {
            perror("writev_test: read");
            break;
        }

        if ((size_t)rc != msg_len) {
            fprintf(stderr, "%s: %s: data size mismatch (%zd vs. %zd)\n", __func__, "read",
                    (size_t)rc, msg_len);
            break;
        }

        if (memcmp(tx0_buf, rx_buf, iovs[0].iov_len)) {
            fprintf(stderr, "%s: data mismatch: buf 0\n", __func__);
            break;
        }

        if (memcmp(tx1_buf, rx_buf + iovs[0].iov_len, iovs[1].iov_len)) {
            fprintf(stderr, "%s: data mismatch, buf 1\n", __func__);
            break;
        }
    }

    tipc_close(echo_fd);

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int readv_test(const struct tipc_test_params* params) {
    uint i;
    ssize_t rc;
    size_t msg_len;
    int echo_fd = -1;
    char tx_buf[params->msgsize];
    char rx0_buf[params->msgsize];
    char rx1_buf[params->msgsize];
    struct iovec iovs[2] = {{rx0_buf, 0}, {rx1_buf, 0}};

    if (!params->silent) {
        printf("%s: repeat %u: params->msgsize %u: variable %s\n", __func__, params->repeat,
               params->msgsize, params->variable ? "true" : "false");
    }

    echo_fd = tipc_connect(params->dev_name, echo_name);
    if (echo_fd < 0) {
        fprintf(stderr, "Failed to connect to service\n");
        return echo_fd;
    }

    for (i = 0; i < params->repeat; i++) {
        msg_len = params->msgsize;
        if (params->variable && params->msgsize) {
            msg_len = rand() % params->msgsize;
        }

        iovs[0].iov_len = msg_len / 3;
        iovs[1].iov_len = msg_len - iovs[0].iov_len;

        memset(tx_buf, i + 1, sizeof(tx_buf));
        memset(rx0_buf, i + 2, iovs[0].iov_len);
        memset(rx1_buf, i + 3, iovs[1].iov_len);

        rc = write(echo_fd, tx_buf, msg_len);
        if (rc < 0) {
            perror("readv_test: write");
            break;
        }

        if ((size_t)rc != msg_len) {
            fprintf(stderr, "%s: %s: data size mismatch (%zd vs. %zd)\n", __func__, "write",
                    (size_t)rc, msg_len);
            break;
        }

        rc = readv(echo_fd, iovs, 2);
        if (rc < 0) {
            perror("readv_test: readv");
            break;
        }

        if ((size_t)rc != msg_len) {
            fprintf(stderr, "%s: %s: data size mismatch (%zd vs. %zd)\n", __func__, "write",
                    (size_t)rc, msg_len);
            break;
        }

        if (memcmp(rx0_buf, tx_buf, iovs[0].iov_len)) {
            fprintf(stderr, "%s: data mismatch: buf 0\n", __func__);
            break;
        }

        if (memcmp(rx1_buf, tx_buf + iovs[0].iov_len, iovs[1].iov_len)) {
            fprintf(stderr, "%s: data mismatch, buf 1\n", __func__);
            break;
        }
    }

    tipc_close(echo_fd);

    if (!params->silent) {
        printf("%s: done\n", __func__);
    }

    return 0;
}

static int send_fd_test(const struct tipc_test_params* params) {
    int ret;
    int dma_buf = -1;
    int fd = -1;
    volatile char* buf = MAP_FAILED;
    BufferAllocator* allocator = NULL;

    const size_t num_chunks = 10;

    fd = tipc_connect(params->dev_name, receiver_name);
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to test support TA - is it missing?\n");
        ret = -1;
        goto cleanup;
    }

    allocator = CreateDmabufHeapBufferAllocator();
    if (!allocator) {
        fprintf(stderr, "Failed to create dma-buf allocator.\n");
        ret = -1;
        goto cleanup;
    }

    size_t buf_size = memref_chunk_size * num_chunks;
    dma_buf = DmabufHeapAlloc(allocator, "system", buf_size, 0, 0 /* legacy align */);
    if (dma_buf < 0) {
        ret = dma_buf;
        fprintf(stderr, "Failed to create dma-buf fd of size %zu err (%d)\n", buf_size, ret);
        goto cleanup;
    }

    buf = mmap(0, buf_size, PROT_READ | PROT_WRITE, MAP_SHARED, dma_buf, 0);
    if (buf == MAP_FAILED) {
        fprintf(stderr, "Failed to map dma-buf: %s\n", strerror(errno));
        ret = -1;
        goto cleanup;
    }

    strcpy((char*)buf, "From NS");

    struct trusty_shm shm = {
            .fd = dma_buf,
            .transfer = TRUSTY_SHARE,
    };

    ssize_t rc = tipc_send(fd, NULL, 0, &shm, 1);
    if (rc < 0) {
        fprintf(stderr, "tipc_send failed: %zd\n", rc);
        ret = rc;
        goto cleanup;
    }
    char c;
    read(fd, &c, 1);
    tipc_close(fd);

    ret = 0;
    for (size_t skip = 0; skip < num_chunks; skip++) {
        int cmp = strcmp("Hello from Trusty!",
                         (const char*)&buf[skip * memref_chunk_size]) ? (-1) : 0;
        if (cmp)
            fprintf(stderr, "Failed: Unexpected content at page %zu in dmabuf\n", skip);
        ret |= cmp;
    }

cleanup:
    if (buf != MAP_FAILED) {
        munmap((char*)buf, buf_size);
    }
    close(dma_buf);
    if (allocator) {
        FreeDmabufHeapBufferAllocator(allocator);
    }
    tipc_close(fd);
    return ret;
}

uint64_t get_time_us(void) {
    struct timespec spec;

    clock_gettime(CLOCK_MONOTONIC, &spec);
    return spec.tv_sec * 1000000 + spec.tv_nsec / 1000;
}

static const struct tipc_test_def tipc_tests[] = {
        {"connect", connect_test},
        {"connect_foo", connect_foo},
        {"burst_write", burst_write_test},
        {"select", select_test},
        {"blocked_read", blocked_read_test},
        {"closer1", closer1_test},
        {"closer2", closer2_test},
        {"closer3", closer3_test},
        {"echo", echo_test},
        {"ta2ta-ipc", ta2ta_ipc_test},
        {"dev-uuid", dev_uuid_test},
        {"ta-access", ta_access_test},
        {"writev", writev_test},
        {"readv", readv_test},
        {"send-fd", send_fd_test},
};

tipc_test_func_t get_test_function(const struct tipc_test_params* params) {
    for (size_t i = 0; i < sizeof(tipc_tests) / sizeof(tipc_tests[0]); i++) {
        if (strcmp(params->test_name, tipc_tests[i].test_name) == 0) {
            return tipc_tests[i].func;
        }
    }
    fprintf(stderr, "Unrecognized test name '%s'\n", params->test_name);
    exit(1);
}

static int run_as_bench(const struct tipc_test_params* params) {
    int rc = 0;
    int64_t min = INT64_MAX;
    int64_t max = 0;
    int64_t avg = 0;
    int64_t cold = 0;

    uint64_t start;
    uint64_t end;

    tipc_test_func_t test = get_test_function(params);

    for (size_t i = 0; (i < params->bench + 1) && rc == 0; ++i) {
        start = get_time_us();
        rc |= test(params);
        end = get_time_us();
        int64_t t = end - start;

        if (i == 0) {
            cold = t;
        } else {
            min = (t < min) ? t : min;
            max = (t > max) ? t : max;
            avg += t;
        }
    }
    avg /= params->bench;

    printf(BENCH_RESULT_TPL, params->test_name, min, max, avg, cold, min, max, avg, cold);
    return rc;
}

int main(int argc, char **argv)
{
    int rc = 0;

    if (argc <= 1) {
        print_usage_and_exit(argv[0], EXIT_FAILURE, false);
    }
    struct tipc_test_params params;
    init_params(&params);
    parse_options(argc, argv, &params);

    if (!params.dev_name) {
        params.dev_name = TIPC_DEFAULT_DEVNAME;
    }

    if (!params.test_name) {
        fprintf(stderr, "need a Test to run\n");
        print_usage_and_exit(argv[0], EXIT_FAILURE, true);
    }

    if (params.bench > 0) {
        rc = run_as_bench(&params);
        params.bench = 0;
    } else {
        tipc_test_func_t test = get_test_function(&params);
        rc = test(&params);
    }
    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
