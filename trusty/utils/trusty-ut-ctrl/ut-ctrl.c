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

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <trusty/tipc.h>

#define TIPC_DEFAULT_DEVNAME "/dev/trusty-ipc-dev0"

static const char* dev_name = NULL;
static const char* ut_app = NULL;

static const char* _sopts = "hD:";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"dev", required_argument, 0, 'D'},
        {0, 0, 0, 0},
};

static const char* usage =
        "Usage: %s [options] unittest-app\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -D, --dev name        Trusty device name\n"
        "\n";

static const char* usage_long = "\n";

static bool opt_silent = false;

static void print_usage_and_exit(const char* prog, int code, bool verbose) {
    fprintf(stderr, usage, prog);
    if (verbose) {
        fprintf(stderr, "%s", usage_long);
    }
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
            case 'D':
                dev_name = strdup(optarg);
                break;

            case 's':
                opt_silent = true;
                break;

            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS, true);
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE, false);
        }
    }

    if (optind < argc) {
        ut_app = strdup(argv[optind]);
    }
}

enum test_message_header {
    TEST_PASSED = 0,
    TEST_FAILED = 1,
    TEST_MESSAGE = 2,
};

static int run_trusty_unitest(const char* utapp) {
    int fd;
    int rc;
    char rx_buf[1024];

    /* connect to unitest app */
    fd = tipc_connect(dev_name, utapp);
    if (fd < 0) {
        fprintf(stderr, "failed to connect to '%s' app: %s\n", utapp, strerror(-fd));
        return fd;
    }

    /* wait for test to complete */
    for (;;) {
        rc = read(fd, rx_buf, sizeof(rx_buf));
        if (rc <= 0 || rc >= (int)sizeof(rx_buf)) {
            fprintf(stderr, "%s: Read failed: %d\n", __func__, rc);
            tipc_close(fd);
            return -1;
        }

        if (rx_buf[0] == TEST_PASSED) {
            break;
        } else if (rx_buf[0] == TEST_FAILED) {
            break;
        } else if (rx_buf[0] == TEST_MESSAGE) {
            write(STDOUT_FILENO, rx_buf + 1, rc - 1);
        } else {
            fprintf(stderr, "%s: Bad message header: %d\n", __func__, rx_buf[0]);
            break;
        }
    }

    /* close connection to unitest app */
    tipc_close(fd);

    return rx_buf[0] == TEST_PASSED ? 0 : -1;
}

int main(int argc, char** argv) {
    int rc = 0;

    if (argc <= 1) {
        print_usage_and_exit(argv[0], EXIT_FAILURE, false);
    }

    parse_options(argc, argv);

    if (!dev_name) {
        dev_name = TIPC_DEFAULT_DEVNAME;
    }

    if (!ut_app) {
        fprintf(stderr, "Unittest app must be specified\n");
        print_usage_and_exit(argv[0], EXIT_FAILURE, false);
    }

    rc = run_trusty_unitest(ut_app);

    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
