/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define LOG_TAG "android.hardware.gatekeeper-service.trusty"

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <getopt.h>

#include "trusty_gatekeeper.h"
#include "trusty_gatekeeper_ipc.h"

using aidl::android::hardware::gatekeeper::TrustyGateKeeperDevice;

static const char* _sopts = "hD:";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"dev", required_argument, 0, 'D'},
        {0, 0, 0, 0},
};

static const char* usage =
        "Usage: %s [options]\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -D, --dev name        Trusty device name\n"
        "\n";

static const char* usage_long = "\n";

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
                trusty_gatekeeper_set_dev_name(optarg);
                break;

            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS, true);
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE, false);
        }
    }
}

int main(int argc, char** argv) {
    parse_options(argc, argv);

    ABinderProcess_setThreadPoolMaxThreadCount(0);

    std::shared_ptr<TrustyGateKeeperDevice> gatekeeper =
            ndk::SharedRefBase::make<TrustyGateKeeperDevice>();

    const std::string instance = std::string() + TrustyGateKeeperDevice::descriptor + "/default";
    binder_status_t status =
            AServiceManager_addService(gatekeeper->asBinder().get(), instance.c_str());
    CHECK_EQ(status, STATUS_OK);

    ABinderProcess_joinThreadPool();

    return -1;  // Should never get here.
}
