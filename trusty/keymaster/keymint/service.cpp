/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "android.hardware.security.keymint-service.trusty"
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <getopt.h>

#include <trusty_keymaster/TrustyKeyMintDevice.h>
#include <trusty_keymaster/TrustyRemotelyProvisionedComponentDevice.h>
#include <trusty_keymaster/TrustySecureClock.h>
#include <trusty_keymaster/TrustySharedSecret.h>
#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>

using aidl::android::hardware::security::keymint::trusty::TrustyKeyMintDevice;
using aidl::android::hardware::security::keymint::trusty::TrustyRemotelyProvisionedComponentDevice;
using aidl::android::hardware::security::secureclock::trusty::TrustySecureClock;
using aidl::android::hardware::security::sharedsecret::trusty::TrustySharedSecret;

template <typename T, class... Args>
std::shared_ptr<T> addService(Args&&... args) {
    std::shared_ptr<T> service = ndk::SharedRefBase::make<T>(std::forward<Args>(args)...);
    auto instanceName = std::string(T::descriptor) + "/default";
    LOG(ERROR) << "Adding service instance: " << instanceName;
    auto status = AServiceManager_addService(service->asBinder().get(), instanceName.c_str());
    CHECK(status == STATUS_OK) << "Failed to add service " << instanceName;
    return service;
}

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
                trusty_keymaster_set_dev_name(optarg);
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
    auto trustyKeymaster = std::make_shared<keymaster::TrustyKeymaster>();
    int err = trustyKeymaster->Initialize(keymaster::KmVersion::KEYMINT_3);
    if (err != 0) {
        LOG(FATAL) << "Could not initialize TrustyKeymaster for KeyMint (" << err << ")";
        return -1;
    }

    // Zero threads seems like a useless pool but below we'll join this thread to it, increasing
    // the pool size to 1.
    ABinderProcess_setThreadPoolMaxThreadCount(0);

    auto keyMint = addService<TrustyKeyMintDevice>(trustyKeymaster);
    auto secureClock = addService<TrustySecureClock>(trustyKeymaster);
    auto sharedSecret = addService<TrustySharedSecret>(trustyKeymaster);
    auto remotelyProvisionedComponent =
            addService<TrustyRemotelyProvisionedComponentDevice>(trustyKeymaster);
    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
