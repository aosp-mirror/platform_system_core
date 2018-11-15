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

#include "boringssl_self_test.h"

#include <android-base/logging.h>
#include <cutils/android_reboot.h>
#include <openssl/crypto.h>
#include <sys/types.h>
#include <unistd.h>

namespace android {
namespace init {

Result<Success> StartBoringSslSelfTest(const BuiltinArguments&) {
    pid_t id = fork();

    if (id == 0) {
        if (BORINGSSL_self_test() != 1) {
            LOG(INFO) << "BoringSSL crypto self tests failed";

            // This check has failed, so the device should refuse
            // to boot. Rebooting to bootloader to wait for
            // further action from the user.

            int result =
                android_reboot(ANDROID_RB_RESTART2, 0, "bootloader,boringssl-self-check-failed");
            if (result != 0) {
                LOG(ERROR) << "Failed to reboot into bootloader";
            }
        }

        _exit(0);
    } else if (id == -1) {
        // Failed to fork, so cannot run the test. Refuse to continue.
        PLOG(FATAL) << "Failed to fork for BoringSSL self test";
    }

    return Success();
}

}  // namespace init
}  // namespace android
