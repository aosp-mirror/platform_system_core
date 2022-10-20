/*
 * Copyright 2020, The Android Open Source Project
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

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include <TrustyConfirmationuiHal.h>

using ::aidl::android::hardware::confirmationui::createTrustyConfirmationUI;
using ::aidl::android::hardware::confirmationui::IConfirmationUI;

int main() {
    ABinderProcess_setThreadPoolMaxThreadCount(0);

    auto confirmationui = createTrustyConfirmationUI();

    const auto instance = std::string(IConfirmationUI::descriptor) + "/default";
    binder_status_t status =
        AServiceManager_addService(confirmationui->asBinder().get(), instance.c_str());

    if (status != STATUS_OK) {
        LOG(FATAL) << "Could not register service for " << instance.c_str() << "(" << status << ")";
        return -1;
    }

    ABinderProcess_joinThreadPool();
    return -1;
}
