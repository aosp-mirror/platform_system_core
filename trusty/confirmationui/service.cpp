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
#include <hidl/HidlTransportSupport.h>

#include <TrustyConfirmationuiHal.h>

using android::sp;
using android::hardware::confirmationui::V1_0::implementation::createTrustyConfirmationUI;

int main() {
    ::android::hardware::configureRpcThreadpool(1, true /*willJoinThreadpool*/);
    auto service = createTrustyConfirmationUI();
    auto status = service->registerAsService();
    if (status != android::OK) {
        LOG(FATAL) << "Could not register service for ConfirmationUI 1.0 (" << status << ")";
        return -1;
    }
    ::android::hardware::joinRpcThreadpool();
    return -1;
}
