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

#define LOG_TAG "usbd"

#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/hardware/usb/gadget/1.0/IUsbGadget.h>

#define PERSISTENT_USB_CONFIG "persist.sys.usb.config"

using android::base::GetProperty;
using android::base::SetProperty;
using android::hardware::usb::gadget::V1_0::GadgetFunction;
using android::hardware::usb::gadget::V1_0::IUsbGadget;
using android::hardware::Return;

int main(int /*argc*/, char** /*argv*/) {
    android::sp<IUsbGadget> gadget = IUsbGadget::getService();
    Return<void> ret;

    if (gadget != nullptr) {
        LOG(INFO) << "Usb HAL found.";
        std::string function = GetProperty(PERSISTENT_USB_CONFIG, "");
        if (function == "adb") {
            LOG(INFO) << "peristent prop is adb";
            SetProperty("ctl.start", "adbd");
            ret = gadget->setCurrentUsbFunctions(static_cast<uint64_t>(GadgetFunction::ADB),
                                                 nullptr, 0);
        } else {
            LOG(INFO) << "Signal MTP to enable default functions";
            ret = gadget->setCurrentUsbFunctions(static_cast<uint64_t>(GadgetFunction::MTP),
                                                 nullptr, 0);
        }

        if (!ret.isOk()) LOG(ERROR) << "Error while invoking usb hal";
    } else {
        LOG(INFO) << "Usb HAL not found";
    }
    exit(0);
}
