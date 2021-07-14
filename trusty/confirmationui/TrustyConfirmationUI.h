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

#ifndef ANDROID_HARDWARE_CONFIRMATIONUI_V1_0_TRUSTY_CONFIRMATIONUI_H
#define ANDROID_HARDWARE_CONFIRMATIONUI_V1_0_TRUSTY_CONFIRMATIONUI_H

#include <android/hardware/confirmationui/1.0/IConfirmationUI.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <hidl/Status.h>

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <teeui/generic_messages.h>
#include <thread>

#include "TrustyApp.h"

namespace android {
namespace hardware {
namespace confirmationui {
namespace V1_0 {
namespace implementation {

using ::android::sp;
using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;

using ::android::trusty::confirmationui::TrustyApp;

class TrustyConfirmationUI : public IConfirmationUI {
  public:
    TrustyConfirmationUI();
    virtual ~TrustyConfirmationUI();
    // Methods from ::android::hardware::confirmationui::V1_0::IConfirmationUI
    // follow.
    Return<ResponseCode> promptUserConfirmation(const sp<IConfirmationResultCallback>& resultCB,
                                                const hidl_string& promptText,
                                                const hidl_vec<uint8_t>& extraData,
                                                const hidl_string& locale,
                                                const hidl_vec<UIOption>& uiOptions) override;
    Return<ResponseCode> deliverSecureInputEvent(
        const ::android::hardware::keymaster::V4_0::HardwareAuthToken& secureInputToken) override;
    Return<void> abort() override;

  private:
    std::weak_ptr<TrustyApp> app_;
    std::thread callback_thread_;

    enum class ListenerState : uint32_t {
        None,
        Starting,
        SetupDone,
        Interactive,
        Terminating,
    };

    /*
     * listener_state is protected by listener_state_lock. It makes transitions between phases
     * of the confirmation operation atomic.
     * (See TrustyConfirmationUI.cpp#promptUserConfirmation_ for details about operation phases)
     */
    ListenerState listener_state_;
    /*
     * abort_called_ is also protected by listener_state_lock_ and indicates that the HAL user
     * called abort.
     */
    bool abort_called_;
    std::mutex listener_state_lock_;
    std::condition_variable listener_state_condv_;
    ResponseCode prompt_result_;
    bool secureInputDelivered_;

    std::tuple<teeui::ResponseCode, teeui::MsgVector<uint8_t>, teeui::MsgVector<uint8_t>>
    promptUserConfirmation_(const teeui::MsgString& promptText,
                            const teeui::MsgVector<uint8_t>& extraData,
                            const teeui::MsgString& locale,
                            const teeui::MsgVector<teeui::UIOption>& uiOptions);
};

}  // namespace implementation
}  // namespace V1_0
}  // namespace confirmationui
}  // namespace hardware
}  // namespace android

#endif  // ANDROID_HARDWARE_CONFIRMATIONUI_V1_0_TRUSTY_CONFIRMATIONUI_H
