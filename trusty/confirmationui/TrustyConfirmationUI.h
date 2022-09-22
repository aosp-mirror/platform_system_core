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

#include <aidl/android/hardware/confirmationui/BnConfirmationUI.h>
#include <aidl/android/hardware/confirmationui/IConfirmationResultCallback.h>
#include <aidl/android/hardware/confirmationui/UIOption.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <android/binder_manager.h>

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <teeui/generic_messages.h>
#include <thread>

#include "TrustyApp.h"

namespace aidl::android::hardware::confirmationui {

using std::shared_ptr;
using std::string;
using std::vector;

using ::aidl::android::hardware::security::keymint::HardwareAuthToken;
using ::android::trusty::confirmationui::TrustyApp;

class TrustyConfirmationUI : public BnConfirmationUI {
  public:
    TrustyConfirmationUI();
    virtual ~TrustyConfirmationUI();
    // Methods from ::aidl::android::hardware::confirmationui::IConfirmationUI
    // follow.
    ::ndk::ScopedAStatus
    promptUserConfirmation(const shared_ptr<IConfirmationResultCallback>& resultCB,
                           const vector<uint8_t>& promptText, const vector<uint8_t>& extraData,
                           const string& locale, const vector<UIOption>& uiOptions) override;
    ::ndk::ScopedAStatus
    deliverSecureInputEvent(const HardwareAuthToken& secureInputToken) override;

    ::ndk::ScopedAStatus abort() override;

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
    int prompt_result_;
    bool secureInputDelivered_;

    std::tuple<teeui::ResponseCode, teeui::MsgVector<uint8_t>, teeui::MsgVector<uint8_t>>
    promptUserConfirmation_(const teeui::MsgString& promptText,
                            const teeui::MsgVector<uint8_t>& extraData,
                            const teeui::MsgString& locale,
                            const teeui::MsgVector<teeui::UIOption>& uiOptions);
};

}  // namespace aidl::android::hardware::confirmationui

#endif  // ANDROID_HARDWARE_CONFIRMATIONUI_V1_0_TRUSTY_CONFIRMATIONUI_H
