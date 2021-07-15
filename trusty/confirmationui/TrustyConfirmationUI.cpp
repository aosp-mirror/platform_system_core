/*
 *
 * Copyright 2019, The Android Open Source Project
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

#include "TrustyConfirmationUI.h"

#include <android-base/logging.h>
#include <android/hardware/confirmationui/1.0/types.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <pthread.h>
#include <secure_input/evdev.h>
#include <secure_input/secure_input_device.h>
#include <secure_input/secure_input_proto.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <teeui/msg_formatting.h>
#include <teeui/utils.h>
#include <time.h>

#include <atomic>
#include <functional>
#include <memory>
#include <thread>
#include <tuple>
#include <vector>

namespace android {
namespace hardware {
namespace confirmationui {
namespace V1_0 {
namespace implementation {

using namespace secure_input;

using ::android::trusty::confirmationui::TrustyAppError;

using ::teeui::AbortMsg;
using ::teeui::DeliverTestCommandMessage;
using ::teeui::DeliverTestCommandResponse;
using ::teeui::FetchConfirmationResult;
using ::teeui::MsgString;
using ::teeui::MsgVector;
using ::teeui::PromptUserConfirmationMsg;
using ::teeui::PromptUserConfirmationResponse;
using ::teeui::ResultMsg;

using ::secure_input::createSecureInput;

using ::android::hardware::keymaster::V4_0::HardwareAuthToken;

using ::std::tie;

using TeeuiRc = ::teeui::ResponseCode;

constexpr const char kTrustyDeviceName[] = "/dev/trusty-ipc-dev0";
constexpr const char kConfirmationuiAppName[] = CONFIRMATIONUI_PORT;

namespace {

class Finalize {
  private:
    std::function<void()> f_;

  public:
    Finalize(std::function<void()> f) : f_(f) {}
    ~Finalize() {
        if (f_) f_();
    }
    void release() { f_ = {}; }
};

ResponseCode convertRc(TeeuiRc trc) {
    static_assert(
        uint32_t(TeeuiRc::OK) == uint32_t(ResponseCode::OK) &&
            uint32_t(TeeuiRc::Canceled) == uint32_t(ResponseCode::Canceled) &&
            uint32_t(TeeuiRc::Aborted) == uint32_t(ResponseCode::Aborted) &&
            uint32_t(TeeuiRc::OperationPending) == uint32_t(ResponseCode::OperationPending) &&
            uint32_t(TeeuiRc::Ignored) == uint32_t(ResponseCode::Ignored) &&
            uint32_t(TeeuiRc::SystemError) == uint32_t(ResponseCode::SystemError) &&
            uint32_t(TeeuiRc::Unimplemented) == uint32_t(ResponseCode::Unimplemented) &&
            uint32_t(TeeuiRc::Unexpected) == uint32_t(ResponseCode::Unexpected) &&
            uint32_t(TeeuiRc::UIError) == uint32_t(ResponseCode::UIError) &&
            uint32_t(TeeuiRc::UIErrorMissingGlyph) == uint32_t(ResponseCode::UIErrorMissingGlyph) &&
            uint32_t(TeeuiRc::UIErrorMessageTooLong) ==
                uint32_t(ResponseCode::UIErrorMessageTooLong) &&
            uint32_t(TeeuiRc::UIErrorMalformedUTF8Encoding) ==
                uint32_t(ResponseCode::UIErrorMalformedUTF8Encoding),
        "teeui::ResponseCode and "
        "::android::hardware::confirmationui::V1_0::Responsecude are out of "
        "sync");
    return ResponseCode(trc);
}

teeui::UIOption convertUIOption(UIOption uio) {
    static_assert(uint32_t(UIOption::AccessibilityInverted) ==
                          uint32_t(teeui::UIOption::AccessibilityInverted) &&
                      uint32_t(UIOption::AccessibilityMagnified) ==
                          uint32_t(teeui::UIOption::AccessibilityMagnified),
                  "teeui::UIOPtion and ::android::hardware::confirmationui::V1_0::UIOption "
                  "anre out of sync");
    return teeui::UIOption(uio);
}

inline MsgString hidl2MsgString(const hidl_string& s) {
    return {s.c_str(), s.c_str() + s.size()};
}
template <typename T> inline MsgVector<T> hidl2MsgVector(const hidl_vec<T>& v) {
    return {v};
}

inline MsgVector<teeui::UIOption> hidl2MsgVector(const hidl_vec<UIOption>& v) {
    MsgVector<teeui::UIOption> result(v.size());
    for (unsigned int i = 0; i < v.size(); ++i) {
        result[i] = convertUIOption(v[i]);
    }
    return result;
}

}  // namespace

TrustyConfirmationUI::TrustyConfirmationUI()
    : listener_state_(ListenerState::None), prompt_result_(ResponseCode::Ignored) {}

TrustyConfirmationUI::~TrustyConfirmationUI() {
    ListenerState state = listener_state_;
    if (state == ListenerState::SetupDone || state == ListenerState::Interactive) {
        abort();
    }
    if (state != ListenerState::None) {
        callback_thread_.join();
    }
}

std::tuple<TeeuiRc, MsgVector<uint8_t>, MsgVector<uint8_t>>
TrustyConfirmationUI::promptUserConfirmation_(const MsgString& promptText,
                                              const MsgVector<uint8_t>& extraData,
                                              const MsgString& locale,
                                              const MsgVector<teeui::UIOption>& uiOptions) {
    std::unique_lock<std::mutex> stateLock(listener_state_lock_);
    /*
     * This is the main listener thread function. The listener thread life cycle
     * is equivalent to the life cycle of a single confirmation request. The life
     * cycle is devided in four phases.
     *  * The starting phase:
     *    * The Trusted App gets loaded and/or the connection to it gets established.
     *    * A connection to the secure input device is established.
     *    * The prompt is initiated. This sends all information required by the
     *      confirmation dialog to the TA. The dialog is not yet displayed.
     *    * An event loop is created.
     *      * The event loop listens for user input events, fetches them from the
     *        secure input device, and delivers them to the TA.
     *    * All evdev devices are grabbed to give confirmationui exclusive access
     *      to user input.
     *
     * Note: During the starting phase the hwbinder service thread is blocked and
     * waiting for possible Errors. If the setup phase concludes sucessfully, the
     * hwbinder service thread gets unblocked and returns successfully. Errors
     * that occur after the first phase are delivered by callback interface.
     *
     *  * The 2nd phase - non interactive phase
     *    * The event loop thread is started.
     *    * After a grace period:
     *      * A handshake between the secure input device SecureInput and the TA
     *        is performed.
     *      * The input event handler are armed to process user input events.
     *
     *  * The 3rd phase - interactive phase
     *    * We wait to any external event
     *      * Abort
     *      * Secure user input asserted
     *      * Secure input delivered (for non interactive VTS testing)
     *    * The result is fetched from the TA.
     *
     *  * The 4th phase - cleanup
     *    The cleanup phase is given by the scope of automatic variables created
     *    in this function. The cleanup commences in reverse order of their creation.
     *    Here is a list of more complex items in the order in which they go out of
     *    scope
     *    * finalizeSecureTouch - signals and joins the secure touch thread.
     *    * eventloop - signals and joins the event loop thread. The event
     *      handlers also own all EventDev instances which ungrab the event devices.
     *      When the eventloop goes out of scope the EventDevs get destroyed
     *      relinquishing the exclusive hold on the event devices.
     *    * finalizeConfirmationPrompt - calls abort on the TA, making sure a
     *      pending operation gets canceled. If the prompt concluded successfully this
     *      is a spurious call but semantically a no op.
     *    * secureInput - shuts down the connection to the secure input device
     *      SecureInput.
     *    * app - disconnects the TA. Since app is a shared pointer this may not
     *      unload the app here. It is possible that more instances of the shared
     *      pointer are held in TrustyConfirmationUI::deliverSecureInputEvent and
     *      TrustyConfirmationUI::abort. But these instances are extremely short lived
     *      and it is safe if they are destroyed by either.
     *    * stateLock - unlocks the listener_state_lock_ if it happens to be held
     *      at the time of return.
     */

    std::tuple<TeeuiRc, MsgVector<uint8_t>, MsgVector<uint8_t>> result;
    TeeuiRc& rc = std::get<TeeuiRc>(result);
    rc = TeeuiRc::SystemError;

    listener_state_ = ListenerState::Starting;

    auto app = std::make_shared<TrustyApp>(kTrustyDeviceName, kConfirmationuiAppName);
    if (!app) return result;  // TeeuiRc::SystemError

    app_ = app;

    auto hsBegin = [&]() -> std::tuple<TeeuiRc, Nonce> {
        auto [error, result] =
            app->issueCmd<secure_input::InputHandshake, secure_input::InputHandshakeResponse>();
        auto& [rc, nCo] = result;

        if (error != TrustyAppError::OK || rc != TeeuiRc::OK) {
            LOG(ERROR) << "Failed to begin secure input handshake (" << int32_t(error) << "/"
                       << uint32_t(rc) << ")";
            rc = error != TrustyAppError::OK ? TeeuiRc::SystemError : rc;
        }
        return result;
    };

    auto hsFinalize = [&](const Signature& sig, const Nonce& nCi) -> TeeuiRc {
        auto [error, finalizeResponse] =
            app->issueCmd<FinalizeInputSessionHandshake, FinalizeInputSessionHandshakeResponse>(
                nCi, sig);
        auto& [rc] = finalizeResponse;
        if (error != TrustyAppError::OK || rc != TeeuiRc::OK) {
            LOG(ERROR) << "Failed to finalize secure input handshake (" << int32_t(error) << "/"
                       << uint32_t(rc) << ")";
            rc = error != TrustyAppError::OK ? TeeuiRc::SystemError : rc;
        }
        return rc;
    };

    auto deliverInput = [&](DTupKeyEvent event,
                            const Signature& sig) -> std::tuple<TeeuiRc, InputResponse> {
        auto [error, result] =
            app->issueCmd<DeliverInputEvent, DeliverInputEventResponse>(event, sig);
        auto& [rc, ir] = result;
        if (error != TrustyAppError::OK) {
            LOG(ERROR) << "Failed to deliver input command";
            rc = TeeuiRc::SystemError;
        }
        return result;
    };

    std::atomic<TeeuiRc> eventRC = TeeuiRc::OperationPending;
    auto inputResult = [&](TeeuiRc rc) {
        TeeuiRc expected = TeeuiRc::OperationPending;
        if (eventRC.compare_exchange_strong(expected, rc)) {
            listener_state_condv_.notify_all();
        }
    };

    // create Secure Input device.
    auto secureInput = createSecureInput(hsBegin, hsFinalize, deliverInput, inputResult);
    if (!secureInput || !(*secureInput)) {
        LOG(ERROR) << "Failed to open secure input device";
        return result;  // TeeuiRc::SystemError;
    }

    Finalize finalizeConfirmationPrompt([app] {
        LOG(INFO) << "Calling abort for cleanup";
        app->issueCmd<AbortMsg>();
    });

    // initiate prompt
    LOG(INFO) << "Initiating prompt";
    TrustyAppError error;
    auto initResponse = std::tie(rc);
    std::tie(error, initResponse) =
        app->issueCmd<PromptUserConfirmationMsg, PromptUserConfirmationResponse>(
            promptText, extraData, locale, uiOptions);
    if (error == TrustyAppError::MSG_TOO_LONG) {
        LOG(ERROR) << "PromptUserConfirmationMsg failed: message too long";
        rc = TeeuiRc::UIErrorMessageTooLong;
        return result;
    } else if (error != TrustyAppError::OK) {
        LOG(ERROR) << "PromptUserConfirmationMsg failed: " << int32_t(error);
        return result;  // TeeuiRc::SystemError;
    }
    if (rc != TeeuiRc::OK) {
        LOG(ERROR) << "PromptUserConfirmationMsg failed: " << uint32_t(rc);
        return result;
    }

    LOG(INFO) << "Grabbing event devices";
    EventLoop eventloop;
    bool grabbed =
        grabAllEvDevsAndRegisterCallbacks(&eventloop, [&](short flags, const EventDev& evDev) {
            if (!(flags & POLLIN)) return;
            secureInput->handleEvent(evDev);
        });

    if (!grabbed) {
        rc = TeeuiRc::SystemError;
        return result;
    }

    abort_called_ = false;
    secureInputDelivered_ = false;

    //  ############################## Start 2nd Phase #############################################
    listener_state_ = ListenerState::SetupDone;
    stateLock.unlock();
    listener_state_condv_.notify_all();

    if (!eventloop.start()) {
        rc = TeeuiRc::SystemError;
        return result;
    }

    stateLock.lock();

    LOG(INFO) << "going to sleep for the grace period";
    auto then = std::chrono::system_clock::now() +
                std::chrono::milliseconds(kUserPreInputGracePeriodMillis) +
                std::chrono::microseconds(50);
    listener_state_condv_.wait_until(stateLock, then, [&]() { return abort_called_; });
    LOG(INFO) << "waking up";

    if (abort_called_) {
        LOG(ERROR) << "Abort called";
        result = {TeeuiRc::Aborted, {}, {}};
        return result;
    }

    LOG(INFO) << "Arming event poller";
    // tell the event poller to act on received input events from now on.
    secureInput->start();

    //  ############################## Start 3rd Phase - interactive phase #########################
    LOG(INFO) << "Transition to Interactive";
    listener_state_ = ListenerState::Interactive;
    stateLock.unlock();
    listener_state_condv_.notify_all();

    stateLock.lock();
    listener_state_condv_.wait(stateLock, [&]() {
        return eventRC != TeeuiRc::OperationPending || abort_called_ || secureInputDelivered_;
    });
    LOG(INFO) << "Listener waking up";
    if (abort_called_) {
        LOG(ERROR) << "Abort called";
        result = {TeeuiRc::Aborted, {}, {}};
        return result;
    }

    if (!secureInputDelivered_) {
        if (eventRC != TeeuiRc::OK) {
            LOG(ERROR) << "Bad input response";
            result = {eventRC, {}, {}};
            return result;
        }
    }

    stateLock.unlock();

    LOG(INFO) << "Fetching Result";
    std::tie(error, result) = app->issueCmd<FetchConfirmationResult, ResultMsg>();
    LOG(INFO) << "Result yields " << int32_t(error) << "/" << uint32_t(rc);
    if (error != TrustyAppError::OK) {
        result = {TeeuiRc::SystemError, {}, {}};
    }
    return result;

    //  ############################## Start 4th Phase - cleanup ##################################
}

// Methods from ::android::hardware::confirmationui::V1_0::IConfirmationUI
// follow.
Return<ResponseCode> TrustyConfirmationUI::promptUserConfirmation(
    const sp<IConfirmationResultCallback>& resultCB, const hidl_string& promptText,
    const hidl_vec<uint8_t>& extraData, const hidl_string& locale,
    const hidl_vec<UIOption>& uiOptions) {
    std::unique_lock<std::mutex> stateLock(listener_state_lock_, std::defer_lock);
    if (!stateLock.try_lock()) {
        return ResponseCode::OperationPending;
    }
    switch (listener_state_) {
    case ListenerState::None:
        break;
    case ListenerState::Starting:
    case ListenerState::SetupDone:
    case ListenerState::Interactive:
        return ResponseCode::OperationPending;
    case ListenerState::Terminating:
        callback_thread_.join();
        listener_state_ = ListenerState::None;
        break;
    default:
        return ResponseCode::Unexpected;
    }

    assert(listener_state_ == ListenerState::None);

    callback_thread_ = std::thread(
        [this](sp<IConfirmationResultCallback> resultCB, hidl_string promptText,
               hidl_vec<uint8_t> extraData, hidl_string locale, hidl_vec<UIOption> uiOptions) {
            auto [trc, msg, token] =
                promptUserConfirmation_(hidl2MsgString(promptText), hidl2MsgVector(extraData),
                                        hidl2MsgString(locale), hidl2MsgVector(uiOptions));
            bool do_callback = (listener_state_ == ListenerState::Interactive ||
                                listener_state_ == ListenerState::SetupDone) &&
                               resultCB;
            prompt_result_ = convertRc(trc);
            listener_state_ = ListenerState::Terminating;
            if (do_callback) {
                auto error = resultCB->result(prompt_result_, msg, token);
                if (!error.isOk()) {
                    LOG(ERROR) << "Result callback failed " << error.description();
                }
            } else {
                listener_state_condv_.notify_all();
            }
        },
        resultCB, promptText, extraData, locale, uiOptions);

    listener_state_condv_.wait(stateLock, [this] {
        return listener_state_ == ListenerState::SetupDone ||
               listener_state_ == ListenerState::Interactive ||
               listener_state_ == ListenerState::Terminating;
    });
    if (listener_state_ == ListenerState::Terminating) {
        callback_thread_.join();
        listener_state_ = ListenerState::None;
        return prompt_result_;
    }
    return ResponseCode::OK;
}

Return<ResponseCode>
TrustyConfirmationUI::deliverSecureInputEvent(const HardwareAuthToken& secureInputToken) {
    ResponseCode rc = ResponseCode::Ignored;
    {
        /*
         * deliverSecureInputEvent is only used by the VTS test to mock human input. A correct
         * implementation responds with a mock confirmation token signed with a test key. The
         * problem is that the non interactive grace period was not formalized in the HAL spec,
         * so that the VTS test does not account for the grace period. (It probably should.)
         * This means we can only pass the VTS test if we block until the grace period is over
         * (SetupDone -> Interactive) before we deliver the input event.
         *
         * The true secure input is delivered by a different mechanism and gets ignored -
         * not queued - until the grace period is over.
         *
         */
        std::unique_lock<std::mutex> stateLock(listener_state_lock_);
        listener_state_condv_.wait(stateLock,
                                   [this] { return listener_state_ != ListenerState::SetupDone; });

        if (listener_state_ != ListenerState::Interactive) return ResponseCode::Ignored;
        auto sapp = app_.lock();
        if (!sapp) return ResponseCode::Ignored;
        auto [error, response] =
            sapp->issueCmd<DeliverTestCommandMessage, DeliverTestCommandResponse>(
                static_cast<teeui::TestModeCommands>(secureInputToken.challenge));
        if (error != TrustyAppError::OK) return ResponseCode::SystemError;
        auto& [trc] = response;
        if (trc != TeeuiRc::Ignored) secureInputDelivered_ = true;
        rc = convertRc(trc);
    }
    if (secureInputDelivered_) listener_state_condv_.notify_all();
    // VTS test expect an OK response if the event was successfully delivered.
    // But since the TA returns the callback response now, we have to translate
    // Canceled into OK. Canceled is only returned if the delivered event canceled
    // the operation, which means that the event was successfully delivered. Thus
    // we return OK.
    if (rc == ResponseCode::Canceled) return ResponseCode::OK;
    return rc;
}

Return<void> TrustyConfirmationUI::abort() {
    {
        std::unique_lock<std::mutex> stateLock(listener_state_lock_);
        if (listener_state_ == ListenerState::SetupDone ||
            listener_state_ == ListenerState::Interactive) {
            auto sapp = app_.lock();
            if (sapp) sapp->issueCmd<AbortMsg>();
            abort_called_ = true;
        }
    }
    listener_state_condv_.notify_all();
    return Void();
}

android::sp<IConfirmationUI> createTrustyConfirmationUI() {
    return new TrustyConfirmationUI();
}

}  // namespace implementation
}  // namespace V1_0
}  // namespace confirmationui
}  // namespace hardware
}  // namespace android
