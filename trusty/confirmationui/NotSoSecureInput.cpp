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
#include <endian.h>
#include <memory>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <secure_input/evdev.h>
#include <secure_input/secure_input_device.h>
#include <teeui/utils.h>

#include <initializer_list>

using namespace secure_input;

using teeui::AuthTokenKey;
using teeui::ByteBufferProxy;
using teeui::Hmac;
using teeui::optional;
using teeui::ResponseCode;
using teeui::TestKeyBits;

constexpr const auto kTestKey = AuthTokenKey::fill(static_cast<uint8_t>(TestKeyBits::BYTE));

class SecureInputHMacer {
  public:
    static optional<Hmac> hmac256(const AuthTokenKey& key,
                                  std::initializer_list<ByteBufferProxy> buffers) {
        HMAC_CTX hmacCtx;
        HMAC_CTX_init(&hmacCtx);
        if (!HMAC_Init_ex(&hmacCtx, key.data(), key.size(), EVP_sha256(), nullptr)) {
            return {};
        }
        for (auto& buffer : buffers) {
            if (!HMAC_Update(&hmacCtx, buffer.data(), buffer.size())) {
                return {};
            }
        }
        Hmac result;
        if (!HMAC_Final(&hmacCtx, result.data(), nullptr)) {
            return {};
        }
        return result;
    }
};

using HMac = teeui::HMac<SecureInputHMacer>;

Nonce generateNonce() {
    /*
     * Completely random nonce.
     * Running the secure input protocol from the HAL service is not secure
     * because we don't trust the non-secure world (i.e., HLOS/Android/Linux). So
     * using a constant "nonce" here does not weaken security. If this code runs
     * on a truly trustworthy source of input events this function needs to return
     * hight entropy nonces.
     * As of this writing the call to RAND_bytes is commented, because the
     * emulator this HAL service runs on does not have a good source of entropy.
     * It would block the call to RAND_bytes indefinitely.
     */
    Nonce result{0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
    // RAND_bytes(result.data(), result.size());
    return result;
}

/**
 * This is an implementation of the SecureInput protocol in unserspace. This is
 * just an example and should not be used as is. The protocol implemented her
 * should be used by a trusted input device that can assert user events with
 * high assurance even if the HLOS kernel is compromised. A confirmationui HAL
 * that links directly against this implementation is not secure and shal not be
 * used on a production device.
 */
class NotSoSecureInput : public SecureInput {
  public:
    NotSoSecureInput(HsBeginCb hsBeginCb, HsFinalizeCb hsFinalizeCb, DeliverEventCb deliverEventCb,
                     InputResultCb inputResultCb)
        : hsBeginCb_{hsBeginCb}, hsFinalizeCb_{hsFinalizeCb}, deliverEventCb_{deliverEventCb},
          inputResultCb_{inputResultCb}, discardEvents_{true} {}

    operator bool() const override { return true; }

    void handleEvent(const EventDev& evdev) override {
        bool gotEvent;
        input_event evt;
        std::tie(gotEvent, evt) = evdev.readEvent();
        while (gotEvent) {
            if (!(discardEvents_) && evt.type == EV_KEY &&
                (evt.code == KEY_POWER || evt.code == KEY_VOLUMEDOWN || evt.code == KEY_VOLUMEUP) &&
                evt.value == 1) {
                DTupKeyEvent event = DTupKeyEvent::RESERVED;

                // Translate the event code into DTupKeyEvent which the TA understands.
                switch (evt.code) {
                case KEY_POWER:
                    event = DTupKeyEvent::PWR;
                    break;
                case KEY_VOLUMEDOWN:
                    event = DTupKeyEvent::VOL_DOWN;
                    break;
                case KEY_VOLUMEUP:
                    event = DTupKeyEvent::VOL_UP;
                    break;
                }

                // The event goes into the HMAC in network byte order.
                uint32_t keyEventBE = htobe32(static_cast<uint32_t>(event));
                auto signature = HMac::hmac256(kTestKey, kConfirmationUIEventLabel,
                                               teeui::bytesCast(keyEventBE), nCi_);

                teeui::ResponseCode rc;
                InputResponse ir;
                auto response = std::tie(rc, ir);
                if (event != DTupKeyEvent::RESERVED) {
                    response = deliverEventCb_(event, *signature);
                    if (rc != ResponseCode::OK) {
                        LOG(ERROR) << "DeliverInputEvent returned with " << uint32_t(rc);
                        inputResultCb_(rc);
                    } else {
                        switch (ir) {
                        case InputResponse::OK:
                            inputResultCb_(rc);
                            break;
                        case InputResponse::PENDING_MORE:
                            rc = performDTUPHandshake();
                            if (rc != ResponseCode::OK) {
                                inputResultCb_(rc);
                            }
                            break;
                        case InputResponse::TIMED_OUT:
                            inputResultCb_(rc);
                            break;
                        }
                    }
                }
            }
            std::tie(gotEvent, evt) = evdev.readEvent();
        }
    }

    void start() override {
        auto rc = performDTUPHandshake();
        if (rc != ResponseCode::OK) {
            inputResultCb_(rc);
        }
        discardEvents_ = false;
    };

  private:
    teeui::ResponseCode performDTUPHandshake() {
        ResponseCode rc;
        LOG(INFO) << "Start handshake";
        Nonce nCo;
        std::tie(rc, nCo) = hsBeginCb_();
        if (rc != ResponseCode::OK) {
            LOG(ERROR) << "Failed to begin secure input handshake (" << uint32_t(rc) << ")";
            return rc;
        }

        nCi_ = generateNonce();
        rc =
            hsFinalizeCb_(*HMac::hmac256(kTestKey, kConfirmationUIHandshakeLabel, nCo, nCi_), nCi_);

        if (rc != ResponseCode::OK) {
            LOG(ERROR) << "Failed to finalize secure input handshake (" << uint32_t(rc) << ")";
            return rc;
        }
        return ResponseCode::OK;
    }

    HsBeginCb hsBeginCb_;
    HsFinalizeCb hsFinalizeCb_;
    DeliverEventCb deliverEventCb_;
    InputResultCb inputResultCb_;

    std::atomic_bool discardEvents_;
    Nonce nCi_;
};

namespace secure_input {

std::shared_ptr<SecureInput> createSecureInput(SecureInput::HsBeginCb hsBeginCb,
                                               SecureInput::HsFinalizeCb hsFinalizeCb,
                                               SecureInput::DeliverEventCb deliverEventCb,
                                               SecureInput::InputResultCb inputResultCb) {
    return std::make_shared<NotSoSecureInput>(hsBeginCb, hsFinalizeCb, deliverEventCb,
                                              inputResultCb);
}

}  // namespace secure_input
