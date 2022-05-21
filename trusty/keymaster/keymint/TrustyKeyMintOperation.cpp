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

#include <trusty_keymaster/TrustyKeyMintOperation.h>

#define TAG TrustyKeyMintOperation
#include <android-base/logging.h>

#include <aidl/android/hardware/security/keymint/ErrorCode.h>
#include <aidl/android/hardware/security/secureclock/ISecureClock.h>

#include <KeyMintUtils.h>
#include <keymaster/android_keymaster.h>
#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>

namespace aidl::android::hardware::security::keymint {

using ::keymaster::AbortOperationRequest;
using ::keymaster::AbortOperationResponse;
using ::keymaster::FinishOperationRequest;
using ::keymaster::FinishOperationResponse;
using ::keymaster::TAG_ASSOCIATED_DATA;
using ::keymaster::TAG_AUTH_TOKEN;
using ::keymaster::TAG_CONFIRMATION_TOKEN;
using ::keymaster::UpdateOperationRequest;
using ::keymaster::UpdateOperationResponse;
using km_utils::authToken2AidlVec;
using km_utils::kmError2ScopedAStatus;
using secureclock::TimeStampToken;

TrustyKeyMintOperation::TrustyKeyMintOperation(shared_ptr<TrustyKeymaster> implementation,
                                               keymaster_operation_handle_t opHandle)
    : impl_(std::move(implementation)), opHandle_(opHandle) {}

TrustyKeyMintOperation::~TrustyKeyMintOperation() {
    if (opHandle_ != 0) {
        abort();
    }
}

ScopedAStatus TrustyKeyMintOperation::updateAad(
        const vector<uint8_t>& input, const optional<HardwareAuthToken>& authToken,
        const optional<TimeStampToken>& /* timestampToken */) {
    UpdateOperationRequest request(impl_->message_version());
    request.op_handle = opHandle_;
    request.additional_params.push_back(TAG_ASSOCIATED_DATA, input.data(), input.size());
    if (authToken) {
        auto tokenAsVec(authToken2AidlVec(*authToken));
        request.additional_params.push_back(TAG_AUTH_TOKEN, tokenAsVec.data(), tokenAsVec.size());
    }

    UpdateOperationResponse response(impl_->message_version());
    impl_->UpdateOperation(request, &response);

    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus TrustyKeyMintOperation::update(const vector<uint8_t>& input,
                                             const optional<HardwareAuthToken>& authToken,
                                             const optional<TimeStampToken>& /* timestampToken */,
                                             vector<uint8_t>* output) {
    if (!output) return kmError2ScopedAStatus(KM_ERROR_OUTPUT_PARAMETER_NULL);

    UpdateOperationRequest request(impl_->message_version());
    request.op_handle = opHandle_;
    if (authToken) {
        auto tokenAsVec(authToken2AidlVec(*authToken));
        request.additional_params.push_back(TAG_AUTH_TOKEN, tokenAsVec.data(), tokenAsVec.size());
    }

    size_t serialized_size = request.SerializedSize();
    if (serialized_size > TRUSTY_KEYMASTER_SEND_BUF_SIZE) {
        return kmError2ScopedAStatus(KM_ERROR_INVALID_INPUT_LENGTH);
    }

    const uint8_t* input_pos = input.data();
    const uint8_t* input_end = input.data() + input.size();
    const size_t max_chunk_size = TRUSTY_KEYMASTER_SEND_BUF_SIZE - serialized_size;
    output->clear();

    while (input_pos < input_end) {
        size_t to_send = std::min(max_chunk_size, static_cast<size_t>(input_end - input_pos));
        LOG(DEBUG) << "update:  Sending " << to_send << " of " << (input_end - input_pos)
                   << " bytes";
        request.input.Reinitialize(input_pos, to_send);

        UpdateOperationResponse response(impl_->message_version());
        impl_->UpdateOperation(request, &response);
        if (response.error != KM_ERROR_OK) {
            opHandle_ = 0;  // Operation has ended, the handle is invalid.  This saves an abort().
            return kmError2ScopedAStatus(response.error);
        }

        input_pos += response.input_consumed;
        output->insert(output->end(), response.output.begin(), response.output.end());
    }

    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintOperation::finish(const optional<vector<uint8_t>>& input,      //
                                             const optional<vector<uint8_t>>& signature,  //
                                             const optional<HardwareAuthToken>& authToken,
                                             const optional<TimeStampToken>& /* timestampToken */,
                                             const optional<vector<uint8_t>>& confirmationToken,
                                             vector<uint8_t>* output) {
    if (!output) {
        return ScopedAStatus(AStatus_fromServiceSpecificError(
                static_cast<int32_t>(ErrorCode::OUTPUT_PARAMETER_NULL)));
    }
    output->clear();

    FinishOperationRequest request(impl_->message_version());

    if (authToken) {
        auto tokenAsVec(authToken2AidlVec(*authToken));
        request.additional_params.push_back(TAG_AUTH_TOKEN, tokenAsVec.data(), tokenAsVec.size());
    }
    if (confirmationToken) {
        request.additional_params.push_back(TAG_CONFIRMATION_TOKEN, confirmationToken->data(),
                                            confirmationToken->size());
    }

    request.op_handle = opHandle_;
    if (signature) request.signature.Reinitialize(signature->data(), signature->size());
    size_t serialized_size = request.SerializedSize();
    if (serialized_size > TRUSTY_KEYMASTER_SEND_BUF_SIZE) {
        return kmError2ScopedAStatus(KM_ERROR_INVALID_INPUT_LENGTH);
    }

    if (input) {
        const size_t max_chunk_size = TRUSTY_KEYMASTER_SEND_BUF_SIZE - serialized_size;

        if (input->size() > max_chunk_size) {
            LOG(DEBUG) << "Sending an update to process finish() data";
            // Use update to process all but the last max_chunk_size bytes.
            auto result = update({input->begin(), input->end() - max_chunk_size}, authToken,
                                 std::nullopt /* timestampToken */, output);
            if (!result.isOk()) return result;

            // Process the last max_chunk_size with finish.
            request.input.Reinitialize(input->data() + (input->size() - max_chunk_size),
                                       max_chunk_size);
        } else {
            request.input.Reinitialize(input->data(), input->size());
        }
    }

    FinishOperationResponse response(impl_->message_version());
    impl_->FinishOperation(request, &response);
    opHandle_ = 0;

    if (response.error != KM_ERROR_OK) return kmError2ScopedAStatus(response.error);

    *output = {response.output.begin(), response.output.end()};
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintOperation::abort() {
    AbortOperationRequest request(impl_->message_version());
    request.op_handle = opHandle_;

    AbortOperationResponse response(impl_->message_version());
    impl_->AbortOperation(request, &response);
    opHandle_ = 0;

    return kmError2ScopedAStatus(response.error);
}

}  // namespace aidl::android::hardware::security::keymint
