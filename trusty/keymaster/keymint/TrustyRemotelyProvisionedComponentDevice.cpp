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

#include <trusty_keymaster/TrustyRemotelyProvisionedComponentDevice.h>

#include <assert.h>
#include <variant>

#include <KeyMintUtils.h>
#include <keymaster/keymaster_configuration.h>

#include <trusty_keymaster/TrustyKeyMintDevice.h>

namespace aidl::android::hardware::security::keymint::trusty {

using keymaster::GenerateCsrRequest;
using keymaster::GenerateCsrResponse;
using keymaster::GenerateCsrV2Request;
using keymaster::GenerateCsrV2Response;
using keymaster::GenerateRkpKeyRequest;
using keymaster::GenerateRkpKeyResponse;
using keymaster::GetHwInfoRequest;
using keymaster::GetHwInfoResponse;
using keymaster::KeymasterBlob;
using km_utils::kmError2ScopedAStatus;
using ::std::string;
using ::std::unique_ptr;
using ::std::vector;
using bytevec = ::std::vector<uint8_t>;

namespace {

constexpr auto STATUS_FAILED = IRemotelyProvisionedComponent::STATUS_FAILED;

struct AStatusDeleter {
    void operator()(AStatus* p) { AStatus_delete(p); }
};

class Status {
  public:
    Status() : status_(AStatus_newOk()) {}
    Status(int32_t errCode, const std::string& errMsg)
        : status_(AStatus_fromServiceSpecificErrorWithMessage(errCode, errMsg.c_str())) {}
    explicit Status(const std::string& errMsg)
        : status_(AStatus_fromServiceSpecificErrorWithMessage(STATUS_FAILED, errMsg.c_str())) {}
    explicit Status(AStatus* status) : status_(status ? status : AStatus_newOk()) {}

    Status(Status&&) = default;
    Status(const Status&) = delete;

    operator ::ndk::ScopedAStatus() && {  // NOLINT(google-explicit-constructor)
        return ndk::ScopedAStatus(status_.release());
    }

    bool isOk() const { return AStatus_isOk(status_.get()); }

    const char* getMessage() const { return AStatus_getMessage(status_.get()); }

  private:
    std::unique_ptr<AStatus, AStatusDeleter> status_;
};

}  // namespace

ScopedAStatus TrustyRemotelyProvisionedComponentDevice::getHardwareInfo(RpcHardwareInfo* info) {
    GetHwInfoResponse response = impl_->GetHwInfo();
    if (response.error != KM_ERROR_OK) {
        return Status(-static_cast<int32_t>(response.error), "Failed to get hardware info.");
    }

    info->versionNumber = response.version;
    info->rpcAuthorName = std::move(response.rpcAuthorName);
    info->supportedEekCurve = response.supportedEekCurve;
    info->uniqueId = std::move(response.uniqueId);
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyRemotelyProvisionedComponentDevice::generateEcdsaP256KeyPair(
        bool testMode, MacedPublicKey* macedPublicKey, bytevec* privateKeyHandle) {
    GenerateRkpKeyRequest request(impl_->message_version());
    request.test_mode = testMode;
    GenerateRkpKeyResponse response(impl_->message_version());
    impl_->GenerateRkpKey(request, &response);
    if (response.error != KM_ERROR_OK) {
        return Status(-static_cast<int32_t>(response.error), "Failure in key generation.");
    }

    macedPublicKey->macedKey = km_utils::kmBlob2vector(response.maced_public_key);
    *privateKeyHandle = km_utils::kmBlob2vector(response.key_blob);
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyRemotelyProvisionedComponentDevice::generateCertificateRequest(
        bool testMode, const vector<MacedPublicKey>& keysToSign,
        const bytevec& endpointEncCertChain, const bytevec& challenge, DeviceInfo* deviceInfo,
        ProtectedData* protectedData, bytevec* keysToSignMac) {
    GenerateCsrRequest request(impl_->message_version());
    request.test_mode = testMode;
    request.num_keys = keysToSign.size();
    request.keys_to_sign_array = new KeymasterBlob[keysToSign.size()];
    for (size_t i = 0; i < keysToSign.size(); i++) {
        request.SetKeyToSign(i, keysToSign[i].macedKey.data(), keysToSign[i].macedKey.size());
    }
    request.SetEndpointEncCertChain(endpointEncCertChain.data(), endpointEncCertChain.size());
    request.SetChallenge(challenge.data(), challenge.size());
    GenerateCsrResponse response(impl_->message_version());
    impl_->GenerateCsr(request, &response);

    if (response.error != KM_ERROR_OK) {
        return Status(-static_cast<int32_t>(response.error), "Failure in CSR Generation.");
    }
    deviceInfo->deviceInfo = km_utils::kmBlob2vector(response.device_info_blob);
    protectedData->protectedData = km_utils::kmBlob2vector(response.protected_data_blob);
    *keysToSignMac = km_utils::kmBlob2vector(response.keys_to_sign_mac);
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyRemotelyProvisionedComponentDevice::generateCertificateRequestV2(
        const std::vector<MacedPublicKey>& keysToSign, const std::vector<uint8_t>& challenge,
        std::vector<uint8_t>* csr) {
    GenerateCsrV2Request request(impl_->message_version());
    if (!request.InitKeysToSign(keysToSign.size())) {
        return kmError2ScopedAStatus(static_cast<keymaster_error_t>(STATUS_FAILED));
    }
    for (size_t i = 0; i < keysToSign.size(); i++) {
        request.SetKeyToSign(i, keysToSign[i].macedKey.data(), keysToSign[i].macedKey.size());
    }
    request.SetChallenge(challenge.data(), challenge.size());
    GenerateCsrV2Response response(impl_->message_version());
    impl_->GenerateCsrV2(request, &response);

    if (response.error != KM_ERROR_OK) {
        return Status(-static_cast<int32_t>(response.error), "Failure in CSR v2 generation.");
    }
    *csr = km_utils::kmBlob2vector(response.csr);
    return ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::security::keymint::trusty
