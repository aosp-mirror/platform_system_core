/*
 **
 ** Copyright 2018, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#define LOG_TAG "android.hardware.keymaster@4.0-impl.trusty"

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <cutils/log.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/authorization_set.h>
#include <keymaster_tags.h>
#include <trusty_keymaster/TrustyKeymaster4Device.h>
#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>

using ::keymaster::AbortOperationRequest;
using ::keymaster::AbortOperationResponse;
using ::keymaster::AddEntropyRequest;
using ::keymaster::AddEntropyResponse;
using ::keymaster::AttestKeyRequest;
using ::keymaster::AttestKeyResponse;
using ::keymaster::AuthorizationSet;
using ::keymaster::BeginOperationRequest;
using ::keymaster::BeginOperationResponse;
using ::keymaster::ExportKeyRequest;
using ::keymaster::ExportKeyResponse;
using ::keymaster::FinishOperationRequest;
using ::keymaster::FinishOperationResponse;
using ::keymaster::GenerateKeyRequest;
using ::keymaster::GenerateKeyResponse;
using ::keymaster::GetKeyCharacteristicsRequest;
using ::keymaster::GetKeyCharacteristicsResponse;
using ::keymaster::ImportKeyRequest;
using ::keymaster::ImportKeyResponse;
using ::keymaster::UpdateOperationRequest;
using ::keymaster::UpdateOperationResponse;
using ::keymaster::ng::Tag;

typedef ::android::hardware::keymaster::V3_0::Tag Tag3;
using ::android::hardware::keymaster::V4_0::Constants;

namespace keymaster {
namespace V4_0 {
namespace {

inline keymaster_tag_t legacy_enum_conversion(const Tag value) {
    return keymaster_tag_t(value);
}
inline Tag legacy_enum_conversion(const keymaster_tag_t value) {
    return Tag(value);
}
inline keymaster_purpose_t legacy_enum_conversion(const KeyPurpose value) {
    return keymaster_purpose_t(value);
}
inline keymaster_key_format_t legacy_enum_conversion(const KeyFormat value) {
    return keymaster_key_format_t(value);
}

inline SecurityLevel legacy_enum_conversion(const keymaster_security_level_t value) {
    return static_cast<SecurityLevel>(value);
}

inline hw_authenticator_type_t legacy_enum_conversion(const HardwareAuthenticatorType value) {
    return static_cast<hw_authenticator_type_t>(value);
}

inline ErrorCode legacy_enum_conversion(const keymaster_error_t value) {
    return ErrorCode(value);
}

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
}

/*
 * injectAuthToken translates a KM4 authToken into a legacy AUTH_TOKEN tag
 *
 * Currently, system/keymaster's reference implementation only accepts this
 * method for passing an auth token, so until that changes we need to
 * translate to the old format.
 */
inline hidl_vec<KeyParameter> injectAuthToken(const hidl_vec<KeyParameter>& keyParamsBase,
                                              const HardwareAuthToken& authToken) {
    std::vector<KeyParameter> keyParams(keyParamsBase);
    const size_t mac_len = static_cast<size_t>(Constants::AUTH_TOKEN_MAC_LENGTH);
    /*
     * mac.size() == 0 indicates no token provided, so we should not copy.
     * mac.size() != mac_len means it is incompatible with the old
     *   hw_auth_token_t structure. This is forbidden by spec, but to be safe
     *   we only copy if mac.size() == mac_len, e.g. there is an authToken
     *   with a hw_auth_token_t compatible MAC.
     */
    if (authToken.mac.size() == mac_len) {
        KeyParameter p;
        p.tag = static_cast<Tag>(Tag3::AUTH_TOKEN);
        p.blob.resize(sizeof(hw_auth_token_t));

        hw_auth_token_t* auth_token = reinterpret_cast<hw_auth_token_t*>(p.blob.data());
        auth_token->version = 0;
        auth_token->challenge = authToken.challenge;
        auth_token->user_id = authToken.userId;
        auth_token->authenticator_id = authToken.authenticatorId;
        auth_token->authenticator_type =
                htobe32(static_cast<uint32_t>(authToken.authenticatorType));
        auth_token->timestamp = htobe64(authToken.timestamp);
        static_assert(mac_len == sizeof(auth_token->hmac));
        memcpy(auth_token->hmac, authToken.mac.data(), mac_len);
        keyParams.push_back(p);
    }

    return hidl_vec<KeyParameter>(std::move(keyParams));
}

class KmParamSet : public keymaster_key_param_set_t {
  public:
    KmParamSet(const hidl_vec<KeyParameter>& keyParams) {
        params = new keymaster_key_param_t[keyParams.size()];
        length = keyParams.size();
        for (size_t i = 0; i < keyParams.size(); ++i) {
            auto tag = legacy_enum_conversion(keyParams[i].tag);
            switch (typeFromTag(tag)) {
                case KM_ENUM:
                case KM_ENUM_REP:
                    params[i] = keymaster_param_enum(tag, keyParams[i].f.integer);
                    break;
                case KM_UINT:
                case KM_UINT_REP:
                    params[i] = keymaster_param_int(tag, keyParams[i].f.integer);
                    break;
                case KM_ULONG:
                case KM_ULONG_REP:
                    params[i] = keymaster_param_long(tag, keyParams[i].f.longInteger);
                    break;
                case KM_DATE:
                    params[i] = keymaster_param_date(tag, keyParams[i].f.dateTime);
                    break;
                case KM_BOOL:
                    if (keyParams[i].f.boolValue)
                        params[i] = keymaster_param_bool(tag);
                    else
                        params[i].tag = KM_TAG_INVALID;
                    break;
                case KM_BIGNUM:
                case KM_BYTES:
                    params[i] = keymaster_param_blob(tag, &keyParams[i].blob[0],
                                                     keyParams[i].blob.size());
                    break;
                case KM_INVALID:
                default:
                    params[i].tag = KM_TAG_INVALID;
                    /* just skip */
                    break;
            }
        }
    }
    KmParamSet(KmParamSet&& other) noexcept
        : keymaster_key_param_set_t{other.params, other.length} {
        other.length = 0;
        other.params = nullptr;
    }
    KmParamSet(const KmParamSet&) = delete;
    ~KmParamSet() { delete[] params; }
};

inline hidl_vec<uint8_t> kmBlob2hidlVec(const keymaster_key_blob_t& blob) {
    hidl_vec<uint8_t> result;
    result.setToExternal(const_cast<unsigned char*>(blob.key_material), blob.key_material_size);
    return result;
}

inline hidl_vec<uint8_t> kmBlob2hidlVec(const keymaster_blob_t& blob) {
    hidl_vec<uint8_t> result;
    result.setToExternal(const_cast<unsigned char*>(blob.data), blob.data_length);
    return result;
}

inline hidl_vec<uint8_t> kmBuffer2hidlVec(const ::keymaster::Buffer& buf) {
    hidl_vec<uint8_t> result;
    result.setToExternal(const_cast<unsigned char*>(buf.peek_read()), buf.available_read());
    return result;
}

inline static hidl_vec<hidl_vec<uint8_t>> kmCertChain2Hidl(
        const keymaster_cert_chain_t& cert_chain) {
    hidl_vec<hidl_vec<uint8_t>> result;
    if (!cert_chain.entry_count || !cert_chain.entries) return result;

    result.resize(cert_chain.entry_count);
    for (size_t i = 0; i < cert_chain.entry_count; ++i) {
        result[i] = kmBlob2hidlVec(cert_chain.entries[i]);
    }

    return result;
}

static inline hidl_vec<KeyParameter> kmParamSet2Hidl(const keymaster_key_param_set_t& set) {
    hidl_vec<KeyParameter> result;
    if (set.length == 0 || set.params == nullptr) return result;

    result.resize(set.length);
    keymaster_key_param_t* params = set.params;
    for (size_t i = 0; i < set.length; ++i) {
        auto tag = params[i].tag;
        result[i].tag = legacy_enum_conversion(tag);
        switch (typeFromTag(tag)) {
            case KM_ENUM:
            case KM_ENUM_REP:
                result[i].f.integer = params[i].enumerated;
                break;
            case KM_UINT:
            case KM_UINT_REP:
                result[i].f.integer = params[i].integer;
                break;
            case KM_ULONG:
            case KM_ULONG_REP:
                result[i].f.longInteger = params[i].long_integer;
                break;
            case KM_DATE:
                result[i].f.dateTime = params[i].date_time;
                break;
            case KM_BOOL:
                result[i].f.boolValue = params[i].boolean;
                break;
            case KM_BIGNUM:
            case KM_BYTES:
                result[i].blob.setToExternal(const_cast<unsigned char*>(params[i].blob.data),
                                             params[i].blob.data_length);
                break;
            case KM_INVALID:
            default:
                params[i].tag = KM_TAG_INVALID;
                /* just skip */
                break;
        }
    }
    return result;
}

void addClientAndAppData(const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData,
                         ::keymaster::AuthorizationSet* params) {
    params->Clear();
    if (clientId.size()) {
        params->push_back(::keymaster::TAG_APPLICATION_ID, clientId.data(), clientId.size());
    }
    if (appData.size()) {
        params->push_back(::keymaster::TAG_APPLICATION_DATA, appData.data(), appData.size());
    }
}

}  // anonymous namespace

TrustyKeymaster4Device::TrustyKeymaster4Device(TrustyKeymaster* impl) : impl_(impl) {}

TrustyKeymaster4Device::~TrustyKeymaster4Device() {}

Return<void> TrustyKeymaster4Device::getHardwareInfo(getHardwareInfo_cb _hidl_cb) {
    _hidl_cb(SecurityLevel::TRUSTED_ENVIRONMENT, "TrustyKeymaster", "Google");
    return Void();
}

Return<void> TrustyKeymaster4Device::getHmacSharingParameters(
        getHmacSharingParameters_cb _hidl_cb) {
    const GetHmacSharingParametersResponse response = impl_->GetHmacSharingParameters();
    // response.params is not the same as the HIDL structure, we need to convert it
    V4_0::HmacSharingParameters params;
    params.seed.setToExternal(const_cast<uint8_t*>(response.params.seed.data),
                              response.params.seed.data_length);
    static_assert(sizeof(response.params.nonce) == params.nonce.size(), "Nonce sizes don't match");
    memcpy(params.nonce.data(), response.params.nonce, params.nonce.size());
    _hidl_cb(legacy_enum_conversion(response.error), params);
    return Void();
}

Return<void> TrustyKeymaster4Device::computeSharedHmac(
        const hidl_vec<HmacSharingParameters>& params, computeSharedHmac_cb _hidl_cb) {
    ComputeSharedHmacRequest request(impl_->message_version());
    request.params_array.params_array = new keymaster::HmacSharingParameters[params.size()];
    request.params_array.num_params = params.size();
    for (size_t i = 0; i < params.size(); ++i) {
        request.params_array.params_array[i].seed = {params[i].seed.data(), params[i].seed.size()};
        static_assert(sizeof(request.params_array.params_array[i].nonce) ==
                              decltype(params[i].nonce)::size(),
                      "Nonce sizes don't match");
        memcpy(request.params_array.params_array[i].nonce, params[i].nonce.data(),
               params[i].nonce.size());
    }

    auto response = impl_->ComputeSharedHmac(request);
    hidl_vec<uint8_t> sharing_check;
    if (response.error == KM_ERROR_OK) {
        sharing_check = kmBlob2hidlVec(response.sharing_check);
    }

    _hidl_cb(legacy_enum_conversion(response.error), sharing_check);
    return Void();
}

Return<void> TrustyKeymaster4Device::verifyAuthorization(
        uint64_t challenge, const hidl_vec<KeyParameter>& parametersToVerify,
        const HardwareAuthToken& authToken, verifyAuthorization_cb _hidl_cb) {
    VerifyAuthorizationRequest request(impl_->message_version());
    request.challenge = challenge;
    request.parameters_to_verify.Reinitialize(KmParamSet(parametersToVerify));
    request.auth_token.challenge = authToken.challenge;
    request.auth_token.user_id = authToken.userId;
    request.auth_token.authenticator_id = authToken.authenticatorId;
    request.auth_token.authenticator_type = legacy_enum_conversion(authToken.authenticatorType);
    request.auth_token.timestamp = authToken.timestamp;
    KeymasterBlob mac(authToken.mac.data(), authToken.mac.size());
    request.auth_token.mac = mac;

    auto response = impl_->VerifyAuthorization(request);

    ::android::hardware::keymaster::V4_0::VerificationToken token;
    token.challenge = response.token.challenge;
    token.timestamp = response.token.timestamp;
    token.parametersVerified = kmParamSet2Hidl(response.token.parameters_verified);
    token.securityLevel = legacy_enum_conversion(response.token.security_level);
    token.mac = kmBlob2hidlVec(response.token.mac);

    _hidl_cb(legacy_enum_conversion(response.error), token);

    return Void();
}

Return<ErrorCode> TrustyKeymaster4Device::addRngEntropy(const hidl_vec<uint8_t>& data) {
    if (data.size() == 0) return ErrorCode::OK;
    AddEntropyRequest request(impl_->message_version());
    request.random_data.Reinitialize(data.data(), data.size());

    AddEntropyResponse response(impl_->message_version());
    impl_->AddRngEntropy(request, &response);

    return legacy_enum_conversion(response.error);
}

Return<void> TrustyKeymaster4Device::generateKey(const hidl_vec<KeyParameter>& keyParams,
                                                 generateKey_cb _hidl_cb) {
    GenerateKeyRequest request(impl_->message_version());
    request.key_description.Reinitialize(KmParamSet(keyParams));

    GenerateKeyResponse response(impl_->message_version());
    impl_->GenerateKey(request, &response);

    KeyCharacteristics resultCharacteristics;
    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob = kmBlob2hidlVec(response.key_blob);
        resultCharacteristics.hardwareEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob, resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster4Device::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob,
                                                           const hidl_vec<uint8_t>& clientId,
                                                           const hidl_vec<uint8_t>& appData,
                                                           getKeyCharacteristics_cb _hidl_cb) {
    GetKeyCharacteristicsRequest request(impl_->message_version());
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    addClientAndAppData(clientId, appData, &request.additional_params);

    GetKeyCharacteristicsResponse response(impl_->message_version());
    impl_->GetKeyCharacteristics(request, &response);

    KeyCharacteristics resultCharacteristics;
    if (response.error == KM_ERROR_OK) {
        resultCharacteristics.hardwareEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster4Device::importKey(const hidl_vec<KeyParameter>& params,
                                               KeyFormat keyFormat,
                                               const hidl_vec<uint8_t>& keyData,
                                               importKey_cb _hidl_cb) {
    ImportKeyRequest request(impl_->message_version());
    request.key_description.Reinitialize(KmParamSet(params));
    request.key_format = legacy_enum_conversion(keyFormat);
    request.key_data = KeymasterKeyBlob(keyData.data(), keyData.size());

    ImportKeyResponse response(impl_->message_version());
    impl_->ImportKey(request, &response);

    KeyCharacteristics resultCharacteristics;
    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob = kmBlob2hidlVec(response.key_blob);
        resultCharacteristics.hardwareEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob, resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster4Device::importWrappedKey(
        const hidl_vec<uint8_t>& wrappedKeyData, const hidl_vec<uint8_t>& wrappingKeyBlob,
        const hidl_vec<uint8_t>& maskingKey, const hidl_vec<KeyParameter>& unwrappingParams,
        uint64_t passwordSid, uint64_t biometricSid, importWrappedKey_cb _hidl_cb) {
    ImportWrappedKeyRequest request(impl_->message_version());
    request.SetWrappedMaterial(wrappedKeyData.data(), wrappedKeyData.size());
    request.SetWrappingMaterial(wrappingKeyBlob.data(), wrappingKeyBlob.size());
    request.SetMaskingKeyMaterial(maskingKey.data(), maskingKey.size());
    request.additional_params.Reinitialize(KmParamSet(unwrappingParams));
    request.password_sid = passwordSid;
    request.biometric_sid = biometricSid;

    ImportWrappedKeyResponse response(impl_->message_version());
    impl_->ImportWrappedKey(request, &response);

    KeyCharacteristics resultCharacteristics;
    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob = kmBlob2hidlVec(response.key_blob);
        resultCharacteristics.hardwareEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob, resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster4Device::exportKey(KeyFormat exportFormat,
                                               const hidl_vec<uint8_t>& keyBlob,
                                               const hidl_vec<uint8_t>& clientId,
                                               const hidl_vec<uint8_t>& appData,
                                               exportKey_cb _hidl_cb) {
    ExportKeyRequest request(impl_->message_version());
    request.key_format = legacy_enum_conversion(exportFormat);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    addClientAndAppData(clientId, appData, &request.additional_params);

    ExportKeyResponse response(impl_->message_version());
    impl_->ExportKey(request, &response);

    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob.setToExternal(response.key_data, response.key_data_length);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob);
    return Void();
}

Return<void> TrustyKeymaster4Device::attestKey(const hidl_vec<uint8_t>& keyToAttest,
                                               const hidl_vec<KeyParameter>& attestParams,
                                               attestKey_cb _hidl_cb) {
    AttestKeyRequest request(impl_->message_version());
    request.SetKeyMaterial(keyToAttest.data(), keyToAttest.size());
    request.attest_params.Reinitialize(KmParamSet(attestParams));

    AttestKeyResponse response(impl_->message_version());
    impl_->AttestKey(request, &response);

    hidl_vec<hidl_vec<uint8_t>> resultCertChain;
    if (response.error == KM_ERROR_OK) {
        resultCertChain = kmCertChain2Hidl(response.certificate_chain);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultCertChain);
    return Void();
}

Return<void> TrustyKeymaster4Device::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade,
                                                const hidl_vec<KeyParameter>& upgradeParams,
                                                upgradeKey_cb _hidl_cb) {
    UpgradeKeyRequest request(impl_->message_version());
    request.SetKeyMaterial(keyBlobToUpgrade.data(), keyBlobToUpgrade.size());
    request.upgrade_params.Reinitialize(KmParamSet(upgradeParams));

    UpgradeKeyResponse response(impl_->message_version());
    impl_->UpgradeKey(request, &response);

    if (response.error == KM_ERROR_OK) {
        _hidl_cb(ErrorCode::OK, kmBlob2hidlVec(response.upgraded_key));
    } else {
        _hidl_cb(legacy_enum_conversion(response.error), hidl_vec<uint8_t>());
    }
    return Void();
}

Return<ErrorCode> TrustyKeymaster4Device::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    DeleteKeyRequest request(impl_->message_version());
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());

    DeleteKeyResponse response(impl_->message_version());
    impl_->DeleteKey(request, &response);

    return legacy_enum_conversion(response.error);
}

Return<ErrorCode> TrustyKeymaster4Device::deleteAllKeys() {
    DeleteAllKeysRequest request(impl_->message_version());
    DeleteAllKeysResponse response(impl_->message_version());
    impl_->DeleteAllKeys(request, &response);

    return legacy_enum_conversion(response.error);
}

Return<ErrorCode> TrustyKeymaster4Device::destroyAttestationIds() {
    return ErrorCode::UNIMPLEMENTED;
}

Return<void> TrustyKeymaster4Device::begin(KeyPurpose purpose, const hidl_vec<uint8_t>& key,
                                           const hidl_vec<KeyParameter>& inParams,
                                           const HardwareAuthToken& authToken, begin_cb _hidl_cb) {
    hidl_vec<KeyParameter> extendedParams = injectAuthToken(inParams, authToken);
    BeginOperationRequest request(impl_->message_version());
    request.purpose = legacy_enum_conversion(purpose);
    request.SetKeyMaterial(key.data(), key.size());
    request.additional_params.Reinitialize(KmParamSet(extendedParams));

    BeginOperationResponse response(impl_->message_version());
    impl_->BeginOperation(request, &response);

    hidl_vec<KeyParameter> resultParams;
    if (response.error == KM_ERROR_OK) {
        resultParams = kmParamSet2Hidl(response.output_params);
    }

    _hidl_cb(legacy_enum_conversion(response.error), resultParams, response.op_handle);
    return Void();
}

Return<void> TrustyKeymaster4Device::update(uint64_t operationHandle,
                                            const hidl_vec<KeyParameter>& inParams,
                                            const hidl_vec<uint8_t>& input,
                                            const HardwareAuthToken& authToken,
                                            const VerificationToken& verificationToken,
                                            update_cb _hidl_cb) {
    (void)verificationToken;
    UpdateOperationRequest request(impl_->message_version());
    UpdateOperationResponse response(impl_->message_version());
    hidl_vec<KeyParameter> resultParams;
    hidl_vec<uint8_t> resultBlob;
    hidl_vec<KeyParameter> extendedParams = injectAuthToken(inParams, authToken);
    uint32_t resultConsumed = 0;

    request.op_handle = operationHandle;
    request.additional_params.Reinitialize(KmParamSet(extendedParams));

    size_t inp_size = input.size();
    size_t ser_size = request.SerializedSize();

    if (ser_size > TRUSTY_KEYMASTER_SEND_BUF_SIZE) {
        response.error = KM_ERROR_INVALID_INPUT_LENGTH;
    } else {
        if (ser_size + inp_size > TRUSTY_KEYMASTER_SEND_BUF_SIZE) {
            inp_size = TRUSTY_KEYMASTER_SEND_BUF_SIZE - ser_size;
        }
        request.input.Reinitialize(input.data(), inp_size);

        impl_->UpdateOperation(request, &response);

        if (response.error == KM_ERROR_OK) {
            resultConsumed = response.input_consumed;
            resultParams = kmParamSet2Hidl(response.output_params);
            resultBlob = kmBuffer2hidlVec(response.output);
        }
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultConsumed, resultParams, resultBlob);
    return Void();
}

Return<void> TrustyKeymaster4Device::finish(uint64_t operationHandle,
                                            const hidl_vec<KeyParameter>& inParams,
                                            const hidl_vec<uint8_t>& input,
                                            const hidl_vec<uint8_t>& signature,
                                            const HardwareAuthToken& authToken,
                                            const VerificationToken& verificationToken,
                                            finish_cb _hidl_cb) {
    (void)verificationToken;
    FinishOperationRequest request(impl_->message_version());
    hidl_vec<KeyParameter> extendedParams = injectAuthToken(inParams, authToken);
    request.op_handle = operationHandle;
    request.input.Reinitialize(input.data(), input.size());
    request.signature.Reinitialize(signature.data(), signature.size());
    request.additional_params.Reinitialize(KmParamSet(extendedParams));

    FinishOperationResponse response(impl_->message_version());
    impl_->FinishOperation(request, &response);

    hidl_vec<KeyParameter> resultParams;
    hidl_vec<uint8_t> resultBlob;
    if (response.error == KM_ERROR_OK) {
        resultParams = kmParamSet2Hidl(response.output_params);
        resultBlob = kmBuffer2hidlVec(response.output);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultParams, resultBlob);
    return Void();
}

Return<ErrorCode> TrustyKeymaster4Device::abort(uint64_t operationHandle) {
    AbortOperationRequest request(impl_->message_version());
    request.op_handle = operationHandle;

    AbortOperationResponse response(impl_->message_version());
    impl_->AbortOperation(request, &response);

    return legacy_enum_conversion(response.error);
}
}  // namespace V4_0
}  // namespace keymaster
