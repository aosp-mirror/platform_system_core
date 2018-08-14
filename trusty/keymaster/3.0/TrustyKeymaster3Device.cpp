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

#define LOG_TAG "android.hardware.keymaster@3.0-impl.trusty"

#include <authorization_set.h>
#include <cutils/log.h>
#include <keymaster/android_keymaster_messages.h>
#include <trusty_keymaster/TrustyKeymaster3Device.h>

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

namespace keymaster {

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
inline ErrorCode legacy_enum_conversion(const keymaster_error_t value) {
    return ErrorCode(value);
}

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
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
    KmParamSet(KmParamSet&& other) : keymaster_key_param_set_t{other.params, other.length} {
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

TrustyKeymaster3Device::TrustyKeymaster3Device(TrustyKeymaster* impl) : impl_(impl) {}

TrustyKeymaster3Device::~TrustyKeymaster3Device() {}

Return<void> TrustyKeymaster3Device::getHardwareFeatures(getHardwareFeatures_cb _hidl_cb) {
    _hidl_cb(true /* is_secure */, true /* supports_ec */,
             true /* supports_symmetric_cryptography */, true /* supports_attestation */,
             true /* supportsAllDigests */, "TrustyKeymaster", "Google");
    return Void();
}

Return<ErrorCode> TrustyKeymaster3Device::addRngEntropy(const hidl_vec<uint8_t>& data) {
    if (data.size() == 0) return ErrorCode::OK;
    AddEntropyRequest request;
    request.random_data.Reinitialize(data.data(), data.size());

    AddEntropyResponse response;
    impl_->AddRngEntropy(request, &response);

    return legacy_enum_conversion(response.error);
}

Return<void> TrustyKeymaster3Device::generateKey(const hidl_vec<KeyParameter>& keyParams,
                                                 generateKey_cb _hidl_cb) {
    GenerateKeyRequest request;
    request.key_description.Reinitialize(KmParamSet(keyParams));

    GenerateKeyResponse response;
    impl_->GenerateKey(request, &response);

    KeyCharacteristics resultCharacteristics;
    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob = kmBlob2hidlVec(response.key_blob);
        resultCharacteristics.teeEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob, resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster3Device::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob,
                                                           const hidl_vec<uint8_t>& clientId,
                                                           const hidl_vec<uint8_t>& appData,
                                                           getKeyCharacteristics_cb _hidl_cb) {
    GetKeyCharacteristicsRequest request;
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    addClientAndAppData(clientId, appData, &request.additional_params);

    GetKeyCharacteristicsResponse response;
    impl_->GetKeyCharacteristics(request, &response);

    KeyCharacteristics resultCharacteristics;
    if (response.error == KM_ERROR_OK) {
        resultCharacteristics.teeEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster3Device::importKey(const hidl_vec<KeyParameter>& params,
                                               KeyFormat keyFormat,
                                               const hidl_vec<uint8_t>& keyData,
                                               importKey_cb _hidl_cb) {
    ImportKeyRequest request;
    request.key_description.Reinitialize(KmParamSet(params));
    request.key_format = legacy_enum_conversion(keyFormat);
    request.SetKeyMaterial(keyData.data(), keyData.size());

    ImportKeyResponse response;
    impl_->ImportKey(request, &response);

    KeyCharacteristics resultCharacteristics;
    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob = kmBlob2hidlVec(response.key_blob);
        resultCharacteristics.teeEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob, resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster3Device::exportKey(KeyFormat exportFormat,
                                               const hidl_vec<uint8_t>& keyBlob,
                                               const hidl_vec<uint8_t>& clientId,
                                               const hidl_vec<uint8_t>& appData,
                                               exportKey_cb _hidl_cb) {
    ExportKeyRequest request;
    request.key_format = legacy_enum_conversion(exportFormat);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    addClientAndAppData(clientId, appData, &request.additional_params);

    ExportKeyResponse response;
    impl_->ExportKey(request, &response);

    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob.setToExternal(response.key_data, response.key_data_length);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob);
    return Void();
}

Return<void> TrustyKeymaster3Device::attestKey(const hidl_vec<uint8_t>& keyToAttest,
                                               const hidl_vec<KeyParameter>& attestParams,
                                               attestKey_cb _hidl_cb) {
    AttestKeyRequest request;
    request.SetKeyMaterial(keyToAttest.data(), keyToAttest.size());
    request.attest_params.Reinitialize(KmParamSet(attestParams));

    AttestKeyResponse response;
    impl_->AttestKey(request, &response);

    hidl_vec<hidl_vec<uint8_t>> resultCertChain;
    if (response.error == KM_ERROR_OK) {
        resultCertChain = kmCertChain2Hidl(response.certificate_chain);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultCertChain);
    return Void();
}

Return<void> TrustyKeymaster3Device::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade,
                                                const hidl_vec<KeyParameter>& upgradeParams,
                                                upgradeKey_cb _hidl_cb) {
    UpgradeKeyRequest request;
    request.SetKeyMaterial(keyBlobToUpgrade.data(), keyBlobToUpgrade.size());
    request.upgrade_params.Reinitialize(KmParamSet(upgradeParams));

    UpgradeKeyResponse response;
    impl_->UpgradeKey(request, &response);

    if (response.error == KM_ERROR_OK) {
        _hidl_cb(ErrorCode::OK, kmBlob2hidlVec(response.upgraded_key));
    } else {
        _hidl_cb(legacy_enum_conversion(response.error), hidl_vec<uint8_t>());
    }
    return Void();
}

Return<ErrorCode> TrustyKeymaster3Device::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    DeleteKeyRequest request;
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());

    DeleteKeyResponse response;
    impl_->DeleteKey(request, &response);

    return legacy_enum_conversion(response.error);
}

Return<ErrorCode> TrustyKeymaster3Device::deleteAllKeys() {
    DeleteAllKeysRequest request;
    DeleteAllKeysResponse response;
    impl_->DeleteAllKeys(request, &response);

    return legacy_enum_conversion(response.error);
}

Return<ErrorCode> TrustyKeymaster3Device::destroyAttestationIds() {
    return ErrorCode::UNIMPLEMENTED;
}

Return<void> TrustyKeymaster3Device::begin(KeyPurpose purpose, const hidl_vec<uint8_t>& key,
                                           const hidl_vec<KeyParameter>& inParams,
                                           begin_cb _hidl_cb) {
    BeginOperationRequest request;
    request.purpose = legacy_enum_conversion(purpose);
    request.SetKeyMaterial(key.data(), key.size());
    request.additional_params.Reinitialize(KmParamSet(inParams));

    BeginOperationResponse response;
    impl_->BeginOperation(request, &response);

    hidl_vec<KeyParameter> resultParams;
    if (response.error == KM_ERROR_OK) {
        resultParams = kmParamSet2Hidl(response.output_params);
    }

    _hidl_cb(legacy_enum_conversion(response.error), resultParams, response.op_handle);
    return Void();
}

Return<void> TrustyKeymaster3Device::update(uint64_t operationHandle,
                                            const hidl_vec<KeyParameter>& inParams,
                                            const hidl_vec<uint8_t>& input, update_cb _hidl_cb) {
    UpdateOperationRequest request;
    request.op_handle = operationHandle;
    request.input.Reinitialize(input.data(), input.size());
    request.additional_params.Reinitialize(KmParamSet(inParams));

    UpdateOperationResponse response;
    impl_->UpdateOperation(request, &response);

    uint32_t resultConsumed = 0;
    hidl_vec<KeyParameter> resultParams;
    hidl_vec<uint8_t> resultBlob;
    if (response.error == KM_ERROR_OK) {
        resultConsumed = response.input_consumed;
        resultParams = kmParamSet2Hidl(response.output_params);
        resultBlob = kmBuffer2hidlVec(response.output);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultConsumed, resultParams, resultBlob);
    return Void();
}

Return<void> TrustyKeymaster3Device::finish(uint64_t operationHandle,
                                            const hidl_vec<KeyParameter>& inParams,
                                            const hidl_vec<uint8_t>& input,
                                            const hidl_vec<uint8_t>& signature,
                                            finish_cb _hidl_cb) {
    FinishOperationRequest request;
    request.op_handle = operationHandle;
    request.input.Reinitialize(input.data(), input.size());
    request.signature.Reinitialize(signature.data(), signature.size());
    request.additional_params.Reinitialize(KmParamSet(inParams));

    FinishOperationResponse response;
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

Return<ErrorCode> TrustyKeymaster3Device::abort(uint64_t operationHandle) {
    AbortOperationRequest request;
    request.op_handle = operationHandle;

    AbortOperationResponse response;
    impl_->AbortOperation(request, &response);

    return legacy_enum_conversion(response.error);
}
}  // namespace keymaster
