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

#include <trusty_keymaster/TrustyKeyMintDevice.h>

#define TAG TrustyKeyMintDevice
#include <android-base/logging.h>

#include <keymaster/android_keymaster_messages.h>
#include <keymaster/authorization_set.h>

#include <KeyMintUtils.h>

#include <trusty_keymaster/TrustyKeyMintOperation.h>

namespace aidl::android::hardware::security::keymint::trusty {

using keymaster::KeymasterBlob;
using keymaster::KeymasterKeyBlob;
using keymaster::TAG_APPLICATION_DATA;
using keymaster::TAG_APPLICATION_ID;
using keymaster::TAG_AUTH_TOKEN;
using km_utils::authToken2AidlVec;
using km_utils::kmBlob2vector;
using km_utils::kmError2ScopedAStatus;
using km_utils::kmParam2Aidl;
using km_utils::KmParamSet;
using km_utils::kmParamSet2Aidl;
using km_utils::legacy_enum_conversion;

namespace {

auto kSecurityLevel = SecurityLevel::TRUSTED_ENVIRONMENT;

KeyCharacteristics convertAuthSet(SecurityLevel securityLevel,
                                  const keymaster::AuthorizationSet& authorizations) {
    KeyCharacteristics retval{securityLevel, {}};
    std::transform(authorizations.begin(), authorizations.end(),
                   std::back_inserter(retval.authorizations), kmParam2Aidl);
    return retval;
}

vector<KeyCharacteristics> convertKeyCharacteristics(const keymaster::AuthorizationSet& sw_enforced,
                                                     const keymaster::AuthorizationSet& hw_enforced,
                                                     bool includeKeystoreEnforced = true) {
    KeyCharacteristics keyMintEnforced = convertAuthSet(kSecurityLevel, hw_enforced);
    KeyCharacteristics keystoreEnforced = convertAuthSet(SecurityLevel::KEYSTORE, sw_enforced);

    vector<KeyCharacteristics> retval;
    retval.reserve(2);

    if (!keyMintEnforced.authorizations.empty()) retval.push_back(std::move(keyMintEnforced));
    if (includeKeystoreEnforced && !keystoreEnforced.authorizations.empty()) {
        retval.push_back(std::move(keystoreEnforced));
    }

    return retval;
}

Certificate convertCertificate(const keymaster_blob_t& cert) {
    return {std::vector<uint8_t>(cert.data, cert.data + cert.data_length)};
}

vector<Certificate> convertCertificateChain(const keymaster::CertificateChain& chain) {
    vector<Certificate> retval;
    std::transform(chain.begin(), chain.end(), std::back_inserter(retval), convertCertificate);
    return retval;
}

void addClientAndAppData(const vector<uint8_t>& clientId, const vector<uint8_t>& appData,
                         ::keymaster::AuthorizationSet* params) {
    params->Clear();
    if (clientId.size()) params->push_back(TAG_APPLICATION_ID, clientId.data(), clientId.size());
    if (appData.size()) params->push_back(TAG_APPLICATION_DATA, appData.data(), appData.size());
}

}  // namespace

ScopedAStatus TrustyKeyMintDevice::getHardwareInfo(KeyMintHardwareInfo* info) {
    info->versionNumber = 3;
    info->securityLevel = kSecurityLevel;
    info->keyMintName = "TrustyKeyMintDevice";
    info->keyMintAuthorName = "Google";
    info->timestampTokenRequired = false;
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintDevice::addRngEntropy(const vector<uint8_t>& data) {
    if (data.size() == 0) return ScopedAStatus::ok();
    if (data.size() > 2048) {
        LOG(DEBUG) << "Too-large entropy update of " << data.size() << " bytes.";
        return kmError2ScopedAStatus(KM_ERROR_INVALID_INPUT_LENGTH);
    }

    keymaster::AddEntropyRequest request(impl_->message_version());
    request.random_data.Reinitialize(data.data(), data.size());

    keymaster::AddEntropyResponse response(impl_->message_version());
    impl_->AddRngEntropy(request, &response);

    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus TrustyKeyMintDevice::generateKey(const vector<KeyParameter>& keyParams,
                                               const optional<AttestationKey>& attestationKey,
                                               KeyCreationResult* creationResult) {
    keymaster::GenerateKeyRequest request(impl_->message_version());
    request.key_description.Reinitialize(KmParamSet(keyParams));
    if (attestationKey) {
        request.attestation_signing_key_blob =
                KeymasterKeyBlob(attestationKey->keyBlob.data(), attestationKey->keyBlob.size());
        request.attest_key_params.Reinitialize(KmParamSet(attestationKey->attestKeyParams));
        request.issuer_subject = KeymasterBlob(attestationKey->issuerSubjectName.data(),
                                               attestationKey->issuerSubjectName.size());
    }

    keymaster::GenerateKeyResponse response(impl_->message_version());
    impl_->GenerateKey(request, &response);

    if (response.error != KM_ERROR_OK) return kmError2ScopedAStatus(response.error);

    creationResult->keyBlob = kmBlob2vector(response.key_blob);
    creationResult->keyCharacteristics =
            convertKeyCharacteristics(response.unenforced, response.enforced);
    creationResult->certificateChain = convertCertificateChain(response.certificate_chain);
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintDevice::getKeyCharacteristics(
        const vector<uint8_t>& keyBlob,
        const vector<uint8_t>& clientId,  //
        const vector<uint8_t>& appData,   //
        vector<KeyCharacteristics>* characteristics) {
    keymaster::GetKeyCharacteristicsRequest request(impl_->message_version());
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    addClientAndAppData(clientId, appData, &request.additional_params);

    keymaster::GetKeyCharacteristicsResponse response(impl_->message_version());
    impl_->GetKeyCharacteristics(request, &response);

    if (response.error != KM_ERROR_OK) return kmError2ScopedAStatus(response.error);

    *characteristics = convertKeyCharacteristics(response.unenforced, response.enforced,
                                                 false /* includeKeystoreEnforced */);
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintDevice::importKey(const vector<KeyParameter>& keyParams,
                                             KeyFormat keyFormat, const vector<uint8_t>& keyData,
                                             const optional<AttestationKey>& attestationKey,
                                             KeyCreationResult* creationResult) {
    keymaster::ImportKeyRequest request(impl_->message_version());
    request.key_description.Reinitialize(KmParamSet(keyParams));
    request.key_format = legacy_enum_conversion(keyFormat);
    request.key_data = KeymasterKeyBlob(keyData.data(), keyData.size());
    if (attestationKey) {
        request.attestation_signing_key_blob =
                KeymasterKeyBlob(attestationKey->keyBlob.data(), attestationKey->keyBlob.size());
        request.attest_key_params.Reinitialize(KmParamSet(attestationKey->attestKeyParams));
        request.issuer_subject = KeymasterBlob(attestationKey->issuerSubjectName.data(),
                                               attestationKey->issuerSubjectName.size());
    }

    keymaster::ImportKeyResponse response(impl_->message_version());
    impl_->ImportKey(request, &response);

    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    creationResult->keyBlob = kmBlob2vector(response.key_blob);
    creationResult->keyCharacteristics =
            convertKeyCharacteristics(response.unenforced, response.enforced);
    creationResult->certificateChain = convertCertificateChain(response.certificate_chain);

    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintDevice::importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                                    const vector<uint8_t>& wrappingKeyBlob,  //
                                                    const vector<uint8_t>& maskingKey,
                                                    const vector<KeyParameter>& unwrappingParams,
                                                    int64_t passwordSid,  //
                                                    int64_t biometricSid,
                                                    KeyCreationResult* creationResult) {
    keymaster::ImportWrappedKeyRequest request(impl_->message_version());
    request.SetWrappedMaterial(wrappedKeyData.data(), wrappedKeyData.size());
    request.SetWrappingMaterial(wrappingKeyBlob.data(), wrappingKeyBlob.size());
    request.SetMaskingKeyMaterial(maskingKey.data(), maskingKey.size());
    request.additional_params.Reinitialize(KmParamSet(unwrappingParams));
    request.password_sid = static_cast<uint64_t>(passwordSid);
    request.biometric_sid = static_cast<uint64_t>(biometricSid);

    keymaster::ImportWrappedKeyResponse response(impl_->message_version());
    impl_->ImportWrappedKey(request, &response);

    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    creationResult->keyBlob = kmBlob2vector(response.key_blob);
    creationResult->keyCharacteristics =
            convertKeyCharacteristics(response.unenforced, response.enforced);
    creationResult->certificateChain = convertCertificateChain(response.certificate_chain);

    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintDevice::upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                                              const vector<KeyParameter>& upgradeParams,
                                              vector<uint8_t>* keyBlob) {
    keymaster::UpgradeKeyRequest request(impl_->message_version());
    request.SetKeyMaterial(keyBlobToUpgrade.data(), keyBlobToUpgrade.size());
    request.upgrade_params.Reinitialize(KmParamSet(upgradeParams));

    keymaster::UpgradeKeyResponse response(impl_->message_version());
    impl_->UpgradeKey(request, &response);

    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    *keyBlob = kmBlob2vector(response.upgraded_key);
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintDevice::deleteKey(const vector<uint8_t>& keyBlob) {
    keymaster::DeleteKeyRequest request(impl_->message_version());
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());

    keymaster::DeleteKeyResponse response(impl_->message_version());
    impl_->DeleteKey(request, &response);

    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus TrustyKeyMintDevice::deleteAllKeys() {
    // There's nothing to be done to delete software key blobs.
    keymaster::DeleteAllKeysRequest request(impl_->message_version());
    keymaster::DeleteAllKeysResponse response(impl_->message_version());
    impl_->DeleteAllKeys(request, &response);

    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus TrustyKeyMintDevice::destroyAttestationIds() {
    return kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

ScopedAStatus TrustyKeyMintDevice::begin(KeyPurpose purpose, const vector<uint8_t>& keyBlob,
                                         const vector<KeyParameter>& params,
                                         const optional<HardwareAuthToken>& authToken,
                                         BeginResult* result) {
    keymaster::BeginOperationRequest request(impl_->message_version());
    request.purpose = legacy_enum_conversion(purpose);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    request.additional_params.Reinitialize(KmParamSet(params));

    vector<uint8_t> vector_token = authToken2AidlVec(authToken);
    request.additional_params.push_back(
            TAG_AUTH_TOKEN, reinterpret_cast<uint8_t*>(vector_token.data()), vector_token.size());

    keymaster::BeginOperationResponse response(impl_->message_version());
    impl_->BeginOperation(request, &response);

    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    result->params = kmParamSet2Aidl(response.output_params);
    result->challenge = response.op_handle;
    result->operation = ndk::SharedRefBase::make<TrustyKeyMintOperation>(impl_, response.op_handle);
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintDevice::deviceLocked(
        bool passwordOnly, const std::optional<secureclock::TimeStampToken>& timestampToken) {
    keymaster::DeviceLockedRequest request(impl_->message_version());
    request.passwordOnly = passwordOnly;
    if (timestampToken.has_value()) {
        request.token.challenge = timestampToken->challenge;
        request.token.mac = {timestampToken->mac.data(), timestampToken->mac.size()};
        request.token.timestamp = timestampToken->timestamp.milliSeconds;
    }
    keymaster::DeviceLockedResponse response = impl_->DeviceLocked(request);
    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus TrustyKeyMintDevice::earlyBootEnded() {
    keymaster::EarlyBootEndedResponse response = impl_->EarlyBootEnded();
    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus TrustyKeyMintDevice::convertStorageKeyToEphemeral(
        const vector<uint8_t>& storageKeyBlob, vector<uint8_t>* ephemeralKeyBlob) {
    keymaster::ExportKeyRequest request(impl_->message_version());
    request.SetKeyMaterial(storageKeyBlob.data(), storageKeyBlob.size());
    request.key_format = KM_KEY_FORMAT_RAW;

    keymaster::ExportKeyResponse response(impl_->message_version());
    impl_->ExportKey(request, &response);

    if (response.error != KM_ERROR_OK) return kmError2ScopedAStatus(response.error);
    if (response.key_data) {
        *ephemeralKeyBlob = {response.key_data, response.key_data + response.key_data_length};
    }
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintDevice::getRootOfTrustChallenge(array<uint8_t, 16>* /* challenge */) {
    return kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

ScopedAStatus TrustyKeyMintDevice::getRootOfTrust(const array<uint8_t, 16>& challenge,
                                                  vector<uint8_t>* rootOfTrust) {
    if (!rootOfTrust) {
        return kmError2ScopedAStatus(KM_ERROR_UNEXPECTED_NULL_POINTER);
    }
    keymaster::GetRootOfTrustRequest request(impl_->message_version(),
                                             {challenge.begin(), challenge.end()});
    keymaster::GetRootOfTrustResponse response = impl_->GetRootOfTrust(request);
    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    *rootOfTrust = std::move(response.rootOfTrust);
    return ScopedAStatus::ok();
}

ScopedAStatus TrustyKeyMintDevice::sendRootOfTrust(const vector<uint8_t>& /* rootOfTrust */) {
    return kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

}  // namespace aidl::android::hardware::security::keymint::trusty
