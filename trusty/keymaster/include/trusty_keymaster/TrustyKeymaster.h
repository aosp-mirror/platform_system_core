/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef TRUSTY_KEYMASTER_H_
#define TRUSTY_KEYMASTER_H_

#include <keymaster/android_keymaster_messages.h>

namespace keymaster {

class TrustyKeymaster {
  public:
    TrustyKeymaster();
    ~TrustyKeymaster();
    int Initialize(KmVersion version);
    void GetVersion(const GetVersionRequest& request, GetVersionResponse* response);
    void SupportedAlgorithms(const SupportedAlgorithmsRequest& request,
                             SupportedAlgorithmsResponse* response);
    void SupportedBlockModes(const SupportedBlockModesRequest& request,
                             SupportedBlockModesResponse* response);
    void SupportedPaddingModes(const SupportedPaddingModesRequest& request,
                               SupportedPaddingModesResponse* response);
    void SupportedDigests(const SupportedDigestsRequest& request,
                          SupportedDigestsResponse* response);
    void SupportedImportFormats(const SupportedImportFormatsRequest& request,
                                SupportedImportFormatsResponse* response);
    void SupportedExportFormats(const SupportedExportFormatsRequest& request,
                                SupportedExportFormatsResponse* response);
    void AddRngEntropy(const AddEntropyRequest& request, AddEntropyResponse* response);
    void Configure(const ConfigureRequest& request, ConfigureResponse* response);
    void GenerateKey(const GenerateKeyRequest& request, GenerateKeyResponse* response);
    void GenerateRkpKey(const GenerateRkpKeyRequest& request, GenerateRkpKeyResponse* response);
    void GenerateCsr(const GenerateCsrRequest& request, GenerateCsrResponse* response);
    void GetKeyCharacteristics(const GetKeyCharacteristicsRequest& request,
                               GetKeyCharacteristicsResponse* response);
    void ImportKey(const ImportKeyRequest& request, ImportKeyResponse* response);
    void ImportWrappedKey(const ImportWrappedKeyRequest& request,
                          ImportWrappedKeyResponse* response);
    void ExportKey(const ExportKeyRequest& request, ExportKeyResponse* response);
    void AttestKey(const AttestKeyRequest& request, AttestKeyResponse* response);
    void UpgradeKey(const UpgradeKeyRequest& request, UpgradeKeyResponse* response);
    void DeleteKey(const DeleteKeyRequest& request, DeleteKeyResponse* response);
    void DeleteAllKeys(const DeleteAllKeysRequest& request, DeleteAllKeysResponse* response);
    void BeginOperation(const BeginOperationRequest& request, BeginOperationResponse* response);
    void UpdateOperation(const UpdateOperationRequest& request, UpdateOperationResponse* response);
    void FinishOperation(const FinishOperationRequest& request, FinishOperationResponse* response);
    void AbortOperation(const AbortOperationRequest& request, AbortOperationResponse* response);
    GetHmacSharingParametersResponse GetHmacSharingParameters();
    ComputeSharedHmacResponse ComputeSharedHmac(const ComputeSharedHmacRequest& request);
    VerifyAuthorizationResponse VerifyAuthorization(const VerifyAuthorizationRequest& request);
    GetVersion2Response GetVersion2(const GetVersion2Request& request);
    EarlyBootEndedResponse EarlyBootEnded();
    DeviceLockedResponse DeviceLocked(const DeviceLockedRequest& request);
    ConfigureVendorPatchlevelResponse ConfigureVendorPatchlevel(
            const ConfigureVendorPatchlevelRequest& request);
    GetRootOfTrustResponse GetRootOfTrust(const GetRootOfTrustRequest& request);

    uint32_t message_version() const { return message_version_; }

  private:
    uint32_t message_version_;
};

}  // namespace keymaster

#endif  // TRUSTY_KEYMASTER_H_
