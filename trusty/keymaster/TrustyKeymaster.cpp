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

#define LOG_TAG "trusty_keymaster_hal"
#include <android-base/logging.h>

#include <keymaster/android_keymaster_messages.h>
#include <keymaster/keymaster_configuration.h>
#include <trusty_keymaster/TrustyKeymaster.h>
#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>

namespace keymaster {

int TrustyKeymaster::Initialize(KmVersion version) {
    int err;

    LOG(INFO) << "Initializing TrustyKeymaster as KmVersion: " << (int)version;

    err = trusty_keymaster_connect();
    if (err) {
        LOG(ERROR) << "Failed to connect to trusty keymaster (1st try)" << err;
        return err;
    }

    // Try GetVersion2 first.
    GetVersion2Request versionReq;
    versionReq.max_message_version = MessageVersion(version);
    GetVersion2Response versionRsp = GetVersion2(versionReq);
    if (versionRsp.error != KM_ERROR_OK) {
        LOG(WARNING) << "TA appears not to support GetVersion2, falling back (err = "
                     << versionRsp.error << ")";

        err = trusty_keymaster_connect();
        if (err) {
            LOG(FATAL) << "Failed to connect to trusty keymaster (2nd try) " << err;
            return err;
        }

        GetVersionRequest versionReq;
        GetVersionResponse versionRsp;
        GetVersion(versionReq, &versionRsp);
        if (versionRsp.error != KM_ERROR_OK) {
            LOG(FATAL) << "Failed to get TA version " << versionRsp.error;
            return -1;
        } else {
            keymaster_error_t error;
            message_version_ = NegotiateMessageVersion(versionRsp, &error);
            if (error != KM_ERROR_OK) {
                LOG(FATAL) << "Failed to negotiate message version " << error;
                return -1;
            }
        }
    } else {
        message_version_ = NegotiateMessageVersion(versionReq, versionRsp);
    }

    ConfigureRequest req(message_version());
    req.os_version = GetOsVersion();
    req.os_patchlevel = GetOsPatchlevel();

    ConfigureResponse rsp(message_version());
    Configure(req, &rsp);

    if (rsp.error != KM_ERROR_OK) {
        LOG(FATAL) << "Failed to configure keymaster " << rsp.error;
        return -1;
    }

    // Set the vendor patchlevel to value retrieved from system property (which
    // requires SELinux permission).
    ConfigureVendorPatchlevelRequest vendor_req(message_version());
    vendor_req.vendor_patchlevel = GetVendorPatchlevel();
    ConfigureVendorPatchlevelResponse vendor_rsp = ConfigureVendorPatchlevel(vendor_req);
    if (vendor_rsp.error != KM_ERROR_OK) {
        LOG(ERROR) << "Failed to configure keymaster vendor patchlevel: " << vendor_rsp.error;
        // Don't fail if this message isn't understood.
    }

    return 0;
}

TrustyKeymaster::TrustyKeymaster() {}

TrustyKeymaster::~TrustyKeymaster() {
    trusty_keymaster_disconnect();
}

static void ForwardCommand(enum keymaster_command command, const KeymasterMessage& req,
                           KeymasterResponse* rsp) {
    keymaster_error_t err;
    err = trusty_keymaster_send(command, req, rsp);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Cmd " << command << " returned error: " << err;
        rsp->error = err;
    }
}

void TrustyKeymaster::GetVersion(const GetVersionRequest& request, GetVersionResponse* response) {
    ForwardCommand(KM_GET_VERSION, request, response);
}

void TrustyKeymaster::SupportedAlgorithms(const SupportedAlgorithmsRequest& request,
                                          SupportedAlgorithmsResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_ALGORITHMS, request, response);
}

void TrustyKeymaster::SupportedBlockModes(const SupportedBlockModesRequest& request,
                                          SupportedBlockModesResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_BLOCK_MODES, request, response);
}

void TrustyKeymaster::SupportedPaddingModes(const SupportedPaddingModesRequest& request,
                                            SupportedPaddingModesResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_PADDING_MODES, request, response);
}

void TrustyKeymaster::SupportedDigests(const SupportedDigestsRequest& request,
                                       SupportedDigestsResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_DIGESTS, request, response);
}

void TrustyKeymaster::SupportedImportFormats(const SupportedImportFormatsRequest& request,
                                             SupportedImportFormatsResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_IMPORT_FORMATS, request, response);
}

void TrustyKeymaster::SupportedExportFormats(const SupportedExportFormatsRequest& request,
                                             SupportedExportFormatsResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_EXPORT_FORMATS, request, response);
}

void TrustyKeymaster::AddRngEntropy(const AddEntropyRequest& request,
                                    AddEntropyResponse* response) {
    ForwardCommand(KM_ADD_RNG_ENTROPY, request, response);
}

void TrustyKeymaster::Configure(const ConfigureRequest& request, ConfigureResponse* response) {
    ForwardCommand(KM_CONFIGURE, request, response);
}

void TrustyKeymaster::GenerateKey(const GenerateKeyRequest& request,
                                  GenerateKeyResponse* response) {
    if (message_version_ < 4) {
        // Pre-KeyMint we need to add TAG_CREATION_DATETIME if not provided by the caller.
        GenerateKeyRequest datedRequest(request.message_version);
        datedRequest.key_description = request.key_description;

        if (!request.key_description.Contains(TAG_CREATION_DATETIME)) {
            datedRequest.key_description.push_back(TAG_CREATION_DATETIME, java_time(time(NULL)));
        }

        ForwardCommand(KM_GENERATE_KEY, datedRequest, response);
    } else {
        ForwardCommand(KM_GENERATE_KEY, request, response);
    }
}

void TrustyKeymaster::GenerateRkpKey(const GenerateRkpKeyRequest& request,
                                     GenerateRkpKeyResponse* response) {
    ForwardCommand(KM_GENERATE_RKP_KEY, request, response);
}

void TrustyKeymaster::GenerateCsr(const GenerateCsrRequest& request,
                                  GenerateCsrResponse* response) {
    ForwardCommand(KM_GENERATE_CSR, request, response);
}

void TrustyKeymaster::GetKeyCharacteristics(const GetKeyCharacteristicsRequest& request,
                                            GetKeyCharacteristicsResponse* response) {
    ForwardCommand(KM_GET_KEY_CHARACTERISTICS, request, response);
}

void TrustyKeymaster::ImportKey(const ImportKeyRequest& request, ImportKeyResponse* response) {
    ForwardCommand(KM_IMPORT_KEY, request, response);
}

void TrustyKeymaster::ImportWrappedKey(const ImportWrappedKeyRequest& request,
                                       ImportWrappedKeyResponse* response) {
    ForwardCommand(KM_IMPORT_WRAPPED_KEY, request, response);
}

void TrustyKeymaster::ExportKey(const ExportKeyRequest& request, ExportKeyResponse* response) {
    ForwardCommand(KM_EXPORT_KEY, request, response);
}

void TrustyKeymaster::AttestKey(const AttestKeyRequest& request, AttestKeyResponse* response) {
    ForwardCommand(KM_ATTEST_KEY, request, response);
}

void TrustyKeymaster::UpgradeKey(const UpgradeKeyRequest& request, UpgradeKeyResponse* response) {
    ForwardCommand(KM_UPGRADE_KEY, request, response);
}

void TrustyKeymaster::DeleteKey(const DeleteKeyRequest& request, DeleteKeyResponse* response) {
    ForwardCommand(KM_DELETE_KEY, request, response);
}

void TrustyKeymaster::DeleteAllKeys(const DeleteAllKeysRequest& request,
                                    DeleteAllKeysResponse* response) {
    ForwardCommand(KM_DELETE_ALL_KEYS, request, response);
}

void TrustyKeymaster::BeginOperation(const BeginOperationRequest& request,
                                     BeginOperationResponse* response) {
    ForwardCommand(KM_BEGIN_OPERATION, request, response);
}

void TrustyKeymaster::UpdateOperation(const UpdateOperationRequest& request,
                                      UpdateOperationResponse* response) {
    ForwardCommand(KM_UPDATE_OPERATION, request, response);
}

void TrustyKeymaster::FinishOperation(const FinishOperationRequest& request,
                                      FinishOperationResponse* response) {
    ForwardCommand(KM_FINISH_OPERATION, request, response);
}

void TrustyKeymaster::AbortOperation(const AbortOperationRequest& request,
                                     AbortOperationResponse* response) {
    ForwardCommand(KM_ABORT_OPERATION, request, response);
}

GetHmacSharingParametersResponse TrustyKeymaster::GetHmacSharingParameters() {
    GetHmacSharingParametersRequest request(message_version());
    GetHmacSharingParametersResponse response(message_version());
    ForwardCommand(KM_GET_HMAC_SHARING_PARAMETERS, request, &response);
    return response;
}

ComputeSharedHmacResponse TrustyKeymaster::ComputeSharedHmac(
        const ComputeSharedHmacRequest& request) {
    ComputeSharedHmacResponse response(message_version());
    ForwardCommand(KM_COMPUTE_SHARED_HMAC, request, &response);
    return response;
}

VerifyAuthorizationResponse TrustyKeymaster::VerifyAuthorization(
        const VerifyAuthorizationRequest& request) {
    VerifyAuthorizationResponse response(message_version());
    ForwardCommand(KM_VERIFY_AUTHORIZATION, request, &response);
    return response;
}

GetVersion2Response TrustyKeymaster::GetVersion2(const GetVersion2Request& request) {
    GetVersion2Response response(message_version());
    ForwardCommand(KM_GET_VERSION_2, request, &response);
    return response;
}

EarlyBootEndedResponse TrustyKeymaster::EarlyBootEnded() {
    EarlyBootEndedResponse response(message_version());
    ForwardCommand(KM_EARLY_BOOT_ENDED, EarlyBootEndedRequest(message_version()), &response);
    return response;
}

DeviceLockedResponse TrustyKeymaster::DeviceLocked(const DeviceLockedRequest& request) {
    DeviceLockedResponse response(message_version());
    ForwardCommand(KM_DEVICE_LOCKED, request, &response);
    return response;
}

ConfigureVendorPatchlevelResponse TrustyKeymaster::ConfigureVendorPatchlevel(
        const ConfigureVendorPatchlevelRequest& request) {
    ConfigureVendorPatchlevelResponse response(message_version());
    ForwardCommand(KM_CONFIGURE_VENDOR_PATCHLEVEL, request, &response);
    return response;
}

GetRootOfTrustResponse TrustyKeymaster::GetRootOfTrust(const GetRootOfTrustRequest& request) {
    GetRootOfTrustResponse response(message_version());
    ForwardCommand(KM_GET_ROOT_OF_TRUST, request, &response);
    return response;
}

}  // namespace keymaster
