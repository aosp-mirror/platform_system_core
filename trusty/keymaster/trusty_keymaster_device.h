/*
 * Copyright 2014 The Android Open Source Project
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

#ifndef EXTERNAL_KEYMASTER_TRUSTY_KEYMASTER_DEVICE_H_
#define EXTERNAL_KEYMASTER_TRUSTY_KEYMASTER_DEVICE_H_

#include <hardware/keymaster0.h>

#include <keymaster/android_keymaster_messages.h>

#include "keymaster_ipc.h"

namespace keymaster {

/**
 * Software OpenSSL-based Keymaster device.
 *
 * IMPORTANT MAINTAINER NOTE: Pointers to instances of this class must be castable to hw_device_t
 * and keymaster_device. This means it must remain a standard layout class (no virtual functions and
 * no data members which aren't standard layout), and device_ must be the first data member.
 * Assertions in the constructor validate compliance with those constraints.
 */
class TrustyKeymasterDevice {
  public:
    /*
     * These are the only symbols that will be exported by libtrustykeymaster.  All functionality
     * can be reached via the function pointers in device_.
     */
    __attribute__((visibility("default"))) TrustyKeymasterDevice(const hw_module_t* module);
    __attribute__((visibility("default"))) hw_device_t* hw_device();

    ~TrustyKeymasterDevice();

    keymaster_error_t session_error() { return error_; }

    int generate_keypair(const keymaster_keypair_t key_type, const void* key_params,
                         uint8_t** key_blob, size_t* key_blob_length);
    int import_keypair(const uint8_t* key, const size_t key_length, uint8_t** key_blob,
                       size_t* key_blob_length);
    int get_keypair_public(const uint8_t* key_blob, const size_t key_blob_length,
                           uint8_t** x509_data, size_t* x509_data_length);
    int sign_data(const void* signing_params, const uint8_t* key_blob, const size_t key_blob_length,
                  const uint8_t* data, const size_t data_length, uint8_t** signed_data,
                  size_t* signed_data_length);
    int verify_data(const void* signing_params, const uint8_t* key_blob,
                    const size_t key_blob_length, const uint8_t* signed_data,
                    const size_t signed_data_length, const uint8_t* signature,
                    const size_t signature_length);

  private:
    keymaster_error_t Send(uint32_t command, const Serializable& request,
                           KeymasterResponse* response);
    keymaster_error_t Send(const GenerateKeyRequest& request, GenerateKeyResponse* response) {
        return Send(KM_GENERATE_KEY, request, response);
    }
    keymaster_error_t Send(const BeginOperationRequest& request, BeginOperationResponse* response) {
        return Send(KM_BEGIN_OPERATION, request, response);
    }
    keymaster_error_t Send(const UpdateOperationRequest& request,
                           UpdateOperationResponse* response) {
        return Send(KM_UPDATE_OPERATION, request, response);
    }
    keymaster_error_t Send(const FinishOperationRequest& request,
                           FinishOperationResponse* response) {
        return Send(KM_FINISH_OPERATION, request, response);
    }
    keymaster_error_t Send(const ImportKeyRequest& request, ImportKeyResponse* response) {
        return Send(KM_IMPORT_KEY, request, response);
    }
    keymaster_error_t Send(const ExportKeyRequest& request, ExportKeyResponse* response) {
        return Send(KM_EXPORT_KEY, request, response);
    }
    keymaster_error_t Send(const GetVersionRequest& request, GetVersionResponse* response) {
        return Send(KM_GET_VERSION, request, response);
    }

    keymaster_error_t StoreSigningParams(const void* signing_params, const uint8_t* key_blob,
                                         size_t key_blob_length, AuthorizationSet* auth_set);
    void StoreNewKeyParams(AuthorizationSet* auth_set);
    keymaster_error_t GetPkcs8KeyAlgorithm(const uint8_t* key, size_t key_length,
                                           keymaster_algorithm_t* algorithm);

    /*
     * These static methods are the functions referenced through the function pointers in
     * keymaster_device.  They're all trivial wrappers.
     */
    static int close_device(hw_device_t* dev);
    static int generate_keypair(const keymaster0_device_t* dev, const keymaster_keypair_t key_type,
                                const void* key_params, uint8_t** keyBlob, size_t* keyBlobLength);
    static int import_keypair(const keymaster0_device_t* dev, const uint8_t* key,
                              const size_t key_length, uint8_t** key_blob, size_t* key_blob_length);
    static int get_keypair_public(const keymaster0_device_t* dev, const uint8_t* key_blob,
                                  const size_t key_blob_length, uint8_t** x509_data,
                                  size_t* x509_data_length);
    static int sign_data(const keymaster0_device_t* dev, const void* signing_params,
                         const uint8_t* key_blob, const size_t key_blob_length, const uint8_t* data,
                         const size_t data_length, uint8_t** signed_data,
                         size_t* signed_data_length);
    static int verify_data(const keymaster0_device_t* dev, const void* signing_params,
                           const uint8_t* key_blob, const size_t key_blob_length,
                           const uint8_t* signed_data, const size_t signed_data_length,
                           const uint8_t* signature, const size_t signature_length);

    keymaster0_device_t device_;
    keymaster_error_t error_;
    int32_t message_version_;
};

}  // namespace keymaster

#endif  // EXTERNAL_KEYMASTER_TRUSTY_KEYMASTER_DEVICE_H_
