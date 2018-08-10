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

#define LOG_TAG "TrustyKeymaster"

#include <assert.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <type_traits>

#include <hardware/keymaster2.h>
#include <keymaster/authorization_set.h>
#include <log/log.h>

#include <trusty_keymaster/ipc/keymaster_ipc.h>
#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>
#include <trusty_keymaster/legacy/trusty_keymaster_device.h>

const size_t kMaximumAttestationChallengeLength = 128;
const size_t kMaximumFinishInputLength = 2048;

namespace keymaster {

TrustyKeymasterDevice::TrustyKeymasterDevice(const hw_module_t* module) {
    static_assert(std::is_standard_layout<TrustyKeymasterDevice>::value,
                  "TrustyKeymasterDevice must be standard layout");
    static_assert(offsetof(TrustyKeymasterDevice, device_) == 0,
                  "device_ must be the first member of TrustyKeymasterDevice");
    static_assert(offsetof(TrustyKeymasterDevice, device_.common) == 0,
                  "common must be the first member of keymaster2_device");

    ALOGI("Creating device");
    ALOGD("Device address: %p", this);

    device_ = {};

    device_.common.tag = HARDWARE_DEVICE_TAG;
    device_.common.version = 1;
    device_.common.module = const_cast<hw_module_t*>(module);
    device_.common.close = close_device;

    device_.flags = KEYMASTER_SUPPORTS_EC;

    device_.configure = configure;
    device_.add_rng_entropy = add_rng_entropy;
    device_.generate_key = generate_key;
    device_.get_key_characteristics = get_key_characteristics;
    device_.import_key = import_key;
    device_.export_key = export_key;
    device_.attest_key = attest_key;
    device_.upgrade_key = upgrade_key;
    device_.delete_key = nullptr;
    device_.delete_all_keys = nullptr;
    device_.begin = begin;
    device_.update = update;
    device_.finish = finish;
    device_.abort = abort;

    int rc = trusty_keymaster_connect();
    error_ = translate_error(rc);
    if (rc < 0) {
        ALOGE("failed to connect to keymaster (%d)", rc);
        return;
    }

    GetVersionRequest version_request;
    GetVersionResponse version_response;
    error_ = trusty_keymaster_send(KM_GET_VERSION, version_request, &version_response);
    if (error_ == KM_ERROR_INVALID_ARGUMENT || error_ == KM_ERROR_UNIMPLEMENTED) {
        ALOGE("\"Bad parameters\" error on GetVersion call.  Version 0 is not supported.");
        error_ = KM_ERROR_VERSION_MISMATCH;
        return;
    }
    message_version_ = MessageVersion(version_response.major_ver, version_response.minor_ver,
                                      version_response.subminor_ver);
    if (message_version_ < 0) {
        // Can't translate version?  Keymaster implementation must be newer.
        ALOGE("Keymaster version %d.%d.%d not supported.", version_response.major_ver,
              version_response.minor_ver, version_response.subminor_ver);
        error_ = KM_ERROR_VERSION_MISMATCH;
    }
}

TrustyKeymasterDevice::~TrustyKeymasterDevice() {
    trusty_keymaster_disconnect();
}

namespace {

// Allocates a new buffer with malloc and copies the contents of |buffer| to it. Caller takes
// ownership of the returned buffer.
uint8_t* DuplicateBuffer(const uint8_t* buffer, size_t size) {
    uint8_t* tmp = reinterpret_cast<uint8_t*>(malloc(size));
    if (tmp) {
        memcpy(tmp, buffer, size);
    }
    return tmp;
}

template <typename RequestType>
void AddClientAndAppData(const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
                         RequestType* request) {
    request->additional_params.Clear();
    if (client_id) {
        request->additional_params.push_back(TAG_APPLICATION_ID, *client_id);
    }
    if (app_data) {
        request->additional_params.push_back(TAG_APPLICATION_DATA, *app_data);
    }
}

}  //  unnamed namespace

keymaster_error_t TrustyKeymasterDevice::configure(const keymaster_key_param_set_t* params) {
    ALOGD("Device received configure\n");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }
    if (!params) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    AuthorizationSet params_copy(*params);
    ConfigureRequest request(message_version_);
    if (!params_copy.GetTagValue(TAG_OS_VERSION, &request.os_version) ||
        !params_copy.GetTagValue(TAG_OS_PATCHLEVEL, &request.os_patchlevel)) {
        ALOGD("Configuration parameters must contain OS version and patch level");
        return KM_ERROR_INVALID_ARGUMENT;
    }

    ConfigureResponse response(message_version_);
    keymaster_error_t err = trusty_keymaster_send(KM_CONFIGURE, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::add_rng_entropy(const uint8_t* data, size_t data_length) {
    ALOGD("Device received add_rng_entropy");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }

    AddEntropyRequest request(message_version_);
    request.random_data.Reinitialize(data, data_length);
    AddEntropyResponse response(message_version_);
    return trusty_keymaster_send(KM_ADD_RNG_ENTROPY, request, &response);
}

keymaster_error_t TrustyKeymasterDevice::generate_key(
        const keymaster_key_param_set_t* params, keymaster_key_blob_t* key_blob,
        keymaster_key_characteristics_t* characteristics) {
    ALOGD("Device received generate_key");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }
    if (!params) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!key_blob) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    GenerateKeyRequest request(message_version_);
    request.key_description.Reinitialize(*params);
    request.key_description.push_back(TAG_CREATION_DATETIME, java_time(time(NULL)));

    GenerateKeyResponse response(message_version_);
    keymaster_error_t err = trusty_keymaster_send(KM_GENERATE_KEY, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    key_blob->key_material_size = response.key_blob.key_material_size;
    key_blob->key_material =
            DuplicateBuffer(response.key_blob.key_material, response.key_blob.key_material_size);
    if (!key_blob->key_material) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    if (characteristics) {
        response.enforced.CopyToParamSet(&characteristics->hw_enforced);
        response.unenforced.CopyToParamSet(&characteristics->sw_enforced);
    }

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::get_key_characteristics(
        const keymaster_key_blob_t* key_blob, const keymaster_blob_t* client_id,
        const keymaster_blob_t* app_data, keymaster_key_characteristics_t* characteristics) {
    ALOGD("Device received get_key_characteristics");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }
    if (!key_blob || !key_blob->key_material) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!characteristics) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    GetKeyCharacteristicsRequest request(message_version_);
    request.SetKeyMaterial(*key_blob);
    AddClientAndAppData(client_id, app_data, &request);

    GetKeyCharacteristicsResponse response(message_version_);
    keymaster_error_t err = trusty_keymaster_send(KM_GET_KEY_CHARACTERISTICS, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    response.enforced.CopyToParamSet(&characteristics->hw_enforced);
    response.unenforced.CopyToParamSet(&characteristics->sw_enforced);

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::import_key(
        const keymaster_key_param_set_t* params, keymaster_key_format_t key_format,
        const keymaster_blob_t* key_data, keymaster_key_blob_t* key_blob,
        keymaster_key_characteristics_t* characteristics) {
    ALOGD("Device received import_key");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }
    if (!params || !key_data) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!key_blob) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    ImportKeyRequest request(message_version_);
    request.key_description.Reinitialize(*params);
    request.key_description.push_back(TAG_CREATION_DATETIME, java_time(time(NULL)));

    request.key_format = key_format;
    request.SetKeyMaterial(key_data->data, key_data->data_length);

    ImportKeyResponse response(message_version_);
    keymaster_error_t err = trusty_keymaster_send(KM_IMPORT_KEY, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    key_blob->key_material_size = response.key_blob.key_material_size;
    key_blob->key_material =
            DuplicateBuffer(response.key_blob.key_material, response.key_blob.key_material_size);
    if (!key_blob->key_material) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    if (characteristics) {
        response.enforced.CopyToParamSet(&characteristics->hw_enforced);
        response.unenforced.CopyToParamSet(&characteristics->sw_enforced);
    }

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::export_key(keymaster_key_format_t export_format,
                                                    const keymaster_key_blob_t* key_to_export,
                                                    const keymaster_blob_t* client_id,
                                                    const keymaster_blob_t* app_data,
                                                    keymaster_blob_t* export_data) {
    ALOGD("Device received export_key");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }
    if (!key_to_export || !key_to_export->key_material) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!export_data) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    export_data->data = nullptr;
    export_data->data_length = 0;

    ExportKeyRequest request(message_version_);
    request.key_format = export_format;
    request.SetKeyMaterial(*key_to_export);
    AddClientAndAppData(client_id, app_data, &request);

    ExportKeyResponse response(message_version_);
    keymaster_error_t err = trusty_keymaster_send(KM_EXPORT_KEY, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    export_data->data_length = response.key_data_length;
    export_data->data = DuplicateBuffer(response.key_data, response.key_data_length);
    if (!export_data->data) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::attest_key(const keymaster_key_blob_t* key_to_attest,
                                                    const keymaster_key_param_set_t* attest_params,
                                                    keymaster_cert_chain_t* cert_chain) {
    ALOGD("Device received attest_key");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }
    if (!key_to_attest || !attest_params) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!cert_chain) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    cert_chain->entry_count = 0;
    cert_chain->entries = nullptr;

    AttestKeyRequest request(message_version_);
    request.SetKeyMaterial(*key_to_attest);
    request.attest_params.Reinitialize(*attest_params);

    keymaster_blob_t attestation_challenge = {};
    request.attest_params.GetTagValue(TAG_ATTESTATION_CHALLENGE, &attestation_challenge);
    if (attestation_challenge.data_length > kMaximumAttestationChallengeLength) {
        ALOGE("%zu-byte attestation challenge; only %zu bytes allowed",
              attestation_challenge.data_length, kMaximumAttestationChallengeLength);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }

    AttestKeyResponse response(message_version_);
    keymaster_error_t err = trusty_keymaster_send(KM_ATTEST_KEY, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    // Allocate and clear storage for cert_chain.
    keymaster_cert_chain_t& rsp_chain = response.certificate_chain;
    cert_chain->entries = reinterpret_cast<keymaster_blob_t*>(
            malloc(rsp_chain.entry_count * sizeof(*cert_chain->entries)));
    if (!cert_chain->entries) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    cert_chain->entry_count = rsp_chain.entry_count;
    for (keymaster_blob_t& entry : array_range(cert_chain->entries, cert_chain->entry_count)) {
        entry = {};
    }

    // Copy cert_chain contents
    size_t i = 0;
    for (keymaster_blob_t& entry : array_range(rsp_chain.entries, rsp_chain.entry_count)) {
        cert_chain->entries[i].data = DuplicateBuffer(entry.data, entry.data_length);
        if (!cert_chain->entries[i].data) {
            keymaster_free_cert_chain(cert_chain);
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
        cert_chain->entries[i].data_length = entry.data_length;
        ++i;
    }

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::upgrade_key(
        const keymaster_key_blob_t* key_to_upgrade, const keymaster_key_param_set_t* upgrade_params,
        keymaster_key_blob_t* upgraded_key) {
    ALOGD("Device received upgrade_key");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }
    if (!key_to_upgrade || !upgrade_params) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!upgraded_key) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    UpgradeKeyRequest request(message_version_);
    request.SetKeyMaterial(*key_to_upgrade);
    request.upgrade_params.Reinitialize(*upgrade_params);

    UpgradeKeyResponse response(message_version_);
    keymaster_error_t err = trusty_keymaster_send(KM_UPGRADE_KEY, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    upgraded_key->key_material_size = response.upgraded_key.key_material_size;
    upgraded_key->key_material = DuplicateBuffer(response.upgraded_key.key_material,
                                                 response.upgraded_key.key_material_size);
    if (!upgraded_key->key_material) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::begin(keymaster_purpose_t purpose,
                                               const keymaster_key_blob_t* key,
                                               const keymaster_key_param_set_t* in_params,
                                               keymaster_key_param_set_t* out_params,
                                               keymaster_operation_handle_t* operation_handle) {
    ALOGD("Device received begin");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }
    if (!key || !key->key_material) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!operation_handle) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    if (out_params) {
        *out_params = {};
    }

    BeginOperationRequest request(message_version_);
    request.purpose = purpose;
    request.SetKeyMaterial(*key);
    request.additional_params.Reinitialize(*in_params);

    BeginOperationResponse response(message_version_);
    keymaster_error_t err = trusty_keymaster_send(KM_BEGIN_OPERATION, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    if (response.output_params.size() > 0) {
        if (out_params) {
            response.output_params.CopyToParamSet(out_params);
        } else {
            return KM_ERROR_OUTPUT_PARAMETER_NULL;
        }
    }
    *operation_handle = response.op_handle;

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::update(keymaster_operation_handle_t operation_handle,
                                                const keymaster_key_param_set_t* in_params,
                                                const keymaster_blob_t* input,
                                                size_t* input_consumed,
                                                keymaster_key_param_set_t* out_params,
                                                keymaster_blob_t* output) {
    ALOGD("Device received update");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }
    if (!input) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    if (!input_consumed) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    if (out_params) {
        *out_params = {};
    }
    if (output) {
        *output = {};
    }

    UpdateOperationRequest request(message_version_);
    request.op_handle = operation_handle;
    if (in_params) {
        request.additional_params.Reinitialize(*in_params);
    }
    if (input && input->data_length > 0) {
        size_t max_input_size = TRUSTY_KEYMASTER_SEND_BUF_SIZE - request.SerializedSize();
        request.input.Reinitialize(input->data, std::min(input->data_length, max_input_size));
    }

    UpdateOperationResponse response(message_version_);
    keymaster_error_t err = trusty_keymaster_send(KM_UPDATE_OPERATION, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    if (response.output_params.size() > 0) {
        if (out_params) {
            response.output_params.CopyToParamSet(out_params);
        } else {
            return KM_ERROR_OUTPUT_PARAMETER_NULL;
        }
    }
    *input_consumed = response.input_consumed;
    if (output) {
        output->data_length = response.output.available_read();
        output->data = DuplicateBuffer(response.output.peek_read(), output->data_length);
        if (!output->data) {
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    } else if (response.output.available_read() > 0) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::finish(keymaster_operation_handle_t operation_handle,
                                                const keymaster_key_param_set_t* in_params,
                                                const keymaster_blob_t* input,
                                                const keymaster_blob_t* signature,
                                                keymaster_key_param_set_t* out_params,
                                                keymaster_blob_t* output) {
    ALOGD("Device received finish");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }
    if (input && input->data_length > kMaximumFinishInputLength) {
        ALOGE("%zu-byte input to finish; only %zu bytes allowed", input->data_length,
              kMaximumFinishInputLength);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }

    if (out_params) {
        *out_params = {};
    }
    if (output) {
        *output = {};
    }

    FinishOperationRequest request(message_version_);
    request.op_handle = operation_handle;
    if (signature && signature->data && signature->data_length > 0) {
        request.signature.Reinitialize(signature->data, signature->data_length);
    }
    if (input && input->data && input->data_length) {
        request.input.Reinitialize(input->data, input->data_length);
    }
    if (in_params) {
        request.additional_params.Reinitialize(*in_params);
    }

    FinishOperationResponse response(message_version_);
    keymaster_error_t err = trusty_keymaster_send(KM_FINISH_OPERATION, request, &response);
    if (err != KM_ERROR_OK) {
        return err;
    }

    if (response.output_params.size() > 0) {
        if (out_params) {
            response.output_params.CopyToParamSet(out_params);
        } else {
            return KM_ERROR_OUTPUT_PARAMETER_NULL;
        }
    }
    if (output) {
        output->data_length = response.output.available_read();
        output->data = DuplicateBuffer(response.output.peek_read(), output->data_length);
        if (!output->data) {
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        }
    } else if (response.output.available_read() > 0) {
        return KM_ERROR_OUTPUT_PARAMETER_NULL;
    }

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::abort(keymaster_operation_handle_t operation_handle) {
    ALOGD("Device received abort");

    if (error_ != KM_ERROR_OK) {
        return error_;
    }

    AbortOperationRequest request(message_version_);
    request.op_handle = operation_handle;
    AbortOperationResponse response(message_version_);
    return trusty_keymaster_send(KM_ABORT_OPERATION, request, &response);
}

hw_device_t* TrustyKeymasterDevice::hw_device() {
    return &device_.common;
}

static inline TrustyKeymasterDevice* convert_device(const keymaster2_device_t* dev) {
    return reinterpret_cast<TrustyKeymasterDevice*>(const_cast<keymaster2_device_t*>(dev));
}

/* static */
int TrustyKeymasterDevice::close_device(hw_device_t* dev) {
    delete reinterpret_cast<TrustyKeymasterDevice*>(dev);
    return 0;
}

/* static */
keymaster_error_t TrustyKeymasterDevice::configure(const keymaster2_device_t* dev,
                                                   const keymaster_key_param_set_t* params) {
    return convert_device(dev)->configure(params);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::add_rng_entropy(const keymaster2_device_t* dev,
                                                         const uint8_t* data, size_t data_length) {
    return convert_device(dev)->add_rng_entropy(data, data_length);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::generate_key(
        const keymaster2_device_t* dev, const keymaster_key_param_set_t* params,
        keymaster_key_blob_t* key_blob, keymaster_key_characteristics_t* characteristics) {
    return convert_device(dev)->generate_key(params, key_blob, characteristics);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::get_key_characteristics(
        const keymaster2_device_t* dev, const keymaster_key_blob_t* key_blob,
        const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
        keymaster_key_characteristics_t* characteristics) {
    return convert_device(dev)->get_key_characteristics(key_blob, client_id, app_data,
                                                        characteristics);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::import_key(
        const keymaster2_device_t* dev, const keymaster_key_param_set_t* params,
        keymaster_key_format_t key_format, const keymaster_blob_t* key_data,
        keymaster_key_blob_t* key_blob, keymaster_key_characteristics_t* characteristics) {
    return convert_device(dev)->import_key(params, key_format, key_data, key_blob, characteristics);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::export_key(const keymaster2_device_t* dev,
                                                    keymaster_key_format_t export_format,
                                                    const keymaster_key_blob_t* key_to_export,
                                                    const keymaster_blob_t* client_id,
                                                    const keymaster_blob_t* app_data,
                                                    keymaster_blob_t* export_data) {
    return convert_device(dev)->export_key(export_format, key_to_export, client_id, app_data,
                                           export_data);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::attest_key(const keymaster2_device_t* dev,
                                                    const keymaster_key_blob_t* key_to_attest,
                                                    const keymaster_key_param_set_t* attest_params,
                                                    keymaster_cert_chain_t* cert_chain) {
    return convert_device(dev)->attest_key(key_to_attest, attest_params, cert_chain);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::upgrade_key(
        const keymaster2_device_t* dev, const keymaster_key_blob_t* key_to_upgrade,
        const keymaster_key_param_set_t* upgrade_params, keymaster_key_blob_t* upgraded_key) {
    return convert_device(dev)->upgrade_key(key_to_upgrade, upgrade_params, upgraded_key);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::begin(const keymaster2_device_t* dev,
                                               keymaster_purpose_t purpose,
                                               const keymaster_key_blob_t* key,
                                               const keymaster_key_param_set_t* in_params,
                                               keymaster_key_param_set_t* out_params,
                                               keymaster_operation_handle_t* operation_handle) {
    return convert_device(dev)->begin(purpose, key, in_params, out_params, operation_handle);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::update(
        const keymaster2_device_t* dev, keymaster_operation_handle_t operation_handle,
        const keymaster_key_param_set_t* in_params, const keymaster_blob_t* input,
        size_t* input_consumed, keymaster_key_param_set_t* out_params, keymaster_blob_t* output) {
    return convert_device(dev)->update(operation_handle, in_params, input, input_consumed,
                                       out_params, output);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::finish(const keymaster2_device_t* dev,
                                                keymaster_operation_handle_t operation_handle,
                                                const keymaster_key_param_set_t* in_params,
                                                const keymaster_blob_t* input,
                                                const keymaster_blob_t* signature,
                                                keymaster_key_param_set_t* out_params,
                                                keymaster_blob_t* output) {
    return convert_device(dev)->finish(operation_handle, in_params, input, signature, out_params,
                                       output);
}

/* static */
keymaster_error_t TrustyKeymasterDevice::abort(const keymaster2_device_t* dev,
                                               keymaster_operation_handle_t operation_handle) {
    return convert_device(dev)->abort(operation_handle);
}

}  // namespace keymaster
