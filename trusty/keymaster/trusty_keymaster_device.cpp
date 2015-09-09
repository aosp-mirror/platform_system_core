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

#include "trusty_keymaster_device.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>

#include <type_traits>

#include <openssl/evp.h>
#include <openssl/x509.h>

#define LOG_TAG "TrustyKeymaster"
#include <cutils/log.h>
#include <hardware/keymaster0.h>

#include <keymaster/authorization_set.h>

#include "trusty_keymaster_ipc.h"
#include "keymaster_ipc.h"

const uint32_t SEND_BUF_SIZE = 8192;
const uint32_t RECV_BUF_SIZE = 8192;

namespace keymaster {

static keymaster_error_t translate_error(int err) {
    switch (err) {
    case 0:
        return KM_ERROR_OK;
    case -EPERM:
    case -EACCES:
        return KM_ERROR_SECURE_HW_ACCESS_DENIED;

    case -ECANCELED:
        return KM_ERROR_OPERATION_CANCELLED;

    case -ENODEV:
        return KM_ERROR_UNIMPLEMENTED;

    case -ENOMEM:
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    case -EBUSY:
        return KM_ERROR_SECURE_HW_BUSY;

    case -EIO:
        return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;

    case -EOVERFLOW:
        return KM_ERROR_INVALID_INPUT_LENGTH;

    default:
        return KM_ERROR_UNKNOWN_ERROR;
    }
}

TrustyKeymasterDevice::TrustyKeymasterDevice(const hw_module_t* module) {
    static_assert(std::is_standard_layout<TrustyKeymasterDevice>::value,
                  "TrustyKeymasterDevice must be standard layout");
    static_assert(offsetof(TrustyKeymasterDevice, device_) == 0,
                  "device_ must be the first member of KeymasterOpenSsl");
    static_assert(offsetof(TrustyKeymasterDevice, device_.common) == 0,
                  "common must be the first member of keymaster_device");

    ALOGI("Creating device");
    ALOGD("Device address: %p", this);

    memset(&device_, 0, sizeof(device_));

    device_.common.tag = HARDWARE_DEVICE_TAG;
    device_.common.version = 1;
    device_.common.module = const_cast<hw_module_t*>(module);
    device_.common.close = close_device;

    device_.flags = KEYMASTER_BLOBS_ARE_STANDALONE | KEYMASTER_SUPPORTS_EC;

    device_.generate_keypair = generate_keypair;
    device_.import_keypair = import_keypair;
    device_.get_keypair_public = get_keypair_public;
    device_.delete_keypair = NULL;
    device_.delete_all = NULL;
    device_.sign_data = sign_data;
    device_.verify_data = verify_data;

    device_.context = NULL;

    int rc = trusty_keymaster_connect();
    error_ = translate_error(rc);
    if (rc < 0) {
        ALOGE("failed to connect to keymaster (%d)", rc);
        return;
    }

    GetVersionRequest version_request;
    GetVersionResponse version_response;
    error_ = Send(version_request, &version_response);
    if (error_ == KM_ERROR_INVALID_ARGUMENT || error_ == KM_ERROR_UNIMPLEMENTED) {
        ALOGI("\"Bad parameters\" error on GetVersion call.  Assuming version 0.");
        message_version_ = 0;
        error_ = KM_ERROR_OK;
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

const uint64_t HUNDRED_YEARS = 1000LL * 60 * 60 * 24 * 365 * 100;

int TrustyKeymasterDevice::generate_keypair(const keymaster_keypair_t key_type,
                                            const void* key_params, uint8_t** key_blob,
                                            size_t* key_blob_length) {
    ALOGD("Device received generate_keypair");

    if (error_ != KM_ERROR_OK)
        return error_;

    GenerateKeyRequest req(message_version_);
    StoreNewKeyParams(&req.key_description);

    switch (key_type) {
    case TYPE_RSA: {
        req.key_description.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
        const keymaster_rsa_keygen_params_t* rsa_params =
            static_cast<const keymaster_rsa_keygen_params_t*>(key_params);
        ALOGD("Generating RSA pair, modulus size: %u, public exponent: %lu",
              rsa_params->modulus_size, rsa_params->public_exponent);
        req.key_description.push_back(TAG_KEY_SIZE, rsa_params->modulus_size);
        req.key_description.push_back(TAG_RSA_PUBLIC_EXPONENT, rsa_params->public_exponent);
        break;
    }

    case TYPE_EC: {
        req.key_description.push_back(TAG_ALGORITHM, KM_ALGORITHM_EC);
        const keymaster_ec_keygen_params_t* ec_params =
            static_cast<const keymaster_ec_keygen_params_t*>(key_params);
        ALOGD("Generating ECDSA pair, key size: %u", ec_params->field_size);
        req.key_description.push_back(TAG_KEY_SIZE, ec_params->field_size);
        break;
    }
    default:
        ALOGD("Received request for unsuported key type %d", key_type);
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }

    GenerateKeyResponse rsp(message_version_);
    ALOGD("Sending generate request");
    keymaster_error_t err = Send(req, &rsp);
    if (err != KM_ERROR_OK) {
        ALOGE("Got error %d from send", err);
        return err;
    }

    *key_blob_length = rsp.key_blob.key_material_size;
    *key_blob = static_cast<uint8_t*>(malloc(*key_blob_length));
    memcpy(*key_blob, rsp.key_blob.key_material, *key_blob_length);
    ALOGD("Returning %d bytes in key blob\n", (int)*key_blob_length);

    return KM_ERROR_OK;
}

struct EVP_PKEY_Delete {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};

struct PKCS8_PRIV_KEY_INFO_Delete {
    void operator()(PKCS8_PRIV_KEY_INFO* p) const { PKCS8_PRIV_KEY_INFO_free(p); }
};

int TrustyKeymasterDevice::import_keypair(const uint8_t* key, const size_t key_length,
                                          uint8_t** key_blob, size_t* key_blob_length) {
    ALOGD("Device received import_keypair");
    if (error_ != KM_ERROR_OK)
        return error_;

    if (!key)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!key_blob || !key_blob_length)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    ImportKeyRequest request(message_version_);
    StoreNewKeyParams(&request.key_description);
    keymaster_algorithm_t algorithm;
    keymaster_error_t err = GetPkcs8KeyAlgorithm(key, key_length, &algorithm);
    if (err != KM_ERROR_OK)
        return err;
    request.key_description.push_back(TAG_ALGORITHM, algorithm);

    request.SetKeyMaterial(key, key_length);
    request.key_format = KM_KEY_FORMAT_PKCS8;
    ImportKeyResponse response(message_version_);
    err = Send(request, &response);
    if (err != KM_ERROR_OK)
        return err;

    *key_blob_length = response.key_blob.key_material_size;
    *key_blob = static_cast<uint8_t*>(malloc(*key_blob_length));
    memcpy(*key_blob, response.key_blob.key_material, *key_blob_length);
    printf("Returning %d bytes in key blob\n", (int)*key_blob_length);

    return KM_ERROR_OK;
}

keymaster_error_t TrustyKeymasterDevice::GetPkcs8KeyAlgorithm(const uint8_t* key, size_t key_length,
                                                              keymaster_algorithm_t* algorithm) {
    if (key == NULL) {
        ALOGE("No key specified for import");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    UniquePtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_Delete> pkcs8(
        d2i_PKCS8_PRIV_KEY_INFO(NULL, &key, key_length));
    if (pkcs8.get() == NULL) {
        ALOGE("Could not parse PKCS8 key blob");
        return KM_ERROR_INVALID_KEY_BLOB;
    }

    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKCS82PKEY(pkcs8.get()));
    if (pkey.get() == NULL) {
        ALOGE("Could not extract key from PKCS8 key blob");
        return KM_ERROR_INVALID_KEY_BLOB;
    }

    switch (EVP_PKEY_type(pkey->type)) {
    case EVP_PKEY_RSA:
        *algorithm = KM_ALGORITHM_RSA;
        break;
    case EVP_PKEY_EC:
        *algorithm = KM_ALGORITHM_EC;
        break;
    default:
        ALOGE("Unsupported algorithm %d", EVP_PKEY_type(pkey->type));
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }

    return KM_ERROR_OK;
}

int TrustyKeymasterDevice::get_keypair_public(const uint8_t* key_blob, const size_t key_blob_length,
                                              uint8_t** x509_data, size_t* x509_data_length) {
    ALOGD("Device received get_keypair_public");
    if (error_ != KM_ERROR_OK)
        return error_;

    ExportKeyRequest request(message_version_);
    request.SetKeyMaterial(key_blob, key_blob_length);
    request.key_format = KM_KEY_FORMAT_X509;
    ExportKeyResponse response(message_version_);
    keymaster_error_t err = Send(request, &response);
    if (err != KM_ERROR_OK)
        return err;

    *x509_data_length = response.key_data_length;
    *x509_data = static_cast<uint8_t*>(malloc(*x509_data_length));
    memcpy(*x509_data, response.key_data, *x509_data_length);
    printf("Returning %d bytes in x509 key\n", (int)*x509_data_length);

    return KM_ERROR_OK;
}

int TrustyKeymasterDevice::sign_data(const void* signing_params, const uint8_t* key_blob,
                                     const size_t key_blob_length, const uint8_t* data,
                                     const size_t data_length, uint8_t** signed_data,
                                     size_t* signed_data_length) {
    ALOGD("Device received sign_data, %d", error_);
    if (error_ != KM_ERROR_OK)
        return error_;

    BeginOperationRequest begin_request(message_version_);
    begin_request.purpose = KM_PURPOSE_SIGN;
    begin_request.SetKeyMaterial(key_blob, key_blob_length);
    keymaster_error_t err = StoreSigningParams(signing_params, key_blob, key_blob_length,
                                               &begin_request.additional_params);
    if (err != KM_ERROR_OK) {
        ALOGE("Error extracting signing params: %d", err);
        return err;
    }

    BeginOperationResponse begin_response(message_version_);
    ALOGD("Sending signing request begin");
    err = Send(begin_request, &begin_response);
    if (err != KM_ERROR_OK) {
        ALOGE("Error sending sign begin: %d", err);
        return err;
    }

    UpdateOperationRequest update_request(message_version_);
    update_request.op_handle = begin_response.op_handle;
    update_request.input.Reinitialize(data, data_length);
    UpdateOperationResponse update_response(message_version_);
    ALOGD("Sending signing request update");
    err = Send(update_request, &update_response);
    if (err != KM_ERROR_OK) {
        ALOGE("Error sending sign update: %d", err);
        return err;
    }

    FinishOperationRequest finish_request(message_version_);
    finish_request.op_handle = begin_response.op_handle;
    FinishOperationResponse finish_response(message_version_);
    ALOGD("Sending signing request finish");
    err = Send(finish_request, &finish_response);
    if (err != KM_ERROR_OK) {
        ALOGE("Error sending sign finish: %d", err);
        return err;
    }

    *signed_data_length = finish_response.output.available_read();
    *signed_data = static_cast<uint8_t*>(malloc(*signed_data_length));
    if (!finish_response.output.read(*signed_data, *signed_data_length)) {
        ALOGE("Error reading response data: %d", err);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

int TrustyKeymasterDevice::verify_data(const void* signing_params, const uint8_t* key_blob,
                                       const size_t key_blob_length, const uint8_t* signed_data,
                                       const size_t signed_data_length, const uint8_t* signature,
                                       const size_t signature_length) {
    ALOGD("Device received verify_data");
    if (error_ != KM_ERROR_OK)
        return error_;

    BeginOperationRequest begin_request(message_version_);
    begin_request.purpose = KM_PURPOSE_VERIFY;
    begin_request.SetKeyMaterial(key_blob, key_blob_length);
    keymaster_error_t err = StoreSigningParams(signing_params, key_blob, key_blob_length,
                                               &begin_request.additional_params);
    if (err != KM_ERROR_OK)
        return err;

    BeginOperationResponse begin_response(message_version_);
    err = Send(begin_request, &begin_response);
    if (err != KM_ERROR_OK)
        return err;

    UpdateOperationRequest update_request(message_version_);
    update_request.op_handle = begin_response.op_handle;
    update_request.input.Reinitialize(signed_data, signed_data_length);
    UpdateOperationResponse update_response(message_version_);
    err = Send(update_request, &update_response);
    if (err != KM_ERROR_OK)
        return err;

    FinishOperationRequest finish_request(message_version_);
    finish_request.op_handle = begin_response.op_handle;
    finish_request.signature.Reinitialize(signature, signature_length);
    FinishOperationResponse finish_response(message_version_);
    err = Send(finish_request, &finish_response);
    if (err != KM_ERROR_OK)
        return err;
    return KM_ERROR_OK;
}

hw_device_t* TrustyKeymasterDevice::hw_device() {
    return &device_.common;
}

static inline TrustyKeymasterDevice* convert_device(const keymaster0_device_t* dev) {
    return reinterpret_cast<TrustyKeymasterDevice*>(const_cast<keymaster0_device_t*>(dev));
}

/* static */
int TrustyKeymasterDevice::close_device(hw_device_t* dev) {
    delete reinterpret_cast<TrustyKeymasterDevice*>(dev);
    return 0;
}

/* static */
int TrustyKeymasterDevice::generate_keypair(const keymaster0_device_t* dev,
                                            const keymaster_keypair_t key_type,
                                            const void* key_params, uint8_t** keyBlob,
                                            size_t* keyBlobLength) {
    ALOGD("Generate keypair, sending to device: %p", convert_device(dev));
    return convert_device(dev)->generate_keypair(key_type, key_params, keyBlob, keyBlobLength);
}

/* static */
int TrustyKeymasterDevice::import_keypair(const keymaster0_device_t* dev, const uint8_t* key,
                                          const size_t key_length, uint8_t** key_blob,
                                          size_t* key_blob_length) {
    return convert_device(dev)->import_keypair(key, key_length, key_blob, key_blob_length);
}

/* static */
int TrustyKeymasterDevice::get_keypair_public(const keymaster0_device_t* dev,
                                              const uint8_t* key_blob, const size_t key_blob_length,
                                              uint8_t** x509_data, size_t* x509_data_length) {
    return convert_device(dev)
        ->get_keypair_public(key_blob, key_blob_length, x509_data, x509_data_length);
}

/* static */
int TrustyKeymasterDevice::sign_data(const keymaster0_device_t* dev, const void* params,
                                     const uint8_t* keyBlob, const size_t keyBlobLength,
                                     const uint8_t* data, const size_t dataLength,
                                     uint8_t** signedData, size_t* signedDataLength) {
    return convert_device(dev)
        ->sign_data(params, keyBlob, keyBlobLength, data, dataLength, signedData, signedDataLength);
}

/* static */
int TrustyKeymasterDevice::verify_data(const keymaster0_device_t* dev, const void* params,
                                       const uint8_t* keyBlob, const size_t keyBlobLength,
                                       const uint8_t* signedData, const size_t signedDataLength,
                                       const uint8_t* signature, const size_t signatureLength) {
    return convert_device(dev)->verify_data(params, keyBlob, keyBlobLength, signedData,
                                            signedDataLength, signature, signatureLength);
}

keymaster_error_t TrustyKeymasterDevice::Send(uint32_t command, const Serializable& req,
                                              KeymasterResponse* rsp) {
    uint32_t req_size = req.SerializedSize();
    if (req_size > SEND_BUF_SIZE)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    uint8_t send_buf[SEND_BUF_SIZE];
    Eraser send_buf_eraser(send_buf, SEND_BUF_SIZE);
    req.Serialize(send_buf, send_buf + req_size);

    // Send it
    uint8_t recv_buf[RECV_BUF_SIZE];
    Eraser recv_buf_eraser(recv_buf, RECV_BUF_SIZE);
    uint32_t rsp_size = RECV_BUF_SIZE;
    printf("Sending %d byte request\n", (int)req.SerializedSize());
    int rc = trusty_keymaster_call(command, send_buf, req_size, recv_buf, &rsp_size);
    if (rc < 0) {
        ALOGE("tipc error: %d\n", rc);
        // TODO(swillden): Distinguish permanent from transient errors and set error_ appropriately.
        return translate_error(rc);
    } else {
        ALOGV("Received %d byte response\n", rsp_size);
    }

    const keymaster_message* msg = (keymaster_message *) recv_buf;
    const uint8_t *p = msg->payload;
    if (!rsp->Deserialize(&p, p + rsp_size)) {
        ALOGE("Error deserializing response of size %d\n", (int)rsp_size);
        return KM_ERROR_UNKNOWN_ERROR;
    } else if (rsp->error != KM_ERROR_OK) {
        ALOGE("Response of size %d contained error code %d\n", (int)rsp_size, (int)rsp->error);
        return rsp->error;
    }
    return rsp->error;
}

keymaster_error_t TrustyKeymasterDevice::StoreSigningParams(const void* signing_params,
                                                            const uint8_t* key_blob,
                                                            size_t key_blob_length,
                                                            AuthorizationSet* auth_set) {
    uint8_t* pub_key_data;
    size_t pub_key_data_length;
    int err = get_keypair_public(&device_, key_blob, key_blob_length, &pub_key_data,
                                 &pub_key_data_length);
    if (err < 0) {
        ALOGE("Error %d extracting public key to determine algorithm", err);
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    UniquePtr<uint8_t, Malloc_Delete> pub_key(pub_key_data);

    const uint8_t* p = pub_key_data;
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(
        d2i_PUBKEY(nullptr /* allocate new struct */, &p, pub_key_data_length));

    switch (EVP_PKEY_type(pkey->type)) {
    case EVP_PKEY_RSA: {
        const keymaster_rsa_sign_params_t* rsa_params =
            reinterpret_cast<const keymaster_rsa_sign_params_t*>(signing_params);
        if (rsa_params->digest_type != DIGEST_NONE)
            return KM_ERROR_UNSUPPORTED_DIGEST;
        if (rsa_params->padding_type != PADDING_NONE)
            return KM_ERROR_UNSUPPORTED_PADDING_MODE;
        if (!auth_set->push_back(TAG_DIGEST, KM_DIGEST_NONE) ||
            !auth_set->push_back(TAG_PADDING, KM_PAD_NONE))
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    } break;
    case EVP_PKEY_EC: {
        const keymaster_ec_sign_params_t* ecdsa_params =
            reinterpret_cast<const keymaster_ec_sign_params_t*>(signing_params);
        if (ecdsa_params->digest_type != DIGEST_NONE)
            return KM_ERROR_UNSUPPORTED_DIGEST;
        if (!auth_set->push_back(TAG_DIGEST, KM_DIGEST_NONE))
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    } break;
    default:
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }
    return KM_ERROR_OK;
}

void TrustyKeymasterDevice::StoreNewKeyParams(AuthorizationSet* auth_set) {
    auth_set->push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
    auth_set->push_back(TAG_PURPOSE, KM_PURPOSE_VERIFY);
    auth_set->push_back(TAG_ALL_USERS);
    auth_set->push_back(TAG_NO_AUTH_REQUIRED);
    uint64_t now = java_time(time(NULL));
    auth_set->push_back(TAG_CREATION_DATETIME, now);
    auth_set->push_back(TAG_ORIGINATION_EXPIRE_DATETIME, now + HUNDRED_YEARS);
    if (message_version_ == 0) {
        auth_set->push_back(TAG_DIGEST_OLD, KM_DIGEST_NONE);
        auth_set->push_back(TAG_PADDING_OLD, KM_PAD_NONE);
    } else {
        auth_set->push_back(TAG_DIGEST, KM_DIGEST_NONE);
        auth_set->push_back(TAG_PADDING, KM_PAD_NONE);
    }
}

}  // namespace keymaster
