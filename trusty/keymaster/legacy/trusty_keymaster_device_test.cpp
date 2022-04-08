/*
 * Copyright (C) 2014 The Android Open Source Project
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
#include <algorithm>
#include <fstream>
#include <memory>

#include <gtest/gtest.h>
#include <openssl/engine.h>

#include <hardware/keymaster0.h>

#include <keymaster/android_keymaster.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/android_keymaster_utils.h>
#include <keymaster/keymaster_tags.h>
#include <keymaster/soft_keymaster_context.h>

#include <trusty_keymaster/legacy/trusty_keymaster_device.h>
#include "android_keymaster_test_utils.h"
#include "openssl_utils.h"

using std::ifstream;
using std::istreambuf_iterator;
using std::string;

static keymaster::AndroidKeymaster* impl_ = nullptr;

extern "C" {
int __android_log_print();
}

int __android_log_print() {
    return 0;
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    // Clean up stuff OpenSSL leaves around, so Valgrind doesn't complain.
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return result;
}

int trusty_keymaster_connect() {
    impl_ = new keymaster::AndroidKeymaster(new keymaster::SoftKeymasterContext(nullptr), 16);
}

void trusty_keymaster_disconnect() {
    delete static_cast<keymaster::AndroidKeymaster*>(priv_);
}

template <typename Req, typename Rsp>
static int fake_call(keymaster::AndroidKeymaster* device,
                     void (keymaster::AndroidKeymaster::*method)(const Req&, Rsp*), void* in_buf,
                     uint32_t in_size, void* out_buf, uint32_t* out_size) {
    Req req;
    const uint8_t* in = static_cast<uint8_t*>(in_buf);
    req.Deserialize(&in, in + in_size);
    Rsp rsp;
    (device->*method)(req, &rsp);

    *out_size = rsp.SerializedSize();
    uint8_t* out = static_cast<uint8_t*>(out_buf);
    rsp.Serialize(out, out + *out_size);
    return 0;
}

int trusty_keymaster_call(uint32_t cmd, void* in_buf, uint32_t in_size, void* out_buf,
                          uint32_t* out_size) {
    switch (cmd) {
        case KM_GENERATE_KEY:
            return fake_call(impl_, &keymaster::AndroidKeymaster::GenerateKey, in_buf, in_size,
                             out_buf, out_size);
        case KM_BEGIN_OPERATION:
            return fake_call(impl_, &keymaster::AndroidKeymaster::BeginOperation, in_buf, in_size,
                             out_buf, out_size);
        case KM_UPDATE_OPERATION:
            return fake_call(impl_, &keymaster::AndroidKeymaster::UpdateOperation, in_buf, in_size,
                             out_buf, out_size);
        case KM_FINISH_OPERATION:
            return fake_call(impl_, &keymaster::AndroidKeymaster::FinishOperation, in_buf, in_size,
                             out_buf, out_size);
        case KM_IMPORT_KEY:
            return fake_call(impl_, &keymaster::AndroidKeymaster::ImportKey, in_buf, in_size,
                             out_buf, out_size);
        case KM_EXPORT_KEY:
            return fake_call(impl_, &keymaster::AndroidKeymaster::ExportKey, in_buf, in_size,
                             out_buf, out_size);
    }
    return -EINVAL;
}

namespace keymaster {
namespace test {

class TrustyKeymasterTest : public testing::Test {
  protected:
    TrustyKeymasterTest() : device(NULL) {}

    keymaster_rsa_keygen_params_t build_rsa_params() {
        keymaster_rsa_keygen_params_t rsa_params;
        rsa_params.public_exponent = 65537;
        rsa_params.modulus_size = 2048;
        return rsa_params;
    }

    uint8_t* build_message(size_t length) {
        uint8_t* msg = new uint8_t[length];
        memset(msg, 'a', length);
        return msg;
    }

    size_t dsa_message_len(const keymaster_dsa_keygen_params_t& params) {
        switch (params.key_size) {
            case 256:
            case 1024:
                return 48;
            case 2048:
            case 4096:
                return 72;
            default:
                // Oops.
                return 0;
        }
    }

    TrustyKeymasterDevice device;
};

class Malloc_Delete {
  public:
    Malloc_Delete(void* p) : p_(p) {}
    ~Malloc_Delete() { free(p_); }

  private:
    void* p_;
};

typedef TrustyKeymasterTest KeyGenTest;
TEST_F(KeyGenTest, RsaSuccess) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);
}

TEST_F(KeyGenTest, EcdsaSuccess) {
    keymaster_ec_keygen_params_t ec_params = {256};
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_EC, &ec_params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);
}

typedef TrustyKeymasterTest SigningTest;
TEST_F(SigningTest, RsaSuccess) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_rsa_sign_params_t sig_params = {DIGEST_NONE, PADDING_NONE};
    size_t message_len = params.modulus_size / 8;
    std::unique_ptr<uint8_t[]> message(build_message(message_len));
    uint8_t* signature;
    size_t siglen;
    EXPECT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message.get(), message_len,
                                            &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_EQ(message_len, siglen);
}

TEST_F(SigningTest, RsaShortMessage) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_rsa_sign_params_t sig_params = {DIGEST_NONE, PADDING_NONE};
    size_t message_len = params.modulus_size / 8 - 1;
    std::unique_ptr<uint8_t[]> message(build_message(message_len));
    uint8_t* signature;
    size_t siglen;
    EXPECT_EQ(KM_ERROR_UNKNOWN_ERROR, device.sign_data(&sig_params, ptr, size, message.get(),
                                                       message_len, &signature, &siglen));
}

TEST_F(SigningTest, RsaLongMessage) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_rsa_sign_params_t sig_params = {DIGEST_NONE, PADDING_NONE};
    size_t message_len = params.modulus_size / 8 + 1;
    std::unique_ptr<uint8_t[]> message(build_message(message_len));
    uint8_t* signature;
    size_t siglen;
    EXPECT_EQ(KM_ERROR_UNKNOWN_ERROR, device.sign_data(&sig_params, ptr, size, message.get(),
                                                       message_len, &signature, &siglen));
}

TEST_F(SigningTest, EcdsaSuccess) {
    keymaster_ec_keygen_params_t params = {256};
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_EC, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_ec_sign_params_t sig_params = {DIGEST_NONE};
    uint8_t message[] = "12345678901234567890123456789012";
    uint8_t* signature;
    size_t siglen;
    ASSERT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message,
                                            array_size(message) - 1, &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_GT(siglen, 69U);
    EXPECT_LT(siglen, 73U);
}

TEST_F(SigningTest, EcdsaEmptyMessageSuccess) {
    keymaster_ec_keygen_params_t params = {256};
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_EC, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_ec_sign_params_t sig_params = {DIGEST_NONE};
    uint8_t message[] = "";
    uint8_t* signature;
    size_t siglen;
    ASSERT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message,
                                            array_size(message) - 1, &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_GT(siglen, 69U);
    EXPECT_LT(siglen, 73U);
}

TEST_F(SigningTest, EcdsaLargeMessageSuccess) {
    keymaster_ec_keygen_params_t params = {256};
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_EC, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_ec_sign_params_t sig_params = {DIGEST_NONE};
    size_t message_len = 1024 * 7;
    std::unique_ptr<uint8_t[]> message(new uint8_t[message_len]);
    // contents of message don't matter.
    uint8_t* signature;
    size_t siglen;
    ASSERT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message.get(), message_len,
                                            &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_GT(siglen, 69U);
    EXPECT_LT(siglen, 73U);
}

typedef TrustyKeymasterTest VerificationTest;
TEST_F(VerificationTest, RsaSuccess) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_rsa_sign_params_t sig_params = {DIGEST_NONE, PADDING_NONE};
    size_t message_len = params.modulus_size / 8;
    std::unique_ptr<uint8_t[]> message(build_message(message_len));
    uint8_t* signature;
    size_t siglen;
    EXPECT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message.get(), message_len,
                                            &signature, &siglen));
    Malloc_Delete sig_deleter(signature);

    EXPECT_EQ(KM_ERROR_OK, device.verify_data(&sig_params, ptr, size, message.get(), message_len,
                                              signature, siglen));
}

TEST_F(VerificationTest, RsaBadSignature) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_rsa_sign_params_t sig_params = {DIGEST_NONE, PADDING_NONE};
    size_t message_len = params.modulus_size / 8;
    std::unique_ptr<uint8_t[]> message(build_message(message_len));
    uint8_t* signature;
    size_t siglen;
    EXPECT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message.get(), message_len,
                                            &signature, &siglen));

    Malloc_Delete sig_deleter(signature);
    signature[siglen / 2]++;
    EXPECT_EQ(KM_ERROR_VERIFICATION_FAILED,
              device.verify_data(&sig_params, ptr, size, message.get(), message_len, signature,
                                 siglen));
}

TEST_F(VerificationTest, RsaBadMessage) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_rsa_sign_params_t sig_params = {DIGEST_NONE, PADDING_NONE};
    size_t message_len = params.modulus_size / 8;
    std::unique_ptr<uint8_t[]> message(build_message(message_len));
    uint8_t* signature;
    size_t siglen;
    EXPECT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message.get(), message_len,
                                            &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    message[0]++;
    EXPECT_EQ(KM_ERROR_VERIFICATION_FAILED,
              device.verify_data(&sig_params, ptr, size, message.get(), message_len, signature,
                                 siglen));
}

TEST_F(VerificationTest, RsaShortMessage) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_rsa_sign_params_t sig_params = {DIGEST_NONE, PADDING_NONE};
    size_t message_len = params.modulus_size / 8;
    std::unique_ptr<uint8_t[]> message(build_message(message_len));
    uint8_t* signature;
    size_t siglen;
    EXPECT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message.get(), message_len,
                                            &signature, &siglen));

    Malloc_Delete sig_deleter(signature);
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH,
              device.verify_data(&sig_params, ptr, size, message.get(), message_len - 1, signature,
                                 siglen));
}

TEST_F(VerificationTest, RsaLongMessage) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_rsa_sign_params_t sig_params = {DIGEST_NONE, PADDING_NONE};
    size_t message_len = params.modulus_size / 8;
    std::unique_ptr<uint8_t[]> message(build_message(message_len + 1));
    uint8_t* signature;
    size_t siglen;
    EXPECT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message.get(), message_len,
                                            &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH,
              device.verify_data(&sig_params, ptr, size, message.get(), message_len + 1, signature,
                                 siglen));
}

TEST_F(VerificationTest, EcdsaSuccess) {
    keymaster_ec_keygen_params_t params = {256};
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_EC, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_ec_sign_params_t sig_params = {DIGEST_NONE};
    uint8_t message[] = "12345678901234567890123456789012";
    uint8_t* signature;
    size_t siglen;
    ASSERT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message,
                                            array_size(message) - 1, &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_EQ(KM_ERROR_OK, device.verify_data(&sig_params, ptr, size, message,
                                              array_size(message) - 1, signature, siglen));
}

TEST_F(VerificationTest, EcdsaLargeMessageSuccess) {
    keymaster_ec_keygen_params_t params = {256};
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_EC, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    keymaster_ec_sign_params_t sig_params = {DIGEST_NONE};
    size_t message_len = 1024 * 7;
    std::unique_ptr<uint8_t[]> message(new uint8_t[message_len]);
    // contents of message don't matter.
    uint8_t* signature;
    size_t siglen;
    ASSERT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message.get(), message_len,
                                            &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_EQ(KM_ERROR_OK, device.verify_data(&sig_params, ptr, size, message.get(), message_len,
                                              signature, siglen));
}

static string read_file(const string& file_name) {
    ifstream file_stream(file_name, std::ios::binary);
    istreambuf_iterator<char> file_begin(file_stream);
    istreambuf_iterator<char> file_end;
    return string(file_begin, file_end);
}

typedef TrustyKeymasterTest ImportKeyTest;
TEST_F(ImportKeyTest, RsaSuccess) {
    string pk8_key = read_file("../../../../system/keymaster/rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());

    uint8_t* key = NULL;
    size_t size;
    ASSERT_EQ(KM_ERROR_OK, device.import_keypair(reinterpret_cast<const uint8_t*>(pk8_key.data()),
                                                 pk8_key.size(), &key, &size));
    Malloc_Delete key_deleter(key);

    keymaster_rsa_sign_params_t sig_params = {DIGEST_NONE, PADDING_NONE};
    size_t message_size = 1024 /* key size */ / 8;
    std::unique_ptr<uint8_t[]> message(new uint8_t[message_size]);
    memset(message.get(), 'a', message_size);
    uint8_t* signature;
    size_t siglen;
    ASSERT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, key, size, message.get(), message_size,
                                            &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_EQ(KM_ERROR_OK, device.verify_data(&sig_params, key, size, message.get(), message_size,
                                              signature, siglen));
}

TEST_F(ImportKeyTest, EcdsaSuccess) {
    string pk8_key = read_file("../../../../system/keymaster/ec_privkey_pk8.der");
    ASSERT_EQ(138U, pk8_key.size());

    uint8_t* key = NULL;
    size_t size;
    ASSERT_EQ(KM_ERROR_OK, device.import_keypair(reinterpret_cast<const uint8_t*>(pk8_key.data()),
                                                 pk8_key.size(), &key, &size));
    Malloc_Delete key_deleter(key);

    keymaster_ec_sign_params_t sig_params = {DIGEST_NONE};
    uint8_t message[] = "12345678901234567890123456789012";
    uint8_t* signature;
    size_t siglen;
    ASSERT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, key, size, message,
                                            array_size(message) - 1, &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_EQ(KM_ERROR_OK, device.verify_data(&sig_params, key, size, message,
                                              array_size(message) - 1, signature, siglen));
}

struct EVP_PKEY_CTX_Delete {
    void operator()(EVP_PKEY_CTX* p) { EVP_PKEY_CTX_free(p); }
};

static void VerifySignature(const uint8_t* key, size_t key_len, const uint8_t* signature,
                            size_t signature_len, const uint8_t* message, size_t message_len) {
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Delete> pkey(d2i_PUBKEY(NULL, &key, key_len));
    ASSERT_TRUE(pkey.get() != NULL);
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Delete> ctx(EVP_PKEY_CTX_new(pkey.get(), NULL));
    ASSERT_TRUE(ctx.get() != NULL);
    ASSERT_EQ(1, EVP_PKEY_verify_init(ctx.get()));
    if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA)
        ASSERT_EQ(1, EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_NO_PADDING));
    EXPECT_EQ(1, EVP_PKEY_verify(ctx.get(), signature, signature_len, message, message_len));
}

typedef TrustyKeymasterTest ExportKeyTest;
TEST_F(ExportKeyTest, RsaSuccess) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    uint8_t* exported;
    size_t exported_size;
    EXPECT_EQ(KM_ERROR_OK, device.get_keypair_public(ptr, size, &exported, &exported_size));
    Malloc_Delete exported_deleter(exported);

    // Sign a message so we can verify it with the exported pubkey.
    keymaster_rsa_sign_params_t sig_params = {DIGEST_NONE, PADDING_NONE};
    size_t message_len = params.modulus_size / 8;
    std::unique_ptr<uint8_t[]> message(build_message(message_len));
    uint8_t* signature;
    size_t siglen;
    EXPECT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, ptr, size, message.get(), message_len,
                                            &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_EQ(message_len, siglen);
    const uint8_t* tmp = exported;

    VerifySignature(exported, exported_size, signature, siglen, message.get(), message_len);
}

typedef TrustyKeymasterTest ExportKeyTest;
TEST_F(ExportKeyTest, EcdsaSuccess) {
    keymaster_ec_keygen_params_t params = {256};
    uint8_t* key = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_EC, &params, &key, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(key);

    uint8_t* exported;
    size_t exported_size;
    EXPECT_EQ(KM_ERROR_OK, device.get_keypair_public(key, size, &exported, &exported_size));
    Malloc_Delete exported_deleter(exported);

    // Sign a message so we can verify it with the exported pubkey.
    keymaster_ec_sign_params_t sig_params = {DIGEST_NONE};
    uint8_t message[] = "12345678901234567890123456789012";
    uint8_t* signature;
    size_t siglen;
    ASSERT_EQ(KM_ERROR_OK, device.sign_data(&sig_params, key, size, message,
                                            array_size(message) - 1, &signature, &siglen));
    Malloc_Delete sig_deleter(signature);
    EXPECT_EQ(KM_ERROR_OK, device.verify_data(&sig_params, key, size, message,
                                              array_size(message) - 1, signature, siglen));

    VerifySignature(exported, exported_size, signature, siglen, message, array_size(message) - 1);
}

}  // namespace test
}  // namespace keymaster
