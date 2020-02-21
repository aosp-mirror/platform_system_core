/*
 * Copyright 2020 The Android Open Source Project
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

#define LOG_TAG "AdbPairingAuthTest"

#include <gtest/gtest.h>

#include <adb/pairing/pairing_auth.h>
#include <android-base/endian.h>

namespace adb {
namespace pairing {

static void PairingAuthDeleter(PairingAuthCtx* p) {
    pairing_auth_destroy(p);
}

class AdbPairingAuthTest : public testing::Test {
  protected:
    virtual void SetUp() override {}

    virtual void TearDown() override {}

    using PairingAuthUniquePtr = std::unique_ptr<PairingAuthCtx, decltype(&PairingAuthDeleter)>;

    PairingAuthUniquePtr makeClient(std::vector<uint8_t> pswd) {
        return PairingAuthUniquePtr(pairing_auth_client_new(pswd.data(), pswd.size()),
                                    PairingAuthDeleter);
    }

    PairingAuthUniquePtr makeServer(std::vector<uint8_t> pswd) {
        return PairingAuthUniquePtr(pairing_auth_server_new(pswd.data(), pswd.size()),
                                    PairingAuthDeleter);
    }
};

TEST_F(AdbPairingAuthTest, EmptyPassword) {
    // Context creation should fail if password is empty
    PairingAuthUniquePtr client(nullptr, PairingAuthDeleter);
    ASSERT_DEATH(
            {
                client = PairingAuthUniquePtr(pairing_auth_client_new(nullptr, 0),
                                              PairingAuthDeleter);
            },
            "");
    ASSERT_DEATH(
            {
                client = PairingAuthUniquePtr(pairing_auth_client_new(nullptr, 2),
                                              PairingAuthDeleter);
            },
            "");
    ASSERT_DEATH(
            {
                uint8_t p;
                client = PairingAuthUniquePtr(pairing_auth_client_new(&p, 0), PairingAuthDeleter);
            },
            "");
}

TEST_F(AdbPairingAuthTest, ValidPassword) {
    const char* kPswd = "password";
    std::vector<uint8_t> pswd(kPswd, kPswd + sizeof(kPswd));
    auto client = makeClient(pswd);
    auto server = makeServer(pswd);

    ASSERT_NE(nullptr, client);
    ASSERT_NE(nullptr, server);

    // msg should not be empty.
    {
        size_t msg_size = pairing_auth_msg_size(client.get());
        std::vector<uint8_t> buf(msg_size);
        ASSERT_GT(msg_size, 0);
        pairing_auth_get_spake2_msg(client.get(), buf.data());
    }
    {
        size_t msg_size = pairing_auth_msg_size(server.get());
        std::vector<uint8_t> buf(msg_size);
        ASSERT_GT(msg_size, 0);
        pairing_auth_get_spake2_msg(server.get(), buf.data());
    }
}

TEST_F(AdbPairingAuthTest, NoInitCipher) {
    // Register a non-empty password, but not the peer's msg.
    // You should not be able to encrypt/decrypt messages.
    const char* kPswd = "password";
    std::vector<uint8_t> pswd(kPswd, kPswd + sizeof(kPswd));
    std::vector<uint8_t> data{0x01, 0x02, 0x03};
    uint8_t outbuf[256];
    size_t outsize;

    // All other functions should crash if cipher hasn't been initialized.
    ASSERT_DEATH(
            {
                auto server = makeServer(pswd);
                pairing_auth_init_cipher(server.get(), nullptr, 0);
            },
            "");
    ASSERT_DEATH(
            {
                auto server = makeServer(pswd);
                pairing_auth_encrypt(server.get(), data.data(), data.size(), outbuf, &outsize);
            },
            "");
    ASSERT_DEATH(
            {
                auto server = makeServer(pswd);
                pairing_auth_decrypt(server.get(), data.data(), data.size(), outbuf, &outsize);
            },
            "");
    ASSERT_DEATH(
            {
                auto server = makeServer(pswd);
                pairing_auth_safe_decrypted_size(server.get(), data.data(), data.size());
            },
            "");
    ASSERT_DEATH(
            {
                auto server = makeServer(pswd);
                pairing_auth_safe_encrypted_size(server.get(), data.size());
            },
            "");
}

TEST_F(AdbPairingAuthTest, DifferentPasswords) {
    // Register different passwords and then exchange the msgs. The
    // encryption should succeed, but the decryption should fail, since the
    // ciphers have been initialized with different keys.
    auto client = makeClient({0x01, 0x02, 0x03});
    std::vector<uint8_t> client_msg(pairing_auth_msg_size(client.get()));
    ASSERT_FALSE(client_msg.empty());
    pairing_auth_get_spake2_msg(client.get(), client_msg.data());

    auto server = makeServer({0x01, 0x02, 0x04});
    std::vector<uint8_t> server_msg(pairing_auth_msg_size(server.get()));
    ASSERT_FALSE(server_msg.empty());
    pairing_auth_get_spake2_msg(server.get(), server_msg.data());

    EXPECT_TRUE(pairing_auth_init_cipher(client.get(), server_msg.data(), server_msg.size()));
    EXPECT_TRUE(pairing_auth_init_cipher(server.get(), client_msg.data(), client_msg.size()));

    // We shouldn't be able to decrypt.
    std::vector<uint8_t> msg{0x2a, 0x2b, 0x2c};
    // Client encrypts, server can't decrypt
    size_t out_size;
    client_msg.resize(pairing_auth_safe_encrypted_size(client.get(), msg.size()));
    ASSERT_GT(client_msg.size(), 0);
    ASSERT_TRUE(pairing_auth_encrypt(client.get(), msg.data(), msg.size(), client_msg.data(),
                                     &out_size));
    ASSERT_GT(out_size, 0);
    client_msg.resize(out_size);

    server_msg.resize(
            pairing_auth_safe_decrypted_size(server.get(), client_msg.data(), client_msg.size()));
    ASSERT_GT(server_msg.size(), 0);
    ASSERT_FALSE(pairing_auth_decrypt(server.get(), client_msg.data(), client_msg.size(),
                                      server_msg.data(), &out_size));

    // Server encrypts, client can't decrypt
    server_msg.resize(pairing_auth_safe_encrypted_size(server.get(), msg.size()));
    ASSERT_GT(server_msg.size(), 0);
    ASSERT_TRUE(pairing_auth_encrypt(server.get(), msg.data(), msg.size(), server_msg.data(),
                                     &out_size));
    ASSERT_GT(out_size, 0);
    server_msg.resize(out_size);

    client_msg.resize(
            pairing_auth_safe_decrypted_size(client.get(), server_msg.data(), server_msg.size()));
    ASSERT_GT(client_msg.size(), 0);
    ASSERT_FALSE(pairing_auth_decrypt(client.get(), server_msg.data(), server_msg.size(),
                                      client_msg.data(), &out_size));
}

TEST_F(AdbPairingAuthTest, SamePasswords) {
    // Register same password and then exchange the msgs. The
    // encryption and decryption should succeed and have the same, unencrypted
    // values.
    std::vector<uint8_t> pswd{0x4f, 0x5a, 0x01, 0x46};
    auto client = makeClient(pswd);
    std::vector<uint8_t> client_msg(pairing_auth_msg_size(client.get()));
    ASSERT_FALSE(client_msg.empty());
    pairing_auth_get_spake2_msg(client.get(), client_msg.data());

    auto server = makeServer(pswd);
    std::vector<uint8_t> server_msg(pairing_auth_msg_size(server.get()));
    ASSERT_FALSE(server_msg.empty());
    pairing_auth_get_spake2_msg(server.get(), server_msg.data());

    EXPECT_TRUE(pairing_auth_init_cipher(client.get(), server_msg.data(), server_msg.size()));
    EXPECT_TRUE(pairing_auth_init_cipher(server.get(), client_msg.data(), client_msg.size()));

    // We should be able to decrypt.
    std::vector<uint8_t> msg{0x2a, 0x2b, 0x2c, 0xff, 0x45, 0x12, 0x33};
    // Client encrypts, server decrypts
    size_t out_size;
    client_msg.resize(pairing_auth_safe_encrypted_size(client.get(), msg.size()));
    ASSERT_GT(client_msg.size(), 0);
    ASSERT_TRUE(pairing_auth_encrypt(client.get(), msg.data(), msg.size(), client_msg.data(),
                                     &out_size));
    ASSERT_GT(out_size, 0);
    client_msg.resize(out_size);

    server_msg.resize(
            pairing_auth_safe_decrypted_size(server.get(), client_msg.data(), client_msg.size()));
    ASSERT_GT(server_msg.size(), 0);
    ASSERT_TRUE(pairing_auth_decrypt(server.get(), client_msg.data(), client_msg.size(),
                                     server_msg.data(), &out_size));
    ASSERT_EQ(out_size, msg.size());
    EXPECT_EQ(memcmp(msg.data(), server_msg.data(), out_size), 0);

    // Server encrypts, client decrypt
    server_msg.resize(pairing_auth_safe_encrypted_size(server.get(), msg.size()));
    ASSERT_GT(server_msg.size(), 0);
    ASSERT_TRUE(pairing_auth_encrypt(server.get(), msg.data(), msg.size(), server_msg.data(),
                                     &out_size));
    ASSERT_GT(out_size, 0);
    server_msg.resize(out_size);

    client_msg.resize(
            pairing_auth_safe_decrypted_size(client.get(), server_msg.data(), server_msg.size()));
    ASSERT_GT(client_msg.size(), 0);
    ASSERT_TRUE(pairing_auth_decrypt(client.get(), server_msg.data(), server_msg.size(),
                                     client_msg.data(), &out_size));
    ASSERT_EQ(out_size, msg.size());
    EXPECT_EQ(memcmp(msg.data(), client_msg.data(), out_size), 0);
}

TEST_F(AdbPairingAuthTest, CorruptedPayload) {
    // Do a matching password for both server/client, but let's fudge with the
    // header payload field. The decryption should fail.
    std::vector<uint8_t> pswd{0x4f, 0x5a, 0x01, 0x46};
    auto client = makeClient(pswd);
    std::vector<uint8_t> client_msg(pairing_auth_msg_size(client.get()));
    ASSERT_FALSE(client_msg.empty());
    pairing_auth_get_spake2_msg(client.get(), client_msg.data());

    auto server = makeServer(pswd);
    std::vector<uint8_t> server_msg(pairing_auth_msg_size(server.get()));
    ASSERT_FALSE(server_msg.empty());
    pairing_auth_get_spake2_msg(server.get(), server_msg.data());

    EXPECT_TRUE(pairing_auth_init_cipher(client.get(), server_msg.data(), server_msg.size()));
    EXPECT_TRUE(pairing_auth_init_cipher(server.get(), client_msg.data(), client_msg.size()));

    std::vector<uint8_t> msg{0x2a, 0x2b, 0x2c, 0xff, 0x45, 0x12,
                             0x33, 0x45, 0x12, 0xea, 0xf2, 0xdb};
    {
        // Client encrypts whole msg, server decrypts msg. Should be fine.
        size_t out_size;
        client_msg.resize(pairing_auth_safe_encrypted_size(client.get(), msg.size()));
        ASSERT_GT(client_msg.size(), 0);
        ASSERT_TRUE(pairing_auth_encrypt(client.get(), msg.data(), msg.size(), client_msg.data(),
                                         &out_size));
        ASSERT_GT(out_size, 0);
        client_msg.resize(out_size);

        server_msg.resize(pairing_auth_safe_decrypted_size(server.get(), client_msg.data(),
                                                           client_msg.size()));
        ASSERT_GT(server_msg.size(), 0);
        ASSERT_TRUE(pairing_auth_decrypt(server.get(), client_msg.data(), client_msg.size(),
                                         server_msg.data(), &out_size));
        ASSERT_EQ(out_size, msg.size());
        EXPECT_EQ(memcmp(msg.data(), server_msg.data(), out_size), 0);
    }
    {
        // 1) Client encrypts msg
        // 2) append some data to the encrypted msg
        // 3) change the payload field
        // 4) server tries to decrypt. It should fail.
        size_t out_size;
        client_msg.resize(pairing_auth_safe_encrypted_size(client.get(), msg.size()));
        ASSERT_GT(client_msg.size(), 0);
        ASSERT_TRUE(pairing_auth_encrypt(client.get(), msg.data(), msg.size(), client_msg.data(),
                                         &out_size));
        ASSERT_GT(out_size, 0);
        client_msg.resize(out_size);
        client_msg.push_back(0xaa);
        // This requires knowledge of the layout of the data. payload is the
        // first four bytes of the client_msg.
        uint32_t* payload = reinterpret_cast<uint32_t*>(client_msg.data());
        *payload = ntohl(*payload);
        *payload = htonl(*payload + 1);

        server_msg.resize(pairing_auth_safe_decrypted_size(server.get(), client_msg.data(),
                                                           client_msg.size()));
        ASSERT_GT(server_msg.size(), 0);
        ASSERT_FALSE(pairing_auth_decrypt(server.get(), client_msg.data(), client_msg.size(),
                                          server_msg.data(), &out_size));
    }
    {
        // 1) Client encrypts msg
        // 3) decrement the payload field
        // 4) server tries to decrypt. It should fail.
        size_t out_size;
        client_msg.resize(pairing_auth_safe_encrypted_size(client.get(), msg.size()));
        ASSERT_GT(client_msg.size(), 0);
        ASSERT_TRUE(pairing_auth_encrypt(client.get(), msg.data(), msg.size(), client_msg.data(),
                                         &out_size));
        ASSERT_GT(out_size, 0);
        client_msg.resize(out_size);
        // This requires knowledge of the layout of the data. payload is the
        // first four bytes of the client_msg.
        uint32_t* payload = reinterpret_cast<uint32_t*>(client_msg.data());
        *payload = ntohl(*payload);
        *payload = htonl(*payload - 1);

        server_msg.resize(pairing_auth_safe_decrypted_size(server.get(), client_msg.data(),
                                                           client_msg.size()));
        ASSERT_GT(server_msg.size(), 0);
        ASSERT_FALSE(pairing_auth_decrypt(server.get(), client_msg.data(), client_msg.size(),
                                          server_msg.data(), &out_size));
    }
}

}  // namespace pairing
}  // namespace adb
