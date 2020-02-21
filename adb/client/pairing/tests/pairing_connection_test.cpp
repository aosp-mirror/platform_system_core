/*
 * Copyright 2019 The Android Open Source Project
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

#define LOG_TAG "AdbWifiPairingConnectionTest"

#include <condition_variable>
#include <mutex>
#include <thread>

#include <adbwifi/pairing/pairing_server.h>
#include <android-base/logging.h>
#include <gtest/gtest.h>

#include "adb/client/pairing/tests/pairing_client.h"

namespace adbwifi {
namespace pairing {

static const std::string kTestServerCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBljCCAT2gAwIBAgIBATAKBggqhkjOPQQDAjAzMQswCQYDVQQGEwJVUzEQMA4G\n"
        "A1UECgwHQW5kcm9pZDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTE5MTEwNzAyMDkx\n"
        "NVoXDTI5MTEwNDAyMDkxNVowMzELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJv\n"
        "aWQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n"
        "BCXRovy3RhtK0Khle48vUmkcuI0OF7K8o9sVPE4oVnp24l+cCYr3BtrgifoHPgj4\n"
        "vq7n105qzK7ngBHH+LBmYIijQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/\n"
        "BAQDAgGGMB0GA1UdDgQWBBQi4eskzqVG3SCX2CwJF/aTZqUcuTAKBggqhkjOPQQD\n"
        "AgNHADBEAiBPYvLOCIvPDtq3vMF7A2z7t7JfcCmbC7g8ftEVJucJBwIgepf+XjTb\n"
        "L7RCE16p7iVkpHUrWAOl7zDxqD+jaji5MkQ=\n"
        "-----END CERTIFICATE-----\n";

static const std::string kTestServerPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSCaskWPtutIgh8uQ\n"
        "UBH6ZIea5Kxm7m6kkGNkd8FYPSOhRANCAAQl0aL8t0YbStCoZXuPL1JpHLiNDhey\n"
        "vKPbFTxOKFZ6duJfnAmK9wba4In6Bz4I+L6u59dOasyu54ARx/iwZmCI\n"
        "-----END PRIVATE KEY-----\n";

static const std::string kTestClientCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBlzCCAT2gAwIBAgIBATAKBggqhkjOPQQDAjAzMQswCQYDVQQGEwJVUzEQMA4G\n"
        "A1UECgwHQW5kcm9pZDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTE5MTEwOTAxNTAy\n"
        "OFoXDTI5MTEwNjAxNTAyOFowMzELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJv\n"
        "aWQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n"
        "BGW+RuoEIzbt42zAuZzbXaC0bvh8n4OLFDnqkkW6kWA43GYg/mUMVc9vg/nuxyuM\n"
        "aT0KqbTaLhm+NjCXVRnxBrajQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/\n"
        "BAQDAgGGMB0GA1UdDgQWBBTjCaC8/NXgdBz9WlMVCNwhx7jn0jAKBggqhkjOPQQD\n"
        "AgNIADBFAiB/xp2boj7b1KK2saS6BL59deo/TvfgZ+u8HPq4k4VP3gIhAMXswp9W\n"
        "XdlziccQdj+0KpbUojDKeHOr4fIj/+LxsWPa\n"
        "-----END CERTIFICATE-----\n";

static const std::string kTestClientPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFw/CWY1f6TSB70AF\n"
        "yVe8n6QdYFu8HW5t/tij2SrXx42hRANCAARlvkbqBCM27eNswLmc212gtG74fJ+D\n"
        "ixQ56pJFupFgONxmIP5lDFXPb4P57scrjGk9Cqm02i4ZvjYwl1UZ8Qa2\n"
        "-----END PRIVATE KEY-----\n";

class AdbWifiPairingConnectionTest : public testing::Test {
  protected:
    virtual void SetUp() override {}

    virtual void TearDown() override {}

    void initPairing(const std::vector<uint8_t> server_pswd,
                     const std::vector<uint8_t> client_pswd) {
        std::vector<uint8_t> cert;
        std::vector<uint8_t> key;
        // Include the null-byte as well.
        cert.assign(reinterpret_cast<const uint8_t*>(kTestServerCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestServerCert.data()) +
                            kTestServerCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()) +
                           kTestServerPrivKey.size() + 1);
        server_ = PairingServer::create(server_pswd, server_info_, cert, key, kDefaultPairingPort);
        cert.assign(reinterpret_cast<const uint8_t*>(kTestClientCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestClientCert.data()) +
                            kTestClientCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()) +
                           kTestClientPrivKey.size() + 1);
        client_ = PairingClient::create(client_pswd, client_info_, cert, key, "127.0.0.1");
    }

    std::unique_ptr<PairingServer> createServer(const std::vector<uint8_t> pswd) {
        std::vector<uint8_t> cert;
        std::vector<uint8_t> key;
        // Include the null-byte as well.
        cert.assign(reinterpret_cast<const uint8_t*>(kTestServerCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestServerCert.data()) +
                            kTestServerCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()) +
                           kTestServerPrivKey.size() + 1);
        return PairingServer::create(pswd, server_info_, cert, key, kDefaultPairingPort);
    }

    std::unique_ptr<PairingClient> createClient(const std::vector<uint8_t> pswd) {
        std::vector<uint8_t> cert;
        std::vector<uint8_t> key;
        // Include the null-byte as well.
        cert.assign(reinterpret_cast<const uint8_t*>(kTestClientCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestClientCert.data()) +
                            kTestClientCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()) +
                           kTestClientPrivKey.size() + 1);
        return PairingClient::create(pswd, client_info_, cert, key, "127.0.0.1");
    }

    std::unique_ptr<PairingServer> server_;
    const PeerInfo server_info_ = {
            .name = "my_server_name",
            .guid = "my_server_guid",
    };
    std::unique_ptr<PairingClient> client_;
    const PeerInfo client_info_ = {
            .name = "my_client_name",
            .guid = "my_client_guid",
    };
};

TEST_F(AdbWifiPairingConnectionTest, ServerCreation) {
    // All parameters bad
    auto server = PairingServer::create({}, {}, {}, {}, -1);
    EXPECT_EQ(nullptr, server);
    // Bad password
    server = PairingServer::create({}, server_info_, {0x01}, {0x01}, -1);
    EXPECT_EQ(nullptr, server);
    // Bad peer_info
    server = PairingServer::create({0x01}, {}, {0x01}, {0x01}, -1);
    EXPECT_EQ(nullptr, server);
    // Bad certificate
    server = PairingServer::create({0x01}, server_info_, {}, {0x01}, -1);
    EXPECT_EQ(nullptr, server);
    // Bad private key
    server = PairingServer::create({0x01}, server_info_, {0x01}, {}, -1);
    EXPECT_EQ(nullptr, server);
    // Bad port
    server = PairingServer::create({0x01}, server_info_, {0x01}, {0x01}, -1);
    EXPECT_EQ(nullptr, server);
    // Valid params
    server = PairingServer::create({0x01}, server_info_, {0x01}, {0x01}, 7776);
    EXPECT_NE(nullptr, server);
}

TEST_F(AdbWifiPairingConnectionTest, ClientCreation) {
    // All parameters bad
    auto client = PairingClient::create({}, client_info_, {}, {}, "");
    EXPECT_EQ(nullptr, client);
    // Bad password
    client = PairingClient::create({}, client_info_, {0x01}, {0x01}, "127.0.0.1");
    EXPECT_EQ(nullptr, client);
    // Bad peer_info
    client = PairingClient::create({0x01}, {}, {0x01}, {0x01}, "127.0.0.1");
    EXPECT_EQ(nullptr, client);
    // Bad certificate
    client = PairingClient::create({0x01}, client_info_, {}, {0x01}, "127.0.0.1");
    EXPECT_EQ(nullptr, client);
    // Bad private key
    client = PairingClient::create({0x01}, client_info_, {0x01}, {}, "127.0.0.1");
    EXPECT_EQ(nullptr, client);
    // Bad ip address
    client = PairingClient::create({0x01}, client_info_, {0x01}, {0x01}, "");
    EXPECT_EQ(nullptr, client);
    // Valid params
    client = PairingClient::create({0x01}, client_info_, {0x01}, {0x01}, "127.0.0.1");
    EXPECT_NE(nullptr, client);
}

TEST_F(AdbWifiPairingConnectionTest, SmokeValidPairing) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    initPairing(pswd, pswd);

    // Start the server first, to open the port for connections
    std::mutex server_mutex;
    std::condition_variable server_cv;
    std::unique_lock<std::mutex> server_lock(server_mutex);

    auto server_callback = [&](const PeerInfo* peer_info, const std::vector<uint8_t>* cert,
                               void* opaque) {
        ASSERT_NE(nullptr, peer_info);
        ASSERT_NE(nullptr, cert);
        EXPECT_FALSE(cert->empty());
        EXPECT_EQ(nullptr, opaque);

        // Verify the peer_info and cert
        ASSERT_EQ(strlen(peer_info->name), strlen(client_info_.name));
        EXPECT_EQ(::memcmp(peer_info->name, client_info_.name, strlen(client_info_.name)), 0);
        ASSERT_EQ(strlen(peer_info->guid), strlen(client_info_.guid));
        EXPECT_EQ(::memcmp(peer_info->guid, client_info_.guid, strlen(client_info_.guid)), 0);
        ASSERT_EQ(cert->size(), kTestClientCert.size() + 1);
        EXPECT_EQ(::memcmp(cert->data(), kTestClientCert.data(), kTestClientCert.size() + 1), 0);

        std::lock_guard<std::mutex> lock(server_mutex);
        server_cv.notify_one();
    };
    ASSERT_TRUE(server_->start(server_callback, nullptr));

    // Start the client
    bool got_valid_pairing = false;
    std::mutex client_mutex;
    std::condition_variable client_cv;
    std::unique_lock<std::mutex> client_lock(client_mutex);
    auto client_callback = [&](const PeerInfo* peer_info, const std::vector<uint8_t>* cert,
                               void* opaque) {
        ASSERT_NE(nullptr, peer_info);
        ASSERT_NE(nullptr, cert);
        EXPECT_FALSE(cert->empty());
        EXPECT_EQ(nullptr, opaque);

        // Verify the peer_info and cert
        ASSERT_EQ(strlen(peer_info->name), strlen(server_info_.name));
        EXPECT_EQ(::memcmp(peer_info->name, server_info_.name, strlen(server_info_.name)), 0);
        ASSERT_EQ(strlen(peer_info->guid), strlen(server_info_.guid));
        EXPECT_EQ(::memcmp(peer_info->guid, server_info_.guid, strlen(server_info_.guid)), 0);
        ASSERT_EQ(cert->size(), kTestServerCert.size() + 1);
        EXPECT_EQ(::memcmp(cert->data(), kTestServerCert.data(), kTestServerCert.size() + 1), 0);

        got_valid_pairing = (peer_info != nullptr && cert != nullptr && !cert->empty());
        std::lock_guard<std::mutex> lock(client_mutex);
        client_cv.notify_one();
    };
    ASSERT_TRUE(client_->start(client_callback, nullptr));
    client_cv.wait(client_lock);

    // Kill server if the pairing failed, since server only shuts down when
    // it gets a valid pairing.
    if (!got_valid_pairing) {
        server_lock.unlock();
        server_.reset();
    } else {
        server_cv.wait(server_lock);
    }
}

TEST_F(AdbWifiPairingConnectionTest, CancelPairing) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};
    initPairing(pswd, pswd2);

    // Start the server first, to open the port for connections
    std::mutex server_mutex;
    std::condition_variable server_cv;
    std::unique_lock<std::mutex> server_lock(server_mutex);

    bool server_got_valid_pairing = true;
    auto server_callback = [&](const PeerInfo* peer_info, const std::vector<uint8_t>* cert,
                               void* opaque) {
        // Pairing will be cancelled, which should initiate this callback with
        // empty values.
        ASSERT_EQ(nullptr, peer_info);
        ASSERT_EQ(nullptr, cert);
        EXPECT_EQ(nullptr, opaque);
        std::lock_guard<std::mutex> lock(server_mutex);
        server_cv.notify_one();
        server_got_valid_pairing = false;
    };
    ASSERT_TRUE(server_->start(server_callback, nullptr));

    // Start the client (should fail because of different passwords).
    bool got_valid_pairing = false;
    std::mutex client_mutex;
    std::condition_variable client_cv;
    std::unique_lock<std::mutex> client_lock(client_mutex);
    auto client_callback = [&](const PeerInfo* peer_info, const std::vector<uint8_t>* cert,
                               void* opaque) {
        ASSERT_EQ(nullptr, peer_info);
        ASSERT_EQ(nullptr, cert);
        EXPECT_EQ(nullptr, opaque);

        got_valid_pairing = (peer_info != nullptr && cert != nullptr && !cert->empty());
        std::lock_guard<std::mutex> lock(client_mutex);
        client_cv.notify_one();
    };
    ASSERT_TRUE(client_->start(client_callback, nullptr));
    client_cv.wait(client_lock);

    server_lock.unlock();
    // This should trigger the callback to be on the same thread.
    server_.reset();
    EXPECT_FALSE(server_got_valid_pairing);
}

TEST_F(AdbWifiPairingConnectionTest, MultipleClientsAllFail) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};

    auto server = createServer(pswd);
    ASSERT_NE(nullptr, server);
    // Start the server first, to open the port for connections
    std::mutex server_mutex;
    std::condition_variable server_cv;
    std::unique_lock<std::mutex> server_lock(server_mutex);

    bool server_got_valid_pairing = true;
    auto server_callback = [&](const PeerInfo* peer_info, const std::vector<uint8_t>* cert,
                               void* opaque) {
        // Pairing will be cancelled, which should initiate this callback with
        // empty values.
        ASSERT_EQ(nullptr, peer_info);
        ASSERT_EQ(nullptr, cert);
        EXPECT_EQ(nullptr, opaque);
        std::lock_guard<std::mutex> lock(server_mutex);
        server_cv.notify_one();
        server_got_valid_pairing = false;
    };
    ASSERT_TRUE(server->start(server_callback, nullptr));

    // Start multiple clients, all with bad passwords
    std::vector<std::unique_ptr<PairingClient>> clients;
    int num_clients_done = 0;
    int test_num_clients = 5;
    std::mutex client_mutex;
    std::condition_variable client_cv;
    std::unique_lock<std::mutex> client_lock(client_mutex);
    while (clients.size() < test_num_clients) {
        auto client = createClient(pswd2);
        ASSERT_NE(nullptr, client);
        auto callback = [&](const PeerInfo* peer_info, const std::vector<uint8_t>* cert,
                            void* opaque) {
            ASSERT_EQ(nullptr, peer_info);
            ASSERT_EQ(nullptr, cert);
            EXPECT_EQ(nullptr, opaque);

            {
                std::lock_guard<std::mutex> lock(client_mutex);
                num_clients_done++;
            }
            client_cv.notify_one();
        };
        ASSERT_TRUE(client->start(callback, nullptr));
        clients.push_back(std::move(client));
    }

    client_cv.wait(client_lock, [&]() { return (num_clients_done == test_num_clients); });
    EXPECT_EQ(num_clients_done, test_num_clients);

    server_lock.unlock();
    // This should trigger the callback to be on the same thread.
    server.reset();
    EXPECT_FALSE(server_got_valid_pairing);
}

TEST_F(AdbWifiPairingConnectionTest, MultipleClientsOnePass) {
    // Send multiple clients with bad passwords, but send the last one with the
    // correct password.
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};

    auto server = createServer(pswd);
    ASSERT_NE(nullptr, server);
    // Start the server first, to open the port for connections
    std::mutex server_mutex;
    std::condition_variable server_cv;
    std::unique_lock<std::mutex> server_lock(server_mutex);

    bool server_got_valid_pairing = false;
    auto server_callback = [&](const PeerInfo* peer_info, const std::vector<uint8_t>* cert,
                               void* opaque) {
        // Pairing will be cancelled, which should initiate this callback with
        // empty values.

        ASSERT_NE(nullptr, peer_info);
        ASSERT_NE(nullptr, cert);
        EXPECT_FALSE(cert->empty());
        EXPECT_EQ(nullptr, opaque);

        // Verify the peer_info and cert
        ASSERT_EQ(strlen(peer_info->name), strlen(client_info_.name));
        EXPECT_EQ(::memcmp(peer_info->name, client_info_.name, strlen(client_info_.name)), 0);
        ASSERT_EQ(strlen(peer_info->guid), strlen(client_info_.guid));
        EXPECT_EQ(::memcmp(peer_info->guid, client_info_.guid, strlen(client_info_.guid)), 0);
        ASSERT_EQ(cert->size(), kTestClientCert.size() + 1);
        EXPECT_EQ(::memcmp(cert->data(), kTestClientCert.data(), kTestClientCert.size() + 1), 0);

        std::lock_guard<std::mutex> lock(server_mutex);
        server_got_valid_pairing = true;
        server_cv.notify_one();
    };
    ASSERT_TRUE(server->start(server_callback, nullptr));

    // Start multiple clients, all with bad passwords (except for the last one)
    std::vector<std::unique_ptr<PairingClient>> clients;
    int num_clients_done = 0;
    int test_num_clients = 5;
    std::mutex client_mutex;
    std::condition_variable client_cv;
    std::unique_lock<std::mutex> client_lock(client_mutex);
    bool got_valid_pairing = false;
    while (clients.size() < test_num_clients) {
        std::unique_ptr<PairingClient> client;
        if (clients.size() == test_num_clients - 1) {
            // Make this one have the valid password
            client = createClient(pswd);
            ASSERT_NE(nullptr, client);
            auto callback = [&](const PeerInfo* peer_info, const std::vector<uint8_t>* cert,
                                void* opaque) {
                ASSERT_NE(nullptr, peer_info);
                ASSERT_NE(nullptr, cert);
                EXPECT_FALSE(cert->empty());
                EXPECT_EQ(nullptr, opaque);

                // Verify the peer_info and cert
                ASSERT_EQ(strlen(peer_info->name), strlen(server_info_.name));
                EXPECT_EQ(::memcmp(peer_info->name, server_info_.name, strlen(server_info_.name)),
                          0);
                ASSERT_EQ(strlen(peer_info->guid), strlen(server_info_.guid));
                EXPECT_EQ(::memcmp(peer_info->guid, server_info_.guid, strlen(server_info_.guid)),
                          0);
                ASSERT_EQ(cert->size(), kTestServerCert.size() + 1);
                EXPECT_EQ(
                        ::memcmp(cert->data(), kTestServerCert.data(), kTestServerCert.size() + 1),
                        0);
                got_valid_pairing = (peer_info != nullptr && cert != nullptr && !cert->empty());

                {
                    std::lock_guard<std::mutex> lock(client_mutex);
                    num_clients_done++;
                }
                client_cv.notify_one();
            };
            ASSERT_TRUE(client->start(callback, nullptr));
        } else {
            client = createClient(pswd2);
            ASSERT_NE(nullptr, client);
            auto callback = [&](const PeerInfo* peer_info, const std::vector<uint8_t>* cert,
                                void* opaque) {
                ASSERT_EQ(nullptr, peer_info);
                ASSERT_EQ(nullptr, cert);
                EXPECT_EQ(nullptr, opaque);

                {
                    std::lock_guard<std::mutex> lock(client_mutex);
                    num_clients_done++;
                }
                client_cv.notify_one();
            };
            ASSERT_TRUE(client->start(callback, nullptr));
        }
        clients.push_back(std::move(client));
    }

    client_cv.wait(client_lock, [&]() { return (num_clients_done == test_num_clients); });
    EXPECT_EQ(num_clients_done, test_num_clients);

    // Kill server if the pairing failed, since server only shuts down when
    // it gets a valid pairing.
    if (!got_valid_pairing) {
        server_lock.unlock();
        server_.reset();
    } else {
        server_cv.wait(server_lock);
    }
    EXPECT_TRUE(server_got_valid_pairing);
}

}  // namespace pairing
}  // namespace adbwifi
