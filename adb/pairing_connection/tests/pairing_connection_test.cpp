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

#define LOG_TAG "AdbPairingConnectionTest"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <adb/pairing/pairing_server.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

#include "../internal/constants.h"
#include "pairing_client.h"

using namespace std::chrono_literals;

namespace adb {
namespace pairing {

// Test X.509 certificates (RSA 2048)
static const std::string kTestRsa2048ServerCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMQswCQYDVQQGEwJVUzEQ\n"
        "MA4GA1UECgwHQW5kcm9pZDEMMAoGA1UEAwwDQWRiMB4XDTIwMDEyMTIyMjU1NVoX\n"
        "DTMwMDExODIyMjU1NVowLTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQx\n"
        "DDAKBgNVBAMMA0FkYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK8E\n"
        "2Ck9TfuKlz7wqWdMfknjZ1luFDp2IHxAUZzh/F6jeI2dOFGAjpeloSnGOE86FIaT\n"
        "d1EvpyTh7nBwbrLZAA6XFZTo7Bl6BdNOQdqb2d2+cLEN0inFxqUIycevRtohUE1Y\n"
        "FHM9fg442X1jOTWXjDZWeiqFWo95paAPhzm6pWqfJK1+YKfT1LsWZpYqJGGQE5pi\n"
        "C3qOBYYgFpoXMxTYJNoZo3uOYEdM6upc8/vh15nMgIxX/ymJxEY5BHPpZPPWjXLg\n"
        "BfzVaV9fUfv0JT4HQ4t2WvxC3cD/UsjWp2a6p454uUp2ENrANa+jRdRJepepg9D2\n"
        "DKsx9L8zjc5Obqexrt0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
        "Af8EBAMCAYYwHQYDVR0OBBYEFDFW+8GTErwoZN5Uu9KyY4QdGYKpMA0GCSqGSIb3\n"
        "DQEBCwUAA4IBAQBCDEn6SHXGlq5TU7J8cg1kRPd9bsJW+0hDuKSq0REXDkl0PcBf\n"
        "fy282Agg9enKPPKmnpeQjM1dmnxdM8tT8LIUbMl779i3fn6v9HJVB+yG4gmRFThW\n"
        "c+AGlBnrIT820cX/gU3h3R3FTahfsq+1rrSJkEgHyuC0HYeRyveSckBdaEOLvx0S\n"
        "toun+32JJl5hWydpUUZhE9Mbb3KHBRM2YYZZU9JeJ08Apjl+3lRUeMAUwI5fkAAu\n"
        "z/1SqnuGL96bd8P5ixdkA1+rF8FPhodGcq9mQOuUGP9g5HOXjaNoJYvwVRUdLeGh\n"
        "cP/ReOTwQIzM1K5a83p8cX8AGGYmM7dQp7ec\n"
        "-----END CERTIFICATE-----\n";

static const std::string kTestRsa2048ServerPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCvBNgpPU37ipc+\n"
        "8KlnTH5J42dZbhQ6diB8QFGc4fxeo3iNnThRgI6XpaEpxjhPOhSGk3dRL6ck4e5w\n"
        "cG6y2QAOlxWU6OwZegXTTkHam9ndvnCxDdIpxcalCMnHr0baIVBNWBRzPX4OONl9\n"
        "Yzk1l4w2VnoqhVqPeaWgD4c5uqVqnyStfmCn09S7FmaWKiRhkBOaYgt6jgWGIBaa\n"
        "FzMU2CTaGaN7jmBHTOrqXPP74deZzICMV/8picRGOQRz6WTz1o1y4AX81WlfX1H7\n"
        "9CU+B0OLdlr8Qt3A/1LI1qdmuqeOeLlKdhDawDWvo0XUSXqXqYPQ9gyrMfS/M43O\n"
        "Tm6nsa7dAgMBAAECggEAFCS2bPdUKIgjbzLgtHW+hT+J2hD20rcHdyAp+dNH/2vI\n"
        "yLfDJHJA4chGMRondKA704oDw2bSJxxlG9t83326lB35yxPhye7cM8fqgWrK8PVl\n"
        "tU22FhO1ZgeJvb9OeXWNxKZyDW9oOOJ8eazNXVMuEo+dFj7B6l3MXQyHJPL2mJDm\n"
        "u9ofFLdypX+gJncVO0oW0FNJnEUn2MMwHDNlo7gc4WdQuidPkuZItKRGcB8TTGF3\n"
        "Ka1/2taYdTQ4Aq//Z84LlFvE0zD3T4c8LwYYzOzD4gGGTXvft7vSHzIun1S8YLRS\n"
        "dEKXdVjtaFhgH3uUe4j+1b/vMvSHeoGBNX/G88GD+wKBgQDWUYVlMVqc9HD2IeYi\n"
        "EfBcNwAJFJkh51yAl5QbUBgFYgFJVkkS/EDxEGFPvEmI3/pAeQFHFY13BI466EPs\n"
        "o8Z8UUwWDp+Z1MFHHKQKnFakbsZbZlbqjJ9VJsqpezbpWhMHTOmcG0dmE7rf0lyM\n"
        "eQv9slBB8qp2NEUs5Of7f2C2bwKBgQDRDq4nUuMQF1hbjM05tGKSIwkobmGsLspv\n"
        "TMhkM7fq4RpbFHmbNgsFqMhcqYZ8gY6/scv5KCuAZ4yHUkbqwf5h+QCwrJ4uJeUJ\n"
        "ZgJfHus2mmcNSo8FwSkNoojIQtzcbJav7bs2K9VTuertk/i7IJLApU4FOZZ5pghN\n"
        "EXu0CZF1cwKBgDWFGhjRIF29tU/h20R60llU6s9Zs3wB+NmsALJpZ/ZAKS4VPB5f\n"
        "nCAXBRYSYRKrTCU5kpYbzb4BBzuysPOxWmnFK4j+keCqfrGxd02nCQP7HdHJVr8v\n"
        "6sIq88UrHeVcNxBFprjzHvtgxfQK5k22FMZ/9wbhAKyQFQ5HA5+MiaxFAoGAIcZZ\n"
        "ZIkDninnYIMS9OursShv5lRO+15j3i9tgKLKZ+wOMgDQ1L6acUOfezj4PU1BHr8+\n"
        "0PYocQpJreMhCfRlgLaV4fVBaPs+UZJld7CrF5tCYudUy/01ALrtlk0XGZWBktK5\n"
        "mDrksC4tQkzRtonAq9cJD9cJ9IVaefkFH0UcdvkCgYBpZj50VLeGhnHHBnkJRlV1\n"
        "fV+/P6PAq6RtqjA6O9Qdaoj5V3w2d63aQcQXQLJjH2BBmtCIy47r04rFvZpbCxP7\n"
        "NH/OnK9NHpk2ucRTe8TAnVbvF/TZzPJoIxAO/D3OWaW6df4R8en8u6GYzWFglAyT\n"
        "sydGT8yfWD1FYUWgfrVRbg==\n"
        "-----END PRIVATE KEY-----\n";

static const std::string kTestRsa2048ClientCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDFzCCAf+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAtMQswCQYDVQQGEwJVUzEQ\n"
        "MA4GA1UECgwHQW5kcm9pZDEMMAoGA1UEAwwDQWRiMB4XDTIwMDEyMTIyMjU1NloX\n"
        "DTMwMDExODIyMjU1NlowLTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQx\n"
        "DDAKBgNVBAMMA0FkYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI3a\n"
        "EXh1S5FTbet7JVONswffRPaekdIK53cb8SnAbSO9X5OLA4zGwdkrBvDTsd96SKrp\n"
        "JxmoNOE1DhbZh05KPlWAPkGKacjGWaz+S7biDOL0I6aaLbTlU/il1Ub9olPSBVUx\n"
        "0nhdtEFgIOzddnP6/1KmyIIeRxS5lTKeg4avqUkZNXkz/wL1dHBFL7FNFf0SCcbo\n"
        "tsub/deFbjZ27LTDN+SIBgFttTNqC5NTvoBAoMdyCOAgNYwaHO+fKiK3edfJieaw\n"
        "7HD8qqmQxcpCtRlA8CUPj7GfR+WHiCJmlevhnkFXCo56R1BS0F4wuD4KPdSWt8gc\n"
        "27ejH/9/z2cKo/6SLJMCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
        "Af8EBAMCAYYwHQYDVR0OBBYEFO/Mr5ygqqpyU/EHM9v7RDvcqaOkMA0GCSqGSIb3\n"
        "DQEBCwUAA4IBAQAH33KMouzF2DYbjg90KDrDQr4rq3WfNb6P743knxdUFuvb+40U\n"
        "QjC2OJZHkSexH7wfG/y6ic7vfCfF4clNs3QvU1lEjOZC57St8Fk7mdNdsWLwxEMD\n"
        "uePFz0dvclSxNUHyCVMqNxddzQYzxiDWQRmXWrUBliMduQqEQelcxW2yDtg8bj+s\n"
        "aMpR1ra9scaD4jzIZIIxLoOS9zBMuNRbgP217sZrniyGMhzoI1pZ/izN4oXpyH7O\n"
        "THuaCzzRT3ph2f8EgmHSodz3ttgSf2DHzi/Ez1xUkk7NOlgNtmsxEdrM47+cC5ae\n"
        "fIf2V+1o1JW8J7D11RmRbNPh3vfisueB4f88\n"
        "-----END CERTIFICATE-----\n";

static const std::string kTestRsa2048ClientPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCN2hF4dUuRU23r\n"
        "eyVTjbMH30T2npHSCud3G/EpwG0jvV+TiwOMxsHZKwbw07Hfekiq6ScZqDThNQ4W\n"
        "2YdOSj5VgD5BimnIxlms/ku24gzi9COmmi205VP4pdVG/aJT0gVVMdJ4XbRBYCDs\n"
        "3XZz+v9SpsiCHkcUuZUynoOGr6lJGTV5M/8C9XRwRS+xTRX9EgnG6LbLm/3XhW42\n"
        "duy0wzfkiAYBbbUzaguTU76AQKDHcgjgIDWMGhzvnyoit3nXyYnmsOxw/KqpkMXK\n"
        "QrUZQPAlD4+xn0flh4giZpXr4Z5BVwqOekdQUtBeMLg+Cj3UlrfIHNu3ox//f89n\n"
        "CqP+kiyTAgMBAAECggEAAa64eP6ggCob1P3c73oayYPIbvRqiQdAFOrr7Vwu7zbr\n"
        "z0rde+n6RU0mrpc+4NuzyPMtrOGQiatLbidJB5Cx3z8U00ovqbCl7PtcgorOhFKe\n"
        "VEzihebCcYyQqbWQcKtpDMhOgBxRwFoXieJb6VGXfa96FAZalCWvXgOrTl7/BF2X\n"
        "qMqIm9nJi+yS5tIO8VdOsOmrMWRH/b/ENUcef4WpLoxTXr0EEgyKWraeZ/hhXo1e\n"
        "z29dZKqdr9wMsq11NPsRddwS94jnDkXTo+EQyWVTfB7gb6yyp07s8jysaDb21tVv\n"
        "UXB9MRhDV1mOv0ncXfXZ4/+4A2UahmZaLDAVLaat4QKBgQDAVRredhGRGl2Nkic3\n"
        "KvZCAfyxug788CgasBdEiouz19iCCwcgMIDwnq0s3/WM7h/laCamT2x38riYDnpq\n"
        "rkYMfuVtU9CjEL9pTrdfwbIRhTwYNqADaPz2mXwQUhRXutE5TIdgxxC/a+ZTh0qN\n"
        "S+vhTj/4hf0IZhMh5Nqj7IPExQKBgQC8zxEzhmSGjys0GuE6Wl6Doo2TpiR6vwvi\n"
        "xPLU9lmIz5eca/Rd/eERioFQqeoIWDLzx52DXuz6rUoQhbJWz9hP3yqCwXD+pbNP\n"
        "oDJqDDbCC4IMYEb0IK/PEPH+gIpnTjoFcW+ecKDFG7W5Lt05J8WsJsfOaJvMrOU+\n"
        "dLXq3IgxdwKBgQC5RAFq0v6e8G+3hFaEHL0z3igkpt3zJf7rnj37hx2FMmDa+3Z0\n"
        "umQp5B9af61PgL12xLmeMBmC/Wp1BlVDV/Yf6Uhk5Hyv5t0KuomHEtTNbbLyfAPs\n"
        "5P/vJu/L5NS1oT4S3LX3MineyjgGs+bLbpub3z1dzutrYLADUSiPCK/xJQKBgBQt\n"
        "nQ0Ao+Wtj1R2OvPdjJRM3wyUiPmFSWPm4HzaBx+T8AQLlYYmB9O0FbXlMtnJc0iS\n"
        "YMcVcgYoVu4FG9YjSF7g3s4yljzgwJUV7c1fmMqMKE3iTDLy+1cJ3JLycdgwiArk\n"
        "4KTyLHxkRbuQwpvFIF8RlfD9RQlOwQE3v+llwDhpAoGBAL6XG6Rp6mBoD2Ds5c9R\n"
        "943yYgSUes3ji1SI9zFqeJtj8Ml/enuK1xu+8E/BxB0//+vgZsH6i3i8GFwygKey\n"
        "CGJF8CbiHc3EJc3NQIIRXcni/CGacf0HwC6m+PGFDBIpA4H2iDpVvCSofxttQiq0\n"
        "/Z7HXmXUvZHVyYi/QzX2Gahj\n"
        "-----END PRIVATE KEY-----\n";

struct ServerDeleter {
    void operator()(PairingServerCtx* p) { pairing_server_destroy(p); }
};
using ServerPtr = std::unique_ptr<PairingServerCtx, ServerDeleter>;

struct ResultWaiter {
    std::mutex mutex_;
    std::condition_variable cv_;
    std::optional<bool> is_valid_;
    PeerInfo peer_info_;

    static void ResultCallback(const PeerInfo* peer_info, void* opaque) {
        auto* p = reinterpret_cast<ResultWaiter*>(opaque);
        {
            std::unique_lock<std::mutex> lock(p->mutex_);
            if (peer_info) {
                memcpy(&(p->peer_info_), peer_info, sizeof(PeerInfo));
            }
            p->is_valid_ = (peer_info != nullptr);
        }
        p->cv_.notify_one();
    }
};

class AdbPairingConnectionTest : public testing::Test {
  protected:
    virtual void SetUp() override {}

    virtual void TearDown() override {}

    void InitPairing(const std::vector<uint8_t>& server_pswd,
                     const std::vector<uint8_t>& client_pswd) {
        server_ = CreateServer(server_pswd);
        client_ = CreateClient(client_pswd);
    }

    ServerPtr CreateServer(const std::vector<uint8_t>& pswd) {
        return CreateServer(pswd, &server_info_, kTestRsa2048ServerCert, kTestRsa2048ServerPrivKey,
                            0);
    }

    std::unique_ptr<PairingClient> CreateClient(const std::vector<uint8_t> pswd) {
        std::vector<uint8_t> cert;
        std::vector<uint8_t> key;
        // Include the null-byte as well.
        cert.assign(reinterpret_cast<const uint8_t*>(kTestRsa2048ClientCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestRsa2048ClientCert.data()) +
                            kTestRsa2048ClientCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestRsa2048ClientPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestRsa2048ClientPrivKey.data()) +
                           kTestRsa2048ClientPrivKey.size() + 1);
        return PairingClient::Create(pswd, client_info_, cert, key);
    }

    static ServerPtr CreateServer(const std::vector<uint8_t>& pswd, const PeerInfo* peer_info,
                                  const std::string_view cert, const std::string_view priv_key,
                                  int port) {
        return ServerPtr(pairing_server_new(
                pswd.data(), pswd.size(), peer_info, reinterpret_cast<const uint8_t*>(cert.data()),
                cert.size(), reinterpret_cast<const uint8_t*>(priv_key.data()), priv_key.size(),
                port));
    }

    ServerPtr server_;
    const PeerInfo server_info_ = {
            .type = ADB_DEVICE_GUID,
            .data = "my_server_info",
    };
    std::unique_ptr<PairingClient> client_;
    const PeerInfo client_info_ = {
            .type = ADB_RSA_PUB_KEY,
            .data = "my_client_info",
    };
    std::string ip_addr_ = "127.0.0.1:";
};

TEST_F(AdbPairingConnectionTest, ServerCreation) {
    // All parameters bad
    ASSERT_DEATH({ auto server = CreateServer({}, nullptr, "", "", 0); }, "");
    // Bad password
    ASSERT_DEATH(
            {
                auto server = CreateServer({}, &server_info_, kTestRsa2048ServerCert,
                                           kTestRsa2048ServerPrivKey, 0);
            },
            "");
    // Bad peer_info
    ASSERT_DEATH(
            {
                auto server = CreateServer({0x01}, nullptr, kTestRsa2048ServerCert,
                                           kTestRsa2048ServerPrivKey, 0);
            },
            "");
    // Bad certificate
    ASSERT_DEATH(
            {
                auto server = CreateServer({0x01}, &server_info_, "", kTestRsa2048ServerPrivKey, 0);
            },
            "");
    // Bad private key
    ASSERT_DEATH(
            { auto server = CreateServer({0x01}, &server_info_, kTestRsa2048ServerCert, "", 0); },
            "");
    // Valid params
    auto server = CreateServer({0x01}, &server_info_, kTestRsa2048ServerCert,
                               kTestRsa2048ServerPrivKey, 0);
    EXPECT_NE(nullptr, server);
}

TEST_F(AdbPairingConnectionTest, ClientCreation) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    // Bad password
    ASSERT_DEATH(
            {
                pairing_connection_client_new(
                        nullptr, pswd.size(), &client_info_,
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientCert.data()),
                        kTestRsa2048ClientCert.size(),
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientPrivKey.data()),
                        kTestRsa2048ClientPrivKey.size());
            },
            "");
    ASSERT_DEATH(
            {
                pairing_connection_client_new(
                        pswd.data(), 0, &client_info_,
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientCert.data()),
                        kTestRsa2048ClientCert.size(),
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientPrivKey.data()),
                        kTestRsa2048ClientPrivKey.size());
            },
            "");

    // Bad peer_info
    ASSERT_DEATH(
            {
                pairing_connection_client_new(
                        pswd.data(), pswd.size(), nullptr,
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientCert.data()),
                        kTestRsa2048ClientCert.size(),
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientPrivKey.data()),
                        kTestRsa2048ClientPrivKey.size());
            },
            "");

    // Bad certificate
    ASSERT_DEATH(
            {
                pairing_connection_client_new(
                        pswd.data(), pswd.size(), &client_info_, nullptr,
                        kTestRsa2048ClientCert.size(),
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientPrivKey.data()),
                        kTestRsa2048ClientPrivKey.size());
            },
            "");
    ASSERT_DEATH(
            {
                pairing_connection_client_new(
                        pswd.data(), pswd.size(), &client_info_,
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientCert.data()), 0,
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientPrivKey.data()),
                        kTestRsa2048ClientPrivKey.size());
            },
            "");

    // Bad private key
    ASSERT_DEATH(
            {
                pairing_connection_client_new(
                        pswd.data(), pswd.size(), &client_info_,
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientCert.data()),
                        kTestRsa2048ClientCert.size(), nullptr, kTestRsa2048ClientPrivKey.size());
            },
            "");
    ASSERT_DEATH(
            {
                pairing_connection_client_new(
                        pswd.data(), pswd.size(), &client_info_,
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientCert.data()),
                        kTestRsa2048ClientCert.size(),
                        reinterpret_cast<const uint8_t*>(kTestRsa2048ClientPrivKey.data()), 0);
            },
            "");

    // Valid params
    auto client = pairing_connection_client_new(
            pswd.data(), pswd.size(), &client_info_,
            reinterpret_cast<const uint8_t*>(kTestRsa2048ClientCert.data()),
            kTestRsa2048ClientCert.size(),
            reinterpret_cast<const uint8_t*>(kTestRsa2048ClientPrivKey.data()),
            kTestRsa2048ClientPrivKey.size());
    EXPECT_NE(nullptr, client);
}

TEST_F(AdbPairingConnectionTest, SmokeValidPairing) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    InitPairing(pswd, pswd);

    // Start the server
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    auto port = pairing_server_start(server_.get(), server_waiter.ResultCallback, &server_waiter);
    ASSERT_GT(port, 0);
    ip_addr_ += std::to_string(port);

    // Start the client
    ResultWaiter client_waiter;
    std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
    ASSERT_TRUE(client_->Start(ip_addr_, client_waiter.ResultCallback, &client_waiter));
    client_waiter.cv_.wait(client_lock, [&]() { return client_waiter.is_valid_.has_value(); });
    ASSERT_TRUE(*(client_waiter.is_valid_));
    ASSERT_EQ(strlen(reinterpret_cast<const char*>(client_waiter.peer_info_.data)),
              strlen(reinterpret_cast<const char*>(server_info_.data)));
    EXPECT_EQ(memcmp(client_waiter.peer_info_.data, server_info_.data, sizeof(server_info_.data)),
              0);

    // Kill server if the pairing failed, since server only shuts down when
    // it gets a valid pairing.
    if (!client_waiter.is_valid_) {
        server_lock.unlock();
        server_.reset();
    } else {
        server_waiter.cv_.wait(server_lock, [&]() { return server_waiter.is_valid_.has_value(); });
        ASSERT_TRUE(*(server_waiter.is_valid_));
        ASSERT_EQ(strlen(reinterpret_cast<const char*>(server_waiter.peer_info_.data)),
                  strlen(reinterpret_cast<const char*>(client_info_.data)));
        EXPECT_EQ(
                memcmp(server_waiter.peer_info_.data, client_info_.data, sizeof(client_info_.data)),
                0);
    }
}

TEST_F(AdbPairingConnectionTest, CancelPairing) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};
    InitPairing(pswd, pswd2);

    // Start the server
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    auto port = pairing_server_start(server_.get(), server_waiter.ResultCallback, &server_waiter);
    ASSERT_GT(port, 0);
    ip_addr_ += std::to_string(port);

    // Start the client. Client should fail to pair
    ResultWaiter client_waiter;
    std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
    ASSERT_TRUE(client_->Start(ip_addr_, client_waiter.ResultCallback, &client_waiter));
    client_waiter.cv_.wait(client_lock, [&]() { return client_waiter.is_valid_.has_value(); });
    ASSERT_FALSE(*(client_waiter.is_valid_));

    // Kill the server. We should still receive the callback with no valid
    // pairing.
    server_lock.unlock();
    server_.reset();
    server_lock.lock();
    ASSERT_TRUE(server_waiter.is_valid_.has_value());
    EXPECT_FALSE(*(server_waiter.is_valid_));
}

TEST_F(AdbPairingConnectionTest, MultipleClientsAllFail) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};

    // Start the server
    auto server = CreateServer(pswd);
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    auto port = pairing_server_start(server.get(), server_waiter.ResultCallback, &server_waiter);
    ASSERT_GT(port, 0);
    ip_addr_ += std::to_string(port);

    // Start multiple clients, all with bad passwords
    int test_num_clients = 5;
    int num_clients_done = 0;
    std::mutex global_clients_mutex;
    std::unique_lock<std::mutex> global_clients_lock(global_clients_mutex);
    std::condition_variable global_cv_;
    for (int i = 0; i < test_num_clients; ++i) {
        std::thread([&]() {
            auto client = CreateClient(pswd2);
            ResultWaiter client_waiter;
            std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
            ASSERT_TRUE(client->Start(ip_addr_, client_waiter.ResultCallback, &client_waiter));
            client_waiter.cv_.wait(client_lock,
                                   [&]() { return client_waiter.is_valid_.has_value(); });
            ASSERT_FALSE(*(client_waiter.is_valid_));
            {
                std::lock_guard<std::mutex> global_lock(global_clients_mutex);
                ++num_clients_done;
            }
            global_cv_.notify_one();
        }).detach();
    }

    global_cv_.wait(global_clients_lock, [&]() { return num_clients_done == test_num_clients; });
    server_lock.unlock();
    server.reset();
    server_lock.lock();
    ASSERT_TRUE(server_waiter.is_valid_.has_value());
    EXPECT_FALSE(*(server_waiter.is_valid_));
}

TEST_F(AdbPairingConnectionTest, MultipleClientsOnePass) {
    // Send multiple clients with bad passwords, but send the last one with the
    // correct password.
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};

    // Start the server
    auto server = CreateServer(pswd);
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    auto port = pairing_server_start(server.get(), server_waiter.ResultCallback, &server_waiter);
    ASSERT_GT(port, 0);
    ip_addr_ += std::to_string(port);

    // Start multiple clients, all with bad passwords
    int test_num_clients = 5;
    int num_clients_done = 0;
    std::mutex global_clients_mutex;
    std::unique_lock<std::mutex> global_clients_lock(global_clients_mutex);
    std::condition_variable global_cv_;
    for (int i = 0; i < test_num_clients; ++i) {
        std::thread([&, i]() {
            bool good_client = (i == (test_num_clients - 1));
            auto client = CreateClient((good_client ? pswd : pswd2));
            ResultWaiter client_waiter;
            std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
            ASSERT_TRUE(client->Start(ip_addr_, client_waiter.ResultCallback, &client_waiter));
            client_waiter.cv_.wait(client_lock,
                                   [&]() { return client_waiter.is_valid_.has_value(); });
            if (good_client) {
                ASSERT_TRUE(*(client_waiter.is_valid_));
                ASSERT_EQ(strlen(reinterpret_cast<const char*>(client_waiter.peer_info_.data)),
                          strlen(reinterpret_cast<const char*>(server_info_.data)));
                EXPECT_EQ(memcmp(client_waiter.peer_info_.data, server_info_.data,
                                 sizeof(server_info_.data)),
                          0);
            } else {
                ASSERT_FALSE(*(client_waiter.is_valid_));
            }
            {
                std::lock_guard<std::mutex> global_lock(global_clients_mutex);
                ++num_clients_done;
            }
            global_cv_.notify_one();
        }).detach();
    }

    global_cv_.wait(global_clients_lock, [&]() { return num_clients_done == test_num_clients; });
    server_waiter.cv_.wait(server_lock, [&]() { return server_waiter.is_valid_.has_value(); });
    ASSERT_TRUE(*(server_waiter.is_valid_));
    ASSERT_EQ(strlen(reinterpret_cast<const char*>(server_waiter.peer_info_.data)),
              strlen(reinterpret_cast<const char*>(client_info_.data)));
    EXPECT_EQ(memcmp(server_waiter.peer_info_.data, client_info_.data, sizeof(client_info_.data)),
              0);
}

}  // namespace pairing
}  // namespace adb
