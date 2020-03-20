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

#define LOG_TAG "AdbCAListTest"

#include <gtest/gtest.h>

#include <adb/tls/adb_ca_list.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <openssl/ssl.h>

namespace adb {
namespace tls {

class AdbCAListTest : public testing::Test {
  protected:
    virtual void SetUp() override {}

    virtual void TearDown() override {}
};

TEST_F(AdbCAListTest, SHA256BitsToHexString_BadParam) {
    // Should crash if not exactly SHA256_DIGEST_LENGTH size
    ASSERT_DEATH(
            {
                // empty
                std::string sha;
                SHA256BitsToHexString(sha);
            },
            "");
    ASSERT_DEATH(
            {
                std::string sha(1, 0x80);
                SHA256BitsToHexString(sha);
            },
            "");
    ASSERT_DEATH(
            {
                std::string sha(SHA256_DIGEST_LENGTH - 1, 0x80);
                SHA256BitsToHexString(sha);
            },
            "");
    ASSERT_DEATH(
            {
                std::string sha(SHA256_DIGEST_LENGTH + 1, 0x80);
                SHA256BitsToHexString(sha);
            },
            "");
}

TEST_F(AdbCAListTest, SHA256HexStringToBits_BadParam) {
    {
        // empty
        std::string sha_str;
        auto res = SHA256HexStringToBits(sha_str);
        EXPECT_FALSE(res.has_value());
    }
    {
        std::string sha_str(1, 'a');
        auto res = SHA256HexStringToBits(sha_str);
        EXPECT_FALSE(res.has_value());
    }
    {
        std::string sha_str(SHA256_DIGEST_LENGTH * 2 - 1, 'a');
        auto res = SHA256HexStringToBits(sha_str);
        EXPECT_FALSE(res.has_value());
    }
    {
        std::string sha_str(SHA256_DIGEST_LENGTH * 2 + 1, 'a');
        auto res = SHA256HexStringToBits(sha_str);
        EXPECT_FALSE(res.has_value());
    }
    {
        // Non-hex chars
        std::string sha_str(SHA256_DIGEST_LENGTH * 2, 'a');
        sha_str[32] = 'x';
        auto res = SHA256HexStringToBits(sha_str);
        EXPECT_FALSE(res.has_value());
    }
}

TEST_F(AdbCAListTest, SHA256BitsToHexString_ValidParam) {
    uint8_t ct = 0;
    // Test every possible byte
    std::vector<std::string> expectedStr = {
            "000102030405060708090A0B0C0D0E0F"
            "101112131415161718191A1B1C1D1E1F",

            "202122232425262728292A2B2C2D2E2F"
            "303132333435363738393A3B3C3D3E3F",

            "404142434445464748494A4B4C4D4E4F"
            "505152535455565758595A5B5C5D5E5F",

            "606162636465666768696A6B6C6D6E6F"
            "707172737475767778797A7B7C7D7E7F",

            "808182838485868788898A8B8C8D8E8F"
            "909192939495969798999A9B9C9D9E9F",

            "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF",

            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF"
            "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF",

            "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEF"
            "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF",
    };

    for (auto& expected : expectedStr) {
        std::string sha;
        while (sha.size() < SHA256_DIGEST_LENGTH) {
            sha += ct++;
        }

        auto sha_str = SHA256BitsToHexString(sha);
        EXPECT_EQ(expected, sha_str);

        // try to convert back to bits
        auto out_sha = SHA256HexStringToBits(sha_str);
        ASSERT_TRUE(out_sha.has_value());
        EXPECT_EQ(*out_sha, sha);
    }
}

TEST_F(AdbCAListTest, CreateCAIssuerFromEncodedKey_EmptyKey) {
    ASSERT_DEATH({ auto issuer = CreateCAIssuerFromEncodedKey(""); }, "");
}

TEST_F(AdbCAListTest, Smoke) {
    {
        std::string key =
                "A45BC1FF6C89BF0E"
                "65F9BA153FBC9876"
                "4969B4113F1CF878"
                "EEF9BF1C3F9C9227";
        auto issuer = CreateCAIssuerFromEncodedKey(key);
        ASSERT_NE(issuer, nullptr);

        // Try to parse the encoded key out of the X509_NAME
        auto out_key = ParseEncodedKeyFromCAIssuer(issuer.get());
        ASSERT_TRUE(out_key.has_value());
        EXPECT_EQ(key, *out_key);
    }
}

}  // namespace tls
}  // namespace adb
