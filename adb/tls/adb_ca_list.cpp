/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "adb/tls/adb_ca_list.h"

#include <iomanip>
#include <sstream>
#include <vector>

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <openssl/ssl.h>

namespace adb {
namespace tls {

namespace {

// CA issuer identifier to distinguished embedded keys. Also has version
// information appended to the end of the string (e.g. "AdbKey-0").
static constexpr int kAdbKeyIdentifierNid = NID_organizationName;
static constexpr char kAdbKeyIdentifierV0[] = "AdbKey-0";

// Where we store the actual data
static constexpr int kAdbKeyValueNid = NID_commonName;

// TODO: Remove this once X509_NAME_add_entry_by_NID is fixed to use const unsigned char*
// https://boringssl-review.googlesource.com/c/boringssl/+/39764
int X509_NAME_add_entry_by_NID_const(X509_NAME* name, int nid, int type, const unsigned char* bytes,
                                     int len, int loc, int set) {
    return X509_NAME_add_entry_by_NID(name, nid, type, const_cast<unsigned char*>(bytes), len, loc,
                                      set);
}

bool IsHexDigit(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

// Wrapper around X509_NAME_get_text_by_NID that first calculates the size
// of the string. Returns empty string on failure.
std::optional<std::string> GetX509NameTextByNid(X509_NAME* name, int nid) {
    // |len| is the len of the text excluding the final null
    int len = X509_NAME_get_text_by_NID(name, nid, nullptr, -1);
    if (len <= 0) {
        return std::nullopt;
    }

    // Include the space for the final null byte
    std::vector<char> buf(len + 1, '\0');
    CHECK(X509_NAME_get_text_by_NID(name, nid, buf.data(), buf.size()));
    return std::make_optional(std::string(buf.data()));
}

}  // namespace

// Takes an encoded public key and generates a X509_NAME that can be used in
// TlsConnection::SetClientCAList(), to allow the client to figure out which of
// its keys it should try to use in the TLS handshake.
bssl::UniquePtr<X509_NAME> CreateCAIssuerFromEncodedKey(std::string_view key) {
    // "O=AdbKey-0;CN=<key>;"
    CHECK(!key.empty());

    std::string identifier = kAdbKeyIdentifierV0;
    bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
    CHECK(X509_NAME_add_entry_by_NID_const(name.get(), kAdbKeyIdentifierNid, MBSTRING_ASC,
                                           reinterpret_cast<const uint8_t*>(identifier.data()),
                                           identifier.size(), -1, 0));

    CHECK(X509_NAME_add_entry_by_NID_const(name.get(), kAdbKeyValueNid, MBSTRING_ASC,
                                           reinterpret_cast<const uint8_t*>(key.data()), key.size(),
                                           -1, 0));
    return name;
}

// Parses a CA issuer and returns the encoded key, if any.
std::optional<std::string> ParseEncodedKeyFromCAIssuer(X509_NAME* issuer) {
    CHECK(issuer);

    auto buf = GetX509NameTextByNid(issuer, kAdbKeyIdentifierNid);
    if (!buf) {
        return std::nullopt;
    }

    // Check for supported versions
    if (*buf == kAdbKeyIdentifierV0) {
        return GetX509NameTextByNid(issuer, kAdbKeyValueNid);
    }
    return std::nullopt;
}

std::string SHA256BitsToHexString(std::string_view sha256) {
    CHECK_EQ(sha256.size(), static_cast<size_t>(SHA256_DIGEST_LENGTH));
    std::stringstream ss;
    auto* u8 = reinterpret_cast<const uint8_t*>(sha256.data());
    ss << std::uppercase << std::setfill('0') << std::hex;
    // Convert to hex-string representation
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        // Need to cast to something bigger than one byte, or
        // stringstream will interpret it as a char value.
        ss << std::setw(2) << static_cast<uint16_t>(u8[i]);
    }
    return ss.str();
}

std::optional<std::string> SHA256HexStringToBits(std::string_view sha256_str) {
    if (sha256_str.size() != SHA256_DIGEST_LENGTH * 2) {
        return std::nullopt;
    }

    std::string result;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        auto bytestr = std::string(sha256_str.substr(i * 2, 2));
        if (!IsHexDigit(bytestr[0]) || !IsHexDigit(bytestr[1])) {
            LOG(ERROR) << "SHA256 string has invalid non-hex chars";
            return std::nullopt;
        }
        result += static_cast<char>(std::stol(bytestr, nullptr, 16));
    }
    return result;
}

}  // namespace tls
}  // namespace adb
