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

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string_view>
#include <vector>

#include <android-base/unique_fd.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace adb {
namespace tls {

class TlsConnection {
  public:
    // This class will require both client and server to exchange valid
    // certificates.
    enum class Role {
        Server,
        Client,
    };

    enum class TlsError : uint8_t {
        Success = 0,
        // An error indicating that we rejected the peer's certificate.
        CertificateRejected,
        // An error indicating that the peer rejected our certificate.
        PeerRejectedCertificate,
        // Add more if needed
        UnknownFailure,
    };

    using CertVerifyCb = std::function<int(X509_STORE_CTX*)>;
    using SetCertCb = std::function<int(SSL*)>;

    virtual ~TlsConnection() = default;

    // Adds a trusted certificate to the list for the SSL connection.
    // During the handshake phase, it will check the list of trusted certificates.
    // The connection will fail if the peer's certificate is not in the list. If
    // you would like to accept any certificate, use #SetCertVerifyCallback and
    // set your callback to always return 1.
    //
    // Returns true if |cert| was successfully added, false otherwise.
    virtual bool AddTrustedCertificate(std::string_view cert) = 0;

    // Sets a custom certificate verify callback. |cb| must return 1 if the
    // certificate is trusted. Otherwise, return 0 if not.
    virtual void SetCertVerifyCallback(CertVerifyCb cb) = 0;

    // Configures a client |ca_list| that the server sends to the client in the
    // CertificateRequest message.
    virtual void SetClientCAList(STACK_OF(X509_NAME) * ca_list) = 0;

    // Sets a callback that will be called to select a certificate. See
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_set_cert_cb
    // for more details.
    virtual void SetCertificateCallback(SetCertCb cb) = 0;

    // Exports a value derived from the master secret used in the TLS
    // connection. This value should be used alongside any PAKE to ensure the
    // peer is the intended peer. |length| is the requested length for the
    // keying material. This is only valid after |DoHandshake| succeeds.
    virtual std::vector<uint8_t> ExportKeyingMaterial(size_t length) = 0;

    // Enable client-side check on whether server accepted the handshake. In TLS
    // 1.3, client will not know the server rejected the handshake until after
    // performing a read operation. Basically, this will perform an
    // SSL_peek right after the handshake and see whether that succeeds.
    //
    // IMPORTANT: this will only work if the protocol is a server-speaks-first
    // type. Enabling this for the server is a no-op. This is disabled by
    // default.
    virtual void EnableClientPostHandshakeCheck(bool enable) = 0;

    // Starts the handshake process. Returns TlsError::Success if handshake
    // succeeded.
    virtual TlsError DoHandshake() = 0;

    // Reads |size| bytes and returns the data. The returned data has either
    // size |size| or zero, in which case the read failed.
    virtual std::vector<uint8_t> ReadFully(size_t size) = 0;

    // Overloaded ReadFully method, which accepts a buffer for writing in.
    // Returns true iff exactly |size| amount of data was written into |buf|,
    // false otherwise.
    virtual bool ReadFully(void* buf, size_t size) = 0;

    // Writes |size| bytes. Returns true if all |size| bytes were read.
    // Returns false otherwise.
    virtual bool WriteFully(std::string_view data) = 0;

    // Create a new TlsConnection instance. |cert| and |priv_key| cannot be
    // empty.
    static std::unique_ptr<TlsConnection> Create(Role role, std::string_view cert,
                                                 std::string_view priv_key,
                                                 android::base::borrowed_fd fd);

    // Helper to set the certificate and key strings to a SSL client/server.
    // Useful when in the set-certificate callback.
    static bool SetCertAndKey(SSL* ssl, std::string_view cert_chain, std::string_view priv_key);

  protected:
    TlsConnection() = default;
};  // TlsConnection

}  // namespace tls
}  // namespace adb
