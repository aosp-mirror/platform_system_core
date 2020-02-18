/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "adb/tls/tls_connection.h"

#include <algorithm>
#include <vector>

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

using android::base::borrowed_fd;

namespace adb {
namespace tls {

namespace {

static constexpr char kExportedKeyLabel[] = "adb-label";

class TlsConnectionImpl : public TlsConnection {
  public:
    explicit TlsConnectionImpl(Role role, std::string_view cert, std::string_view priv_key,
                               borrowed_fd fd);
    ~TlsConnectionImpl() override;

    bool AddTrustedCertificate(std::string_view cert) override;
    void SetCertVerifyCallback(CertVerifyCb cb) override;
    void SetCertificateCallback(SetCertCb cb) override;
    void SetClientCAList(STACK_OF(X509_NAME) * ca_list) override;
    std::vector<uint8_t> ExportKeyingMaterial(size_t length) override;
    void EnableClientPostHandshakeCheck(bool enable) override;
    TlsError DoHandshake() override;
    std::vector<uint8_t> ReadFully(size_t size) override;
    bool ReadFully(void* buf, size_t size) override;
    bool WriteFully(std::string_view data) override;

    static bssl::UniquePtr<EVP_PKEY> EvpPkeyFromPEM(std::string_view pem);
    static bssl::UniquePtr<CRYPTO_BUFFER> BufferFromPEM(std::string_view pem);

  private:
    static int SSLSetCertVerifyCb(X509_STORE_CTX* ctx, void* opaque);
    static int SSLSetCertCb(SSL* ssl, void* opaque);

    static bssl::UniquePtr<X509> X509FromBuffer(bssl::UniquePtr<CRYPTO_BUFFER> buffer);
    static const char* SSLErrorString();
    void Invalidate();
    TlsError GetFailureReason(int err);
    const char* RoleToString() { return role_ == Role::Server ? kServerRoleStr : kClientRoleStr; }

    Role role_;
    bssl::UniquePtr<EVP_PKEY> priv_key_;
    bssl::UniquePtr<CRYPTO_BUFFER> cert_;

    bssl::UniquePtr<STACK_OF(X509_NAME)> ca_list_;
    bssl::UniquePtr<SSL_CTX> ssl_ctx_;
    bssl::UniquePtr<SSL> ssl_;
    std::vector<bssl::UniquePtr<X509>> known_certificates_;
    bool client_verify_post_handshake_ = false;

    CertVerifyCb cert_verify_cb_;
    SetCertCb set_cert_cb_;
    borrowed_fd fd_;
    static constexpr char kClientRoleStr[] = "[client]: ";
    static constexpr char kServerRoleStr[] = "[server]: ";
};  // TlsConnectionImpl

TlsConnectionImpl::TlsConnectionImpl(Role role, std::string_view cert, std::string_view priv_key,
                                     borrowed_fd fd)
    : role_(role), fd_(fd) {
    CHECK(!cert.empty() && !priv_key.empty());
    LOG(INFO) << RoleToString() << "Initializing adbwifi TlsConnection";
    cert_ = BufferFromPEM(cert);
    CHECK(cert_);
    priv_key_ = EvpPkeyFromPEM(priv_key);
    CHECK(priv_key_);
}

TlsConnectionImpl::~TlsConnectionImpl() {
    // shutdown the SSL connection
    if (ssl_ != nullptr) {
        SSL_shutdown(ssl_.get());
    }
}

// static
const char* TlsConnectionImpl::SSLErrorString() {
    auto sslerr = ERR_peek_last_error();
    return ERR_reason_error_string(sslerr);
}

// static
bssl::UniquePtr<EVP_PKEY> TlsConnectionImpl::EvpPkeyFromPEM(std::string_view pem) {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(), pem.size()));
    return bssl::UniquePtr<EVP_PKEY>(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

// static
bssl::UniquePtr<CRYPTO_BUFFER> TlsConnectionImpl::BufferFromPEM(std::string_view pem) {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(), pem.size()));
    char* name = nullptr;
    char* header = nullptr;
    uint8_t* data = nullptr;
    long data_len = 0;

    if (!PEM_read_bio(bio.get(), &name, &header, &data, &data_len)) {
        LOG(ERROR) << "Failed to read certificate";
        return nullptr;
    }
    OPENSSL_free(name);
    OPENSSL_free(header);

    auto ret = bssl::UniquePtr<CRYPTO_BUFFER>(CRYPTO_BUFFER_new(data, data_len, nullptr));
    OPENSSL_free(data);
    return ret;
}

// static
bssl::UniquePtr<X509> TlsConnectionImpl::X509FromBuffer(bssl::UniquePtr<CRYPTO_BUFFER> buffer) {
    if (!buffer) {
        return nullptr;
    }
    return bssl::UniquePtr<X509>(X509_parse_from_buffer(buffer.get()));
}

// static
int TlsConnectionImpl::SSLSetCertVerifyCb(X509_STORE_CTX* ctx, void* opaque) {
    auto* p = reinterpret_cast<TlsConnectionImpl*>(opaque);
    return p->cert_verify_cb_(ctx);
}

// static
int TlsConnectionImpl::SSLSetCertCb(SSL* ssl, void* opaque) {
    auto* p = reinterpret_cast<TlsConnectionImpl*>(opaque);
    return p->set_cert_cb_(ssl);
}

bool TlsConnectionImpl::AddTrustedCertificate(std::string_view cert) {
    // Create X509 buffer from the certificate string
    auto buf = X509FromBuffer(BufferFromPEM(cert));
    if (buf == nullptr) {
        LOG(ERROR) << RoleToString() << "Failed to create a X509 buffer for the certificate.";
        return false;
    }
    known_certificates_.push_back(std::move(buf));
    return true;
}

void TlsConnectionImpl::SetCertVerifyCallback(CertVerifyCb cb) {
    cert_verify_cb_ = cb;
}

void TlsConnectionImpl::SetCertificateCallback(SetCertCb cb) {
    set_cert_cb_ = cb;
}

void TlsConnectionImpl::SetClientCAList(STACK_OF(X509_NAME) * ca_list) {
    CHECK(role_ == Role::Server);
    ca_list_.reset(ca_list != nullptr ? SSL_dup_CA_list(ca_list) : nullptr);
}

std::vector<uint8_t> TlsConnectionImpl::ExportKeyingMaterial(size_t length) {
    if (ssl_.get() == nullptr) {
        return {};
    }

    std::vector<uint8_t> out(length);
    if (SSL_export_keying_material(ssl_.get(), out.data(), out.size(), kExportedKeyLabel,
                                   sizeof(kExportedKeyLabel), nullptr, 0, false) == 0) {
        return {};
    }
    return out;
}

void TlsConnectionImpl::EnableClientPostHandshakeCheck(bool enable) {
    client_verify_post_handshake_ = enable;
}

TlsConnection::TlsError TlsConnectionImpl::GetFailureReason(int err) {
    switch (ERR_GET_REASON(err)) {
        case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
        case SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE:
        case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED:
        case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:
        case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
        case SSL_R_TLSV1_ALERT_ACCESS_DENIED:
        case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
        case SSL_R_TLSV1_CERTIFICATE_REQUIRED:
            return TlsError::PeerRejectedCertificate;
        case SSL_R_CERTIFICATE_VERIFY_FAILED:
            return TlsError::CertificateRejected;
        default:
            return TlsError::UnknownFailure;
    }
}

TlsConnection::TlsError TlsConnectionImpl::DoHandshake() {
    LOG(INFO) << RoleToString() << "Starting adbwifi tls handshake";
    ssl_ctx_.reset(SSL_CTX_new(TLS_method()));
    // TODO: Remove set_max_proto_version() once external/boringssl is updated
    // past
    // https://boringssl.googlesource.com/boringssl/+/58d56f4c59969a23e5f52014e2651c76fea2f877
    if (ssl_ctx_.get() == nullptr ||
        !SSL_CTX_set_min_proto_version(ssl_ctx_.get(), TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ssl_ctx_.get(), TLS1_3_VERSION)) {
        LOG(ERROR) << RoleToString() << "Failed to create SSL context";
        return TlsError::UnknownFailure;
    }

    // Register user-supplied known certificates
    for (auto const& cert : known_certificates_) {
        if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ssl_ctx_.get()), cert.get()) == 0) {
            LOG(ERROR) << RoleToString() << "Unable to add certificates into the X509_STORE";
            return TlsError::UnknownFailure;
        }
    }

    // Custom certificate verification
    if (cert_verify_cb_) {
        SSL_CTX_set_cert_verify_callback(ssl_ctx_.get(), SSLSetCertVerifyCb, this);
    }

    // set select certificate callback, if any.
    if (set_cert_cb_) {
        SSL_CTX_set_cert_cb(ssl_ctx_.get(), SSLSetCertCb, this);
    }

    // Server-allowed client CA list
    if (ca_list_ != nullptr) {
        bssl::UniquePtr<STACK_OF(X509_NAME)> names(SSL_dup_CA_list(ca_list_.get()));
        SSL_CTX_set_client_CA_list(ssl_ctx_.get(), names.release());
    }

    // Register our certificate and private key.
    std::vector<CRYPTO_BUFFER*> cert_chain = {
            cert_.get(),
    };
    if (!SSL_CTX_set_chain_and_key(ssl_ctx_.get(), cert_chain.data(), cert_chain.size(),
                                   priv_key_.get(), nullptr)) {
        LOG(ERROR) << RoleToString()
                   << "Unable to register the certificate chain file and private key ["
                   << SSLErrorString() << "]";
        Invalidate();
        return TlsError::UnknownFailure;
    }

    SSL_CTX_set_verify(ssl_ctx_.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

    // Okay! Let's try to do the handshake!
    ssl_.reset(SSL_new(ssl_ctx_.get()));
    if (!SSL_set_fd(ssl_.get(), fd_.get())) {
        LOG(ERROR) << RoleToString() << "SSL_set_fd failed. [" << SSLErrorString() << "]";
        return TlsError::UnknownFailure;
    }

    switch (role_) {
        case Role::Server:
            SSL_set_accept_state(ssl_.get());
            break;
        case Role::Client:
            SSL_set_connect_state(ssl_.get());
            break;
    }
    if (SSL_do_handshake(ssl_.get()) != 1) {
        LOG(ERROR) << RoleToString() << "Handshake failed in SSL_accept/SSL_connect ["
                   << SSLErrorString() << "]";
        auto sslerr = ERR_get_error();
        Invalidate();
        return GetFailureReason(sslerr);
    }

    if (client_verify_post_handshake_ && role_ == Role::Client) {
        uint8_t check;
        // Try to peek one byte for any failures. This assumes on success that
        // the server actually sends something.
        if (SSL_peek(ssl_.get(), &check, 1) <= 0) {
            LOG(ERROR) << RoleToString() << "Post-handshake SSL_peek failed [" << SSLErrorString()
                       << "]";
            auto sslerr = ERR_get_error();
            Invalidate();
            return GetFailureReason(sslerr);
        }
    }

    LOG(INFO) << RoleToString() << "Handshake succeeded.";
    return TlsError::Success;
}

void TlsConnectionImpl::Invalidate() {
    ssl_.reset();
    ssl_ctx_.reset();
}

std::vector<uint8_t> TlsConnectionImpl::ReadFully(size_t size) {
    std::vector<uint8_t> buf(size);
    if (!ReadFully(buf.data(), buf.size())) {
        return {};
    }

    return buf;
}

bool TlsConnectionImpl::ReadFully(void* buf, size_t size) {
    CHECK_GT(size, 0U);
    if (!ssl_) {
        LOG(ERROR) << RoleToString() << "Tried to read on a null SSL connection";
        return false;
    }

    size_t offset = 0;
    uint8_t* p8 = reinterpret_cast<uint8_t*>(buf);
    while (size > 0) {
        int bytes_read =
                SSL_read(ssl_.get(), p8 + offset, std::min(static_cast<size_t>(INT_MAX), size));
        if (bytes_read <= 0) {
            LOG(ERROR) << RoleToString() << "SSL_read failed [" << SSLErrorString() << "]";
            return false;
        }
        size -= bytes_read;
        offset += bytes_read;
    }
    return true;
}

bool TlsConnectionImpl::WriteFully(std::string_view data) {
    CHECK(!data.empty());
    if (!ssl_) {
        LOG(ERROR) << RoleToString() << "Tried to read on a null SSL connection";
        return false;
    }

    while (!data.empty()) {
        int bytes_out = SSL_write(ssl_.get(), data.data(),
                                  std::min(static_cast<size_t>(INT_MAX), data.size()));
        if (bytes_out <= 0) {
            LOG(ERROR) << RoleToString() << "SSL_write failed [" << SSLErrorString() << "]";
            return false;
        }
        data = data.substr(bytes_out);
    }
    return true;
}
}  // namespace

// static
std::unique_ptr<TlsConnection> TlsConnection::Create(TlsConnection::Role role,
                                                     std::string_view cert,
                                                     std::string_view priv_key, borrowed_fd fd) {
    CHECK(!cert.empty());
    CHECK(!priv_key.empty());

    return std::make_unique<TlsConnectionImpl>(role, cert, priv_key, fd);
}

// static
bool TlsConnection::SetCertAndKey(SSL* ssl, std::string_view cert, std::string_view priv_key) {
    CHECK(ssl);
    // Note: declaring these in local scope is okay because
    // SSL_set_chain_and_key will increase the refcount (bssl::UpRef).
    auto x509_cert = TlsConnectionImpl::BufferFromPEM(cert);
    auto evp_pkey = TlsConnectionImpl::EvpPkeyFromPEM(priv_key);
    if (x509_cert == nullptr || evp_pkey == nullptr) {
        return false;
    }

    std::vector<CRYPTO_BUFFER*> cert_chain = {
            x509_cert.get(),
    };
    if (!SSL_set_chain_and_key(ssl, cert_chain.data(), cert_chain.size(), evp_pkey.get(),
                               nullptr)) {
        LOG(ERROR) << "SSL_set_chain_and_key failed";
        return false;
    }

    return true;
}

}  // namespace tls
}  // namespace adb
