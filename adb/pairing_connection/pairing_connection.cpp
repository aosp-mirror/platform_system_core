/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "adb/pairing/pairing_connection.h"

#include <stddef.h>
#include <stdint.h>

#include <functional>
#include <memory>
#include <string_view>
#include <thread>
#include <vector>

#include <adb/pairing/pairing_auth.h>
#include <adb/tls/tls_connection.h>
#include <android-base/endian.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/unique_fd.h>

#include "pairing.pb.h"

using namespace adb;
using android::base::unique_fd;
using TlsError = tls::TlsConnection::TlsError;

const uint8_t kCurrentKeyHeaderVersion = 1;
const uint8_t kMinSupportedKeyHeaderVersion = 1;
const uint8_t kMaxSupportedKeyHeaderVersion = 1;
const uint32_t kMaxPayloadSize = kMaxPeerInfoSize * 2;

struct PairingPacketHeader {
    uint8_t version;   // PairingPacket version
    uint8_t type;      // the type of packet (PairingPacket.Type)
    uint32_t payload;  // Size of the payload in bytes
} __attribute__((packed));

struct PairingAuthDeleter {
    void operator()(PairingAuthCtx* p) { pairing_auth_destroy(p); }
};  // PairingAuthDeleter
using PairingAuthPtr = std::unique_ptr<PairingAuthCtx, PairingAuthDeleter>;

// PairingConnectionCtx encapsulates the protocol to authenticate two peers with
// each other. This class will open the tcp sockets and handle the pairing
// process. On completion, both sides will have each other's public key
// (certificate) if successful, otherwise, the pairing failed. The tcp port
// number is hardcoded (see pairing_connection.cpp).
//
// Each PairingConnectionCtx instance represents a different device trying to
// pair. So for the device, we can have multiple PairingConnectionCtxs while the
// host may have only one (unless host has a PairingServer).
//
// See pairing_connection_test.cpp for example usage.
//
struct PairingConnectionCtx {
  public:
    using Data = std::vector<uint8_t>;
    using ResultCallback = pairing_result_cb;
    enum class Role {
        Client,
        Server,
    };

    explicit PairingConnectionCtx(Role role, const Data& pswd, const PeerInfo& peer_info,
                                  const Data& certificate, const Data& priv_key);
    virtual ~PairingConnectionCtx();

    // Starts the pairing connection on a separate thread.
    // Upon completion, if the pairing was successful,
    // |cb| will be called with the peer information and certificate.
    // Otherwise, |cb| will be called with empty data. |fd| should already
    // be opened. PairingConnectionCtx will take ownership of the |fd|.
    //
    // Pairing is successful if both server/client uses the same non-empty
    // |pswd|, and they are able to exchange the information. |pswd| and
    // |certificate| must be non-empty. Start() can only be called once in the
    // lifetime of this object.
    //
    // Returns true if the thread was successfully started, false otherwise.
    bool Start(int fd, ResultCallback cb, void* opaque);

  private:
    // Setup the tls connection.
    bool SetupTlsConnection();

    /************ PairingPacketHeader methods ****************/
    // Tries to write out the header and payload.
    bool WriteHeader(const PairingPacketHeader* header, std::string_view payload);
    // Tries to parse incoming data into the |header|. Returns true if header
    // is valid and header version is supported. |header| is filled on success.
    // |header| may contain garbage if unsuccessful.
    bool ReadHeader(PairingPacketHeader* header);
    // Creates a PairingPacketHeader.
    void CreateHeader(PairingPacketHeader* header, adb::proto::PairingPacket::Type type,
                      uint32_t payload_size);
    // Checks if actual matches expected.
    bool CheckHeaderType(adb::proto::PairingPacket::Type expected, uint8_t actual);

    /*********** State related methods **************/
    // Handles the State::ExchangingMsgs state.
    bool DoExchangeMsgs();
    // Handles the State::ExchangingPeerInfo state.
    bool DoExchangePeerInfo();

    // The background task to do the pairing.
    void StartWorker();

    // Calls |cb_| and sets the state to Stopped.
    void NotifyResult(const PeerInfo* p);

    static PairingAuthPtr CreatePairingAuthPtr(Role role, const Data& pswd);

    enum class State {
        Ready,
        ExchangingMsgs,
        ExchangingPeerInfo,
        Stopped,
    };

    std::atomic<State> state_{State::Ready};
    Role role_;
    Data pswd_;
    PeerInfo peer_info_;
    Data cert_;
    Data priv_key_;

    // Peer's info
    PeerInfo their_info_;

    ResultCallback cb_;
    void* opaque_ = nullptr;
    std::unique_ptr<tls::TlsConnection> tls_;
    PairingAuthPtr auth_;
    unique_fd fd_;
    std::thread thread_;
    static constexpr size_t kExportedKeySize = 64;
};  // PairingConnectionCtx

PairingConnectionCtx::PairingConnectionCtx(Role role, const Data& pswd, const PeerInfo& peer_info,
                                           const Data& cert, const Data& priv_key)
    : role_(role), pswd_(pswd), peer_info_(peer_info), cert_(cert), priv_key_(priv_key) {
    CHECK(!pswd_.empty() && !cert_.empty() && !priv_key_.empty());
}

PairingConnectionCtx::~PairingConnectionCtx() {
    // Force close the fd and wait for the worker thread to finish.
    fd_.reset();
    if (thread_.joinable()) {
        thread_.join();
    }
}

bool PairingConnectionCtx::SetupTlsConnection() {
    tls_ = tls::TlsConnection::Create(
            role_ == Role::Server ? tls::TlsConnection::Role::Server
                                  : tls::TlsConnection::Role::Client,
            std::string_view(reinterpret_cast<const char*>(cert_.data()), cert_.size()),
            std::string_view(reinterpret_cast<const char*>(priv_key_.data()), priv_key_.size()),
            fd_);

    if (tls_ == nullptr) {
        LOG(ERROR) << "Unable to start TlsConnection. Unable to pair fd=" << fd_.get();
        return false;
    }

    // Allow any peer certificate
    tls_->SetCertVerifyCallback([](X509_STORE_CTX*) { return 1; });

    // SSL doesn't seem to behave correctly with fdevents so just do a blocking
    // read for the pairing data.
    if (tls_->DoHandshake() != TlsError::Success) {
        LOG(ERROR) << "Failed to handshake with the peer fd=" << fd_.get();
        return false;
    }

    // To ensure the connection is not stolen while we do the PAKE, append the
    // exported key material from the tls connection to the password.
    std::vector<uint8_t> exportedKeyMaterial = tls_->ExportKeyingMaterial(kExportedKeySize);
    if (exportedKeyMaterial.empty()) {
        LOG(ERROR) << "Failed to export key material";
        return false;
    }
    pswd_.insert(pswd_.end(), std::make_move_iterator(exportedKeyMaterial.begin()),
                 std::make_move_iterator(exportedKeyMaterial.end()));
    auth_ = CreatePairingAuthPtr(role_, pswd_);

    return true;
}

bool PairingConnectionCtx::WriteHeader(const PairingPacketHeader* header,
                                       std::string_view payload) {
    PairingPacketHeader network_header = *header;
    network_header.payload = htonl(network_header.payload);
    if (!tls_->WriteFully(std::string_view(reinterpret_cast<const char*>(&network_header),
                                           sizeof(PairingPacketHeader))) ||
        !tls_->WriteFully(payload)) {
        LOG(ERROR) << "Failed to write out PairingPacketHeader";
        state_ = State::Stopped;
        return false;
    }
    return true;
}

bool PairingConnectionCtx::ReadHeader(PairingPacketHeader* header) {
    auto data = tls_->ReadFully(sizeof(PairingPacketHeader));
    if (data.empty()) {
        return false;
    }

    uint8_t* p = data.data();
    // First byte is always PairingPacketHeader version
    header->version = *p;
    ++p;
    if (header->version < kMinSupportedKeyHeaderVersion ||
        header->version > kMaxSupportedKeyHeaderVersion) {
        LOG(ERROR) << "PairingPacketHeader version mismatch (us=" << kCurrentKeyHeaderVersion
                   << " them=" << header->version << ")";
        return false;
    }
    // Next byte is the PairingPacket::Type
    if (!adb::proto::PairingPacket::Type_IsValid(*p)) {
        LOG(ERROR) << "Unknown PairingPacket type=" << static_cast<uint32_t>(*p);
        return false;
    }
    header->type = *p;
    ++p;
    // Last, the payload size
    header->payload = ntohl(*(reinterpret_cast<uint32_t*>(p)));
    if (header->payload == 0 || header->payload > kMaxPayloadSize) {
        LOG(ERROR) << "header payload not within a safe payload size (size=" << header->payload
                   << ")";
        return false;
    }

    return true;
}

void PairingConnectionCtx::CreateHeader(PairingPacketHeader* header,
                                        adb::proto::PairingPacket::Type type,
                                        uint32_t payload_size) {
    header->version = kCurrentKeyHeaderVersion;
    uint8_t type8 = static_cast<uint8_t>(static_cast<int>(type));
    header->type = type8;
    header->payload = payload_size;
}

bool PairingConnectionCtx::CheckHeaderType(adb::proto::PairingPacket::Type expected_type,
                                           uint8_t actual) {
    uint8_t expected = *reinterpret_cast<uint8_t*>(&expected_type);
    if (actual != expected) {
        LOG(ERROR) << "Unexpected header type (expected=" << static_cast<uint32_t>(expected)
                   << " actual=" << static_cast<uint32_t>(actual) << ")";
        return false;
    }
    return true;
}

void PairingConnectionCtx::NotifyResult(const PeerInfo* p) {
    cb_(p, fd_.get(), opaque_);
    state_ = State::Stopped;
}

bool PairingConnectionCtx::Start(int fd, ResultCallback cb, void* opaque) {
    if (fd < 0) {
        return false;
    }
    fd_.reset(fd);

    State expected = State::Ready;
    if (!state_.compare_exchange_strong(expected, State::ExchangingMsgs)) {
        return false;
    }

    cb_ = cb;
    opaque_ = opaque;

    thread_ = std::thread([this] { StartWorker(); });
    return true;
}

bool PairingConnectionCtx::DoExchangeMsgs() {
    uint32_t payload = pairing_auth_msg_size(auth_.get());
    std::vector<uint8_t> msg(payload);
    pairing_auth_get_spake2_msg(auth_.get(), msg.data());

    PairingPacketHeader header;
    CreateHeader(&header, adb::proto::PairingPacket::SPAKE2_MSG, payload);

    // Write our SPAKE2 msg
    if (!WriteHeader(&header,
                     std::string_view(reinterpret_cast<const char*>(msg.data()), msg.size()))) {
        LOG(ERROR) << "Failed to write SPAKE2 msg.";
        return false;
    }

    // Read the peer's SPAKE2 msg header
    if (!ReadHeader(&header)) {
        LOG(ERROR) << "Invalid PairingPacketHeader.";
        return false;
    }
    if (!CheckHeaderType(adb::proto::PairingPacket::SPAKE2_MSG, header.type)) {
        return false;
    }

    // Read the SPAKE2 msg payload and initialize the cipher for
    // encrypting the PeerInfo and certificate.
    auto their_msg = tls_->ReadFully(header.payload);
    if (their_msg.empty() ||
        !pairing_auth_init_cipher(auth_.get(), their_msg.data(), their_msg.size())) {
        LOG(ERROR) << "Unable to initialize pairing cipher [their_msg.size=" << their_msg.size()
                   << "]";
        return false;
    }

    return true;
}

bool PairingConnectionCtx::DoExchangePeerInfo() {
    // Encrypt PeerInfo
    std::vector<uint8_t> buf;
    uint8_t* p = reinterpret_cast<uint8_t*>(&peer_info_);
    buf.assign(p, p + sizeof(peer_info_));
    std::vector<uint8_t> outbuf(pairing_auth_safe_encrypted_size(auth_.get(), buf.size()));
    CHECK(!outbuf.empty());
    size_t outsize;
    if (!pairing_auth_encrypt(auth_.get(), buf.data(), buf.size(), outbuf.data(), &outsize)) {
        LOG(ERROR) << "Failed to encrypt peer info";
        return false;
    }
    outbuf.resize(outsize);

    // Write out the packet header
    PairingPacketHeader out_header;
    out_header.version = kCurrentKeyHeaderVersion;
    out_header.type = static_cast<uint8_t>(static_cast<int>(adb::proto::PairingPacket::PEER_INFO));
    out_header.payload = htonl(outbuf.size());
    if (!tls_->WriteFully(
                std::string_view(reinterpret_cast<const char*>(&out_header), sizeof(out_header)))) {
        LOG(ERROR) << "Unable to write PairingPacketHeader";
        return false;
    }

    // Write out the encrypted payload
    if (!tls_->WriteFully(
                std::string_view(reinterpret_cast<const char*>(outbuf.data()), outbuf.size()))) {
        LOG(ERROR) << "Unable to write encrypted peer info";
        return false;
    }

    // Read in the peer's packet header
    PairingPacketHeader header;
    if (!ReadHeader(&header)) {
        LOG(ERROR) << "Invalid PairingPacketHeader.";
        return false;
    }

    if (!CheckHeaderType(adb::proto::PairingPacket::PEER_INFO, header.type)) {
        return false;
    }

    // Read in the encrypted peer certificate
    buf = tls_->ReadFully(header.payload);
    if (buf.empty()) {
        return false;
    }

    // Try to decrypt the certificate
    outbuf.resize(pairing_auth_safe_decrypted_size(auth_.get(), buf.data(), buf.size()));
    if (outbuf.empty()) {
        LOG(ERROR) << "Unsupported payload while decrypting peer info.";
        return false;
    }

    if (!pairing_auth_decrypt(auth_.get(), buf.data(), buf.size(), outbuf.data(), &outsize)) {
        LOG(ERROR) << "Failed to decrypt";
        return false;
    }
    outbuf.resize(outsize);

    // The decrypted message should contain the PeerInfo.
    if (outbuf.size() != sizeof(PeerInfo)) {
        LOG(ERROR) << "Got size=" << outbuf.size() << "PeerInfo.size=" << sizeof(PeerInfo);
        return false;
    }

    p = outbuf.data();
    ::memcpy(&their_info_, p, sizeof(PeerInfo));
    p += sizeof(PeerInfo);

    return true;
}

void PairingConnectionCtx::StartWorker() {
    // Setup the secure transport
    if (!SetupTlsConnection()) {
        NotifyResult(nullptr);
        return;
    }

    for (;;) {
        switch (state_) {
            case State::ExchangingMsgs:
                if (!DoExchangeMsgs()) {
                    NotifyResult(nullptr);
                    return;
                }
                state_ = State::ExchangingPeerInfo;
                break;
            case State::ExchangingPeerInfo:
                if (!DoExchangePeerInfo()) {
                    NotifyResult(nullptr);
                    return;
                }
                NotifyResult(&their_info_);
                return;
            case State::Ready:
            case State::Stopped:
                LOG(FATAL) << __func__ << ": Got invalid state";
                return;
        }
    }
}

// static
PairingAuthPtr PairingConnectionCtx::CreatePairingAuthPtr(Role role, const Data& pswd) {
    switch (role) {
        case Role::Client:
            return PairingAuthPtr(pairing_auth_client_new(pswd.data(), pswd.size()));
            break;
        case Role::Server:
            return PairingAuthPtr(pairing_auth_server_new(pswd.data(), pswd.size()));
            break;
    }
}

static PairingConnectionCtx* CreateConnection(PairingConnectionCtx::Role role, const uint8_t* pswd,
                                              size_t pswd_len, const PeerInfo* peer_info,
                                              const uint8_t* x509_cert_pem, size_t x509_size,
                                              const uint8_t* priv_key_pem, size_t priv_size) {
    CHECK(pswd);
    CHECK_GT(pswd_len, 0U);
    CHECK(x509_cert_pem);
    CHECK_GT(x509_size, 0U);
    CHECK(priv_key_pem);
    CHECK_GT(priv_size, 0U);
    CHECK(peer_info);
    std::vector<uint8_t> vec_pswd(pswd, pswd + pswd_len);
    std::vector<uint8_t> vec_x509_cert(x509_cert_pem, x509_cert_pem + x509_size);
    std::vector<uint8_t> vec_priv_key(priv_key_pem, priv_key_pem + priv_size);
    return new PairingConnectionCtx(role, vec_pswd, *peer_info, vec_x509_cert, vec_priv_key);
}

PairingConnectionCtx* pairing_connection_client_new(const uint8_t* pswd, size_t pswd_len,
                                                    const PeerInfo* peer_info,
                                                    const uint8_t* x509_cert_pem, size_t x509_size,
                                                    const uint8_t* priv_key_pem, size_t priv_size) {
    return CreateConnection(PairingConnectionCtx::Role::Client, pswd, pswd_len, peer_info,
                            x509_cert_pem, x509_size, priv_key_pem, priv_size);
}

PairingConnectionCtx* pairing_connection_server_new(const uint8_t* pswd, size_t pswd_len,
                                                    const PeerInfo* peer_info,
                                                    const uint8_t* x509_cert_pem, size_t x509_size,
                                                    const uint8_t* priv_key_pem, size_t priv_size) {
    return CreateConnection(PairingConnectionCtx::Role::Server, pswd, pswd_len, peer_info,
                            x509_cert_pem, x509_size, priv_key_pem, priv_size);
}

void pairing_connection_destroy(PairingConnectionCtx* ctx) {
    CHECK(ctx);
    delete ctx;
}

bool pairing_connection_start(PairingConnectionCtx* ctx, int fd, pairing_result_cb cb,
                              void* opaque) {
    return ctx->Start(fd, cb, opaque);
}
