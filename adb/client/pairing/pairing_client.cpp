/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "client/pairing/pairing_client.h"

#include <atomic>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#include <android-base/logging.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include "sysdeps.h"

namespace adbwifi {
namespace pairing {

using android::base::unique_fd;

namespace {

struct ConnectionDeleter {
    void operator()(PairingConnectionCtx* p) { pairing_connection_destroy(p); }
};  // ConnectionDeleter
using ConnectionPtr = std::unique_ptr<PairingConnectionCtx, ConnectionDeleter>;

class PairingClientImpl : public PairingClient {
  public:
    virtual ~PairingClientImpl();

    explicit PairingClientImpl(const Data& pswd, const PeerInfo& peer_info, const Data& cert,
                               const Data& priv_key);

    // Starts the pairing client. This call is non-blocking. Upon pairing
    // completion, |cb| will be called with the PeerInfo on success,
    // or an empty value on failure.
    //
    // Returns true if PairingClient was successfully started. Otherwise,
    // return false.
    virtual bool Start(std::string_view ip_addr, pairing_client_result_cb cb,
                       void* opaque) override;

    static void OnPairingResult(const PeerInfo* peer_info, int fd, void* opaque);

  private:
    // Setup and start the PairingConnection
    bool StartConnection();

    enum class State {
        Ready,
        Running,
        Stopped,
    };

    State state_ = State::Ready;
    Data pswd_;
    PeerInfo peer_info_;
    Data cert_;
    Data priv_key_;
    std::string host_;
    int port_;

    ConnectionPtr connection_;
    pairing_client_result_cb cb_;
    void* opaque_ = nullptr;
};  // PairingClientImpl

PairingClientImpl::PairingClientImpl(const Data& pswd, const PeerInfo& peer_info, const Data& cert,
                                     const Data& priv_key)
    : pswd_(pswd), peer_info_(peer_info), cert_(cert), priv_key_(priv_key) {
    CHECK(!pswd_.empty() && !cert_.empty() && !priv_key_.empty());

    state_ = State::Ready;
}

PairingClientImpl::~PairingClientImpl() {
    // Make sure to kill the PairingConnection before terminating the fdevent
    // looper.
    if (connection_ != nullptr) {
        connection_.reset();
    }
}

bool PairingClientImpl::Start(std::string_view ip_addr, pairing_client_result_cb cb, void* opaque) {
    CHECK(!ip_addr.empty());
    cb_ = cb;
    opaque_ = opaque;

    if (state_ != State::Ready) {
        LOG(ERROR) << "PairingClient already running or finished";
        return false;
    }

    // Try to parse the host address
    std::string err;
    CHECK(android::base::ParseNetAddress(std::string(ip_addr), &host_, &port_, nullptr, &err));
    CHECK(port_ > 0 && port_ <= 65535);

    if (!StartConnection()) {
        LOG(ERROR) << "Unable to start PairingClient connection";
        state_ = State::Stopped;
        return false;
    }

    state_ = State::Running;
    return true;
}

bool PairingClientImpl::StartConnection() {
    std::string err;
    const int timeout = 10;  // seconds
    unique_fd fd(network_connect(host_, port_, SOCK_STREAM, timeout, &err));
    if (fd.get() == -1) {
        LOG(ERROR) << "Failed to start pairing connection client [" << err << "]";
        return false;
    }
    int off = 1;
    adb_setsockopt(fd.get(), IPPROTO_TCP, TCP_NODELAY, &off, sizeof(off));

    connection_ = ConnectionPtr(
            pairing_connection_client_new(pswd_.data(), pswd_.size(), &peer_info_, cert_.data(),
                                          cert_.size(), priv_key_.data(), priv_key_.size()));
    CHECK(connection_);

    int osh = cast_handle_to_int(adb_get_os_handle(fd.release()));
    if (!pairing_connection_start(connection_.get(), osh, OnPairingResult, this)) {
        LOG(ERROR) << "PairingClient failed to start the PairingConnection";
        state_ = State::Stopped;
        return false;
    }

    return true;
}

// static
void PairingClientImpl::OnPairingResult(const PeerInfo* peer_info, int /* fd */, void* opaque) {
    auto* p = reinterpret_cast<PairingClientImpl*>(opaque);
    p->cb_(peer_info, p->opaque_);
}

}  // namespace

// static
std::unique_ptr<PairingClient> PairingClient::Create(const Data& pswd, const PeerInfo& peer_info,
                                                     const Data& cert, const Data& priv_key) {
    CHECK(!pswd.empty());
    CHECK(!cert.empty());
    CHECK(!priv_key.empty());

    return std::unique_ptr<PairingClient>(new PairingClientImpl(pswd, peer_info, cert, priv_key));
}

}  // namespace pairing
}  // namespace adbwifi
