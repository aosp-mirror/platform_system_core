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

#include "adb/pairing/pairing_server.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <atomic>
#include <deque>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <vector>

#include <adb/crypto/rsa_2048_key.h>
#include <adb/crypto/x509_generator.h>
#include <adb/pairing/pairing_connection.h>
#include <android-base/logging.h>
#include <android-base/parsenetaddress.h>
#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#include "internal/constants.h"

using android::base::ScopedLockAssertion;
using android::base::unique_fd;
using namespace adb::crypto;
using namespace adb::pairing;

// The implementation has two background threads running: one to handle and
// accept any new pairing connection requests (socket accept), and the other to
// handle connection events (connection started, connection finished).
struct PairingServerCtx {
  public:
    using Data = std::vector<uint8_t>;

    virtual ~PairingServerCtx();

    // All parameters must be non-empty.
    explicit PairingServerCtx(const Data& pswd, const PeerInfo& peer_info, const Data& cert,
                              const Data& priv_key, uint16_t port);

    // Starts the pairing server. This call is non-blocking. Upon completion,
    // if the pairing was successful, then |cb| will be called with the PublicKeyHeader
    // containing the info of the trusted peer. Otherwise, |cb| will be
    // called with an empty value. Start can only be called once in the lifetime
    // of this object.
    //
    // Returns the port number if PairingServerCtx was successfully started. Otherwise,
    // returns 0.
    uint16_t Start(pairing_server_result_cb cb, void* opaque);

  private:
    // Setup the server socket to accept incoming connections. Returns the
    // server port number (> 0 on success).
    uint16_t SetupServer();
    // Force stop the server thread.
    void StopServer();

    // handles a new pairing client connection
    bool HandleNewClientConnection(int fd) EXCLUDES(conn_mutex_);

    // ======== connection events thread =============
    std::mutex conn_mutex_;
    std::condition_variable conn_cv_;

    using FdVal = int;
    struct ConnectionDeleter {
        void operator()(PairingConnectionCtx* p) { pairing_connection_destroy(p); }
    };
    using ConnectionPtr = std::unique_ptr<PairingConnectionCtx, ConnectionDeleter>;
    static ConnectionPtr CreatePairingConnection(const Data& pswd, const PeerInfo& peer_info,
                                                 const Data& cert, const Data& priv_key);
    using NewConnectionEvent = std::tuple<unique_fd, ConnectionPtr>;
    // <fd, PeerInfo.type, PeerInfo.data>
    using ConnectionFinishedEvent = std::tuple<FdVal, uint8_t, std::optional<std::string>>;
    using ConnectionEvent = std::variant<NewConnectionEvent, ConnectionFinishedEvent>;
    // Queue for connections to write into. We have a separate queue to read
    // from, in order to minimize the time the server thread is blocked.
    std::deque<ConnectionEvent> conn_write_queue_ GUARDED_BY(conn_mutex_);
    std::deque<ConnectionEvent> conn_read_queue_;
    // Map of fds to their PairingConnections currently running.
    std::unordered_map<FdVal, ConnectionPtr> connections_;

    // Two threads launched when starting the pairing server:
    // 1) A server thread that waits for incoming client connections, and
    // 2) A connection events thread that synchonizes events from all of the
    //    clients, since each PairingConnection is running in it's own thread.
    void StartConnectionEventsThread();
    void StartServerThread();

    static void PairingConnectionCallback(const PeerInfo* peer_info, int fd, void* opaque);

    std::thread conn_events_thread_;
    void ConnectionEventsWorker();
    std::thread server_thread_;
    void ServerWorker();
    bool is_terminate_ GUARDED_BY(conn_mutex_) = false;

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
    uint16_t port_;

    pairing_server_result_cb cb_;
    void* opaque_ = nullptr;
    bool got_valid_pairing_ = false;

    static const int kEpollConstSocket = 0;
    // Used to break the server thread from epoll_wait
    static const int kEpollConstEventFd = 1;
    unique_fd epoll_fd_;
    unique_fd server_fd_;
    unique_fd event_fd_;
};  // PairingServerCtx

// static
PairingServerCtx::ConnectionPtr PairingServerCtx::CreatePairingConnection(const Data& pswd,
                                                                          const PeerInfo& peer_info,
                                                                          const Data& cert,
                                                                          const Data& priv_key) {
    return ConnectionPtr(pairing_connection_server_new(pswd.data(), pswd.size(), &peer_info,
                                                       cert.data(), cert.size(), priv_key.data(),
                                                       priv_key.size()));
}

PairingServerCtx::PairingServerCtx(const Data& pswd, const PeerInfo& peer_info, const Data& cert,
                                   const Data& priv_key, uint16_t port)
    : pswd_(pswd), peer_info_(peer_info), cert_(cert), priv_key_(priv_key), port_(port) {
    CHECK(!pswd_.empty() && !cert_.empty() && !priv_key_.empty());
}

PairingServerCtx::~PairingServerCtx() {
    // Since these connections have references to us, let's make sure they
    // destruct before us.
    if (server_thread_.joinable()) {
        StopServer();
        server_thread_.join();
    }

    {
        std::lock_guard<std::mutex> lock(conn_mutex_);
        is_terminate_ = true;
    }
    conn_cv_.notify_one();
    if (conn_events_thread_.joinable()) {
        conn_events_thread_.join();
    }

    // Notify the cb_ if it hasn't already.
    if (!got_valid_pairing_ && cb_ != nullptr) {
        cb_(nullptr, opaque_);
    }
}

uint16_t PairingServerCtx::Start(pairing_server_result_cb cb, void* opaque) {
    cb_ = cb;
    opaque_ = opaque;

    if (state_ != State::Ready) {
        LOG(ERROR) << "PairingServerCtx already running or stopped";
        return 0;
    }

    port_ = SetupServer();
    if (port_ == 0) {
        LOG(ERROR) << "Unable to start PairingServer";
        state_ = State::Stopped;
        return 0;
    }
    LOG(INFO) << "Pairing server started on port " << port_;

    state_ = State::Running;
    return port_;
}

void PairingServerCtx::StopServer() {
    if (event_fd_.get() == -1) {
        return;
    }
    uint64_t value = 1;
    ssize_t rc = write(event_fd_.get(), &value, sizeof(value));
    if (rc == -1) {
        // This can happen if the server didn't start.
        PLOG(ERROR) << "write to eventfd failed";
    } else if (rc != sizeof(value)) {
        LOG(FATAL) << "write to event returned short (" << rc << ")";
    }
}

uint16_t PairingServerCtx::SetupServer() {
    epoll_fd_.reset(epoll_create1(EPOLL_CLOEXEC));
    if (epoll_fd_ == -1) {
        PLOG(ERROR) << "failed to create epoll fd";
        return 0;
    }

    event_fd_.reset(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (event_fd_ == -1) {
        PLOG(ERROR) << "failed to create eventfd";
        return 0;
    }

    server_fd_.reset(socket_inaddr_any_server(port_, SOCK_STREAM));
    if (server_fd_.get() == -1) {
        PLOG(ERROR) << "Failed to start pairing connection server";
        return 0;
    } else if (fcntl(server_fd_.get(), F_SETFD, FD_CLOEXEC) != 0) {
        PLOG(ERROR) << "Failed to make server socket cloexec";
        return 0;
    } else if (fcntl(server_fd_.get(), F_SETFD, O_NONBLOCK) != 0) {
        PLOG(ERROR) << "Failed to make server socket nonblocking";
        return 0;
    }

    StartConnectionEventsThread();
    StartServerThread();
    int port = socket_get_local_port(server_fd_.get());
    return (port <= 0 ? 0 : port);
}

void PairingServerCtx::StartServerThread() {
    server_thread_ = std::thread([this]() { ServerWorker(); });
}

void PairingServerCtx::StartConnectionEventsThread() {
    conn_events_thread_ = std::thread([this]() { ConnectionEventsWorker(); });
}

void PairingServerCtx::ServerWorker() {
    {
        struct epoll_event event;
        event.events = EPOLLIN;
        event.data.u64 = kEpollConstSocket;
        CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, server_fd_.get(), &event));
    }

    {
        struct epoll_event event;
        event.events = EPOLLIN;
        event.data.u64 = kEpollConstEventFd;
        CHECK_EQ(0, epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, event_fd_.get(), &event));
    }

    while (true) {
        struct epoll_event events[2];
        int rc = TEMP_FAILURE_RETRY(epoll_wait(epoll_fd_.get(), events, 2, -1));
        if (rc == -1) {
            PLOG(ERROR) << "epoll_wait failed";
            return;
        } else if (rc == 0) {
            LOG(ERROR) << "epoll_wait returned 0";
            return;
        }

        for (int i = 0; i < rc; ++i) {
            struct epoll_event& event = events[i];
            switch (event.data.u64) {
                case kEpollConstSocket:
                    HandleNewClientConnection(server_fd_.get());
                    break;
                case kEpollConstEventFd:
                    uint64_t dummy;
                    int rc = TEMP_FAILURE_RETRY(read(event_fd_.get(), &dummy, sizeof(dummy)));
                    if (rc != sizeof(dummy)) {
                        PLOG(FATAL) << "failed to read from eventfd (rc=" << rc << ")";
                    }
                    return;
            }
        }
    }
}

// static
void PairingServerCtx::PairingConnectionCallback(const PeerInfo* peer_info, int fd, void* opaque) {
    auto* p = reinterpret_cast<PairingServerCtx*>(opaque);

    ConnectionFinishedEvent event;
    if (peer_info != nullptr) {
        if (peer_info->type == ADB_RSA_PUB_KEY) {
            event = std::make_tuple(fd, peer_info->type,
                                    std::string(reinterpret_cast<const char*>(peer_info->data)));
        } else {
            LOG(WARNING) << "Ignoring successful pairing because of unknown "
                         << "PeerInfo type=" << peer_info->type;
        }
    } else {
        event = std::make_tuple(fd, 0, std::nullopt);
    }
    {
        std::lock_guard<std::mutex> lock(p->conn_mutex_);
        p->conn_write_queue_.push_back(std::move(event));
    }
    p->conn_cv_.notify_one();
}

void PairingServerCtx::ConnectionEventsWorker() {
    uint8_t num_tries = 0;
    for (;;) {
        // Transfer the write queue to the read queue.
        {
            std::unique_lock<std::mutex> lock(conn_mutex_);
            ScopedLockAssertion assume_locked(conn_mutex_);

            if (is_terminate_) {
                // We check |is_terminate_| twice because condition_variable's
                // notify() only wakes up a thread if it is in the wait state
                // prior to notify(). Furthermore, we aren't holding the mutex
                // when processing the events in |conn_read_queue_|.
                return;
            }
            if (conn_write_queue_.empty()) {
                // We need to wait for new events, or the termination signal.
                conn_cv_.wait(lock, [this]() REQUIRES(conn_mutex_) {
                    return (is_terminate_ || !conn_write_queue_.empty());
                });
            }
            if (is_terminate_) {
                // We're done.
                return;
            }
            // Move all events into the read queue.
            conn_read_queue_ = std::move(conn_write_queue_);
            conn_write_queue_.clear();
        }

        // Process all events in the read queue.
        while (conn_read_queue_.size() > 0) {
            auto& event = conn_read_queue_.front();
            if (auto* p = std::get_if<NewConnectionEvent>(&event)) {
                // Ignore if we are already at the max number of connections
                if (connections_.size() >= internal::kMaxConnections) {
                    conn_read_queue_.pop_front();
                    continue;
                }
                auto [ufd, connection] = std::move(*p);
                int fd = ufd.release();
                bool started = pairing_connection_start(connection.get(), fd,
                                                        PairingConnectionCallback, this);
                if (!started) {
                    LOG(ERROR) << "PairingServer unable to start a PairingConnection fd=" << fd;
                    ufd.reset(fd);
                } else {
                    connections_[fd] = std::move(connection);
                }
            } else if (auto* p = std::get_if<ConnectionFinishedEvent>(&event)) {
                auto [fd, info_type, public_key] = std::move(*p);
                if (public_key.has_value() && !public_key->empty()) {
                    // Valid pairing. Let's shutdown the server and close any
                    // pairing connections in progress.
                    StopServer();
                    connections_.clear();

                    PeerInfo info = {};
                    info.type = info_type;
                    strncpy(reinterpret_cast<char*>(info.data), public_key->data(),
                            public_key->size());

                    cb_(&info, opaque_);

                    got_valid_pairing_ = true;
                    return;
                }
                // Invalid pairing. Close the invalid connection.
                if (connections_.find(fd) != connections_.end()) {
                    connections_.erase(fd);
                }

                if (++num_tries >= internal::kMaxPairingAttempts) {
                    cb_(nullptr, opaque_);
                    // To prevent the destructor from calling it again.
                    cb_ = nullptr;
                    return;
                }
            }
            conn_read_queue_.pop_front();
        }
    }
}

bool PairingServerCtx::HandleNewClientConnection(int fd) {
    unique_fd ufd(TEMP_FAILURE_RETRY(accept4(fd, nullptr, nullptr, SOCK_CLOEXEC)));
    if (ufd == -1) {
        PLOG(WARNING) << "adb_socket_accept failed fd=" << fd;
        return false;
    }
    auto connection = CreatePairingConnection(pswd_, peer_info_, cert_, priv_key_);
    if (connection == nullptr) {
        LOG(ERROR) << "PairingServer unable to create a PairingConnection fd=" << fd;
        return false;
    }
    // send the new connection to the connection thread for further processing
    NewConnectionEvent event = std::make_tuple(std::move(ufd), std::move(connection));
    {
        std::lock_guard<std::mutex> lock(conn_mutex_);
        conn_write_queue_.push_back(std::move(event));
    }
    conn_cv_.notify_one();

    return true;
}

uint16_t pairing_server_start(PairingServerCtx* ctx, pairing_server_result_cb cb, void* opaque) {
    return ctx->Start(cb, opaque);
}

PairingServerCtx* pairing_server_new(const uint8_t* pswd, size_t pswd_len,
                                     const PeerInfo* peer_info, const uint8_t* x509_cert_pem,
                                     size_t x509_size, const uint8_t* priv_key_pem,
                                     size_t priv_size, uint16_t port) {
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
    return new PairingServerCtx(vec_pswd, *peer_info, vec_x509_cert, vec_priv_key, port);
}

PairingServerCtx* pairing_server_new_no_cert(const uint8_t* pswd, size_t pswd_len,
                                             const PeerInfo* peer_info, uint16_t port) {
    auto rsa_2048 = CreateRSA2048Key();
    auto x509_cert = GenerateX509Certificate(rsa_2048->GetEvpPkey());
    std::string pkey_pem = Key::ToPEMString(rsa_2048->GetEvpPkey());
    std::string cert_pem = X509ToPEMString(x509_cert.get());

    return pairing_server_new(pswd, pswd_len, peer_info,
                              reinterpret_cast<const uint8_t*>(cert_pem.data()), cert_pem.size(),
                              reinterpret_cast<const uint8_t*>(pkey_pem.data()), pkey_pem.size(),
                              port);
}

void pairing_server_destroy(PairingServerCtx* ctx) {
    CHECK(ctx);
    delete ctx;
}
