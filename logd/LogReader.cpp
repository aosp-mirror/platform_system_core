/*
 * Copyright (C) 2012-2013 The Android Open Source Project
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

#include <ctype.h>
#include <inttypes.h>
#include <poll.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <chrono>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#include "LogBuffer.h"
#include "LogBufferElement.h"
#include "LogPermissions.h"
#include "LogReader.h"
#include "LogUtils.h"
#include "LogWriter.h"

static bool CanReadSecurityLogs(SocketClient* client) {
    return client->getUid() == AID_SYSTEM || client->getGid() == AID_SYSTEM;
}

static std::string SocketClientToName(SocketClient* client) {
    return android::base::StringPrintf("pid %d, fd %d", client->getPid(), client->getSocket());
}

class SocketLogWriter : public LogWriter {
  public:
    SocketLogWriter(LogReader* reader, SocketClient* client, bool privileged)
        : LogWriter(client->getUid(), privileged), reader_(reader), client_(client) {}

    bool Write(const logger_entry& entry, const char* msg) override {
        struct iovec iovec[2];
        iovec[0].iov_base = const_cast<logger_entry*>(&entry);
        iovec[0].iov_len = entry.hdr_size;
        iovec[1].iov_base = const_cast<char*>(msg);
        iovec[1].iov_len = entry.len;

        return client_->sendDatav(iovec, 1 + (entry.len != 0)) == 0;
    }

    void Release() override {
        reader_->release(client_);
        client_->decRef();
    }

    void Shutdown() override { shutdown(client_->getSocket(), SHUT_RDWR); }

    std::string name() const override { return SocketClientToName(client_); }

  private:
    LogReader* reader_;
    SocketClient* client_;
};

LogReader::LogReader(LogBuffer* logbuf, LogReaderList* reader_list)
    : SocketListener(getLogSocket(), true), log_buffer_(logbuf), reader_list_(reader_list) {}

// Note returning false will release the SocketClient instance.
bool LogReader::onDataAvailable(SocketClient* cli) {
    static bool name_set;
    if (!name_set) {
        prctl(PR_SET_NAME, "logd.reader");
        name_set = true;
    }

    char buffer[255];

    int len = read(cli->getSocket(), buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        DoSocketDelete(cli);
        return false;
    }
    buffer[len] = '\0';

    // Clients are only allowed to send one command, disconnect them if they send another.
    if (DoSocketDelete(cli)) {
        return false;
    }

    unsigned long tail = 0;
    static const char _tail[] = " tail=";
    char* cp = strstr(buffer, _tail);
    if (cp) {
        tail = atol(cp + sizeof(_tail) - 1);
    }

    log_time start(log_time::EPOCH);
    static const char _start[] = " start=";
    cp = strstr(buffer, _start);
    if (cp) {
        // Parse errors will result in current time
        start.strptime(cp + sizeof(_start) - 1, "%s.%q");
    }

    std::chrono::steady_clock::time_point deadline = {};
    static const char _timeout[] = " timeout=";
    cp = strstr(buffer, _timeout);
    if (cp) {
        long timeout_seconds = atol(cp + sizeof(_timeout) - 1);
        deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    }

    unsigned int logMask = -1;
    static const char _logIds[] = " lids=";
    cp = strstr(buffer, _logIds);
    if (cp) {
        logMask = 0;
        cp += sizeof(_logIds) - 1;
        while (*cp != '\0') {
            int val = 0;
            while (isdigit(*cp)) {
                val = val * 10 + *cp - '0';
                ++cp;
            }
            logMask |= 1 << val;
            if (*cp != ',') {
                break;
            }
            ++cp;
        }
    }

    pid_t pid = 0;
    static const char _pid[] = " pid=";
    cp = strstr(buffer, _pid);
    if (cp) {
        pid = atol(cp + sizeof(_pid) - 1);
    }

    bool nonBlock = false;
    if (!fastcmp<strncmp>(buffer, "dumpAndClose", 12)) {
        // Allow writer to get some cycles, and wait for pending notifications
        sched_yield();
        logd_lock.lock();
        logd_lock.unlock();
        sched_yield();
        nonBlock = true;
    }

    bool privileged = clientHasLogCredentials(cli);
    bool can_read_security = CanReadSecurityLogs(cli);
    if (!can_read_security) {
        logMask &= ~(1 << LOG_ID_SECURITY);
    }

    std::unique_ptr<LogWriter> socket_log_writer(new SocketLogWriter(this, cli, privileged));

    uint64_t sequence = 1;
    // Convert realtime to sequence number
    if (start != log_time::EPOCH) {
        bool start_time_set = false;
        uint64_t last = sequence;
        auto log_find_start = [pid, start, &sequence, &start_time_set, &last](
                                      log_id_t, pid_t element_pid, uint64_t element_sequence,
                                      log_time element_realtime) -> FilterResult {
            if (pid && pid != element_pid) {
                return FilterResult::kSkip;
            }
            if (start == element_realtime) {
                sequence = element_sequence;
                start_time_set = true;
                return FilterResult::kStop;
            } else {
                if (start < element_realtime) {
                    sequence = last;
                    start_time_set = true;
                    return FilterResult::kStop;
                }
                last = element_sequence;
            }
            return FilterResult::kSkip;
        };
        auto lock = std::lock_guard{logd_lock};
        auto flush_to_state = log_buffer_->CreateFlushToState(sequence, logMask);
        log_buffer_->FlushTo(socket_log_writer.get(), *flush_to_state, log_find_start);

        if (!start_time_set) {
            if (nonBlock) {
                return false;
            }
            sequence = log_buffer_->sequence();
        }
    }

    LOG(INFO) << android::base::StringPrintf(
            "logdr: UID=%d GID=%d PID=%d %c tail=%lu logMask=%x pid=%d "
            "start=%" PRIu64 "ns deadline=%" PRIi64 "ns",
            cli->getUid(), cli->getGid(), cli->getPid(), nonBlock ? 'n' : 'b', tail, logMask,
            (int)pid, start.nsec(), static_cast<int64_t>(deadline.time_since_epoch().count()));

    if (start == log_time::EPOCH) {
        deadline = {};
    }

    auto lock = std::lock_guard{logd_lock};
    auto entry = std::make_unique<LogReaderThread>(log_buffer_, reader_list_,
                                                   std::move(socket_log_writer), nonBlock, tail,
                                                   logMask, pid, start, sequence, deadline);
    // release client and entry reference counts once done
    cli->incRef();
    reader_list_->reader_threads().emplace_front(std::move(entry));

    // Set acceptable upper limit to wait for slow reader processing b/27242723
    struct timeval t = { LOGD_SNDTIMEO, 0 };
    setsockopt(cli->getSocket(), SOL_SOCKET, SO_SNDTIMEO, (const char*)&t,
               sizeof(t));

    return true;
}

bool LogReader::DoSocketDelete(SocketClient* cli) {
    auto cli_name = SocketClientToName(cli);
    auto lock = std::lock_guard{logd_lock};
    for (const auto& reader : reader_list_->reader_threads()) {
        if (reader->name() == cli_name) {
            reader->Release();
            return true;
        }
    }
    return false;
}

int LogReader::getLogSocket() {
    static const char socketName[] = "logdr";
    int sock = android_get_control_socket(socketName);

    if (sock < 0) {
        sock = socket_local_server(
            socketName, ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET);
    }

    return sock;
}
