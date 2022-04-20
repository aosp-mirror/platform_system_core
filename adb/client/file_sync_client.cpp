/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include "client/file_sync_client.h"

#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "sysdeps.h"

#include "adb.h"
#include "adb_client.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "brotli_utils.h"
#include "file_sync_protocol.h"
#include "line_printer.h"
#include "sysdeps/errno.h"
#include "sysdeps/stat.h"

#include "client/commandline.h"

#include <android-base/file.h>
#include <android-base/strings.h>
#include <android-base/stringprintf.h>

using namespace std::literals;

typedef void(sync_ls_cb)(unsigned mode, uint64_t size, uint64_t time, const char* name);

struct syncsendbuf {
    unsigned id;
    unsigned size;
    char data[SYNC_DATA_MAX];
};

static void ensure_trailing_separators(std::string& local_path, std::string& remote_path) {
    if (!adb_is_separator(local_path.back())) {
        local_path.push_back(OS_PATH_SEPARATOR);
    }
    if (remote_path.back() != '/') {
        remote_path.push_back('/');
    }
}

static bool should_pull_file(mode_t mode) {
    return S_ISREG(mode) || S_ISBLK(mode) || S_ISCHR(mode);
}

static bool should_push_file(mode_t mode) {
    return S_ISREG(mode) || S_ISLNK(mode);
}

struct copyinfo {
    std::string lpath;
    std::string rpath;
    int64_t time = 0;
    uint32_t mode;
    uint64_t size = 0;
    bool skip = false;

    copyinfo(const std::string& local_path,
             const std::string& remote_path,
             const std::string& name,
             unsigned int mode)
            : lpath(local_path), rpath(remote_path), mode(mode) {
        ensure_trailing_separators(lpath, rpath);
        lpath.append(name);
        rpath.append(name);
        if (S_ISDIR(mode)) {
            ensure_trailing_separators(lpath, rpath);
        }
    }
};

enum class TransferDirection {
    push,
    pull,
};

struct TransferLedger {
    std::chrono::steady_clock::time_point start_time;
    uint64_t files_transferred;
    uint64_t files_skipped;
    uint64_t bytes_transferred;
    uint64_t bytes_expected;
    bool expect_multiple_files;

  private:
    std::string last_progress_str;
    std::chrono::steady_clock::time_point last_progress_time;

  public:
    TransferLedger() {
        Reset();
    }

    bool operator==(const TransferLedger& other) const {
        return files_transferred == other.files_transferred &&
               files_skipped == other.files_skipped && bytes_transferred == other.bytes_transferred;
    }

    bool operator!=(const TransferLedger& other) const {
        return !(*this == other);
    }

    void Reset() {
        start_time = std::chrono::steady_clock::now();
        files_transferred = 0;
        files_skipped = 0;
        bytes_transferred = 0;
        bytes_expected = 0;
        last_progress_str.clear();
        last_progress_time = {};
    }

    std::string TransferRate() {
        if (bytes_transferred == 0) return "";

        std::chrono::duration<double> duration;
        duration = std::chrono::steady_clock::now() - start_time;

        double s = duration.count();
        if (s == 0) {
            return "";
        }
        double rate = (static_cast<double>(bytes_transferred) / s) / (1024 * 1024);
        return android::base::StringPrintf(" %.1f MB/s (%" PRIu64 " bytes in %.3fs)", rate,
                                           bytes_transferred, s);
    }

    void ReportProgress(LinePrinter& lp, const std::string& file, uint64_t file_copied_bytes,
                        uint64_t file_total_bytes) {
        static constexpr auto kProgressReportInterval = 100ms;

        auto now = std::chrono::steady_clock::now();
        if (now < last_progress_time + kProgressReportInterval) {
            return;
        }
        char overall_percentage_str[5] = "?";
        if (bytes_expected != 0 && bytes_transferred <= bytes_expected) {
            int overall_percentage = static_cast<int>(bytes_transferred * 100 / bytes_expected);
            // If we're pulling symbolic links, we'll pull the target of the link rather than
            // just create a local link, and that will cause us to go over 100%.
            if (overall_percentage <= 100) {
                snprintf(overall_percentage_str, sizeof(overall_percentage_str), "%d%%",
                         overall_percentage);
            }
        }

        std::string output;
        if (file_copied_bytes > file_total_bytes || file_total_bytes == 0) {
            // This case can happen if we're racing against something that wrote to the file
            // between our stat and our read, or if we're reading a magic file that lies about
            // its size. Just show how much we've copied.
            output = android::base::StringPrintf("[%4s] %s: %" PRId64 "/?", overall_percentage_str,
                                                 file.c_str(), file_copied_bytes);
        } else {
            // If we're transferring multiple files, we want to know how far through the current
            // file we are, as well as the overall percentage.
            if (expect_multiple_files) {
                int file_percentage = static_cast<int>(file_copied_bytes * 100 / file_total_bytes);
                output = android::base::StringPrintf("[%4s] %s: %d%%", overall_percentage_str,
                                                     file.c_str(), file_percentage);
            } else {
                output =
                    android::base::StringPrintf("[%4s] %s", overall_percentage_str, file.c_str());
            }
        }
        if (output != last_progress_str) {
            lp.Print(output, LinePrinter::LineType::INFO);
            last_progress_str = std::move(output);
            last_progress_time = now;
        }
    }

    void ReportTransferRate(LinePrinter& lp, const std::string& name, TransferDirection direction) {
        const char* direction_str = (direction == TransferDirection::push) ? "pushed" : "pulled";
        std::stringstream ss;
        if (!name.empty()) {
            std::string_view display_name(name);
            char* out = getenv("ANDROID_PRODUCT_OUT");
            if (out) android::base::ConsumePrefix(&display_name, out);
            ss << display_name << ": ";
        }
        ss << files_transferred << " file" << ((files_transferred == 1) ? "" : "s") << " "
           << direction_str << ", " << files_skipped << " skipped.";
        ss << TransferRate();

        lp.Print(ss.str(), LinePrinter::LineType::INFO);
        lp.KeepInfoLine();
    }
};

class SyncConnection {
  public:
    SyncConnection() : acknowledgement_buffer_(sizeof(sync_status) + SYNC_DATA_MAX) {
        acknowledgement_buffer_.resize(0);
        max = SYNC_DATA_MAX; // TODO: decide at runtime.

        std::string error;
        if (!adb_get_feature_set(&features_, &error)) {
            Error("failed to get feature set: %s", error.c_str());
        } else {
            have_stat_v2_ = CanUseFeature(features_, kFeatureStat2);
            have_ls_v2_ = CanUseFeature(features_, kFeatureLs2);
            have_sendrecv_v2_ = CanUseFeature(features_, kFeatureSendRecv2);
            have_sendrecv_v2_brotli_ = CanUseFeature(features_, kFeatureSendRecv2Brotli);
            fd.reset(adb_connect("sync:", &error));
            if (fd < 0) {
                Error("connect failed: %s", error.c_str());
            }
        }
    }

    ~SyncConnection() {
        if (!IsValid()) return;

        if (SendQuit()) {
            // We sent a quit command, so the server should be doing orderly
            // shutdown soon. But if we encountered an error while we were using
            // the connection, the server might still be sending data (before
            // doing orderly shutdown), in which case we won't wait for all of
            // the data nor the coming orderly shutdown. In the common success
            // case, this will wait for the server to do orderly shutdown.
            ReadOrderlyShutdown(fd);
        }

        line_printer_.KeepInfoLine();
    }

    bool HaveSendRecv2() const { return have_sendrecv_v2_; }
    bool HaveSendRecv2Brotli() const { return have_sendrecv_v2_brotli_; }

    const FeatureSet& Features() const { return features_; }

    bool IsValid() { return fd >= 0; }

    void NewTransfer() {
        current_ledger_.Reset();
    }

    void RecordBytesTransferred(size_t bytes) {
        current_ledger_.bytes_transferred += bytes;
        global_ledger_.bytes_transferred += bytes;
    }

    void RecordFileSent(std::string from, std::string to) {
        RecordFilesTransferred(1);
        deferred_acknowledgements_.emplace_back(std::move(from), std::move(to));
    }

    void RecordFilesTransferred(size_t files) {
        current_ledger_.files_transferred += files;
        global_ledger_.files_transferred += files;
    }

    void RecordFilesSkipped(size_t files) {
        current_ledger_.files_skipped += files;
        global_ledger_.files_skipped += files;
    }

    void ReportProgress(const std::string& file, uint64_t file_copied_bytes,
                        uint64_t file_total_bytes) {
        current_ledger_.ReportProgress(line_printer_, file, file_copied_bytes, file_total_bytes);
    }

    void ReportTransferRate(const std::string& file, TransferDirection direction) {
        current_ledger_.ReportTransferRate(line_printer_, file, direction);
    }

    void ReportOverallTransferRate(TransferDirection direction) {
        if (current_ledger_ != global_ledger_) {
            global_ledger_.ReportTransferRate(line_printer_, "", direction);
        }
    }

    bool SendRequest(int id, const std::string& path) {
        if (path.length() > 1024) {
            Error("SendRequest failed: path too long: %zu", path.length());
            errno = ENAMETOOLONG;
            return false;
        }

        // Sending header and payload in a single write makes a noticeable
        // difference to "adb sync" performance.
        std::vector<char> buf(sizeof(SyncRequest) + path.length());
        SyncRequest* req = reinterpret_cast<SyncRequest*>(&buf[0]);
        req->id = id;
        req->path_length = path.length();
        char* data = reinterpret_cast<char*>(req + 1);
        memcpy(data, path.data(), path.length());
        return WriteFdExactly(fd, buf.data(), buf.size());
    }

    bool SendSend2(std::string_view path, mode_t mode, bool compressed) {
        if (path.length() > 1024) {
            Error("SendRequest failed: path too long: %zu", path.length());
            errno = ENAMETOOLONG;
            return false;
        }

        Block buf;

        SyncRequest req;
        req.id = ID_SEND_V2;
        req.path_length = path.length();

        syncmsg msg;
        msg.send_v2_setup.id = ID_SEND_V2;
        msg.send_v2_setup.mode = mode;
        msg.send_v2_setup.flags = compressed ? kSyncFlagBrotli : kSyncFlagNone;

        buf.resize(sizeof(SyncRequest) + path.length() + sizeof(msg.send_v2_setup));

        void* p = buf.data();

        p = mempcpy(p, &req, sizeof(SyncRequest));
        p = mempcpy(p, path.data(), path.length());
        p = mempcpy(p, &msg.send_v2_setup, sizeof(msg.send_v2_setup));

        return WriteFdExactly(fd, buf.data(), buf.size());
    }

    bool SendRecv2(const std::string& path) {
        if (path.length() > 1024) {
            Error("SendRequest failed: path too long: %zu", path.length());
            errno = ENAMETOOLONG;
            return false;
        }

        Block buf;

        SyncRequest req;
        req.id = ID_RECV_V2;
        req.path_length = path.length();

        syncmsg msg;
        msg.recv_v2_setup.id = ID_RECV_V2;
        msg.recv_v2_setup.flags = kSyncFlagBrotli;

        buf.resize(sizeof(SyncRequest) + path.length() + sizeof(msg.recv_v2_setup));

        void* p = buf.data();

        p = mempcpy(p, &req, sizeof(SyncRequest));
        p = mempcpy(p, path.data(), path.length());
        p = mempcpy(p, &msg.recv_v2_setup, sizeof(msg.recv_v2_setup));

        return WriteFdExactly(fd, buf.data(), buf.size());
    }

    bool SendStat(const std::string& path) {
        if (!have_stat_v2_) {
            errno = ENOTSUP;
            return false;
        }
        return SendRequest(ID_STAT_V2, path);
    }

    bool SendLstat(const std::string& path) {
        if (have_stat_v2_) {
            return SendRequest(ID_LSTAT_V2, path);
        } else {
            return SendRequest(ID_LSTAT_V1, path);
        }
    }

    bool FinishStat(struct stat* st) {
        syncmsg msg;

        memset(st, 0, sizeof(*st));
        if (have_stat_v2_) {
            if (!ReadFdExactly(fd.get(), &msg.stat_v2, sizeof(msg.stat_v2))) {
                PLOG(FATAL) << "protocol fault: failed to read stat response";
            }

            if (msg.stat_v2.id != ID_LSTAT_V2 && msg.stat_v2.id != ID_STAT_V2) {
                PLOG(FATAL) << "protocol fault: stat response has wrong message id: "
                            << msg.stat_v2.id;
            }

            if (msg.stat_v2.error != 0) {
                errno = errno_from_wire(msg.stat_v2.error);
                return false;
            }

            st->st_dev = msg.stat_v2.dev;
            st->st_ino = msg.stat_v2.ino;
            st->st_mode = msg.stat_v2.mode;
            st->st_nlink = msg.stat_v2.nlink;
            st->st_uid = msg.stat_v2.uid;
            st->st_gid = msg.stat_v2.gid;
            st->st_size = msg.stat_v2.size;
            st->st_atime = msg.stat_v2.atime;
            st->st_mtime = msg.stat_v2.mtime;
            st->st_ctime = msg.stat_v2.ctime;
            return true;
        } else {
            if (!ReadFdExactly(fd.get(), &msg.stat_v1, sizeof(msg.stat_v1))) {
                PLOG(FATAL) << "protocol fault: failed to read stat response";
            }

            if (msg.stat_v1.id != ID_LSTAT_V1) {
                LOG(FATAL) << "protocol fault: stat response has wrong message id: "
                           << msg.stat_v1.id;
            }

            if (msg.stat_v1.mode == 0 && msg.stat_v1.size == 0 && msg.stat_v1.mtime == 0) {
                // There's no way for us to know what the error was.
                errno = ENOPROTOOPT;
                return false;
            }

            st->st_mode = msg.stat_v1.mode;
            st->st_size = msg.stat_v1.size;
            st->st_ctime = msg.stat_v1.mtime;
            st->st_mtime = msg.stat_v1.mtime;
        }

        return true;
    }

    bool SendLs(const std::string& path) {
        return SendRequest(have_ls_v2_ ? ID_LIST_V2 : ID_LIST_V1, path);
    }

  private:
    template <bool v2>
    static bool FinishLsImpl(borrowed_fd fd, const std::function<sync_ls_cb>& callback) {
        using dent_type =
                std::conditional_t<v2, decltype(syncmsg::dent_v2), decltype(syncmsg::dent_v1)>;

        while (true) {
            dent_type dent;
            if (!ReadFdExactly(fd, &dent, sizeof(dent))) return false;

            uint32_t expected_id = v2 ? ID_DENT_V2 : ID_DENT_V1;
            if (dent.id == ID_DONE) return true;
            if (dent.id != expected_id) return false;

            // Maximum length of a file name excluding null terminator (NAME_MAX) on Linux is 255.
            char buf[256];
            size_t len = dent.namelen;
            if (len > 255) return false;

            if (!ReadFdExactly(fd, buf, len)) return false;
            buf[len] = 0;

            // Address the unlikely scenario wherein a
            // compromised device/service might be able to
            // traverse across directories on the host. Let's
            // shut that door!
            if (strchr(buf, '/')
#if defined(_WIN32)
                || strchr(buf, '\\')
#endif
            ) {
                return false;
            }
            callback(dent.mode, dent.size, dent.mtime, buf);
        }
    }

  public:
    bool FinishLs(const std::function<sync_ls_cb>& callback) {
        if (have_ls_v2_) {
            return FinishLsImpl<true>(this->fd, callback);
        } else {
            return FinishLsImpl<false>(this->fd, callback);
        }
    }

    // Sending header, payload, and footer in a single write makes a huge
    // difference to "adb sync" performance.
    bool SendSmallFile(const std::string& path, mode_t mode, const std::string& lpath,
                       const std::string& rpath, unsigned mtime, const char* data,
                       size_t data_length) {
        std::string path_and_mode = android::base::StringPrintf("%s,%d", path.c_str(), mode);
        if (path_and_mode.length() > 1024) {
            Error("SendSmallFile failed: path too long: %zu", path_and_mode.length());
            errno = ENAMETOOLONG;
            return false;
        }

        std::vector<char> buf(sizeof(SyncRequest) + path_and_mode.length() + sizeof(SyncRequest) +
                              data_length + sizeof(SyncRequest));
        char* p = &buf[0];

        SyncRequest* req_send = reinterpret_cast<SyncRequest*>(p);
        req_send->id = ID_SEND_V1;
        req_send->path_length = path_and_mode.length();
        p += sizeof(SyncRequest);
        memcpy(p, path_and_mode.data(), path_and_mode.size());
        p += path_and_mode.length();

        SyncRequest* req_data = reinterpret_cast<SyncRequest*>(p);
        req_data->id = ID_DATA;
        req_data->path_length = data_length;
        p += sizeof(SyncRequest);
        memcpy(p, data, data_length);
        p += data_length;

        SyncRequest* req_done = reinterpret_cast<SyncRequest*>(p);
        req_done->id = ID_DONE;
        req_done->path_length = mtime;
        p += sizeof(SyncRequest);

        WriteOrDie(lpath, rpath, &buf[0], (p - &buf[0]));

        RecordFileSent(lpath, rpath);
        RecordBytesTransferred(data_length);
        ReportProgress(rpath, data_length, data_length);
        return true;
    }

    bool SendLargeFileCompressed(const std::string& path, mode_t mode, const std::string& lpath,
                                 const std::string& rpath, unsigned mtime) {
        if (!SendSend2(path, mode, true)) {
            Error("failed to send ID_SEND_V2 message '%s': %s", path.c_str(), strerror(errno));
            return false;
        }

        struct stat st;
        if (stat(lpath.c_str(), &st) == -1) {
            Error("cannot stat '%s': %s", lpath.c_str(), strerror(errno));
            return false;
        }

        uint64_t total_size = st.st_size;
        uint64_t bytes_copied = 0;

        unique_fd lfd(adb_open(lpath.c_str(), O_RDONLY | O_CLOEXEC));
        if (lfd < 0) {
            Error("opening '%s' locally failed: %s", lpath.c_str(), strerror(errno));
            return false;
        }

        syncsendbuf sbuf;
        sbuf.id = ID_DATA;

        BrotliEncoder<SYNC_DATA_MAX> encoder;
        bool sending = true;
        while (sending) {
            Block input(SYNC_DATA_MAX);
            int r = adb_read(lfd.get(), input.data(), input.size());
            if (r < 0) {
                Error("reading '%s' locally failed: %s", lpath.c_str(), strerror(errno));
                return false;
            }

            if (r == 0) {
                encoder.Finish();
            } else {
                input.resize(r);
                encoder.Append(std::move(input));
                RecordBytesTransferred(r);
                bytes_copied += r;
                ReportProgress(rpath, bytes_copied, total_size);
            }

            while (true) {
                Block output;
                BrotliEncodeResult result = encoder.Encode(&output);
                if (result == BrotliEncodeResult::Error) {
                    Error("compressing '%s' locally failed", lpath.c_str());
                    return false;
                }

                if (!output.empty()) {
                    sbuf.size = output.size();
                    memcpy(sbuf.data, output.data(), output.size());
                    WriteOrDie(lpath, rpath, &sbuf, sizeof(SyncRequest) + output.size());
                }

                if (result == BrotliEncodeResult::Done) {
                    sending = false;
                    break;
                } else if (result == BrotliEncodeResult::NeedInput) {
                    break;
                } else if (result == BrotliEncodeResult::MoreOutput) {
                    continue;
                }
            }
        }

        syncmsg msg;
        msg.data.id = ID_DONE;
        msg.data.size = mtime;
        RecordFileSent(lpath, rpath);
        return WriteOrDie(lpath, rpath, &msg.data, sizeof(msg.data));
    }

    bool SendLargeFile(const std::string& path, mode_t mode, const std::string& lpath,
                       const std::string& rpath, unsigned mtime, bool compressed) {
        if (compressed && HaveSendRecv2Brotli()) {
            return SendLargeFileCompressed(path, mode, lpath, rpath, mtime);
        }

        std::string path_and_mode = android::base::StringPrintf("%s,%d", path.c_str(), mode);
        if (!SendRequest(ID_SEND_V1, path_and_mode)) {
            Error("failed to send ID_SEND_V1 message '%s': %s", path_and_mode.c_str(),
                  strerror(errno));
            return false;
        }

        struct stat st;
        if (stat(lpath.c_str(), &st) == -1) {
            Error("cannot stat '%s': %s", lpath.c_str(), strerror(errno));
            return false;
        }

        uint64_t total_size = st.st_size;
        uint64_t bytes_copied = 0;

        unique_fd lfd(adb_open(lpath.c_str(), O_RDONLY | O_CLOEXEC));
        if (lfd < 0) {
            Error("opening '%s' locally failed: %s", lpath.c_str(), strerror(errno));
            return false;
        }

        syncsendbuf sbuf;
        sbuf.id = ID_DATA;

        while (true) {
            int bytes_read = adb_read(lfd, sbuf.data, max);
            if (bytes_read == -1) {
                Error("reading '%s' locally failed: %s", lpath.c_str(), strerror(errno));
                return false;
            } else if (bytes_read == 0) {
                break;
            }

            sbuf.size = bytes_read;
            WriteOrDie(lpath, rpath, &sbuf, sizeof(SyncRequest) + bytes_read);

            RecordBytesTransferred(bytes_read);
            bytes_copied += bytes_read;
            ReportProgress(rpath, bytes_copied, total_size);
        }

        syncmsg msg;
        msg.data.id = ID_DONE;
        msg.data.size = mtime;
        RecordFileSent(lpath, rpath);
        return WriteOrDie(lpath, rpath, &msg.data, sizeof(msg.data));
    }

    bool ReportCopyFailure(const std::string& from, const std::string& to, const syncmsg& msg) {
        std::vector<char> buf(msg.status.msglen + 1);
        if (!ReadFdExactly(fd, &buf[0], msg.status.msglen)) {
            Error("failed to copy '%s' to '%s'; failed to read reason (!): %s", from.c_str(),
                  to.c_str(), strerror(errno));
            return false;
        }
        buf[msg.status.msglen] = 0;
        Error("failed to copy '%s' to '%s': remote %s", from.c_str(), to.c_str(), &buf[0]);
        return false;
    }

    void CopyDone() { deferred_acknowledgements_.pop_front(); }

    void ReportDeferredCopyFailure(const std::string& msg) {
        auto& [from, to] = deferred_acknowledgements_.front();
        Error("failed to copy '%s' to '%s': remote %s", from.c_str(), to.c_str(), msg.c_str());
        deferred_acknowledgements_.pop_front();
    }

    bool ReadAcknowledgements(bool read_all = false) {
        // We need to read enough such that adbd's intermediate socket's write buffer can't be
        // full. The default buffer on Linux is 212992 bytes, but there's 576 bytes of bookkeeping
        // overhead per write. The worst case scenario is a continuous string of failures, since
        // each logical packet is divided into two writes. If our packet size if conservatively 512
        // bytes long, this leaves us with space for 128 responses.
        constexpr size_t max_deferred_acks = 128;
        auto& buf = acknowledgement_buffer_;
        adb_pollfd pfd = {.fd = fd.get(), .events = POLLIN};
        while (!deferred_acknowledgements_.empty()) {
            bool should_block = read_all || deferred_acknowledgements_.size() >= max_deferred_acks;

            ssize_t rc = adb_poll(&pfd, 1, should_block ? -1 : 0);
            if (rc == 0) {
                CHECK(!should_block);
                return true;
            }

            if (acknowledgement_buffer_.size() < sizeof(sync_status)) {
                const ssize_t header_bytes_left = sizeof(sync_status) - buf.size();
                ssize_t rc = adb_read(fd, buf.end(), header_bytes_left);
                if (rc <= 0) {
                    Error("failed to read copy response");
                    return false;
                }

                buf.resize(buf.size() + rc);
                if (rc != header_bytes_left) {
                    // Early exit if we run out of data in the socket.
                    return true;
                }

                if (!should_block) {
                    // We don't want to read again yet, because the socket might be empty.
                    continue;
                }
            }

            auto* hdr = reinterpret_cast<sync_status*>(buf.data());
            if (hdr->id == ID_OKAY) {
                buf.resize(0);
                if (hdr->msglen != 0) {
                    Error("received ID_OKAY with msg_len (%" PRIu32 " != 0", hdr->msglen);
                    return false;
                }
                CopyDone();
                continue;
            } else if (hdr->id != ID_FAIL) {
                Error("unexpected response from daemon: id = %#" PRIx32, hdr->id);
                return false;
            } else if (hdr->msglen > SYNC_DATA_MAX) {
                Error("too-long message length from daemon: msglen = %" PRIu32, hdr->msglen);
                return false;
            }

            const ssize_t msg_bytes_left = hdr->msglen + sizeof(sync_status) - buf.size();
            CHECK_GE(msg_bytes_left, 0);
            if (msg_bytes_left > 0) {
                ssize_t rc = adb_read(fd, buf.end(), msg_bytes_left);
                if (rc <= 0) {
                    Error("failed to read copy failure message");
                    return false;
                }

                buf.resize(buf.size() + rc);
                if (rc != msg_bytes_left) {
                    if (should_block) {
                        continue;
                    } else {
                        return true;
                    }
                }

                std::string msg(buf.begin() + sizeof(sync_status), buf.end());
                ReportDeferredCopyFailure(msg);
                buf.resize(0);
                return false;
            }
        }

        return true;
    }

    void Printf(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3))) {
        std::string s;

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::INFO);
    }

    void Println(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3))) {
        std::string s;

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::INFO);
        line_printer_.KeepInfoLine();
    }

    void Error(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3))) {
        std::string s = "adb: error: ";

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::ERROR);
    }

    void Warning(const char* fmt, ...) __attribute__((__format__(__printf__, 2, 3))) {
        std::string s = "adb: warning: ";

        va_list ap;
        va_start(ap, fmt);
        android::base::StringAppendV(&s, fmt, ap);
        va_end(ap);

        line_printer_.Print(s, LinePrinter::WARNING);
    }

    void ComputeExpectedTotalBytes(const std::vector<copyinfo>& file_list) {
        current_ledger_.bytes_expected = 0;
        for (const copyinfo& ci : file_list) {
            // Unfortunately, this doesn't work for symbolic links, because we'll copy the
            // target of the link rather than just creating a link. (But ci.size is the link size.)
            if (!ci.skip) current_ledger_.bytes_expected += ci.size;
        }
        current_ledger_.expect_multiple_files = true;
    }

    void SetExpectedTotalBytes(uint64_t expected_total_bytes) {
        current_ledger_.bytes_expected = expected_total_bytes;
        current_ledger_.expect_multiple_files = false;
    }

    // TODO: add a char[max] buffer here, to replace syncsendbuf...
    unique_fd fd;
    size_t max;

  private:
    std::deque<std::pair<std::string, std::string>> deferred_acknowledgements_;
    Block acknowledgement_buffer_;
    FeatureSet features_;
    bool have_stat_v2_;
    bool have_ls_v2_;
    bool have_sendrecv_v2_;
    bool have_sendrecv_v2_brotli_;

    TransferLedger global_ledger_;
    TransferLedger current_ledger_;
    LinePrinter line_printer_;

    bool SendQuit() {
        return SendRequest(ID_QUIT, ""); // TODO: add a SendResponse?
    }

    bool WriteOrDie(const std::string& from, const std::string& to, const void* data,
                    size_t data_length) {
        if (!WriteFdExactly(fd, data, data_length)) {
            if (errno == ECONNRESET) {
                // Assume adbd told us why it was closing the connection, and
                // try to read failure reason from adbd.
                syncmsg msg;
                if (!ReadFdExactly(fd, &msg.status, sizeof(msg.status))) {
                    Error("failed to copy '%s' to '%s': no response: %s", from.c_str(), to.c_str(),
                          strerror(errno));
                } else if (msg.status.id != ID_FAIL) {
                    Error("failed to copy '%s' to '%s': not ID_FAIL: %d", from.c_str(), to.c_str(),
                          msg.status.id);
                } else {
                    ReportCopyFailure(from, to, msg);
                }
            } else {
                Error("%zu-byte write failed: %s", data_length, strerror(errno));
            }
            _exit(1);
        }
        return true;
    }
};

static bool sync_ls(SyncConnection& sc, const std::string& path,
                    const std::function<sync_ls_cb>& func) {
    return sc.SendLs(path) && sc.FinishLs(func);
}

static bool sync_stat(SyncConnection& sc, const std::string& path, struct stat* st) {
    return sc.SendStat(path) && sc.FinishStat(st);
}

static bool sync_lstat(SyncConnection& sc, const std::string& path, struct stat* st) {
    return sc.SendLstat(path) && sc.FinishStat(st);
}

static bool sync_stat_fallback(SyncConnection& sc, const std::string& path, struct stat* st) {
    if (sync_stat(sc, path, st)) {
        return true;
    }

    if (errno != ENOTSUP) {
        return false;
    }

    // Try to emulate the parts we can when talking to older adbds.
    bool lstat_result = sync_lstat(sc, path, st);
    if (!lstat_result) {
        return false;
    }

    if (S_ISLNK(st->st_mode)) {
        // If the target is a symlink, figure out whether it's a file or a directory.
        // Also, zero out the st_size field, since no one actually cares what the path length is.
        st->st_size = 0;
        std::string dir_path = path;
        dir_path.push_back('/');
        struct stat tmp_st;

        st->st_mode &= ~S_IFMT;
        if (sync_lstat(sc, dir_path, &tmp_st)) {
            st->st_mode |= S_IFDIR;
        } else {
            st->st_mode |= S_IFREG;
        }
    }
    return true;
}

static bool sync_send(SyncConnection& sc, const std::string& lpath, const std::string& rpath,
                      unsigned mtime, mode_t mode, bool sync, bool compressed) {
    if (sync) {
        struct stat st;
        if (sync_lstat(sc, rpath, &st)) {
            if (st.st_mtime == static_cast<time_t>(mtime)) {
                sc.RecordFilesSkipped(1);
                return true;
            }
        }
    }

    if (S_ISLNK(mode)) {
#if !defined(_WIN32)
        char buf[PATH_MAX];
        ssize_t data_length = readlink(lpath.c_str(), buf, PATH_MAX - 1);
        if (data_length == -1) {
            sc.Error("readlink '%s' failed: %s", lpath.c_str(), strerror(errno));
            return false;
        }
        buf[data_length++] = '\0';

        if (!sc.SendSmallFile(rpath, mode, lpath, rpath, mtime, buf, data_length)) {
            return false;
        }
        return sc.ReadAcknowledgements();
#endif
    }

    struct stat st;
    if (stat(lpath.c_str(), &st) == -1) {
        sc.Error("failed to stat local file '%s': %s", lpath.c_str(), strerror(errno));
        return false;
    }
    if (st.st_size < SYNC_DATA_MAX) {
        std::string data;
        if (!android::base::ReadFileToString(lpath, &data, true)) {
            sc.Error("failed to read all of '%s': %s", lpath.c_str(), strerror(errno));
            return false;
        }
        if (!sc.SendSmallFile(rpath, mode, lpath, rpath, mtime, data.data(), data.size())) {
            return false;
        }
    } else {
        if (!sc.SendLargeFile(rpath, mode, lpath, rpath, mtime, compressed)) {
            return false;
        }
    }
    return sc.ReadAcknowledgements();
}

static bool sync_recv_v1(SyncConnection& sc, const char* rpath, const char* lpath, const char* name,
                         uint64_t expected_size) {
    if (!sc.SendRequest(ID_RECV_V1, rpath)) return false;

    adb_unlink(lpath);
    unique_fd lfd(adb_creat(lpath, 0644));
    if (lfd < 0) {
        sc.Error("cannot create '%s': %s", lpath, strerror(errno));
        return false;
    }

    uint64_t bytes_copied = 0;
    while (true) {
        syncmsg msg;
        if (!ReadFdExactly(sc.fd, &msg.data, sizeof(msg.data))) {
            adb_unlink(lpath);
            return false;
        }

        if (msg.data.id == ID_DONE) break;

        if (msg.data.id != ID_DATA) {
            adb_unlink(lpath);
            sc.ReportCopyFailure(rpath, lpath, msg);
            return false;
        }

        if (msg.data.size > sc.max) {
            sc.Error("msg.data.size too large: %u (max %zu)", msg.data.size, sc.max);
            adb_unlink(lpath);
            return false;
        }

        char buffer[SYNC_DATA_MAX];
        if (!ReadFdExactly(sc.fd, buffer, msg.data.size)) {
            adb_unlink(lpath);
            return false;
        }

        if (!WriteFdExactly(lfd, buffer, msg.data.size)) {
            sc.Error("cannot write '%s': %s", lpath, strerror(errno));
            adb_unlink(lpath);
            return false;
        }

        bytes_copied += msg.data.size;

        sc.RecordBytesTransferred(msg.data.size);
        sc.ReportProgress(name != nullptr ? name : rpath, bytes_copied, expected_size);
    }

    sc.RecordFilesTransferred(1);
    return true;
}

static bool sync_recv_v2(SyncConnection& sc, const char* rpath, const char* lpath, const char* name,
                         uint64_t expected_size) {
    if (!sc.SendRecv2(rpath)) return false;

    adb_unlink(lpath);
    unique_fd lfd(adb_creat(lpath, 0644));
    if (lfd < 0) {
        sc.Error("cannot create '%s': %s", lpath, strerror(errno));
        return false;
    }

    uint64_t bytes_copied = 0;

    Block buffer(SYNC_DATA_MAX);
    BrotliDecoder decoder(std::span(buffer.data(), buffer.size()));
    bool reading = true;
    while (reading) {
        syncmsg msg;
        if (!ReadFdExactly(sc.fd, &msg.data, sizeof(msg.data))) {
            adb_unlink(lpath);
            return false;
        }

        if (msg.data.id == ID_DONE) {
            adb_unlink(lpath);
            sc.Error("unexpected ID_DONE");
            return false;
        }

        if (msg.data.id != ID_DATA) {
            adb_unlink(lpath);
            sc.ReportCopyFailure(rpath, lpath, msg);
            return false;
        }

        if (msg.data.size > sc.max) {
            sc.Error("msg.data.size too large: %u (max %zu)", msg.data.size, sc.max);
            adb_unlink(lpath);
            return false;
        }

        Block block(msg.data.size);
        if (!ReadFdExactly(sc.fd, block.data(), msg.data.size)) {
            adb_unlink(lpath);
            return false;
        }
        decoder.Append(std::move(block));

        while (true) {
            std::span<char> output;
            BrotliDecodeResult result = decoder.Decode(&output);

            if (result == BrotliDecodeResult::Error) {
                sc.Error("decompress failed");
                adb_unlink(lpath);
                return false;
            }

            if (!output.empty()) {
                if (!WriteFdExactly(lfd, output.data(), output.size())) {
                    sc.Error("cannot write '%s': %s", lpath, strerror(errno));
                    adb_unlink(lpath);
                    return false;
                }
            }

            bytes_copied += output.size();

            sc.RecordBytesTransferred(msg.data.size);
            sc.ReportProgress(name != nullptr ? name : rpath, bytes_copied, expected_size);

            if (result == BrotliDecodeResult::NeedInput) {
                break;
            } else if (result == BrotliDecodeResult::MoreOutput) {
                continue;
            } else if (result == BrotliDecodeResult::Done) {
                reading = false;
                break;
            } else {
                LOG(FATAL) << "invalid BrotliDecodeResult: " << static_cast<int>(result);
            }
        }
    }

    syncmsg msg;
    if (!ReadFdExactly(sc.fd, &msg.data, sizeof(msg.data))) {
        sc.Error("failed to read ID_DONE");
        return false;
    }

    if (msg.data.id != ID_DONE) {
        sc.Error("unexpected message after transfer: id = %d (expected ID_DONE)", msg.data.id);
        return false;
    }

    sc.RecordFilesTransferred(1);
    return true;
}

static bool sync_recv(SyncConnection& sc, const char* rpath, const char* lpath, const char* name,
                      uint64_t expected_size, bool compressed) {
    if (sc.HaveSendRecv2() && compressed) {
        return sync_recv_v2(sc, rpath, lpath, name, expected_size);
    } else {
        return sync_recv_v1(sc, rpath, lpath, name, expected_size);
    }
}

bool do_sync_ls(const char* path) {
    SyncConnection sc;
    if (!sc.IsValid()) return false;

    return sync_ls(sc, path, [](unsigned mode, uint64_t size, uint64_t time, const char* name) {
        printf("%08x %08" PRIx64 " %08" PRIx64 " %s\n", mode, size, time, name);
    });
}

static bool IsDotOrDotDot(const char* name) {
    return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static bool local_build_list(SyncConnection& sc, std::vector<copyinfo>* file_list,
                             std::vector<std::string>* directory_list, const std::string& lpath,
                             const std::string& rpath) {
    std::vector<copyinfo> dirlist;
    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(lpath.c_str()), closedir);
    if (!dir) {
        sc.Error("cannot open '%s': %s", lpath.c_str(), strerror(errno));
        return false;
    }

    bool empty_dir = true;
    dirent* de;
    while ((de = readdir(dir.get()))) {
        if (IsDotOrDotDot(de->d_name)) {
            continue;
        }

        empty_dir = false;
        std::string stat_path = lpath + de->d_name;

        struct stat st;
        if (lstat(stat_path.c_str(), &st) == -1) {
            sc.Error("cannot lstat '%s': %s", stat_path.c_str(),
                     strerror(errno));
            continue;
        }

        copyinfo ci(lpath, rpath, de->d_name, st.st_mode);
        if (S_ISDIR(st.st_mode)) {
            dirlist.push_back(ci);
        } else {
            if (!should_push_file(st.st_mode)) {
                sc.Warning("skipping special file '%s' (mode = 0o%o)", lpath.c_str(), st.st_mode);
                ci.skip = true;
            }
            ci.time = st.st_mtime;
            ci.size = st.st_size;
            file_list->push_back(ci);
        }
    }

    // Close this directory and recurse.
    dir.reset();

    for (const copyinfo& ci : dirlist) {
        directory_list->push_back(ci.rpath);
        local_build_list(sc, file_list, directory_list, ci.lpath, ci.rpath);
    }

    return true;
}

// dirname("//foo") returns "//", so we can't do the obvious `path == "/"`.
static bool is_root_dir(std::string_view path) {
    for (char c : path) {
        if (c != '/') {
            return false;
        }
    }
    return true;
}

static bool copy_local_dir_remote(SyncConnection& sc, std::string lpath, std::string rpath,
                                  bool check_timestamps, bool list_only, bool compressed) {
    sc.NewTransfer();

    // Make sure that both directory paths end in a slash.
    // Both paths are known to be nonempty, so we don't need to check.
    ensure_trailing_separators(lpath, rpath);

    // Recursively build the list of files to copy.
    std::vector<copyinfo> file_list;
    std::vector<std::string> directory_list;

    for (std::string path = rpath; !is_root_dir(path); path = android::base::Dirname(path)) {
        directory_list.push_back(path);
    }
    std::reverse(directory_list.begin(), directory_list.end());

    int skipped = 0;
    if (!local_build_list(sc, &file_list, &directory_list, lpath, rpath)) {
        return false;
    }

    // b/110953234:
    // P shipped with a bug that causes directory creation as a side-effect of a push to fail.
    // Work around this by explicitly doing a mkdir via shell.
    //
    // Devices that don't support shell_v2 are unhappy if we try to send a too-long packet to them,
    // but they're not affected by this bug, so only apply the workaround if we have shell_v2.
    //
    // TODO(b/25457350): We don't preserve permissions on directories.
    // TODO: Find all of the leaves and `mkdir -p` them instead?
    if (!CanUseFeature(sc.Features(), kFeatureFixedPushMkdir) &&
        CanUseFeature(sc.Features(), kFeatureShell2)) {
        SilentStandardStreamsCallbackInterface cb;
        std::string cmd = "mkdir";
        for (const auto& dir : directory_list) {
            std::string escaped_path = escape_arg(dir);
            if (escaped_path.size() > 16384) {
                // Somewhat arbitrarily limit that probably won't ever happen.
                sc.Error("path too long: %s", escaped_path.c_str());
                return false;
            }

            // The maximum should be 64kiB, but that's not including other stuff that gets tacked
            // onto the command line, so let's be a bit conservative.
            if (cmd.size() + escaped_path.size() > 32768) {
                // Dispatch the command, ignoring failure (since the directory might already exist).
                send_shell_command(cmd, false, &cb);
                cmd = "mkdir";
            }
            cmd += " ";
            cmd += escaped_path;
        }

        if (cmd != "mkdir") {
            send_shell_command(cmd, false, &cb);
        }
    }

    if (check_timestamps) {
        for (const copyinfo& ci : file_list) {
            if (!sc.SendLstat(ci.rpath)) {
                sc.Error("failed to send lstat");
                return false;
            }
        }
        for (copyinfo& ci : file_list) {
            struct stat st;
            if (sc.FinishStat(&st)) {
                if (st.st_size == static_cast<off_t>(ci.size) && st.st_mtime == ci.time) {
                    ci.skip = true;
                }
            }
        }
    }

    sc.ComputeExpectedTotalBytes(file_list);

    for (const copyinfo& ci : file_list) {
        if (!ci.skip) {
            if (list_only) {
                sc.Println("would push: %s -> %s", ci.lpath.c_str(), ci.rpath.c_str());
            } else {
                if (!sync_send(sc, ci.lpath, ci.rpath, ci.time, ci.mode, false, compressed)) {
                    return false;
                }
            }
        } else {
            skipped++;
        }
    }

    sc.RecordFilesSkipped(skipped);
    bool success = sc.ReadAcknowledgements(true);
    sc.ReportTransferRate(lpath, TransferDirection::push);
    return success;
}

bool do_sync_push(const std::vector<const char*>& srcs, const char* dst, bool sync,
                  bool compressed) {
    SyncConnection sc;
    if (!sc.IsValid()) return false;

    bool success = true;
    bool dst_exists;
    bool dst_isdir;

    struct stat st;
    if (sync_stat_fallback(sc, dst, &st)) {
        dst_exists = true;
        dst_isdir = S_ISDIR(st.st_mode);
    } else {
        if (errno == ENOENT || errno == ENOPROTOOPT) {
            dst_exists = false;
            dst_isdir = false;
        } else {
            sc.Error("stat failed when trying to push to %s: %s", dst, strerror(errno));
            return false;
        }
    }

    if (!dst_isdir) {
        if (srcs.size() > 1) {
            sc.Error("target '%s' is not a directory", dst);
            return false;
        } else {
            size_t dst_len = strlen(dst);

            // A path that ends with a slash doesn't have to be a directory if
            // it doesn't exist yet.
            if (dst[dst_len - 1] == '/' && dst_exists) {
                sc.Error("failed to access '%s': Not a directory", dst);
                return false;
            }
        }
    }

    for (const char* src_path : srcs) {
        const char* dst_path = dst;
        struct stat st;
        if (stat(src_path, &st) == -1) {
            sc.Error("cannot stat '%s': %s", src_path, strerror(errno));
            success = false;
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            std::string dst_dir = dst;

            // If the destination path existed originally, the source directory
            // should be copied as a child of the destination.
            if (dst_exists) {
                if (!dst_isdir) {
                    sc.Error("target '%s' is not a directory", dst);
                    return false;
                }
                // dst is a POSIX path, so we don't want to use the sysdeps
                // helpers here.
                if (dst_dir.back() != '/') {
                    dst_dir.push_back('/');
                }
                dst_dir.append(android::base::Basename(src_path));
            }

            success &= copy_local_dir_remote(sc, src_path, dst_dir, sync, false, compressed);
            continue;
        } else if (!should_push_file(st.st_mode)) {
            sc.Warning("skipping special file '%s' (mode = 0o%o)", src_path, st.st_mode);
            continue;
        }

        std::string path_holder;
        if (dst_isdir) {
            // If we're copying a local file to a remote directory,
            // we really want to copy to remote_dir + "/" + local_filename.
            path_holder = dst_path;
            if (path_holder.back() != '/') {
                path_holder.push_back('/');
            }
            path_holder += android::base::Basename(src_path);
            dst_path = path_holder.c_str();
        }

        sc.NewTransfer();
        sc.SetExpectedTotalBytes(st.st_size);
        success &= sync_send(sc, src_path, dst_path, st.st_mtime, st.st_mode, sync, compressed);
        sc.ReportTransferRate(src_path, TransferDirection::push);
    }

    success &= sc.ReadAcknowledgements(true);
    sc.ReportOverallTransferRate(TransferDirection::push);
    return success;
}

static bool remote_build_list(SyncConnection& sc, std::vector<copyinfo>* file_list,
                              const std::string& rpath, const std::string& lpath) {
    std::vector<copyinfo> dirlist;
    std::vector<copyinfo> linklist;

    // Add an entry for the current directory to ensure it gets created before pulling its contents.
    copyinfo ci(android::base::Dirname(lpath), android::base::Dirname(rpath),
                android::base::Basename(lpath), S_IFDIR);
    file_list->push_back(ci);

    // Put the files/dirs in rpath on the lists.
    auto callback = [&](unsigned mode, uint64_t size, uint64_t time, const char* name) {
        if (IsDotOrDotDot(name)) {
            return;
        }

        copyinfo ci(lpath, rpath, name, mode);
        if (S_ISDIR(mode)) {
            dirlist.push_back(ci);
        } else if (S_ISLNK(mode)) {
            linklist.push_back(ci);
        } else {
            if (!should_pull_file(ci.mode)) {
                sc.Warning("skipping special file '%s' (mode = 0o%o)", ci.rpath.c_str(), ci.mode);
                ci.skip = true;
            }
            ci.time = time;
            ci.size = size;
            file_list->push_back(ci);
        }
    };

    if (!sync_ls(sc, rpath.c_str(), callback)) {
        return false;
    }

    // Check each symlink we found to see whether it's a file or directory.
    for (copyinfo& link_ci : linklist) {
        struct stat st;
        if (!sync_stat_fallback(sc, link_ci.rpath.c_str(), &st)) {
            sc.Warning("stat failed for path %s: %s", link_ci.rpath.c_str(), strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            dirlist.emplace_back(std::move(link_ci));
        } else {
            file_list->emplace_back(std::move(link_ci));
        }
    }

    // Recurse into each directory we found.
    while (!dirlist.empty()) {
        copyinfo current = dirlist.back();
        dirlist.pop_back();
        if (!remote_build_list(sc, file_list, current.rpath, current.lpath)) {
            return false;
        }
    }

    return true;
}

static int set_time_and_mode(const std::string& lpath, time_t time,
                             unsigned int mode) {
    struct utimbuf times = { time, time };
    int r1 = utime(lpath.c_str(), &times);

    /* use umask for permissions */
    mode_t mask = umask(0000);
    umask(mask);
    int r2 = chmod(lpath.c_str(), mode & ~mask);

    return r1 ? r1 : r2;
}

static bool copy_remote_dir_local(SyncConnection& sc, std::string rpath, std::string lpath,
                                  bool copy_attrs, bool compressed) {
    sc.NewTransfer();

    // Make sure that both directory paths end in a slash.
    // Both paths are known to be nonempty, so we don't need to check.
    ensure_trailing_separators(lpath, rpath);

    // Recursively build the list of files to copy.
    sc.Printf("pull: building file list...");
    std::vector<copyinfo> file_list;
    if (!remote_build_list(sc, &file_list, rpath, lpath)) {
        return false;
    }

    sc.ComputeExpectedTotalBytes(file_list);

    int skipped = 0;
    for (const copyinfo &ci : file_list) {
        if (!ci.skip) {
            if (S_ISDIR(ci.mode)) {
                // Entry is for an empty directory, create it and continue.
                // TODO(b/25457350): We don't preserve permissions on directories.
                if (!mkdirs(ci.lpath))  {
                    sc.Error("failed to create directory '%s': %s",
                             ci.lpath.c_str(), strerror(errno));
                    return false;
                }
                continue;
            }

            if (!sync_recv(sc, ci.rpath.c_str(), ci.lpath.c_str(), nullptr, ci.size, compressed)) {
                return false;
            }

            if (copy_attrs && set_time_and_mode(ci.lpath, ci.time, ci.mode)) {
                return false;
            }
        } else {
            skipped++;
        }
    }

    sc.RecordFilesSkipped(skipped);
    sc.ReportTransferRate(rpath, TransferDirection::pull);
    return true;
}

bool do_sync_pull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                  bool compressed, const char* name) {
    SyncConnection sc;
    if (!sc.IsValid()) return false;

    bool success = true;
    struct stat st;
    bool dst_exists = true;

    if (stat(dst, &st) == -1) {
        dst_exists = false;

        // If we're only pulling one path, the destination path might point to
        // a path that doesn't exist yet.
        if (srcs.size() == 1 && errno == ENOENT) {
            // However, its parent must exist.
            struct stat parent_st;
            if (stat(android::base::Dirname(dst).c_str(), &parent_st) == -1) {
                sc.Error("cannot create file/directory '%s': %s", dst, strerror(errno));
                return false;
            }
        } else {
            sc.Error("failed to access '%s': %s", dst, strerror(errno));
            return false;
        }
    }

    bool dst_isdir = dst_exists && S_ISDIR(st.st_mode);
    if (!dst_isdir) {
        if (srcs.size() > 1) {
            sc.Error("target '%s' is not a directory", dst);
            return false;
        } else {
            size_t dst_len = strlen(dst);

            // A path that ends with a slash doesn't have to be a directory if
            // it doesn't exist yet.
            if (adb_is_separator(dst[dst_len - 1]) && dst_exists) {
                sc.Error("failed to access '%s': Not a directory", dst);
                return false;
            }
        }
    }

    for (const char* src_path : srcs) {
        const char* dst_path = dst;
        struct stat src_st;
        if (!sync_stat_fallback(sc, src_path, &src_st)) {
            if (errno == ENOPROTOOPT) {
                sc.Error("remote object '%s' does not exist", src_path);
            } else {
                sc.Error("failed to stat remote object '%s': %s", src_path, strerror(errno));
            }

            success = false;
            continue;
        }

        bool src_isdir = S_ISDIR(src_st.st_mode);
        if (src_isdir) {
            std::string dst_dir = dst;

            // If the destination path existed originally, the source directory
            // should be copied as a child of the destination.
            if (dst_exists) {
                if (!dst_isdir) {
                    sc.Error("target '%s' is not a directory", dst);
                    return false;
                }
                if (!adb_is_separator(dst_dir.back())) {
                    dst_dir.push_back(OS_PATH_SEPARATOR);
                }
                dst_dir.append(android::base::Basename(src_path));
            }

            success &= copy_remote_dir_local(sc, src_path, dst_dir, copy_attrs, compressed);
            continue;
        } else if (!should_pull_file(src_st.st_mode)) {
            sc.Warning("skipping special file '%s' (mode = 0o%o)", src_path, src_st.st_mode);
            continue;
        }

        std::string path_holder;
        if (dst_isdir) {
            // If we're copying a remote file to a local directory, we
            // really want to copy to local_dir + OS_PATH_SEPARATOR +
            // basename(remote).
            path_holder = android::base::StringPrintf("%s%c%s", dst_path, OS_PATH_SEPARATOR,
                                                      android::base::Basename(src_path).c_str());
            dst_path = path_holder.c_str();
        }

        sc.NewTransfer();
        sc.SetExpectedTotalBytes(src_st.st_size);
        if (!sync_recv(sc, src_path, dst_path, name, src_st.st_size, compressed)) {
            success = false;
            continue;
        }

        if (copy_attrs && set_time_and_mode(dst_path, src_st.st_mtime, src_st.st_mode) != 0) {
            success = false;
            continue;
        }
        sc.ReportTransferRate(src_path, TransferDirection::pull);
    }

    sc.ReportOverallTransferRate(TransferDirection::pull);
    return success;
}

bool do_sync_sync(const std::string& lpath, const std::string& rpath, bool list_only,
                  bool compressed) {
    SyncConnection sc;
    if (!sc.IsValid()) return false;

    bool success = copy_local_dir_remote(sc, lpath, rpath, true, list_only, compressed);
    if (!list_only) {
        sc.ReportOverallTransferRate(TransferDirection::push);
    }
    return success;
}
